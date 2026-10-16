using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace GitCredentialManager.DpopDemo;

internal sealed class DpopDemoHostProvider
{
    private const int ObservationTtlSeconds = 3600;
    private readonly DpopDemoConfig _config;
    private readonly Func<string, IGithubAuthNative> _createNative;

    internal DpopDemoHostProvider(DpopDemoConfig config, Func<string, IGithubAuthNative> createNative = null)
    {
        _config = config;
        _createNative = createNative ?? (path => new GithubAuthNative(path));
    }

    internal string Execute(string command, GitRequest input)
    {
        if (command is "store" or "erase")
        {
            DpopDemoProtocol.ValidateLegacy(input);
            return null;
        }
        if (command is not ("get" or "observe"))
        {
            throw DpopDemoProtocol.Invalid("Unsupported GCM DPoP demo command.");
        }
        DpopDemoRequest request = DpopDemoProtocol.Validate(input, _config, command);
        byte[] config = _config.NativeConfiguration();
        try
        {
            using IGithubAuthNative native = _createNative(_config.Library);
            using var sdk = new GithubAuthSession(native);
            sdk.Open(config, _config.BrokerInstanceId);

            if (command == "observe")
            {
                if (request.Status == 0)
                {
                    JsonElement discarded = sdk.Call("nonce.discard", new { attempt_id = request.AttemptId });
                    _ = discarded.GetProperty("discarded").GetBoolean();
                    return null;
                }
                JsonElement observed = sdk.Call("nonce.observe", new { attempt_id = request.AttemptId,
                    status = request.Status.Value, headers = request.Headers });
                // Git ignores stdout and chooses its own bounded retry policy.
                // A false verdict is a valid acknowledgement, including on success.
                _ = observed.GetProperty("retry").GetBoolean();
                _ = observed.GetProperty("new_proof_required").GetBoolean();
                return null;
            }

            JsonElement prepared = sdk.Call("request.prepare", new { credential_id = _config.CredentialId,
                method = request.Method, url = request.Url, observation_ttl_seconds = ObservationTtlSeconds });
            JsonElement headers = prepared.GetProperty("headers");
            var entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (JsonProperty entry in headers.EnumerateObject())
            {
                if (!entries.TryAdd(entry.Name, entry.Value.GetString()))
                {
                    throw DpopDemoProtocol.Invalid("Ambiguous native request headers.");
                }
            }
            if (entries.Count != 2 || !entries.TryGetValue("authorization", out string authorization) ||
                authorization is null || !authorization.StartsWith("DPoP ", StringComparison.Ordinal) ||
                !DpopDemoProtocol.IsVisible(authorization[5..], 16384) ||
                !entries.TryGetValue("dpop", out string proof) || !ValidProof(proof) ||
                !prepared.TryGetProperty("attempt_id", out var attemptValue) ||
                !Guid.TryParseExact(attemptValue.GetString(), "D", out _))
            {
                throw DpopDemoProtocol.Invalid("The SDK must return DPoP authorization, a fresh proof, and an attempt; downgrade refused.");
            }

            // These are the only secrets emitted, directly to Git's pipe.
            // Never use upstream AdditionalProperties or tracing for the proof.
            return DpopDemoProtocol.FormatCredential(authorization[5..], proof, attemptValue.GetString());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(config);
        }
    }

    private static bool ValidProof(string proof) =>
        DpopDemoProtocol.IsVisible(proof, 16384) && proof.Split('.') is { Length: 3 } parts &&
        parts.All(x => x.Length > 0 && x.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
}
