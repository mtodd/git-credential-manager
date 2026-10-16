using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GitCredentialManager.DpopDemo;
using Xunit;

namespace GitCredentialManager.Tests.DpopDemo;

public sealed class DpopDemoNativeAbiFactAttribute : FactAttribute
{
    public DpopDemoNativeAbiFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GCM_DPOP_NATIVE_LIBRARY")))
        {
            Skip = "Set GCM_DPOP_NATIVE_LIBRARY to the verified lifecycle-enabled github-auth-ffi library.";
        }
    }
}

public class DpopDemoNativeAbiTests
{
    private const string Origin = "https://127.0.0.1:9443";
    private const string Url = Origin + "/demo.git/info/refs?service=git-upload-pack";

    [DpopDemoNativeAbiFact]
    public void RealNativeBindings_ObserveDiscardAndWindowUseOnlySyntheticMemoryState()
    {
        using var native = new GithubAuthNative(Environment.GetEnvironmentVariable("GCM_DPOP_NATIVE_LIBRARY"));
        Assert.Equal(1U, native.AbiVersion());
        ulong handle = 0;
        byte[] config = MemoryConfig();
        try
        {
            int status = native.Open(config, out handle, out GithubAuthBuffer opened);
            JsonElement info = Take(native, status, opened).GetProperty("result");
            Assert.NotEqual(0UL, handle);
            Assert.Equal("embedded", info.GetProperty("backend").GetProperty("selected").GetString());
            Assert.False(Call(native, handle, "broker.info", new { }).GetProperty("result")
                .GetProperty("state_persistent").GetBoolean());

            JsonElement key = Call(native, handle, "keys.create", new
            {
                label = "GCM native binding test",
                origins = new[] { Origin },
                options = new { provider = "software", allow_software = true }
            }).GetProperty("result");
            Assert.False(key.TryGetProperty("opaque", out _));
            string keyId = key.GetProperty("id").GetString();
            object ProofParameters(int ttl) => new
            {
                key_id = keyId, method = "GET", url = Url, role = "resource",
                ath = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes("synthetic-native-token")))
                    .TrimEnd('=').Replace('+', '-').Replace('/', '_'),
                observation_ttl_seconds = ttl
            };

            JsonElement missingCredential = Call(native, handle, "request.prepare", new
            {
                credential_id = "11111111-1111-4111-8111-111111111111", method = "GET",
                url = Url, observation_ttl_seconds = 3600
            }, expectedStatus: 2);
            Assert.Equal("not_found", missingCredential.GetProperty("error").GetProperty("code").GetString());

            foreach (int invalidTtl in new[] { 0, 3601 })
            {
                JsonElement invalid = Call(native, handle, "dpop.proof", ProofParameters(invalidTtl), expectedStatus: 1);
                Assert.Equal("invalid_request", invalid.GetProperty("error").GetProperty("code").GetString());
            }

            JsonElement first = Call(native, handle, "dpop.proof", ProofParameters(3600)).GetProperty("result");
            string firstAttempt = first.GetProperty("attempt_id").GetString();
            Assert.True(Guid.TryParseExact(firstAttempt, "D", out _));
            JsonElement noResponse = Call(native, handle, "nonce.observe", new
            {
                attempt_id = firstAttempt, status = 0, headers = new { }
            }, expectedStatus: 1);
            Assert.Equal("invalid_request", noResponse.GetProperty("error").GetProperty("code").GetString());
            Assert.True(Call(native, handle, "nonce.discard", new { attempt_id = firstAttempt })
                .GetProperty("result").GetProperty("discarded").GetBoolean());
            Assert.False(Call(native, handle, "nonce.discard", new { attempt_id = firstAttempt })
                .GetProperty("result").GetProperty("discarded").GetBoolean());

            JsonElement second = Call(native, handle, "dpop.proof", ProofParameters(3600)).GetProperty("result");
            string secondAttempt = second.GetProperty("attempt_id").GetString();
            Assert.NotEqual(firstAttempt, secondAttempt);
            Assert.True(first.GetProperty("proof").GetString() != second.GetProperty("proof").GetString(),
                "The native SDK must create a fresh proof.");
            JsonElement observed = Call(native, handle, "nonce.observe", new
            {
                attempt_id = secondAttempt, status = 200,
                headers = new Dictionary<string, string> { ["dpop-nonce"] = "synthetic-native-nonce" }
            }).GetProperty("result");
            Assert.False(observed.GetProperty("retry").GetBoolean());
            Assert.False(observed.GetProperty("new_proof_required").GetBoolean());
            Assert.False(Call(native, handle, "nonce.discard", new { attempt_id = secondAttempt })
                .GetProperty("result").GetProperty("discarded").GetBoolean());

            JsonElement third = Call(native, handle, "dpop.proof", ProofParameters(3600)).GetProperty("result");
            string payload = third.GetProperty("proof").GetString().Split('.')[1].Replace('-', '+').Replace('_', '/');
            byte[] decoded = Convert.FromBase64String(payload.PadRight((payload.Length + 3) / 4 * 4, '='));
            try
            {
                using JsonDocument claims = JsonDocument.Parse(decoded);
                Assert.Equal("synthetic-native-nonce", claims.RootElement.GetProperty("nonce").GetString());
                Assert.Equal("GET", claims.RootElement.GetProperty("htm").GetString());
                Assert.Equal(Origin + "/demo.git/info/refs", claims.RootElement.GetProperty("htu").GetString());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(decoded);
            }
            Assert.True(Call(native, handle, "nonce.discard", new { attempt_id = third.GetProperty("attempt_id").GetString() })
                .GetProperty("result").GetProperty("discarded").GetBoolean());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(config);
            if (handle != 0)
            {
                int status = native.Close(handle, out GithubAuthBuffer closed);
                Take(native, status, closed);
            }
        }
    }

    [DpopDemoNativeAbiFact]
    public void RealNativeSession_RejectsEmbeddedBackendAndClosesWithoutWeakeningBrokerPolicy()
    {
        using var native = new GithubAuthNative(Environment.GetEnvironmentVariable("GCM_DPOP_NATIVE_LIBRARY"));
        using var sdk = new GithubAuthSession(native);
        byte[] config = MemoryConfig();
        Assert.Throws<DpopDemoException>(() => sdk.Open(config, Guid.Empty));
        Assert.All(config, value => Assert.Equal(0, value));
        sdk.Dispose();
        Assert.Throws<DpopDemoException>(() => sdk.Call("broker.info", new { }));
    }

    private static byte[] MemoryConfig() => JsonSerializer.SerializeToUtf8Bytes(new
    {
        mode = "embedded", application_id = "git-dpop-native-binding-test",
        embedded = new { storage = new { kind = "memory" } }
    });

    private static JsonElement Call(GithubAuthNative native, ulong handle, string method,
        object parameters, int expectedStatus = 0)
    {
        byte[] request = JsonSerializer.SerializeToUtf8Bytes(new { method, @params = parameters });
        try
        {
            int status = native.Call(handle, request, out GithubAuthBuffer buffer);
            return Take(native, status, buffer, expectedStatus);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(request);
        }
    }

    private static JsonElement Take(GithubAuthNative native, int status, GithubAuthBuffer buffer, int expectedStatus = 0)
    {
        byte[] bytes = null;
        try
        {
            Assert.Equal(expectedStatus, status);
            Assert.NotEqual(0UL, buffer.Id);
            Assert.NotEqual(IntPtr.Zero, buffer.Data);
            Assert.InRange((ulong)buffer.Length, 1UL, 1024UL * 1024);
            bytes = new byte[(int)buffer.Length];
            Marshal.Copy(buffer.Data, bytes, 0, bytes.Length);
            using JsonDocument document = JsonDocument.Parse(bytes);
            return document.RootElement.Clone();
        }
        finally
        {
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
            if (buffer.Id != 0) Assert.Equal(0, native.Free(buffer.Id));
        }
    }
}
