using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace GitCredentialManager.DpopDemo;

internal sealed class DpopDemoRequest
{
    internal string Method { get; init; }
    internal string Url { get; init; }
    internal string AttemptId { get; init; }
    internal int? Status { get; init; }
    internal Dictionary<string, string> Headers { get; init; }
}

internal static class DpopDemoProtocol
{
    internal const string DpopCapability = "dpop";
    internal const string StatePrefix = "github-client-auth:";
    private static readonly string[] RequiredCapabilities = { "authtype", "state", DpopCapability };
    private const int MaxInput = 65536;
    private const int MaxLine = 16384;

    internal static GitRequest Read(TextReader reader)
    {
        var values = new Dictionary<string, IList<string>>(StringComparer.Ordinal);
        var line = new StringBuilder();
        int lines = 0;
        for (int total = 0; total < MaxInput; total++)
        {
            int ch = reader.Read();
            bool eof = ch < 0;
            if (eof)
            {
                if (line.Length == 0) return new GitRequest(values);
                ch = '\n';
            }
            if (ch == '\n')
            {
                if (line.Length == 0)
                {
                    return new GitRequest(values);
                }
                if (++lines > 128)
                {
                    throw Invalid("Credential protocol input exceeded the limit.");
                }
                string text = line.ToString();
                line.Clear();
                int split = text.IndexOf('=');
                if (split <= 0)
                {
                    throw Invalid("Malformed credential protocol field.");
                }
                string key = text[..split];
                string value = text[(split + 1)..];
                bool array = key.EndsWith("[]", StringComparison.Ordinal);
                if (array)
                {
                    key = key[..^2];
                }
                if (array != (key is "capability" or "state" or "wwwauth"))
                {
                    throw Invalid("Invalid credential protocol field shape.");
                }
                if (!values.TryGetValue(key, out var list))
                {
                    list = new List<string>();
                    values.Add(key, list);
                }
                else if (!array)
                {
                    throw Invalid("Duplicate credential protocol field.");
                }
                if (array && value.Length == 0)
                {
                    list.Clear();
                }
                else
                {
                    list.Add(value);
                }
            }
            else
            {
                if (ch < 0x20 || ch > 0x7e || line.Length >= MaxLine)
                {
                    throw Invalid("Invalid or oversized credential protocol line.");
                }
                line.Append((char)ch);
            }
            if (eof) return new GitRequest(values);
        }
        throw Invalid("Credential protocol input exceeded the limit.");
    }

    internal static DpopDemoRequest Validate(GitRequest request, DpopDemoConfig config, string command = "get")
    {
        IList<string> caps = request.GetMultiArgumentOrDefault("capability");
        if (!RequiredCapabilities.All(caps.Contains))
        {
            throw Invalid("Unsupported Git: the GCM DPoP demo requires authtype, state, and dpop capabilities.");
        }

        string method = request["http-method"];
        if (method is not ("GET" or "POST" or "HEAD"))
        {
            throw Invalid("The DPoP demo requires an explicit GET, POST, or HEAD http-method.");
        }
        string url = request["http-url"];
        Uri target = ValidateUrl(url, allowQuery: true);
        if (!InScope(target, config) || request.Protocol != "https" || request.Host != target.Authority)
        {
            throw Invalid("Credential context or HTTP target is outside the configured DPoP repository.");
        }
        if (request.Path is not null &&
            !InScope(ValidateUrl(config.Origin + "/" + request.Path, allowQuery: true), config))
        {
            throw Invalid("Credential path is outside the configured DPoP repository.");
        }
        if (request.AuthType is not null && request.AuthType != "DPoP")
        {
            throw Invalid("The DPoP demo refuses an authentication downgrade.");
        }

        string attempt = OwnedAttempt(request);
        int? status = null;
        if (command == "observe")
        {
            if (attempt is null || request.AuthType != "DPoP" ||
                request["ephemeral"] is not ("1" or "true"))
            {
                throw Invalid("DPoP observe requires an ephemeral DPoP response and exactly one owned attempt.");
            }
            if (new[] { "credential", "dpop", "password", "oauth_refresh_token", "refresh_token" }
                .Any(key => request.TryGetArgument(key, out _)))
            {
                throw Invalid("DPoP observe must not contain credentials, proofs, passwords, or refresh tokens.");
            }
            string rawStatus = request["http-status"];
            if (rawStatus is null || (rawStatus.Length != 3 && rawStatus != "0") ||
                !int.TryParse(rawStatus, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) ||
                (parsed != 0 && parsed < 100) || parsed > 599)
            {
                throw Invalid("DPoP observe requires status 0 (no response) or a real HTTP status in 100..599.");
            }
            status = parsed;
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string nonce = request["dpop-nonce"];
        if (nonce is not null)
        {
            if (!IsVisible(nonce, 1024))
            {
                throw Invalid("Invalid DPoP nonce header.");
            }
            headers.Add("dpop-nonce", nonce);
        }
        IList<string> challenges = request.GetMultiArgumentOrDefault("wwwauth");
        if (challenges.Count > 8 || challenges.Any(x => !IsVisible(x, 4096, allowSpace: true)))
        {
            throw Invalid("Invalid authentication challenge headers.");
        }
        if (challenges.Count > 0)
        {
            headers.Add("www-authenticate", string.Join(", ", challenges));
        }
        if (command == "observe" && status == 0 && headers.Count != 0)
        {
            throw Invalid("DPoP abandonment must not contain response nonces or authentication challenges.");
        }
        return new DpopDemoRequest { Method = method, Url = url, AttemptId = attempt, Status = status, Headers = headers };
    }

    internal static void ValidateLegacy(GitRequest request)
    {
        if (OwnedAttempt(request) is not null)
        {
            throw Invalid("Owned DPoP attempt state requires observe, not legacy store or erase.");
        }
    }

    private static string OwnedAttempt(GitRequest request)
    {
        string attempt = null;
        foreach (string state in request.GetMultiArgumentOrDefault("state"))
        {
            if (!state.StartsWith(StatePrefix, StringComparison.Ordinal)) continue;
            if (attempt is not null) throw Invalid("Duplicate DPoP attempt state.");
            attempt = state[StatePrefix.Length..];
            if (!Guid.TryParseExact(attempt, "D", out _)) throw Invalid("Malformed DPoP attempt state.");
        }
        return attempt;
    }

    private static bool InScope(Uri target, DpopDemoConfig config) =>
        target.GetLeftPart(UriPartial.Authority) == config.Origin &&
        (target.AbsolutePath == config.Resource.AbsolutePath ||
         target.AbsolutePath.StartsWith(config.Resource.AbsolutePath + "/", StringComparison.Ordinal));

    internal static Uri ValidateUrl(string text, bool allowQuery)
    {
        if (!IsVisible(text, 8192) || !text.StartsWith("https://", StringComparison.Ordinal) ||
            text.Contains('\\') || text.Contains('#'))
        {
            throw Invalid("The DPoP demo requires a canonical HTTPS URL without userinfo or fragment.");
        }
        int start = text.IndexOf('/', "https://".Length);
        if (start < 0)
        {
            throw Invalid("The DPoP demo requires an explicit repository path.");
        }
        string rawPath = text[start..].Split('?')[0];
        if (rawPath.Contains('%') || rawPath.Contains("//", StringComparison.Ordinal) ||
            rawPath.Split('/').Any(x => x is "." or ".."))
        {
            throw Invalid("Encoded or ambiguous repository paths are not supported by the DPoP demo.");
        }
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] != '%') continue;
            if (i + 2 >= text.Length ||
                !byte.TryParse(text.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte decoded) ||
                decoded < 0x20 || decoded == 0x7f || decoded == '\\')
            {
                throw Invalid("Invalid URL escape.");
            }
            i += 2;
        }
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || uri.Port < 1 ||
            (!allowQuery && uri.Query.Length != 0) || uri.AbsoluteUri != text)
        {
            throw Invalid("The DPoP demo requires an unambiguous canonical HTTPS URL.");
        }
        return uri;
    }

    internal static bool IsVisible(string text, int limit, bool allowSpace = false) =>
        !string.IsNullOrEmpty(text) && text.Length <= limit &&
        text.All(c => c >= (allowSpace ? 0x20 : 0x21) && c <= 0x7e);

    internal static string FormatCredential(string token, string proof, string attempt) =>
        string.Concat(RequiredCapabilities.Select(capability => $"capability[]={capability}\n")) +
        $"authtype=DPoP\ncredential={token}\ndpop={proof}\nephemeral=true\n" +
        $"state[]={StatePrefix}{attempt}\n\n";

    internal static DpopDemoException Invalid(string message) => new(message);
}
