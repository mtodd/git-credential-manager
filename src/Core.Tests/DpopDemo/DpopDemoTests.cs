using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using GitCredentialManager.Commands;
using GitCredentialManager.DpopDemo;
using GitCredentialManager.Tests.Objects;
using Moq;
using Xunit;

namespace GitCredentialManager.Tests.DpopDemo;

public class DpopDemoTests
{
    private const string Origin = "https://127.0.0.1:9443";
    private const string Resource = Origin + "/demo.git";
    private const string Attempt = "77777777-7777-4777-8777-777777777777";
    private const string NextAttempt = "88888888-8888-4888-8888-888888888888";
    private const string Secret = "synthetic-access-token-never-log";
    private const string Proof = "eyJhbGciOiJFUzI1NiJ9.eyJodG0iOiJHRVQifQ.c2lnbmF0dXJl";
    private const string Prepared = "{\"result\":{\"headers\":{\"authorization\":\"DPoP " + Secret +
        "\",\"dpop\":\"" + Proof + "\"},\"attempt_id\":\"" + NextAttempt + "\"}}";

    private static string Input(string method = "GET", string url = Resource + "/info/refs?service=git-upload-pack",
        string extra = "") =>
        $"protocol=https\nhost=127.0.0.1:9443\npath=demo.git\ncapability[]=authtype\ncapability[]=state\n" +
        $"capability[]=dpop\nhttp-method={method}\nhttp-url={url}\n{extra}\n";

    private static string Observation(string status = "200", string extra = "") =>
        Input(extra: $"authtype=DPoP\nephemeral=1\nstate[]=github-client-auth:{Attempt}\nhttp-status={status}\n{extra}");

    [Theory]
    [InlineData("protocol=https\nprotocol=http\n\n")]
    [InlineData("state=value\n\n")]
    [InlineData("http-method[]=GET\n\n")]
    [InlineData("=value\n\n")]
    [InlineData("not-a-field\n\n")]
    [InlineData("protocol=https\r\n\n")]
    [InlineData("protocol=htt\0ps\n\n")]
    [InlineData("protocol")]
    public void Parser_RejectsAmbiguityAndControlCharacters(string input) =>
        Assert.Throws<DpopDemoException>(() => DpopDemoProtocol.Read(new StringReader(input)));

    [Fact]
    public void Parser_IsBoundedAndHonorsArrayReset()
    {
        Assert.Throws<DpopDemoException>(() => DpopDemoProtocol.Read(new StringReader("x=" + new string('x', 17000) + "\n\n")));
        Assert.Throws<DpopDemoException>(() => DpopDemoProtocol.Read(new StringReader(string.Concat(Enumerable.Repeat("wwwauth[]=x\n", 129)) + "\n")));
        GitRequest input = DpopDemoProtocol.Read(new StringReader("state[]=other:old\nstate[]=\nstate[]=other:new\n\n"));
        Assert.Equal(new[] { "other:new" }, input.GetMultiArgumentOrDefault("state"));
    }

    [Theory]
    [InlineData("get", false)]
    [InlineData("get", true)]
    [InlineData("observe", false)]
    [InlineData("observe", true)]
    public void GitEofFraming_DoesNotRequireATerminatingBlankLine(string command, bool lastLineHasNewline)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, command == "get" ? Prepared :
            "{\"result\":{\"retry\":false,\"new_proof_required\":false}}"));
        string input = (command == "get" ? Input() : Observation()).TrimEnd('\n');
        if (lastLineHasNewline) input += "\n";
        string output = new DpopDemoHostProvider(files.Config, _ => native).Execute(command, Parse(input));
        Assert.Equal(command == "get" ? "request.prepare" : "nonce.observe",
            native.Calls.Single().GetProperty("method").GetString());
        if (command == "get") Assert.Contains(Secret, output);
        else Assert.Null(output);
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
    }

    [Theory]
    [InlineData("GET", Resource + "/info/refs?service=git-upload-pack&v=a%20b")]
    [InlineData("POST", Resource + "/git-upload-pack")]
    [InlineData("HEAD", Resource)]
    public void Prepare_PreservesExactMethodAndFullUrl(string method, string url)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, Prepared));
        string output = new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input(method, url)));

        Assert.Equal("request.prepare", native.Calls.Single().GetProperty("method").GetString());
        JsonElement args = native.Calls.Single().GetProperty("params");
        Assert.Equal(method, args.GetProperty("method").GetString());
        Assert.Equal(url, args.GetProperty("url").GetString());
        Assert.Equal(files.Config.CredentialId, args.GetProperty("credential_id").GetString());
        Assert.Equal(3600, args.GetProperty("observation_ttl_seconds").GetInt32());
        Assert.Contains("capability[]=authtype\ncapability[]=state\ncapability[]=dpop\n", output);
        Assert.Contains($"authtype=DPoP\ncredential={Secret}\ndpop={Proof}\nephemeral=true\n", output);
        Assert.Contains($"state[]=github-client-auth:{NextAttempt}\n\n", output);
        Assert.DoesNotContain("username=", output);
        Assert.DoesNotContain("password=", output);
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
        Assert.True(native.Disposed);
        Assert.All(native.OpenBytes, b => Assert.Equal(0, b));

        JsonElement config = native.OpenConfig;
        Assert.Equal("require_broker", config.GetProperty("mode").GetString());
        Assert.Equal("git-dpop-demo-gcm", config.GetProperty("application_id").GetString());
        Assert.False(config.TryGetProperty("embedded", out _));
        JsonElement broker = config.GetProperty("broker");
        Assert.Equal("unix", broker.GetProperty("endpoint").GetProperty("kind").GetString());
        Assert.Equal("synthetic-capability", broker.GetProperty("capability").GetString());
        JsonElement policy = broker.GetProperty("required_policy");
        Assert.Equal(new[] { "headers", "prove" }, policy.GetProperty("permissions").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(new[] { Origin }, policy.GetProperty("origins").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(new[] { files.Config.CredentialId }, policy.GetProperty("credentials").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(new[] { files.Config.KeyId }, policy.GetProperty("keys").EnumerateArray().Select(x => x.GetString()));
    }

    [Theory]
    [InlineData("GET", "http://127.0.0.1:9443/demo.git")]
    [InlineData("GET", "https://127.0.0.1:9444/demo.git")]
    [InlineData("GET", "https://example.com:9443/demo.git")]
    [InlineData("GET", Resource + "-other/info/refs")]
    [InlineData("GET", Resource + "/../secrets")]
    [InlineData("GET", Resource + "/%2e%2e/secrets")]
    [InlineData("GET", Resource + "/%252e%252e/secrets")]
    [InlineData("GET", Resource + "/git%2fupload-pack")]
    [InlineData("GET", Resource + "//info/refs")]
    [InlineData("GET", Resource + "/info/refs#fragment")]
    [InlineData("GET", "https://user@127.0.0.1:9443/demo.git")]
    [InlineData("GET", Resource + "/info/refs?q=%0d%0aInjected")]
    [InlineData("GET", Resource + "/info/refs?q=%zz")]
    [InlineData("GET", Resource + "\\other")]
    [InlineData("PUT", Resource)]
    [InlineData("get", Resource)]
    [InlineData("", Resource)]
    public void InvalidTargetOrMethod_DoesNotLoadNativeLibrary(string method, string url)
    {
        using var files = new Fixture();
        int loads = 0;
        var provider = new DpopDemoHostProvider(files.Config, _ => { loads++; return new FakeNative(); });
        Assert.Throws<DpopDemoException>(() => provider.Execute("get", Parse(Input(method, url))));
        Assert.Equal(0, loads);
    }

    [Theory]
    [InlineData("capability[]=dpop\n")]
    [InlineData("capability[]=authtype\n")]
    [InlineData("capability[]=state\n")]
    public void MissingCapability_ExplicitlyFailsBeforeNativeWork(string remove)
    {
        using var files = new Fixture();
        var error = Assert.Throws<DpopDemoException>(() =>
            new DpopDemoHostProvider(files.Config, _ => throw new Exception("native must not load"))
                .Execute("get", Parse(Input().Replace(remove, ""))));
        Assert.Contains("Unsupported Git", error.Message);
    }

    [Theory]
    [InlineData("host=127.0.0.1:9443", "host=example.com")]
    [InlineData("protocol=https", "protocol=http")]
    [InlineData("path=demo.git", "path=another.git")]
    public void CredentialContextMustMatchConfiguredRepository(string old, string replacement)
    {
        using var files = new Fixture();
        Assert.Throws<DpopDemoException>(() => DpopDemoProtocol.Validate(Parse(Input().Replace(old, replacement)), files.Config));
    }

    [Theory]
    [InlineData("authtype=Bearer\n")]
    [InlineData("state[]=github-client-auth:not-an-attempt\nhttp-status=401\n")]
    [InlineData("state[]=github-client-auth:" + Attempt + "\nstate[]=github-client-auth:" + NextAttempt + "\nhttp-status=401\n")]
    [InlineData("dpop-nonce=contains whitespace\n")]
    [InlineData("dpop-nonce=\n")]
    public void InvalidStateResponseOrDowngrade_FailsBeforeNativeWork(string extra)
    {
        using var files = new Fixture();
        Assert.Throws<DpopDemoException>(() => DpopDemoProtocol.Validate(Parse(Input(extra: extra)), files.Config));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InitialChallengeWithoutAttempt_IsNotObserved(bool withStatus)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, Prepared));
        new DpopDemoHostProvider(files.Config, _ => native).Execute("get",
            Parse(Input(extra: (withStatus ? "http-status=401\n" : "") +
                "dpop-nonce=untrusted-first-nonce\nwwwauth[]=DPoP\nstate[]=other-helper:opaque\n")));
        Assert.Single(native.Calls);
        Assert.Equal("request.prepare", native.Calls[0].GetProperty("method").GetString());
    }

    [Fact]
    public void GetWithConsumedState_OnlyPreparesFreshProof()
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, Prepared));
        string response = new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input(extra:
            $"state[]=github-client-auth:{Attempt}\nhttp-status=401\ndpop-nonce=fresh-nonce\n" +
            "wwwauth[]=Bearer realm=\"ignored\"\nwwwauth[]=DPoP error=\"use_dpop_nonce\"\n")));
        Assert.Equal(new[] { "request.prepare" }, native.Calls.Select(c => c.GetProperty("method").GetString()));
        Assert.Contains(NextAttempt, response);
    }

    [Fact]
    public void DedicatedObserve_ReportsHeadersWithoutTokenOrProof()
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, "{\"result\":{\"retry\":true,\"new_proof_required\":true}}"));
        Assert.Null(new DpopDemoHostProvider(files.Config, _ => native).Execute("observe", Parse(Observation("401",
            "dpop-nonce=fresh-nonce\nwwwauth[]=DPoP realm=\"demo\"\nwwwauth[]=DPoP error=\"use_dpop_nonce\"\n"))));
        Assert.Equal(new[] { "nonce.observe" }, native.Calls.Select(c => c.GetProperty("method").GetString()));
        JsonElement args = native.Calls[0].GetProperty("params");
        Assert.Equal(Attempt, args.GetProperty("attempt_id").GetString());
        Assert.Equal(401, args.GetProperty("status").GetInt32());
        Assert.Equal("fresh-nonce", args.GetProperty("headers").GetProperty("dpop-nonce").GetString());
        Assert.Equal("DPoP realm=\"demo\", DPoP error=\"use_dpop_nonce\"",
            args.GetProperty("headers").GetProperty("www-authenticate").GetString());
        Assert.False(args.TryGetProperty("credential", out _));
        Assert.False(args.TryGetProperty("dpop", out _));
        Assert.Equal(1, native.CloseCount);
    }

    [Theory]
    [InlineData(2, "{\"error\":{\"code\":\"not_found\",\"message\":\"SECRET-NATIVE-ERROR\"}}")]
    [InlineData(2, "{\"error\":{\"code\":\"expired\",\"message\":\"SECRET-NATIVE-ERROR\"}}")]
    public void FailedOrExpiredObserve_NeverPreparesAnotherCredential(int status, string json)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((status, json));
        Assert.Throws<DpopDemoException>(() => new DpopDemoHostProvider(files.Config, _ => native).Execute("observe",
            Parse(Observation())));
        Assert.Single(native.Calls);
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
    }

    [Theory]
    [InlineData(100)]
    [InlineData(199)]
    [InlineData(200)]
    [InlineData(401)]
    [InlineData(500)]
    [InlineData(599)]
    public void Observe_AcknowledgesRealHttpStatusesRegardlessOfRetryVerdict(int status)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, "{\"result\":{\"retry\":false,\"new_proof_required\":false}}"));
        Assert.Null(new DpopDemoHostProvider(files.Config, _ => native).Execute("observe", Parse(Observation(status.ToString()))));
        Assert.Single(native.Calls);
        Assert.Equal("nonce.observe", native.Calls[0].GetProperty("method").GetString());
        Assert.Equal(1, native.CloseCount);
    }

    [Theory]
    [InlineData("store")]
    [InlineData("erase")]
    public void StoreAndEraseWithoutAttempt_DoNotOpenNativeOrAccessStorage(string command)
    {
        using var files = new Fixture();
        Assert.Null(new DpopDemoHostProvider(files.Config, _ => throw new Exception("must not load"))
            .Execute(command, Parse("protocol=https\nhost=other.example\nusername=legacy\npassword=synthetic\n\n")));
    }

    [Theory]
    [InlineData("store")]
    [InlineData("erase")]
    public void StoreAndEraseWithOwnedState_FailWithoutNativeWork(string command)
    {
        using var files = new Fixture();
        var error = Assert.Throws<DpopDemoException>(() =>
            new DpopDemoHostProvider(files.Config, _ => throw new Exception("must not load"))
                .Execute(command, Parse(Observation())));
        Assert.Contains("requires observe", error.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("demo.git/subscope")]
    [InlineData("demo.git/info/refs?service=git-upload-pack")]
    public void CredentialPathIsOptionalAndIndependentOfExactHttpTarget(string path)
    {
        using var files = new Fixture();
        string input = Input().Replace("path=demo.git\n", path is null ? "" : $"path={path}\n");
        var request = DpopDemoProtocol.Validate(Parse(input), files.Config);
        Assert.Equal(Resource + "/info/refs?service=git-upload-pack", request.Url);
        string observe = Observation().Replace("path=demo.git\n", path is null ? "" : $"path={path}\n");
        Assert.Equal(request.Url, DpopDemoProtocol.Validate(Parse(observe), files.Config, "observe").Url);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("99")]
    [InlineData("600")]
    [InlineData(" 401")]
    [InlineData("")]
    public void InvalidObserveStatus_FailsBeforeNativeAccess(string status)
    {
        using var files = new Fixture();
        Assert.Throws<DpopDemoException>(() =>
            new DpopDemoHostProvider(files.Config, _ => throw new Exception("must not load"))
                .Execute("observe", Parse(Observation(status))));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void NoResponseObservation_OnlyDiscardsAndAcknowledgesEitherResult(bool discarded)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, JsonSerializer.Serialize(new { result = new { discarded } })));
        var context = new TestCommandContext { Streams = { In = Observation("0") } };
        DpopDemoCommand.Execute(context, "observe", files.ConfigPath, _ => native);
        Assert.Empty(context.Streams.Out.ToString());
        JsonElement call = Assert.Single(native.Calls);
        Assert.Equal("nonce.discard", call.GetProperty("method").GetString());
        JsonProperty parameter = Assert.Single(call.GetProperty("params").EnumerateObject());
        Assert.Equal("attempt_id", parameter.Name);
        Assert.Equal(Attempt, parameter.Value.GetString());
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
        Assert.True(native.Disposed);
    }

    [Theory]
    [InlineData("dpop-nonce=must-not-cache\n")]
    [InlineData("wwwauth[]=DPoP\n")]
    [InlineData("wwwauth[]=DPoP error=\"use_dpop_nonce\"\n")]
    [InlineData("dpop-nonce=\n")]
    public void NoResponseWithResponseMetadata_FailsBeforeNativeAccess(string extra)
    {
        using var files = new Fixture();
        Assert.Throws<DpopDemoException>(() =>
            new DpopDemoHostProvider(files.Config, _ => throw new Exception("must not load"))
                .Execute("observe", Parse(Observation("0", extra))));
    }

    [Fact]
    public void NoResponseAllowsClearedChallengeArray()
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, "{\"result\":{\"discarded\":false}}"));
        Assert.Null(new DpopDemoHostProvider(files.Config, _ => native).Execute("observe",
            Parse(Observation("0", "wwwauth[]=DPoP\nwwwauth[]=\n"))));
        Assert.Equal("nonce.discard", Assert.Single(native.Calls).GetProperty("method").GetString());
    }

    [Theory]
    [InlineData(2, "{\"error\":{\"code\":\"forbidden\",\"message\":\"SECRET-DISCARD-ERROR\"}}")]
    [InlineData(2, "{\"error\":{\"code\":\"unsupported\",\"message\":\"SECRET-DISCARD-ERROR\"}}")]
    [InlineData(0, "{\"result\":{\"discarded\":\"true\"}}")]
    [InlineData(0, "{\"result\":{}}")]
    public void DiscardFailure_NeverAcknowledgesOrFallsBackToHttpObservation(int status, string reply)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((status, reply));
        var context = new TestCommandContext { Streams = { In = Observation("0") } };
        var error = Assert.Throws<DpopDemoException>(() =>
            DpopDemoCommand.Execute(context, "observe", files.ConfigPath, _ => native));
        Assert.DoesNotContain("SECRET-DISCARD-ERROR", error.ToString());
        Assert.Empty(context.Streams.Out.ToString());
        Assert.Equal("nonce.discard", Assert.Single(native.Calls).GetProperty("method").GetString());
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
    }

    [Fact]
    public void DiscardAcknowledgementWaitsForNativeClose()
    {
        using var files = new Fixture();
        var native = new FakeNative { CloseStatus = 2 };
        native.Replies.Enqueue((0, "{\"result\":{\"discarded\":true}}"));
        var context = new TestCommandContext { Streams = { In = Observation("0") } };
        Assert.Throws<DpopDemoException>(() => DpopDemoCommand.Execute(context, "observe", files.ConfigPath, _ => native));
        Assert.Empty(context.Streams.Out.ToString());
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
    }

    [Fact]
    public void GetWithPreviousNoResponseContext_DoesNotDiscardAgain()
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, Prepared));
        string output = new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Observation("0")));
        Assert.Contains(Secret, output);
        JsonElement call = Assert.Single(native.Calls);
        Assert.Equal("request.prepare", call.GetProperty("method").GetString());
        Assert.Equal(3600, call.GetProperty("params").GetProperty("observation_ttl_seconds").GetInt32());
    }

    [Fact]
    public void PrepareLifecycleSupportFailure_DoesNotRetryWithoutTheRequestedWindow()
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((2, "{\"error\":{\"code\":\"invalid_request\",\"message\":\"unsupported observation_ttl_seconds\"}}"));
        var context = new TestCommandContext { Streams = { In = Input() } };
        Assert.Throws<DpopDemoException>(() => DpopDemoCommand.Execute(context, "get", files.ConfigPath, _ => native));
        Assert.Equal("quit=1\n\n", context.Streams.Out.ToString());
        JsonElement call = Assert.Single(native.Calls);
        Assert.Equal("request.prepare", call.GetProperty("method").GetString());
        Assert.Equal(3600, call.GetProperty("params").GetProperty("observation_ttl_seconds").GetInt32());
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
    }

    [Theory]
    [InlineData("http-status=200\n")]
    [InlineData("state[]=github-client-auth:" + Attempt + "\n")]
    [InlineData("capability[]=dpop\n")]
    [InlineData("capability[]=state\n")]
    [InlineData("capability[]=authtype\n")]
    [InlineData("authtype=DPoP\n")]
    [InlineData("ephemeral=1\n")]
    public void ObserveRequiresStateStatusAndNegotiation(string remove)
    {
        using var files = new Fixture();
        Assert.Throws<DpopDemoException>(() =>
            new DpopDemoHostProvider(files.Config, _ => throw new Exception("must not load"))
                .Execute("observe", Parse(Observation().Replace(remove, ""))));
    }

    [Theory]
    [InlineData("credential=synthetic-token\n")]
    [InlineData("dpop=a.b.c\n")]
    [InlineData("password=synthetic-password\n")]
    [InlineData("oauth_refresh_token=synthetic-refresh\n")]
    [InlineData("refresh_token=synthetic-refresh\n")]
    [InlineData("state[]=github-client-auth:" + NextAttempt + "\n")]
    public void ObserveRejectsSecretsOrDuplicateOwnedStateBeforeNativeAccess(string extra)
    {
        using var files = new Fixture();
        Assert.Throws<DpopDemoException>(() =>
            new DpopDemoHostProvider(files.Config, _ => throw new Exception("must not load"))
                .Execute("observe", Parse(Observation(extra: extra))));
    }

    [Fact]
    public void ObserveRejectsMalformedStateBeforeNativeAccess()
    {
        using var files = new Fixture();
        Assert.Throws<DpopDemoException>(() =>
            new DpopDemoHostProvider(files.Config, _ => throw new Exception("must not load"))
                .Execute("observe", Parse(Observation().Replace(Attempt, "malformed"))));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ObserveCommand_EmitsNoStdoutForAcknowledgementOrError(bool fail)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((fail ? 2 : 0, fail
            ? "{\"error\":{\"code\":\"expired\",\"message\":\"SECRET-NATIVE-ERROR\"}}"
            : "{\"result\":{\"retry\":false,\"new_proof_required\":false}}"));
        var context = new TestCommandContext { Streams = { In = Observation() } };
        var traceOutput = new StringWriter();
        var trace = new Trace { IsSecretTracingEnabled = true };
        trace.AddListener(traceOutput);
        context.Trace = trace;
        if (fail)
        {
            var error = Assert.Throws<DpopDemoException>(() => DpopDemoCommand.Execute(context, "observe", files.ConfigPath, _ => native));
            Assert.DoesNotContain("SECRET-NATIVE-ERROR", error.ToString());
        }
        else
        {
            DpopDemoCommand.Execute(context, "observe", files.ConfigPath, _ => native);
        }
        Assert.Empty(context.Streams.Out.ToString());
        Assert.Empty(traceOutput.ToString());
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
    }

    [Theory]
    [InlineData("{\"result\":{\"headers\":{\"authorization\":\"Bearer token\"},\"attempt_id\":null}}")]
    [InlineData("{\"result\":{\"headers\":{\"authorization\":\"DPoP token\",\"dpop\":\"not-a-proof\"},\"attempt_id\":\"" + Attempt + "\"}}")]
    [InlineData("{\"result\":{\"headers\":{\"authorization\":\"DPoP token\\nInjected\",\"dpop\":\"a.b.c\"},\"attempt_id\":\"" + Attempt + "\"}}")]
    [InlineData("{\"result\":{\"headers\":{\"authorization\":\"DPoP token\",\"dpop\":\"a.b.c\"},\"attempt_id\":null}}")]
    [InlineData("{\"result\":{\"headers\":{\"authorization\":\"DPoP token\",\"Authorization\":\"Bearer other\",\"dpop\":\"a.b.c\"},\"attempt_id\":\"" + Attempt + "\"}}")]
    public void PrepareRejectsBearerAndMalformedSecrets(string prepared)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, prepared));
        Assert.Throws<DpopDemoException>(() => new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input())));
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void NativeFailure_ReleasesBufferAndNonzeroHandle(int status)
    {
        using var files = new Fixture();
        var native = new FakeNative { OpenStatus = status };
        Assert.Throws<DpopDemoException>(() => new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input())));
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(2, native.Freed.Count);
        Assert.All(native.OpenBytes, b => Assert.Equal(0, b));
        Assert.True(native.Disposed);
    }

    [Fact]
    public void AbiMismatch_DoesNotOpenSession()
    {
        using var files = new Fixture();
        var native = new FakeNative { Version = 2 };
        Assert.Throws<DpopDemoException>(() => new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input())));
        Assert.Null(native.OpenBytes);
        Assert.Equal(0, native.CloseCount);
        Assert.True(native.Disposed);
    }

    [Theory]
    [InlineData("embedded", "require_broker", "11111111-1111-4111-8111-111111111111")]
    [InlineData("broker", "prefer_broker", "11111111-1111-4111-8111-111111111111")]
    [InlineData("broker", "require_broker", "99999999-9999-4999-8999-999999999999")]
    public void OpenMustPinBrokerBeforeAnyCall(string backend, string mode, string instance)
    {
        using var files = new Fixture();
        var native = new FakeNative { OpenJson = FakeNative.OpenResult(backend, mode, instance) };
        Assert.Throws<DpopDemoException>(() => new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input())));
        Assert.Empty(native.Calls);
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(2, native.Freed.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-json")]
    [InlineData("{\"error\":{\"message\":\"secret\"}}")]
    [InlineData("{\"result\":{},\"result\":{}}")]
    public void MalformedOpenOutput_AlwaysClosesAndFrees(string output)
    {
        using var files = new Fixture();
        var native = new FakeNative { OpenJson = output };
        Assert.ThrowsAny<Exception>(() => new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input())));
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(2, native.Freed.Count);
    }

    [Fact]
    public void OversizedNativeBuffer_IsNotDereferenced()
    {
        var native = new FakeNative { OversizedOpen = true };
        using var session = new GithubAuthSession(native);
        Assert.Throws<DpopDemoException>(() => session.Open(Encoding.UTF8.GetBytes("{}"), Guid.Empty));
        Assert.Single(native.Freed);
    }

    [Fact]
    public void NullNativeData_IsNotDereferencedAndItsBufferIsFreed()
    {
        using var files = new Fixture();
        var native = new FakeNative { NullOpenData = true };
        Assert.Throws<DpopDemoException>(() => new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input())));
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(2, native.Freed.Count);
    }

    [Fact]
    public void ZeroNativeHandle_IsRejectedWithoutClosingAnInvalidHandle()
    {
        using var files = new Fixture();
        var native = new FakeNative { OpenHandle = 0 };
        Assert.Throws<DpopDemoException>(() => new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input())));
        Assert.Equal(0, native.CloseCount);
        Assert.Single(native.Freed);
    }

    [Fact]
    public void BufferReleaseFailure_ClosesSessionBeforeUnloading()
    {
        using var files = new Fixture();
        var native = new FakeNative { FailFirstFree = true };
        Assert.Throws<DpopDemoException>(() => new DpopDemoHostProvider(files.Config, _ => native).Execute("get", Parse(Input())));
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(2, native.Freed.Count);
        Assert.True(native.Disposed);
    }

    public static IEnumerable<object[]> NativeFailureCombinations()
    {
        foreach (bool failOpen in new[] { false, true })
        {
            for (int cleanupFailures = 1; cleanupFailures < 8; cleanupFailures++)
            {
                yield return new object[] { failOpen, (cleanupFailures & 1) != 0,
                    (cleanupFailures & 2) != 0, (cleanupFailures & 4) != 0 };
            }
        }
    }

    [Theory]
    [MemberData(nameof(NativeFailureCombinations))]
    public void CombinedNativeFailures_ReleaseBuffersAndCloseBeforeUnloading(
        bool failOpen, bool failClose, bool failOperationFree, bool failCloseFree)
    {
        using var files = new Fixture();
        const string nativeError = "{\"error\":{\"code\":\"failed\",\"message\":\"SYNTHETIC-NATIVE-FAILURE\"}}";
        var native = new FakeNative
        {
            OpenStatus = failOpen ? 2 : 0,
            OpenJson = failOpen ? nativeError : FakeNative.OpenResult("broker", "require_broker", Fixture.Instance.ToString("D")),
            CloseStatus = failClose ? 2 : 0
        };
        if (!failOpen) native.Replies.Enqueue((2, nativeError));
        ulong operationBuffer = failOpen ? 1UL : 2UL;
        ulong closeBuffer = operationBuffer + 1;
        if (failOperationFree) native.FailedFreeIds.Add(operationBuffer);
        if (failCloseFree) native.FailedFreeIds.Add(closeBuffer);
        var context = new TestCommandContext { Streams = { In = Input() } };

        var error = Assert.Throws<DpopDemoException>(() =>
            DpopDemoCommand.Execute(context, "get", files.ConfigPath, _ => native));

        Assert.DoesNotContain("SYNTHETIC-NATIVE-FAILURE", error.ToString());
        Assert.Equal("quit=1\n\n", context.Streams.Out.ToString());
        Assert.Equal(1, native.CloseCount);
        Assert.Equal((int)closeBuffer, native.Freed.Count);
        Assert.Equal(failOpen ? 0 : 1, native.Calls.Count);
        Assert.All(native.OpenBytes, value => Assert.Equal(0, value));
        Assert.All(native.CallBytes, bytes => Assert.All(bytes, value => Assert.Equal(0, value)));
        Assert.Equal(failOpen
            ? new[] { "open", "free:1", "close", "free:2", "unload" }
            : new[] { "open", "free:1", "call:request.prepare", "free:2", "close", "free:3", "unload" },
            native.Events);
        Assert.True(native.Disposed);
    }

    [Theory]
    [InlineData("get", "200", "request.prepare")]
    [InlineData("observe", "200", "nonce.observe")]
    [InlineData("observe", "0", "nonce.discard")]
    public void NativeSuccess_ClosesAndFreesBeforeUnloading(string command, string status, string method)
    {
        using var files = new Fixture();
        var native = new FakeNative();
        native.Replies.Enqueue((0, command == "get" ? Prepared : status == "0"
            ? "{\"result\":{\"discarded\":true}}"
            : "{\"result\":{\"retry\":false,\"new_proof_required\":false}}"));

        new DpopDemoHostProvider(files.Config, _ => native).Execute(command,
            Parse(command == "get" ? Input() : Observation(status)));

        Assert.Equal(new[] { "open", "free:1", $"call:{method}", "free:2", "close", "free:3", "unload" },
            native.Events);
        Assert.True(native.Disposed);
    }

    [Fact]
    public void SessionCloseIsIdempotentAndCallsAfterCloseFail()
    {
        var native = new FakeNative();
        var sdk = new GithubAuthSession(native);
        sdk.Open(Encoding.UTF8.GetBytes("{}"), Fixture.Instance);
        sdk.Dispose();
        sdk.Dispose();
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(2, native.Freed.Count);
        Assert.Throws<DpopDemoException>(() => sdk.Call("request.prepare", new { }));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Command_NeverLogsSecretsEvenWithSecretTracing(bool closeFails)
    {
        using var files = new Fixture();
        var native = new FakeNative { CloseStatus = closeFails ? 2 : 0 };
        native.Replies.Enqueue((0, Prepared));
        var context = new TestCommandContext { Streams = { In = Input(extra: $"credential={Secret}\ndpop={Proof}\n") } };
        var traceOutput = new StringWriter();
        var trace = new Trace { IsSecretTracingEnabled = true };
        trace.AddListener(traceOutput);
        context.Trace = trace;
        if (closeFails)
        {
            var error = Assert.Throws<DpopDemoException>(() => DpopDemoCommand.Execute(context, "get", files.ConfigPath, _ => native));
            Assert.Equal("quit=1\n\n", context.Streams.Out.ToString());
            Assert.DoesNotContain(Secret, error.ToString());
            Assert.DoesNotContain(Proof, error.ToString());
        }
        else
        {
            DpopDemoCommand.Execute(context, "get", files.ConfigPath, _ => native);
            Assert.Contains(Secret, context.Streams.Out.ToString());
        }
        Assert.DoesNotContain(Secret, traceOutput.ToString());
        Assert.DoesNotContain(Proof, traceOutput.ToString());
        Assert.DoesNotContain("synthetic-capability", traceOutput.ToString());
        Assert.Empty(context.Streams.Error.ToString());
        Assert.Equal(1, native.CloseCount);
        Assert.Equal(3, native.Freed.Count);
    }

    [Theory]
    [InlineData("get")]
    [InlineData("store")]
    [InlineData("erase")]
    public async Task SelectedButInvalidConfig_NeverRoutesToLegacyProvider(string operation)
    {
        var context = new TestCommandContext { Streams = { In = Input() } };
        context.Environment.Variables[DpopDemoCommand.ConfigVariable] = "";
        var registry = new Mock<IHostProviderRegistry>(MockBehavior.Strict);
        GitCommandBase command = operation switch
        {
            "get" => new GetCommand(context, registry.Object),
            "store" => new StoreCommand(context, registry.Object),
            _ => new EraseCommand(context, registry.Object)
        };
        if (operation == "get")
            await Assert.ThrowsAsync<DpopDemoException>(() => command.ExecuteAsync());
        else
            await command.ExecuteAsync();
        registry.VerifyNoOtherCalls();
        Assert.Equal(operation == "get" ? "quit=1\n\n" : "", context.Streams.Out.ToString());
    }

    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, -1)]
    public async Task ObserveCommandIsRegisteredOnlyWhenDemoIsSelected(bool selected, int expectedCode)
    {
        var context = new TestCommandContext { Streams = { In = Observation() } };
        if (selected) context.Environment.Variables[DpopDemoCommand.ConfigVariable] = "";
        using var app = new Application(context);
        Assert.Equal(expectedCode, await app.RunAsync(new[] { "observe" }));
        Assert.Empty(context.Streams.Out.ToString());
    }

    [Theory]
    [InlineData("store")]
    [InlineData("erase")]
    public async Task LegacyCommandWithOwnedStateIsRejectedBeforeConfigOrNativeWork(string operation)
    {
        var context = new TestCommandContext { Streams = { In = Observation() } };
        context.Environment.Variables[DpopDemoCommand.ConfigVariable] = "";
        var registry = new Mock<IHostProviderRegistry>(MockBehavior.Strict);
        GitCommandBase command = operation == "store"
            ? new StoreCommand(context, registry.Object) : new EraseCommand(context, registry.Object);
        var error = await Assert.ThrowsAsync<DpopDemoException>(() => command.ExecuteAsync());
        Assert.Contains("requires observe", error.Message);
        registry.VerifyNoOtherCalls();
        Assert.Empty(context.Streams.Out.ToString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Capability_DpopOnlyWhenExplicitlySelected(bool selected)
    {
        var context = new TestCommandContext();
        if (selected) context.Environment.Variables[DpopDemoCommand.ConfigVariable] = "/unused/config";
        new CapabilityCommand(context).Execute();
        string output = context.Streams.Out.ToString().Replace("\r\n", "\n");
        Assert.Equal("version 0\ncapability state\ncapability authtype\n" +
            (selected ? "capability dpop\n" : ""), output);
    }

    [Fact]
    public void PrivateConfiguration_ValidatesVersionShapeAndPaths()
    {
        using var files = new Fixture();
        Assert.Equal(Resource, DpopDemoConfig.Load(files.ConfigPath).Resource.AbsoluteUri);
        foreach (var change in new (string Key, object Value)[]
        {
            ("version", 2), ("version", "1"), ("broker_endpoint", "relative.sock"),
            ("library", "relative.dylib"), ("capability_file", "relative.token"),
            ("broker_instance_id", "not-a-uuid"), ("credential_id", "invalid\nid"),
            ("resource_url", Resource + "?query"), ("resource_url", Origin + "/")
        })
        {
            var config = files.Fields();
            config[change.Key] = change.Value;
            files.WriteConfig(JsonSerializer.Serialize(config));
            Assert.Throws<DpopDemoException>(() => DpopDemoConfig.Load(files.ConfigPath));
        }
        files.WriteConfig("{\"version\":1,\"version\":1}");
        Assert.Throws<DpopDemoException>(() => DpopDemoConfig.Load(files.ConfigPath));
        var extra = files.Fields();
        extra["capability"] = "embedded-token-not-allowed";
        files.WriteConfig(JsonSerializer.Serialize(extra));
        Assert.Throws<DpopDemoException>(() => DpopDemoConfig.Load(files.ConfigPath));
        files.WriteConfig("not-json-with-SYNTHETIC-SECRET");
        var error = Assert.Throws<DpopDemoException>(() => DpopDemoConfig.Load(files.ConfigPath));
        Assert.DoesNotContain("SYNTHETIC-SECRET", error.ToString());
    }

    [Theory]
    [InlineData("config")]
    [InlineData("capability")]
    public void PrivateFiles_FailClosedForPermissionsSymlinksAndOversize(string which)
    {
        using var files = new Fixture();
        string path = which == "config" ? files.ConfigPath : files.CapabilityPath;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        Assert.Throws<DpopDemoException>(() => PrivateFile.Read(path, 16384));
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        string link = path + ".link";
        File.CreateSymbolicLink(link, path);
        Assert.Throws<DpopDemoException>(() => PrivateFile.Read(link, 16384));
        Assert.Throws<DpopDemoException>(() => PrivateFile.Read(files.Directory, 16384));
        Assert.Throws<DpopDemoException>(() => PrivateFile.Read(path, 1));
        File.WriteAllBytes(path, Array.Empty<byte>());
        Assert.Throws<DpopDemoException>(() => PrivateFile.Read(path, 16384));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4095)]
    [InlineData(4096)]
    [InlineData(4097)]
    [InlineData(16384)]
    public void PrivateFiles_UnbufferedReadsPreserveExactContent(int length)
    {
        using var files = new Fixture();
        byte[] expected = Enumerable.Range(0, length).Select(i => (byte)(i % 251)).ToArray();
        File.WriteAllBytes(files.CapabilityPath, expected);
        byte[] actual = PrivateFile.Read(files.CapabilityPath, 16384);
        try
        {
            Assert.Equal(expected, actual);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(actual);
        }
    }

    [Theory]
    [InlineData("get")]
    [InlineData("observe")]
    public void InvalidPrivateCapability_PreventsNativeLoad(string command)
    {
        using var files = new Fixture();
        File.WriteAllText(files.CapabilityPath, "synthetic\ninjected\n");
        Assert.Throws<DpopDemoException>(() =>
            new DpopDemoHostProvider(files.Config, _ => throw new Exception("must not load"))
                .Execute(command, Parse(command == "get" ? Input() : Observation())));
    }

    private static GitRequest Parse(string input) => DpopDemoProtocol.Read(new StringReader(input));

    private sealed class Fixture : IDisposable
    {
        internal static readonly Guid Instance = Guid.Parse("11111111-1111-4111-8111-111111111111");
        internal string Directory { get; } = Path.Combine(AppContext.BaseDirectory, "gcm-dpop-tests", Guid.NewGuid().ToString("N"));
        internal string ConfigPath => Path.Combine(Directory, "gcm-config.json");
        internal string CapabilityPath => Path.Combine(Directory, "gcm-capability");
        internal DpopDemoConfig Config => DpopDemoConfig.Load(ConfigPath);

        internal Fixture()
        {
            System.IO.Directory.CreateDirectory(Directory);
            File.WriteAllText(Path.Combine(Directory, "gcm-library"), "synthetic-file");
            File.WriteAllText(CapabilityPath, "synthetic-capability\n");
            File.SetUnixFileMode(CapabilityPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            WriteConfig(JsonSerializer.Serialize(Fields()));
        }

        internal Dictionary<string, object> Fields() => new()
        {
            ["version"] = 1,
            ["library"] = Path.Combine(Directory, "gcm-library"),
            ["broker_endpoint"] = Path.Combine(Directory, "gcm-broker.sock"),
            ["capability_file"] = CapabilityPath,
            ["broker_instance_id"] = Instance.ToString("D"),
            ["credential_id"] = "22222222-2222-4222-8222-222222222222",
            ["key_id"] = "33333333-3333-4333-8333-333333333333",
            ["resource_url"] = Resource
        };

        internal void WriteConfig(string text)
        {
            File.WriteAllText(ConfigPath, text);
            File.SetUnixFileMode(ConfigPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        public void Dispose() => System.IO.Directory.Delete(Directory, recursive: true);
    }

    private sealed class FakeNative : IGithubAuthNative
    {
        private ulong _id;
        private readonly Dictionary<ulong, IntPtr> _buffers = new();
        internal HashSet<ulong> Freed { get; } = new();
        internal HashSet<ulong> FailedFreeIds { get; } = new();
        internal List<string> Events { get; } = new();
        internal List<byte[]> CallBytes { get; } = new();
        internal uint Version { get; init; } = 1;
        internal int OpenStatus { get; init; }
        internal int CloseStatus { get; init; }
        internal bool OversizedOpen { get; init; }
        internal bool NullOpenData { get; init; }
        internal bool FailFirstFree { get; init; }
        internal ulong OpenHandle { get; init; } = 42;
        internal string OpenJson { get; init; } = OpenResult("broker", "require_broker", Fixture.Instance.ToString("D"));
        internal int CloseCount { get; private set; }
        internal bool Disposed { get; private set; }
        internal byte[] OpenBytes { get; private set; }
        internal JsonElement OpenConfig { get; private set; }
        internal List<JsonElement> Calls { get; } = new();
        internal Queue<(int Status, string Json)> Replies { get; } = new();

        internal static string OpenResult(string selected, string mode, string instance) =>
            JsonSerializer.Serialize(new { result = new { abi_version = 1,
                backend = new { selected, mode, broker_instance_id = instance } } });

        public uint AbiVersion() => Version;
        public int Open(byte[] config, out ulong handle, out GithubAuthBuffer result)
        {
            Assert.False(Disposed);
            Events.Add("open");
            OpenBytes = config;
            using JsonDocument json = JsonDocument.Parse(config);
            OpenConfig = json.RootElement.Clone();
            handle = OpenHandle;
            result = Buffer(OpenJson);
            if (OversizedOpen) result.Length = 1024 * 1024 + 1;
            if (NullOpenData) result.Data = IntPtr.Zero;
            return OpenStatus;
        }
        public int Call(ulong handle, byte[] request, out GithubAuthBuffer result)
        {
            Assert.False(Disposed);
            Assert.Equal(42UL, handle);
            CallBytes.Add(request);
            using JsonDocument json = JsonDocument.Parse(request);
            Calls.Add(json.RootElement.Clone());
            Events.Add("call:" + json.RootElement.GetProperty("method").GetString());
            var reply = Replies.Dequeue();
            result = Buffer(reply.Json);
            return reply.Status;
        }
        public int Close(ulong handle, out GithubAuthBuffer result)
        {
            Assert.False(Disposed);
            Assert.Equal(42UL, handle);
            Events.Add("close");
            CloseCount++;
            result = Buffer("{\"result\":{}}");
            return CloseStatus;
        }
        public int Free(ulong id)
        {
            Assert.False(Disposed);
            Events.Add($"free:{id}");
            Assert.True(Freed.Add(id), "Native output freed more than once.");
            Marshal.FreeHGlobal(_buffers[id]);
            _buffers.Remove(id);
            return (FailFirstFree && id == 1) || FailedFreeIds.Contains(id) ? 2 : 0;
        }
        public void Dispose()
        {
            Events.Add("unload");
            Assert.Empty(_buffers);
            Disposed = true;
        }
        private GithubAuthBuffer Buffer(string text)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            IntPtr pointer = Marshal.AllocHGlobal(Math.Max(data.Length, 1));
            Marshal.Copy(data, 0, pointer, data.Length);
            ulong id = ++_id;
            _buffers.Add(id, pointer);
            return new GithubAuthBuffer { Id = id, Data = pointer, Length = (nuint)data.Length };
        }
    }
}
