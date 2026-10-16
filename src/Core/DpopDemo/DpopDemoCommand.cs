using System;

namespace GitCredentialManager.DpopDemo;

internal sealed class DpopDemoException : Exception
{
    internal DpopDemoException(string message) : base(message) { }
}

internal static class DpopDemoCommand
{
    internal const string ConfigVariable = "GIT_DPOP_CONFIG";

    internal static void Execute(ICommandContext context, string command, string configPath,
        Func<string, IGithubAuthNative> createNative = null)
    {
        try
        {
            var request = DpopDemoProtocol.Read(context.Streams.In);
            if (command is "store" or "erase")
            {
                DpopDemoProtocol.ValidateLegacy(request);
                return;
            }
            var config = DpopDemoConfig.Load(configPath);
            var provider = new DpopDemoHostProvider(config, createNative);
            var response = provider.Execute(command, request);

            // Native close and all validation must succeed before emitting any secret.
            if (response is not null)
            {
                context.Streams.Out.Write(response);
            }
        }
        catch (Exception ex)
        {
            if (command == "get")
            {
                context.Streams.Out.Write("quit=1\n\n");
            }

            // Upstream's exception handler prints inner exceptions and traces.
            // Do not propagate native payloads, paths, JSON, or runtime error details.
            if (ex is DpopDemoException) throw;
            throw new DpopDemoException("GCM DPoP demo failed; no fallback credential was used.");
        }
    }
}
