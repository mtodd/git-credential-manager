using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace GitCredentialManager.DpopDemo;

internal sealed class DpopDemoConfig
{
    internal string Library { get; init; }
    internal string BrokerEndpoint { get; init; }
    internal string CapabilityFile { get; init; }
    internal Guid BrokerInstanceId { get; init; }
    internal string CredentialId { get; init; }
    internal string KeyId { get; init; }
    internal Uri Resource { get; init; }
    internal string Origin => Resource.GetLeftPart(UriPartial.Authority);

    internal static DpopDemoConfig Load(string path)
    {
        byte[] bytes = PrivateFile.Read(path, 16384);
        try
        {
            using JsonDocument document = JsonDocument.Parse(bytes);
            JsonElement root = document.RootElement;
            var names = new HashSet<string>(StringComparer.Ordinal);
            string[] expected = { "version", "library", "broker_endpoint", "capability_file",
                "broker_instance_id", "credential_id", "key_id", "resource_url" };
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Any(x => !names.Add(x.Name)) ||
                !names.SetEquals(expected) || !root.GetProperty("version").TryGetInt32(out int version) || version != 1)
            {
                throw DpopDemoProtocol.Invalid("Invalid version-1 DPoP demo configuration.");
            }
            string Get(string key) => root.GetProperty(key).GetString();
            string library = Get("library");
            string endpoint = Get("broker_endpoint");
            string capability = Get("capability_file");
            PrivateFile.ValidatePath(library);
            PrivateFile.ValidatePath(endpoint);
            PrivateFile.ValidatePath(capability);
            if (!File.Exists(library) ||
                !Guid.TryParseExact(Get("broker_instance_id"), "D", out Guid instance))
            {
                throw DpopDemoProtocol.Invalid("Invalid DPoP native library or broker instance configuration.");
            }
            string credential = Get("credential_id");
            string key = Get("key_id");
            if (!ValidId(credential) || !ValidId(key))
            {
                throw DpopDemoProtocol.Invalid("Invalid DPoP credential or key identifier.");
            }
            Uri resource = DpopDemoProtocol.ValidateUrl(Get("resource_url"), allowQuery: false);
            if (resource.AbsolutePath == "/" || resource.AbsolutePath.EndsWith("/", StringComparison.Ordinal))
            {
                throw DpopDemoProtocol.Invalid("The DPoP demo requires a non-root repository URL without a trailing slash.");
            }
            return new DpopDemoConfig { Library = library, BrokerEndpoint = endpoint, CapabilityFile = capability,
                BrokerInstanceId = instance, CredentialId = credential, KeyId = key, Resource = resource };
        }
        catch (DpopDemoException) { throw; }
        catch (Exception)
        {
            throw DpopDemoProtocol.Invalid("Malformed DPoP demo configuration.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal byte[] NativeConfiguration()
    {
        byte[] bytes = PrivateFile.Read(CapabilityFile, 4096);
        try
        {
            string capability = new UTF8Encoding(false, true).GetString(bytes);
            // Provisioning tools commonly end the private token file with one LF.
            if (capability.EndsWith("\n", StringComparison.Ordinal)) capability = capability[..^1];
            if (!DpopDemoProtocol.IsVisible(capability, 4096))
            {
                throw DpopDemoProtocol.Invalid("Malformed private broker capability.");
            }
            return JsonSerializer.SerializeToUtf8Bytes(new
            {
                mode = "require_broker",
                application_id = "git-dpop-demo-gcm",
                broker = new
                {
                    endpoint = new { kind = "unix", path = BrokerEndpoint },
                    capability,
                    required_policy = new { permissions = new[] { "headers", "prove" },
                        credentials = new[] { CredentialId }, keys = new[] { KeyId }, origins = new[] { Origin } }
                }
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static bool ValidId(string value) =>
        !string.IsNullOrEmpty(value) && value.Length <= 128 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
}
