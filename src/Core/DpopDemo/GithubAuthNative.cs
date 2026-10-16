using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace GitCredentialManager.DpopDemo;

[StructLayout(LayoutKind.Sequential)]
internal struct GithubAuthBuffer
{
    internal ulong Id;
    internal IntPtr Data;
    internal nuint Length;
}

internal interface IGithubAuthNative : IDisposable
{
    uint AbiVersion();
    int Open(byte[] config, out ulong handle, out GithubAuthBuffer result);
    int Call(ulong handle, byte[] request, out GithubAuthBuffer result);
    int Close(ulong handle, out GithubAuthBuffer result);
    int Free(ulong id);
}

internal sealed class GithubAuthNative : IGithubAuthNative
{
    private IntPtr _library;
    private readonly AbiVersionFunction _version;
    private readonly OpenFunction _open;
    private readonly CallFunction _call;
    private readonly CloseFunction _close;
    private readonly FreeFunction _free;

    internal GithubAuthNative(string path)
    {
        PrivateFile.ValidatePath(path);
        try
        {
            // Resolve this one explicit library, without assembly-global
            // resolvers or changes to PATH/DYLD_LIBRARY_PATH/LD_LIBRARY_PATH.
            _library = NativeLibrary.Load(path);
            T Bind<T>(string symbol) where T : Delegate =>
                Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(_library, symbol));
            _version = Bind<AbiVersionFunction>("github_auth_abi_version");
            _open = Bind<OpenFunction>("github_auth_open");
            _call = Bind<CallFunction>("github_auth_call");
            _close = Bind<CloseFunction>("github_auth_close");
            _free = Bind<FreeFunction>("github_auth_buffer_free");
        }
        catch
        {
            Dispose();
            throw DpopDemoProtocol.Invalid("Unable to load the configured github-auth-ffi ABI.");
        }
    }

    public uint AbiVersion() => _version();
    public int Open(byte[] config, out ulong handle, out GithubAuthBuffer result) =>
        _open(config, (nuint)config.Length, IntPtr.Zero, out handle, out result);
    public int Call(ulong handle, byte[] request, out GithubAuthBuffer result) =>
        _call(handle, request, (nuint)request.Length, out result);
    public int Close(ulong handle, out GithubAuthBuffer result) => _close(handle, out result);
    public int Free(ulong id) => _free(id);

    public void Dispose()
    {
        if (_library != IntPtr.Zero)
        {
            NativeLibrary.Free(_library);
            _library = IntPtr.Zero;
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint AbiVersionFunction();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int OpenFunction([In] byte[] config, nuint length, IntPtr callbacks,
        out ulong handle, out GithubAuthBuffer result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int CallFunction(ulong handle, [In] byte[] request, nuint length, out GithubAuthBuffer result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int CloseFunction(ulong handle, out GithubAuthBuffer result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int FreeFunction(ulong id);
}

internal sealed class GithubAuthSession : IDisposable
{
    private readonly IGithubAuthNative _native;
    private ulong _handle;

    internal GithubAuthSession(IGithubAuthNative native) => _native = native;

    internal void Open(byte[] config, Guid expectedInstance)
    {
        try
        {
            if (_handle != 0 || _native.AbiVersion() != 1)
            {
                throw DpopDemoProtocol.Invalid("Incompatible github-auth-ffi ABI or session lifecycle.");
            }
            int status = _native.Open(config, out _handle, out GithubAuthBuffer buffer);
            JsonElement result = TakeResult(status, buffer);
            JsonElement backend = result.GetProperty("backend");
            if (_handle == 0 || result.GetProperty("abi_version").GetInt32() != 1 ||
                backend.GetProperty("selected").GetString() != "broker" ||
                backend.GetProperty("mode").GetString() != "require_broker" ||
                !Guid.TryParseExact(backend.GetProperty("broker_instance_id").GetString(), "D", out Guid instance) ||
                instance != expectedInstance)
            {
                throw DpopDemoProtocol.Invalid("The native SDK did not select the pinned, required broker instance.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(config);
        }
    }

    internal JsonElement Call(string method, object parameters)
    {
        if (_handle == 0) throw DpopDemoProtocol.Invalid("The native SDK session is not open.");
        byte[] request = JsonSerializer.SerializeToUtf8Bytes(new { method, @params = parameters });
        try
        {
            int status = _native.Call(_handle, request, out GithubAuthBuffer buffer);
            return TakeResult(status, buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(request);
        }
    }

    public void Dispose()
    {
        if (_handle == 0) return;
        ulong handle = _handle;
        _handle = 0;
        // The ABI drains and joins its worker even when close reports failure.
        // The library is retained until after this call and buffer release.
        int status = _native.Close(handle, out GithubAuthBuffer buffer);
        TakeResult(status, buffer);
    }

    private JsonElement TakeResult(int status, GithubAuthBuffer buffer)
    {
        byte[] copy = null;
        try
        {
            if (status != 0)
            {
                // Native messages are deliberately not logged or rethrown:
                // error JSON can contain sensitive host or credential context.
                throw DpopDemoProtocol.Invalid("The native authentication SDK rejected the operation.");
            }
            if (buffer.Id == 0 || buffer.Data == IntPtr.Zero || buffer.Length == 0 || buffer.Length > 1024 * 1024)
            {
                throw DpopDemoProtocol.Invalid("Invalid native authentication SDK result buffer.");
            }
            copy = new byte[(int)buffer.Length];
            Marshal.Copy(buffer.Data, copy, 0, copy.Length);
            using JsonDocument document = JsonDocument.Parse(copy);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw DpopDemoProtocol.Invalid("Malformed native authentication SDK response.");
            }
            var properties = root.EnumerateObject();
            if (!properties.MoveNext() || properties.Current.Name != "result" ||
                properties.Current.Value.ValueKind != JsonValueKind.Object)
            {
                throw DpopDemoProtocol.Invalid("Malformed native authentication SDK response.");
            }
            JsonElement result = properties.Current.Value.Clone();
            if (properties.MoveNext())
            {
                throw DpopDemoProtocol.Invalid("Ambiguous native authentication SDK response.");
            }
            return result;
        }
        finally
        {
            if (copy is not null) CryptographicOperations.ZeroMemory(copy);
            if (buffer.Id != 0 && _native.Free(buffer.Id) != 0)
            {
                throw DpopDemoProtocol.Invalid("The native authentication SDK could not release an output buffer.");
            }
        }
    }
}
