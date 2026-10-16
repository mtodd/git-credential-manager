using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace GitCredentialManager.DpopDemo;

internal static class PrivateFile
{
    internal static void ValidatePath(string path)
    {
        if (string.IsNullOrEmpty(path) || path.IndexOfAny(new[] { '\0', '\r', '\n' }) >= 0 ||
            !Path.IsPathFullyQualified(path) || Path.GetFullPath(path) != path)
        {
            throw DpopDemoProtocol.Invalid("The DPoP demo requires absolute, normalized file and socket paths.");
        }
    }

    internal static byte[] Read(string path, int limit)
    {
        try
        {
            ValidatePath(path);
            bool mac = OperatingSystem.IsMacOS();
            if ((!mac && !OperatingSystem.IsLinux()) || !Environment.Is64BitProcess)
            {
                throw DpopDemoProtocol.Invalid("The DPoP demo supports 64-bit macOS and Linux only.");
            }

            // O_NOFOLLOW defeats final-component symlinks; O_NONBLOCK prevents
            // an untrusted FIFO from blocking before the descriptor is checked.
            int flags = mac ? 0x100 | 0x4 | 0x1000000 : 0x20000 | 0x800 | 0x80000;
            int fd = Open(path, flags);
            if (fd < 0) throw InvalidPrivateFile();
            using var handle = new SafeFileHandle((IntPtr)fd, ownsHandle: true);

            uint mode;
            uint uid;
            uint links;
            ulong size;
            if (mac)
            {
                MacStat stat;
                int result = RuntimeInformation.ProcessArchitecture == Architecture.X64
                    ? MacFStat64(handle, out stat) : MacFStat(handle, out stat);
                if (result != 0 || stat.Size < 0) throw InvalidPrivateFile();
                mode = stat.Mode; uid = stat.Uid; links = stat.Links; size = (ulong)stat.Size;
            }
            else
            {
                // Linux statx has the same defined ABI on x64 and arm64.
                const uint requested = 0x1 | 0x2 | 0x4 | 0x8 | 0x200;
                if (Statx(handle, "", 0x1000, requested, out LinuxStatx stat) != 0 ||
                    (stat.Mask & requested) != requested)
                    throw InvalidPrivateFile();
                mode = stat.Mode; uid = stat.Uid; links = stat.Links; size = stat.Size;
            }
            if ((mode & 0xf000) != 0x8000 || (mode & 0xfff) is not (0x100 or 0x180) ||
                uid != GetEffectiveUid() || links != 1 || size == 0 || size > (ulong)limit)
            {
                throw InvalidPrivateFile();
            }

            // All checks and the read concern the same opened file, not a
            // second pathname lookup. No secret file is modified.
            // Avoid an additional managed FileStream buffer outside the caller's cleanup.
            using var stream = new FileStream(handle, FileAccess.Read, bufferSize: 1, isAsync: false);
            byte[] bytes = new byte[(int)size];
            try
            {
                stream.ReadExactly(bytes);
                if (stream.ReadByte() != -1) throw InvalidPrivateFile();
                return bytes;
            }
            catch
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
                throw;
            }
        }
        catch (DpopDemoException) { throw; }
        catch (Exception)
        {
            throw InvalidPrivateFile();
        }
    }

    private static DpopDemoException InvalidPrivateFile() =>
        DpopDemoProtocol.Invalid("DPoP configuration and capability must be nonempty, owner-only regular files (0400 or 0600), without symlinks or hard links.");

    [DllImport("libc", EntryPoint = "open", CallingConvention = CallingConvention.Cdecl)]
    private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

    [DllImport("libc", EntryPoint = "geteuid", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint GetEffectiveUid();

    [DllImport("libc", EntryPoint = "fstat", CallingConvention = CallingConvention.Cdecl)]
    private static extern int MacFStat(SafeFileHandle handle, out MacStat stat);

    [DllImport("libc", EntryPoint = "fstat$INODE64", CallingConvention = CallingConvention.Cdecl)]
    private static extern int MacFStat64(SafeFileHandle handle, out MacStat stat);

    [DllImport("libc", EntryPoint = "statx", CallingConvention = CallingConvention.Cdecl)]
    private static extern int Statx(SafeFileHandle handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        int flags, uint mask, out LinuxStatx stat);

    // Darwin's 64-bit struct stat and Linux's stable struct statx. Only the
    // required fields are named, but the native functions write the full struct.
    [StructLayout(LayoutKind.Explicit, Size = 144)]
    private struct MacStat
    {
        [FieldOffset(4)] internal ushort Mode;
        [FieldOffset(6)] internal ushort Links;
        [FieldOffset(16)] internal uint Uid;
        [FieldOffset(96)] internal long Size;
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStatx
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(16)] internal uint Links;
        [FieldOffset(20)] internal uint Uid;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(40)] internal ulong Size;
    }
}
