using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Il2CppInterop.Common;

/// <summary>
/// Lightweight cross-platform replacement for <see cref="ProcessModule"/> in code paths
/// that look up the IL2CPP-compiled native module by name and need its base address +
/// loaded size for signature scans.
///
/// <para>
/// The historic implementation (<c>Process.GetCurrentProcess().Modules.OfType&lt;ProcessModule&gt;().Single(...)</c>)
/// works on Windows and Linux but fails on macOS: .NET 6+'s
/// <see cref="Process.Modules"/> on Darwin is implemented as a stub that returns only the
/// main executable, so <c>.Single(x =&gt; x.ModuleName == "GameAssembly.dylib")</c> throws
/// <see cref="InvalidOperationException"/> ("Sequence contains no matching element"). To
/// resolve the IL2CPP module on macOS we have to enumerate <c>dyld</c>'s loaded image list
/// directly via <c>_dyld_image_count</c> / <c>_dyld_get_image_name</c> /
/// <c>_dyld_get_image_header</c>.
/// </para>
/// </summary>
public sealed class Il2CppNativeModule
{
    /// <summary>The bare module file name (e.g. <c>GameAssembly.dll</c>, <c>GameAssembly.dylib</c>, <c>libil2cpp.so</c>).</summary>
    public string ModuleName { get; }

    /// <summary>The runtime virtual address at which the module's image starts.</summary>
    public IntPtr BaseAddress { get; }

    /// <summary>The byte length of the module's loaded image in memory.</summary>
    public long ModuleMemorySize { get; }

    /// <summary>The full path to the module file, when available; otherwise <see cref="ModuleName"/>.</summary>
    public string FileName { get; }

    private Il2CppNativeModule(string moduleName, IntPtr baseAddress, long moduleMemorySize, string fileName)
    {
        ModuleName = moduleName;
        BaseAddress = baseAddress;
        ModuleMemorySize = moduleMemorySize;
        FileName = fileName;
    }

    /// <summary>Wraps a managed <see cref="ProcessModule"/> (used on Windows/Linux where Process.Modules works).</summary>
    public static Il2CppNativeModule FromProcessModule(ProcessModule m) =>
        new(m.ModuleName, m.BaseAddress, m.ModuleMemorySize, m.FileName ?? m.ModuleName);

    /// <summary>
    /// Find the IL2CPP-compiled native module by name. Searches platform-specific module
    /// names: <c>GameAssembly.dll</c>, <c>GameAssembly.dylib</c>, <c>libGameAssembly.dylib</c>,
    /// <c>GameAssembly.so</c>, <c>UserAssembly.dll</c>. Returns <see langword="null"/> if no
    /// matching module is currently loaded.
    /// </summary>
    public static Il2CppNativeModule? FindIl2Cpp()
    {
        var preferred = new[]
        {
            "GameAssembly.dll", "GameAssembly.dylib", "libGameAssembly.dylib", "GameAssembly.so",
            "UserAssembly.dll"
        };

        // Windows / Linux: Process.GetCurrentProcess().Modules works.
        // macOS: ProcessModule.Modules is a stub that only returns the main executable, so we
        // fall through to the dyld enumeration below.
        try
        {
            var processModules = Process.GetCurrentProcess().Modules.OfType<ProcessModule>().ToArray();
            if (processModules.Length > 1)
            {
                var match = processModules.FirstOrDefault(m => preferred.Contains(m.ModuleName));
                if (match != null)
                    return FromProcessModule(match);
            }
        }
        catch
        {
            // best-effort; fall through to dyld enumeration
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return FindViaDyld(preferred);
        }

        return null;
    }

    private static unsafe Il2CppNativeModule? FindViaDyld(string[] preferredNames)
    {
        var count = _dyld_image_count();
        for (uint i = 0; i < count; i++)
        {
            var namePtr = _dyld_get_image_name(i);
            if (namePtr == IntPtr.Zero) continue;
            var fullPath = Marshal.PtrToStringAnsi(namePtr);
            if (string.IsNullOrEmpty(fullPath)) continue;

            var fileName = Path.GetFileName(fullPath);
            if (!preferredNames.Contains(fileName, StringComparer.OrdinalIgnoreCase)) continue;

            var header = _dyld_get_image_header(i);
            if (header == IntPtr.Zero) continue;

            return new Il2CppNativeModule(
                fileName,
                header,
                ComputeMachOImageSize(header),
                fullPath);
        }

        return null;
    }

    /// <summary>
    /// Compute the in-memory size of a Mach-O image by walking its load commands and
    /// summing every <c>LC_SEGMENT_64</c>'s <c>vmsize</c>. The signature scanner
    /// reads this many bytes starting at <see cref="BaseAddress"/>, so it must be the
    /// real address-range size, not the on-disk file size.
    /// </summary>
    private static unsafe long ComputeMachOImageSize(IntPtr machHeader)
    {
        // Both 32-bit and 64-bit Mach-O headers start with `magic` (4 bytes), and the
        // file we're enumerating is ARM64 / x86_64 — so always 64-bit. mach_header_64:
        //   uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
        //   then ncmds load commands, each starting with: uint32_t cmd, uint32_t cmdsize.
        const uint MH_MAGIC_64 = 0xfeedfacf;
        const uint LC_SEGMENT_64 = 0x19;

        var hdr = (uint*) machHeader;
        if (hdr[0] != MH_MAGIC_64)
        {
            // Unexpected format. Fall back to a generous default so signature scans don't
            // immediately give up; arm64 IL2CPP binaries are typically 8–80 MiB.
            return 256L * 1024 * 1024;
        }

        var ncmds = hdr[4];
        var cursor = (byte*) (hdr + 8); // 8 uint32_t = 32 bytes header
        long imageSize = 0;
        for (uint i = 0; i < ncmds; i++)
        {
            var cmd = *(uint*) cursor;
            var cmdSize = *(uint*) (cursor + 4);
            if (cmd == LC_SEGMENT_64)
            {
                // segment_command_64:
                //   uint32_t cmd, cmdsize, char segname[16], uint64_t vmaddr, uint64_t vmsize, ...
                var vmsize = *(ulong*) (cursor + 8 + 16 + 8);
                imageSize += (long) vmsize;
            }
            cursor += cmdSize;
        }

        return imageSize > 0 ? imageSize : 256L * 1024 * 1024;
    }

    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "_dyld_image_count")]
    private static extern uint _dyld_image_count();

    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "_dyld_get_image_name")]
    private static extern IntPtr _dyld_get_image_name(uint imageIndex);

    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "_dyld_get_image_header")]
    private static extern IntPtr _dyld_get_image_header(uint imageIndex);
}
