using System.Runtime.InteropServices;
using Il2CppInterop.Common;
using Il2CppInterop.Common.XrefScans;
using Il2CppInterop.Generator.Contexts;
using Il2CppInterop.Generator.Extensions;
using Microsoft.Extensions.Logging;

namespace Il2CppInterop.Generator.Utils;

internal static class XrefScanMetadataGenerationUtil
{
    internal static long MetadataInitForMethodRva;
    internal static IntPtr MetadataInitForMethodFileOffset;
    private static bool _metadataInitProbeCompleted;

    private static readonly (string Assembly, string Type, string Method)[] MetadataInitCandidates =
    {
        ("UnityEngine.CoreModule", "UnityEngine.Object", ".cctor"),
        ("mscorlib", "System.Exception", "get_Message"),
        ("mscorlib", "System.IntPtr", "Equals")
    };

    private static void FindMetadataInitForMethod(RewriteGlobalContext context, long gameAssemblyBase)
    {
        // The metadata-init RVA scan walks the IL2CPP-generated cctor / get_Message
        // body looking for the first call instruction. That walk uses Iced, which is
        // x86/x64-only — on arm64 IL2CPP binaries (Apple Silicon, Android arm64, etc.)
        // Iced sees nonsense, the JumpTargets enumerable yields no elements, and the
        // .First() below throws "Sequence contains no elements" 12× in parallel from
        // Pass16ScanMethodRefs.
        //
        // The metadata-init scan is a perf-only optimization; the consuming code in
        // FindMetadataInitForMethod(MethodRewriteContext, long) gracefully degrades
        // when MetadataInitForMethodRva stays 0. Rather than crash the whole interop
        // generation, leave the RVAs at 0 on architectures we can't disassemble and
        // log a warning.
        if (_metadataInitProbeCompleted) return;
        _metadataInitProbeCompleted = true;

        if (RuntimeInformation.ProcessArchitecture is not (Architecture.X86 or Architecture.X64))
        {
            Logger.Instance.LogInformation(
                "Skipping metadata-init RVA scan on {Arch} — XrefScanner is x86/x64-only. " +
                "Method-level metadata-init flags will not be cached; runtime resolution still works.",
                RuntimeInformation.ProcessArchitecture);
            return;
        }

        foreach (var metadataInitCandidate in MetadataInitCandidates)
        {
            var assembly =
                context.Assemblies.FirstOrDefault(it =>
                    it.OriginalAssembly.Name == metadataInitCandidate.Assembly);
            var unityObjectCctor = assembly?.TryGetTypeByName(metadataInitCandidate.Type)?.OriginalType.Methods
                .FirstOrDefault(it => it.Name == metadataInitCandidate.Method);

            if (unityObjectCctor == null) continue;

            var firstJumpTarget = XrefScannerLowLevel
                .JumpTargets((IntPtr)(gameAssemblyBase + unityObjectCctor.ExtractOffset()))
                .FirstOrDefault();
            if (firstJumpTarget == IntPtr.Zero) continue;

            MetadataInitForMethodFileOffset = firstJumpTarget;
            MetadataInitForMethodRva = (long)MetadataInitForMethodFileOffset - gameAssemblyBase -
                unityObjectCctor.ExtractOffset() + unityObjectCctor.ExtractRva();

            return;
        }

        // Couldn't find a candidate even on x86/x64. Don't crash; the consuming code
        // gracefully degrades when MetadataInitForMethodRva is 0 — runtime metadata
        // resolution falls back to the slow path.
        Logger.Instance.LogInformation(
            "Unable to find a method with a metadata-init reference; metadata-init RVA cache disabled. " +
            "(This is a perf-only optimization — runtime resolution still works.)");
    }

    internal static (long FlagRva, long TokenRva) FindMetadataInitForMethod(MethodRewriteContext method,
        long gameAssemblyBase)
    {
        if (MetadataInitForMethodRva == 0)
            FindMetadataInitForMethod(method.DeclaringType.AssemblyContext.GlobalContext, gameAssemblyBase);

        var codeStart = (IntPtr)(gameAssemblyBase + method.FileOffset);
        var firstCall = XrefScannerLowLevel.JumpTargets(codeStart).FirstOrDefault();
        if (firstCall != MetadataInitForMethodFileOffset || firstCall == IntPtr.Zero) return (0, 0);

        var tokenPointer =
            XrefScanUtilFinder.FindLastRcxReadAddressBeforeCallTo(codeStart, MetadataInitForMethodFileOffset);
        var initFlagPointer =
            XrefScanUtilFinder.FindByteWriteTargetRightAfterCallTo(codeStart, MetadataInitForMethodFileOffset);

        if (tokenPointer == IntPtr.Zero || initFlagPointer == IntPtr.Zero) return (0, 0);

        return ((long)initFlagPointer - gameAssemblyBase - method.FileOffset + method.Rva,
            (long)tokenPointer - gameAssemblyBase - method.FileOffset + method.Rva);
    }
}
