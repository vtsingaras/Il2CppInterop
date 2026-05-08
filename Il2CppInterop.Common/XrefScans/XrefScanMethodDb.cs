using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using Il2CppInterop.Common.Attributes;
using Il2CppInterop.Common.Maps;

namespace Il2CppInterop.Common.XrefScans;

public static class XrefScanMethodDb
{
    private static readonly MethodAddressToTokenMap MethodMap;
    private static readonly MethodXrefScanCache XrefScanCache;
    private static readonly long GameAssemblyBase;

    private static XrefScanUtil.InitMetadataForMethod ourMetadataInitForMethodDelegate;

    static XrefScanMethodDb()
    {
        MethodMap = new MethodAddressToTokenMap(
            GeneratedDatabasesUtil.GetDatabasePath(MethodAddressToTokenMap.FileName));
        XrefScanCache = new MethodXrefScanCache(GeneratedDatabasesUtil.GetDatabasePath(MethodXrefScanCache.FileName));

        // Use the cross-platform Il2CppNativeModule lookup so this works on macOS too;
        // the historic Process.GetCurrentProcess().Modules iteration finds nothing on
        // Darwin (Process.Modules is a stub on macOS).
        var il2CppModule = Il2CppNativeModule.FindIl2Cpp();
        if (il2CppModule != null)
            GameAssemblyBase = (long)il2CppModule.BaseAddress;
    }

    public static MethodBase TryResolvePointer(IntPtr methodStart)
    {
        return MethodMap.Lookup((long)methodStart - GameAssemblyBase);
    }

    internal static IEnumerable<XrefInstance> ListUsers(CachedScanResultsAttribute attribute)
    {
        for (var i = attribute.RefRangeStart; i < attribute.RefRangeEnd; i++)
            yield return XrefScanCache.GetAt(i).AsXrefInstance(GameAssemblyBase);
    }

    internal static IEnumerable<XrefInstance> CachedXrefScan(CachedScanResultsAttribute attribute)
    {
        for (var i = attribute.XrefRangeStart; i < attribute.XrefRangeEnd; i++)
            yield return XrefScanCache.GetAt(i).AsXrefInstance(GameAssemblyBase);
    }

    internal static void CallMetadataInitForMethod(CachedScanResultsAttribute attribute)
    {
        if (attribute.MetadataInitFlagRva == 0 || attribute.MetadataInitTokenRva == 0)
            return;

        if (Marshal.ReadByte((IntPtr)(GameAssemblyBase + attribute.MetadataInitFlagRva)) != 0)
            return;

        if (ourMetadataInitForMethodDelegate == null)
            ourMetadataInitForMethodDelegate =
                Marshal.GetDelegateForFunctionPointer<XrefScanUtil.InitMetadataForMethod>(
                    (IntPtr)(GameAssemblyBase + XrefScanCache.Header.InitMethodMetadataRva));

        var token = Marshal.ReadInt32((IntPtr)(GameAssemblyBase + attribute.MetadataInitTokenRva));

        ourMetadataInitForMethodDelegate(token);

        Marshal.WriteByte((IntPtr)(GameAssemblyBase + attribute.MetadataInitFlagRva), 1);
    }
}
