using Minidump.Streams;
using System;
using System.Runtime.InteropServices;
using static Minidump.Helpers;

namespace Minidump.Templates
{
    public class tspkg
    {
        public struct TspkgTemplate
        {
            public byte[] signature;
            public long avl_offset;
            public int TSCredTypeSize;
            public int TSCredLocallyUniqueIdentifierOffset;
            public int TSCredOffset;
        }

        public static TspkgTemplate get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            TspkgTemplate template = new TspkgTemplate();
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                template.signature = new byte[] { 0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x0d };
                template.avl_offset = 7;
                if (sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1607)
                {
                    template.TSCredTypeSize = Marshal.SizeOf(new KIWI_TS_CREDENTIAL());
                    template.TSCredLocallyUniqueIdentifierOffset = FieldOffset<KIWI_TS_CREDENTIAL>("LocallyUniqueIdentifier");
                    template.TSCredOffset = FieldOffset<KIWI_TS_CREDENTIAL>("pTsPrimary");
                }
                else if (sysinfo.BuildNumber >= (int)SystemInfo.WindowsBuild.WIN_10_1607)
                {
                    template.TSCredTypeSize = Marshal.SizeOf(new KIWI_TS_CREDENTIAL_1607());
                    template.TSCredLocallyUniqueIdentifierOffset = FieldOffset<KIWI_TS_CREDENTIAL_1607>("LocallyUniqueIdentifier");
                    template.TSCredOffset = FieldOffset<KIWI_TS_CREDENTIAL_1607>("pTsPrimary");
                }
                else
                {
                    //currently doesnt make sense, but keeping it here for future use
                    throw new Exception($"Unknown buildnumber! {sysinfo.BuildNumber}");
                }
            }
            else if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
                {
                    template.signature = new byte[] { 0x8b, 0xff, 0x55, 0x8b, 0xec, 0x51, 0x56, 0xbe };
                    template.avl_offset = 8;
                    template.TSCredTypeSize = Marshal.SizeOf(new KIWI_TS_CREDENTIAL_1607());
                    template.TSCredLocallyUniqueIdentifierOffset = FieldOffset<KIWI_TS_CREDENTIAL_1607>("LocallyUniqueIdentifier");
                    template.TSCredOffset = FieldOffset<KIWI_TS_CREDENTIAL_1607>("pTsPrimary");
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_8 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
                {
                    template.signature = new byte[] { 0x8b, 0xff, 0x53, 0xbb };
                    template.avl_offset = 4;
                    template.TSCredTypeSize = Marshal.SizeOf(new KIWI_TS_CREDENTIAL());
                    template.TSCredLocallyUniqueIdentifierOffset = FieldOffset<KIWI_TS_CREDENTIAL>("LocallyUniqueIdentifier");
                    template.TSCredOffset = FieldOffset<KIWI_TS_CREDENTIAL>("pTsPrimary");
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_BLUE <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1607)
                {
                    template.signature = new byte[] { 0x8b, 0xff, 0x57, 0xbf };
                    template.avl_offset = 4;
                    template.TSCredTypeSize = Marshal.SizeOf(new KIWI_TS_CREDENTIAL_1607());
                    template.TSCredLocallyUniqueIdentifierOffset = FieldOffset<KIWI_TS_CREDENTIAL_1607>("LocallyUniqueIdentifier");
                    template.TSCredOffset = FieldOffset<KIWI_TS_CREDENTIAL_1607>("pTsPrimary");
                }
                else if (sysinfo.BuildNumber >= (int)SystemInfo.WindowsBuild.WIN_10_1607)
                {
                    template.signature = new byte[] { 0x8b, 0xff, 0x57, 0xbf };
                    template.avl_offset = 4;
                    template.TSCredTypeSize = Marshal.SizeOf(new KIWI_TS_CREDENTIAL_1607());
                    template.TSCredLocallyUniqueIdentifierOffset = FieldOffset<KIWI_TS_CREDENTIAL_1607>("LocallyUniqueIdentifier");
                    template.TSCredOffset = FieldOffset<KIWI_TS_CREDENTIAL_1607>("pTsPrimary");
                }
            }
            else
            {
                throw new Exception($"Unknown architecture! {sysinfo.ProcessorArchitecture}");
            }
            return template;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RTL_AVL_TABLE
    {
        public RTL_BALANCED_LINKS BalancedRoot;
        public long OrderedPointer;
        public uint WhichOrderedElement;
        public uint NumberGenericTableElements;
        public uint DepthOfTree;
        public IntPtr RestartKey;
        public uint DeleteCount;
        public IntPtr CompareRoutine;
        public IntPtr AllocateRoutine;
        public IntPtr FreeRoutine;
        public IntPtr TableContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RTL_BALANCED_LINKS
    {
        public long Parent;
        public long LeftChild;
        public long RightChild;
        public byte Balance;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_TS_PRIMARY_CREDENTIAL
    {
        private readonly IntPtr unk0;
        public KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_TS_CREDENTIAL
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 108)]
        public byte[] unk0;

        private readonly LUID LocallyUniqueIdentifier;
        private readonly IntPtr unk1;
        private readonly IntPtr unk2;
        private readonly IntPtr pTsPrimary;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_TS_CREDENTIAL_1607
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 112)]
        public byte[] unk0;

        private readonly LUID LocallyUniqueIdentifier;
        private readonly IntPtr unk1;
        private readonly IntPtr unk2;
        private readonly IntPtr pTsPrimary;
    }
}