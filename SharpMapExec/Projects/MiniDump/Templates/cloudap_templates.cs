using Minidump.Streams;
using System;
using System.Runtime.InteropServices;
using static Minidump.Helpers;

namespace Minidump.Templates
{
    public class cloudap
    {
        public struct CloudapTemplate
        {
            public byte[] signature;
            public int first_entry_offset;
            public int luidOffset;
            public int cacheOffset;
            public int cbPRTOffset;
            public int PRTOffset;
            public int tonameOffset;
            public Type list_entry;
        }

        public static CloudapTemplate get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            CloudapTemplate template = new CloudapTemplate();
            if (sysinfo.BuildNumber <= (int)SystemInfo.WindowsBuild.WIN_10_1903)
            {
                return template;
            }
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                template.signature = new byte[] { 0x44, 0x8b, 0x01, 0x44, 0x39, 0x42, 0x18, 0x75 };
                template.first_entry_offset = -9;
                template.list_entry = typeof(KIWI_CLOUDAP_LOGON_LIST_ENTRY);
            }
            else if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                template.signature = new byte[] { 0x8b, 0x31, 0x39, 0x72, 0x10, 0x75 };
                template.first_entry_offset = -8;
                template.list_entry = typeof(KIWI_CLOUDAP_LOGON_LIST_ENTRY);
            }
            else
            {
                throw new Exception(String.Format("Could not identify template! Architecture: %s sysinfo.BuildNumber: %s", sysinfo.ProcessorArchitecture, sysinfo.BuildNumber));
            }

            template.luidOffset = StructFieldOffset(template.list_entry, "LocallyUniqueIdentifier");
            template.cacheOffset = StructFieldOffset(template.list_entry, "cacheEntry");

            template.cbPRTOffset = StructFieldOffset(typeof(KIWI_CLOUDAP_CACHE_LIST_ENTRY), "cbPRT");
            template.PRTOffset = StructFieldOffset(typeof(KIWI_CLOUDAP_CACHE_LIST_ENTRY), "PRT");
            template.tonameOffset = StructFieldOffset(typeof(KIWI_CLOUDAP_CACHE_LIST_ENTRY), "toname");

            return template;
        }
    }

    public struct KIWI_CLOUDAP_CACHE_UNK
    {
        public uint unk0;
        public uint unk1;
        public uint unk2;
        public uint unkSizeer;

        public Guid guid;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] unk;
    }

    public struct KIWI_CLOUDAP_CACHE_LIST_ENTRY
    {
        public long Flink;
        public long Blink;
        public uint unk0;
        public IntPtr LockList;
        public IntPtr unk1;
        public IntPtr unk2;
        public IntPtr unk3;
        public IntPtr unk4;
        public IntPtr unk5;
        public uint unk6;
        public uint unk7;
        public uint unk8;
        public uint unk9;
        public IntPtr unkLogin0;
        public IntPtr unkLogin1;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 130)]
        public byte[] toname;

        public long Sid;

        public uint unk10;
        public uint unk11;
        public uint unk12;
        public uint unk13;

        //public KIWI_CLOUDAP_CACHE_UNK toDetermine;
        public ulong toDetermine;

        public IntPtr unk14;
        public uint cbPRT;
        public ulong PRT;
    }

    public struct KIWI_CLOUDAP_LOGON_LIST_ENTRY
    {
        public long Flink;
        public long Blink;
        public int unk0;
        public int unk1;
        public LUID LocallyUniqueIdentifier;
        public Int64 unk2;
        public Int64 unk3;
        public long cacheEntry;
    }
}