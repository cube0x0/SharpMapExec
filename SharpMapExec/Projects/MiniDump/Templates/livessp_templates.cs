using Minidump.Streams;
using System;
using static Minidump.Helpers;

namespace Minidump.Templates
{
    public static class livessp
    {
        public struct LiveSspTemplate
        {
            public byte[] signature;
            public long first_entry_offset;
        }

        public static LiveSspTemplate get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            var template = new LiveSspTemplate();
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                template.signature = new byte[] { 0x74, 0x25, 0x8b };
                template.first_entry_offset = -7;
            }
            else if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                template.signature = new byte[] { 0x8b, 0x16, 0x39, 0x51, 0x24, 0x75, 0x08 };
                template.first_entry_offset = -8;
            }
            else
            {
                throw new Exception($"Unknown architecture! {sysinfo.ProcessorArchitecture}");
            }

            return template;
        }
    }

    public struct KIWI_LIVESSP_PRIMARY_CREDENTIAL
    {
        public ulong isSupp;
        public ulong unk0;
        public KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
    }

    public struct KIWI_LIVESSP_LIST_ENTRY
    {
        public long Flink;
        public long Blink;
        public IntPtr unk0;
        public IntPtr unk1;
        public IntPtr unk2;
        public IntPtr unk3;
        public int unk4;
        public int unk5;
        public IntPtr unk6;
        public LUID LocallyUniqueIdentifier;
        public UNICODE_STRING UserName;
        public IntPtr unk7;
        public KIWI_LIVESSP_PRIMARY_CREDENTIAL suppCreds;
    }
}