using Minidump.Streams;
using System;
using System.Runtime.InteropServices;
using static Minidump.Helpers;

namespace Minidump.Templates
{
    public class wdigest
    {
        public struct WdigestTemplate
        {
            public byte[] signature;
            public int first_entry_offset;
            public KIWI_WDIGEST_LIST_ENTRY list_entry;
            public int primary_offset;
            public int USERNAME_OFFSET;
            public int HOSTNAME_OFFSET;
            public int PASSWORD_OFFSET;
        }

        public static WdigestTemplate get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            WdigestTemplate template = new WdigestTemplate();

            template.USERNAME_OFFSET = 0x30;
            template.HOSTNAME_OFFSET = 0x40;
            template.PASSWORD_OFFSET = 0x50;

            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                if ((int)SystemInfo.WindowsMinBuild.WIN_XP <= sysinfo.BuildNumber &&
                    sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_2K3)
                {
                    template.signature = new byte[] { 0x48, 0x3b, 0xda, 0x74 };
                    template.first_entry_offset = -4;
                    template.primary_offset = 36;
                    template.list_entry = new KIWI_WDIGEST_LIST_ENTRY();
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_2K3 <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    template.signature = new byte[] { 0x48, 0x3b, 0xda, 0x74 };
                    template.first_entry_offset = -4;
                    template.primary_offset = 48;
                    template.list_entry = new KIWI_WDIGEST_LIST_ENTRY();
                }
                else if (sysinfo.BuildNumber >= (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    template.signature = new byte[] { 0x48, 0x3b, 0xd9, 0x74 };
                    template.first_entry_offset = -4;
                    template.primary_offset = 48;
                    template.list_entry = new KIWI_WDIGEST_LIST_ENTRY();
                }
                else
                {
                    throw new Exception($"Unknown BuildNumber! {sysinfo.BuildNumber}");
                }
            }
            else if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                if ((int)SystemInfo.WindowsMinBuild.WIN_XP <= sysinfo.BuildNumber &&
                    sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_2K3)
                {
                    template.signature = new byte[] { 0x74, 0x18, 0x8b, 0x4d, 0x08, 0x8b, 0x11 };
                    template.first_entry_offset = -6;
                    template.primary_offset = 36;
                    template.list_entry = new KIWI_WDIGEST_LIST_ENTRY();
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_2K3 <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    template.signature = new byte[] { 0x74, 0x18, 0x8b, 0x4d, 0x08, 0x8b, 0x11 };
                    template.first_entry_offset = -6;
                    template.primary_offset = 28;
                    template.list_entry = new KIWI_WDIGEST_LIST_ENTRY();
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_VISTA <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
                {
                    template.signature = new byte[] { 0x74, 0x11, 0x8b, 0x0b, 0x39, 0x4e, 0x10 };
                    template.first_entry_offset = -6;
                    template.primary_offset = 32;
                    template.list_entry = new KIWI_WDIGEST_LIST_ENTRY();
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_BLUE <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_10)
                {
                    template.signature = new byte[] { 0x74, 0x15, 0x8b, 0x0a, 0x39, 0x4e, 0x10 };
                    template.first_entry_offset = -4;
                    template.primary_offset = 32;
                    template.list_entry = new KIWI_WDIGEST_LIST_ENTRY();
                }
                else if (sysinfo.BuildNumber >= (int)SystemInfo.WindowsMinBuild.WIN_10)
                {
                    template.signature = new byte[] { 0x74, 0x15, 0x8b, 0x0a, 0x39, 0x4e, 0x10 };
                    template.first_entry_offset = -6;
                    template.primary_offset = 32;
                    template.list_entry = new KIWI_WDIGEST_LIST_ENTRY();
                }
                else
                {
                    template.signature = new byte[] { 0x74, 0x15, 0x8b, 0x17, 0x39, 0x56, 0x10 };
                    template.first_entry_offset = -6;
                    template.primary_offset = 32;
                    template.list_entry = new KIWI_WDIGEST_LIST_ENTRY();
                }
            }
            else
            {
                throw new Exception($"Unknown architecture! {sysinfo.ProcessorArchitecture}");
            }

            return template;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_WDIGEST_LIST_ENTRY
        {
            public long Flink;
            public long Blink;
            public int UsageCount;
            public long This;
            public LUID LocallyUniqueIdentifier;

            public UNICODE_STRING UserName;
            public UNICODE_STRING Domain;
            public UNICODE_STRING Password;
        }
    }
}