using Minidump.Streams;
using System;
using System.Runtime.InteropServices;
using static Minidump.Helpers;

namespace Minidump.Templates
{
    public class dpapi
    {
        private const Int32 ANYSIZE_ARRAY = 1;

        public struct DpapiTemplate
        {
            public byte[] signature;
            public int first_entry_offset;
            public object list_entry;
        }

        public static DpapiTemplate get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            DpapiTemplate template = new DpapiTemplate();
            template.list_entry = new KIWI_MASTERKEY_CACHE_ENTRY();
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    template.signature = new byte[] { 0x4d, 0x3b, 0xee, 0x49, 0x8b, 0xfd, 0x0f, 0x85 };
                    template.first_entry_offset = -4;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_VISTA <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_7)
                {
                    template.signature = new byte[] { 0x49, 0x3b, 0xef, 0x48, 0x8b, 0xfd, 0x0f, 0x84 };
                    template.first_entry_offset = -4;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_7 <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
                {
                    template.signature = new byte[] { 0x33, 0xc0, 0xeb, 0x20, 0x48, 0x8d, 0x05 };
                    template.first_entry_offset = 7;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_8 <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
                {
                    template.signature = new byte[]
                        {0x4c, 0x89, 0x1f, 0x48, 0x89, 0x47, 0x08, 0x49, 0x39, 0x43, 0x08, 0x0f, 0x85};
                    template.first_entry_offset = -4;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_BLUE <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1507)
                {
                    template.signature = new byte[] { 0x08, 0x48, 0x39, 0x48, 0x08, 0x0f, 0x85 };
                    template.first_entry_offset = -10;
                }
                else if ((int)SystemInfo.WindowsBuild.WIN_10_1507 <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1607)
                {
                    template.signature = new byte[] { 0x48, 0x89, 0x4e, 0x08, 0x48, 0x39, 0x48, 0x08 };
                    template.first_entry_offset = -7;
                }
                else if (sysinfo.BuildNumber >= (int)SystemInfo.WindowsBuild.WIN_10_1607)
                {
                    template.signature = new byte[] { 0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x78, 0x08 };
                    template.first_entry_offset = 11;
                }
                else
                {
                    //currently doesnt make sense, but keeping it here for future use
                    throw new Exception($"Unknown architecture! {sysinfo.ProcessorArchitecture}");
                }
            }
            else if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
                {
                    template.signature = new byte[] { 0x33, 0xc0, 0x40, 0xa3 };
                    template.first_entry_offset = -4;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_8 <= sysinfo.BuildNumber &&
                         sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
                {
                    template.signature = new byte[] { 0x8b, 0xf0, 0x81, 0xfe, 0xcc, 0x06, 0x00, 0x00, 0x0f, 0x84 };
                    template.first_entry_offset = -16;
                }
                else if (sysinfo.BuildNumber >= (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
                {
                    template.signature = new byte[] { 0x33, 0xc0, 0x40, 0xa3 };
                    template.first_entry_offset = -4;
                }
            }
            else
            {
                throw new Exception($"Unknown architecture! {sysinfo.ProcessorArchitecture}");
            }

            return template;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MASTERKEY_CACHE_ENTRY
        {
            public long Flink;
            public long Blink;
            public LUID LogonId;
            public Guid KeyUid;
            public FILETIME insertTime;
            public uint keySize;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public byte[] key;
        }
    }
}