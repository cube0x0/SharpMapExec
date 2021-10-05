using Minidump.Streams;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Minidump.Templates
{
    public class rdp
    {
        public struct RdpTemplate
        {
            public List<byte[]> signature;
            public int first_entry_offset;
            public object cred_struct;
        }

        public static RdpTemplate get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            RdpTemplate template = new RdpTemplate();

            if (sysinfo.BuildNumber >= (int)SystemInfo.WindowsMinBuild.WIN_8)
            {
                List<byte[]> signatures = new List<byte[]>
                {
                    new byte[] {0x00, 0x00, 0x00, 0x00, 0xbb, 0x47},
                    new byte[] {0x00, 0x00, 0x00, 0x00, 0xf3, 0x47},
                    new byte[] {0x00, 0x00, 0x00, 0x00, 0x3b, 0x01},
                };
                template.signature = signatures;
                template.first_entry_offset = 0;
                template.cred_struct = new WTS_KIWI();
            }
            else
            {
                List<byte[]> signatures = new List<byte[]>()
                {
                    new byte[] { 0xc8, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00 }
                };
                template.signature = signatures;
                template.first_entry_offset = 16;
                template.cred_struct = new WTS_KIWI_2008R2();
            }
            return template;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_KIWI
        {
            public uint unk0;
            public uint unk1;

            public ushort cbDomain;
            public ushort cbUsername;
            public ushort cbPassword;

            public uint unk2;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] Domain;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] UserName;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] Password;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_KIWI_2008R2
        {
            public uint unk0;
            public uint unk1;

            public ushort cbDomain;
            public ushort cbUsername;
            public ushort cbPassword;

            public uint unk2;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] Domain;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] UserName;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] Password;
        }
    }
}