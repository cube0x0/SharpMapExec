using Minidump.Streams;
using System;
using System.Runtime.InteropServices;

namespace Minidump.Templates
{
    public class lsaTemplate_NT6
    {
        public struct LsaTemplate_NT6
        {
            public LSADecyptorKeyPattern key_pattern;
            public object key_handle_struct;
            public object key_struct;
            public string nt_major;
        }

        public static LsaTemplate_NT6 get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            var template = new LsaTemplate_NT6();
            template.nt_major = "6";
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                if (sysinfo.BuildNumber <= (int)SystemInfo.WindowsMinBuild.WIN_XP)
                {
                    throw new Exception("Maybe implemented later");
                }
                else if (sysinfo.BuildNumber <= (int)SystemInfo.WindowsMinBuild.WIN_2K3)
                {
                    template.nt_major = "5";
                    //template = templates["nt5"]["x86"]["1"];
                    template.key_pattern = new LSA_x86_1().key_pattern;
                    template.key_handle_struct = new LSA_x86_1().key_handle_struct;
                    template.key_struct = new LSA_x86_1().key_struct;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_VISTA <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_7)
                {
                    //1
                    //template = templates["nt6"]["x86"]["1"];
                    template.key_pattern = new LSA_x86_1().key_pattern;
                    template.key_handle_struct = new LSA_x86_1().key_handle_struct;
                    template.key_struct = new LSA_x86_1().key_struct;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_7 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
                {
                    //2
                    //template = templates["nt6"]["x86"]["2"];
                    template.key_pattern = new LSA_x86_2().key_pattern;
                    template.key_handle_struct = new LSA_x86_2().key_handle_struct;
                    template.key_struct = new LSA_x86_2().key_struct;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_8 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
                {
                    //3
                    //template = templates["nt6"]["x86"]["3"];
                    template.key_pattern = new LSA_x86_3().key_pattern;
                    template.key_handle_struct = new LSA_x86_3().key_handle_struct;
                    template.key_struct = new LSA_x86_3().key_struct;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_BLUE <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_10)
                {
                    //4
                    //template = templates["nt6"]["x86"]["4"];
                    template.key_pattern = new LSA_x86_4().key_pattern;
                    template.key_handle_struct = new LSA_x86_4().key_handle_struct;
                    template.key_struct = new LSA_x86_4().key_struct;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_10 <= sysinfo.BuildNumber && sysinfo.BuildNumber <= (int)SystemInfo.WindowsBuild.WIN_10_1507)
                {
                    //5
                    //template = templates["nt6"]["x86"]["5"];
                    template.key_pattern = new LSA_x86_5().key_pattern;
                    template.key_handle_struct = new LSA_x86_5().key_handle_struct;
                    template.key_struct = new LSA_x86_5().key_struct;
                }
                else if (sysinfo.BuildNumber > (int)SystemInfo.WindowsBuild.WIN_10_1507)
                {
                    //6
                    //template = templates["nt6"]["x86"]["6"];
                    template.key_pattern = new LSA_x86_6().key_pattern;
                    template.key_handle_struct = new LSA_x86_6().key_handle_struct;
                    template.key_struct = new LSA_x86_6().key_struct;
                }
            }
            else if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                if (sysinfo.BuildNumber <= (int)SystemInfo.WindowsMinBuild.WIN_XP)
                {
                    throw new Exception("Maybe implemented later");
                }
                else if (sysinfo.BuildNumber <= (int)SystemInfo.WindowsMinBuild.WIN_2K3)
                {
                    throw new Exception("Maybe implemented later");
                }
                else if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_7)
                {
                    //vista
                    //1
                    //template = templates["nt6"]["x64"]["1"];
                    template.key_pattern = new LSA_x64_1().key_pattern;
                    template.key_handle_struct = new LSA_x64_1().key_handle_struct;
                    template.key_struct = new LSA_x64_1().key_struct;
                }
                else if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
                {
                    //win 7
                    //2
                    //template = templates["nt6"]["x64"]["2"];
                    template.key_pattern = new LSA_x64_2().key_pattern;
                    template.key_handle_struct = new LSA_x64_2().key_handle_struct;
                    template.key_struct = new LSA_x64_2().key_struct;
                }
                else if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_10)
                {
                    //win 8 and blue
                    //3
                    if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_BLUE)
                    {
                        //template = templates["nt6"]["x64"]["3"];
                        template.key_pattern = new LSA_x64_3().key_pattern;
                        template.key_handle_struct = new LSA_x64_3().key_handle_struct;
                        template.key_struct = new LSA_x64_3().key_struct;
                        //win8
                        //3
                    }
                    else
                    {
                        //template = templates["nt6"]["x64"]["4"];
                        template.key_pattern = new LSA_x64_4().key_pattern;
                        template.key_handle_struct = new LSA_x64_4().key_handle_struct;
                        template.key_struct = new LSA_x64_4().key_struct;
                        //4
                        //win blue
                    }
                }
                else if (sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1809)
                {
                    //template = templates["nt6"]["x64"]["5"];
                    template.key_pattern = new LSA_x64_5().key_pattern;
                    template.key_handle_struct = new LSA_x64_5().key_handle_struct;
                    template.key_struct = new LSA_x64_5().key_struct;
                    //5
                }
                else
                {
                    //template = templates["nt6"]["x64"]["6"];
                    template.key_pattern = new LSA_x64_6().key_pattern;
                    template.key_handle_struct = new LSA_x64_6().key_handle_struct;
                    template.key_struct = new LSA_x64_6().key_struct;
                    //1809
                    //6
                }
            }
            else
            {
                throw new Exception($"Unknown architecture! {sysinfo.ProcessorArchitecture}");
            }

            return template;
        }
    }

    public struct LSADecyptorKeyPattern
    {
        public byte[] signature;
        public int offset_to_IV_ptr;
        public int IV_length;
        public int offset_to_AES_key_ptr;
        public int offset_to_DES_key_ptr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_HARD_KEY
    {
        public int cbSecret;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 60)]
        public byte[] data;
    }

    public struct KIWI_BCRYPT_KEY
    {
        public ulong size;
        public ulong tag;
        public ulong type;
        public ulong unk0;
        public ulong unk1;
        public ulong unk2;
        public KIWI_HARD_KEY hardkey;
    }

    public struct KIWI_BCRYPT_KEY8
    {
        public ulong size;
        public ulong tag;
        public ulong type;
        public ulong unk0;
        public ulong unk1;
        public ulong unk2;
        public ulong unk3;
        public ulong reader;

        //public PVOID unk4;
        public KIWI_HARD_KEY hardkey;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_BCRYPT_KEY81
    {
        private readonly int size;
        private readonly int tag;
        private readonly int type;
        private readonly int unk0;
        private readonly int unk1;
        private readonly int unk2;
        private readonly int unk3;
        private readonly int unk4;
        private readonly long unk5;
        private readonly int unk6;
        private readonly int unk7;
        private readonly int unk8;
        private readonly int unk9;
        public KIWI_HARD_KEY hardkey;
    }

    public class PKIWI_BCRYPT_KEY
    {
        public PKIWI_BCRYPT_KEY(object reader)
        {
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_BCRYPT_HANDLE_KEY
    {
        public int size;
        public int tag;
        public int hAlgorithm;
        public long key;
        public int unk0;
    }

    public class LSA_x64_1
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY key_struct;

        public LSA_x64_1()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 63;
            key_pattern.offset_to_DES_key_ptr = -69;
            key_pattern.offset_to_AES_key_ptr = 25;
            key_struct = new KIWI_BCRYPT_KEY();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x64_2
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY key_struct;

        public LSA_x64_2()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 59;
            key_pattern.offset_to_DES_key_ptr = -61;
            key_pattern.offset_to_AES_key_ptr = 25;
            key_struct = new KIWI_BCRYPT_KEY();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x64_3
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY8 key_struct;

        public LSA_x64_3()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 62;
            key_pattern.offset_to_DES_key_ptr = -70;
            key_pattern.offset_to_AES_key_ptr = 23;
            key_struct = new KIWI_BCRYPT_KEY8();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x64_4
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY81 key_struct;

        public LSA_x64_4()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 62;
            key_pattern.offset_to_DES_key_ptr = -70;
            key_pattern.offset_to_AES_key_ptr = 23;
            key_struct = new KIWI_BCRYPT_KEY81();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x64_5
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY81 key_struct;

        public LSA_x64_5()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 61;
            key_pattern.offset_to_DES_key_ptr = -73;
            key_pattern.offset_to_AES_key_ptr = 16;
            key_struct = new KIWI_BCRYPT_KEY81();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x64_6
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;
        public LSADecyptorKeyPattern key_pattern;
        public KIWI_BCRYPT_KEY81 key_struct;

        public LSA_x64_6()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 67;
            key_pattern.offset_to_DES_key_ptr = -89;
            key_pattern.offset_to_AES_key_ptr = 16;
            key_struct = new KIWI_BCRYPT_KEY81();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x86_1
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY key_struct;

        public LSA_x86_1()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x6a, 0x02, 0x6a, 0x10, 0x68 };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 5;
            key_pattern.offset_to_DES_key_ptr = -76;
            key_pattern.offset_to_AES_key_ptr = -21;
            key_struct = new KIWI_BCRYPT_KEY();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x86_2
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY key_struct;

        public LSA_x86_2()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x6a, 0x02, 0x6a, 0x10, 0x68 };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 5;
            key_pattern.offset_to_DES_key_ptr = -76;
            key_pattern.offset_to_AES_key_ptr = -21;
            key_struct = new KIWI_BCRYPT_KEY();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x86_3
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY8 key_struct;

        public LSA_x86_3()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x6a, 0x02, 0x6a, 0x10, 0x68 };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 5;
            key_pattern.offset_to_DES_key_ptr = -69;
            key_pattern.offset_to_AES_key_ptr = -18;
            key_struct = new KIWI_BCRYPT_KEY8();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x86_4
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY81 key_struct;

        public LSA_x86_4()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x6a, 0x02, 0x6a, 0x10, 0x68 };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 5;
            key_pattern.offset_to_DES_key_ptr = -69;
            key_pattern.offset_to_AES_key_ptr = -18;
            key_struct = new KIWI_BCRYPT_KEY81();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x86_5
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY81 key_struct;

        public LSA_x86_5()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x6a, 0x02, 0x6a, 0x10, 0x68 };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 5;
            key_pattern.offset_to_DES_key_ptr = -79;
            key_pattern.offset_to_AES_key_ptr = -22;
            key_struct = new KIWI_BCRYPT_KEY81();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }

    public class LSA_x86_6
    {
        public KIWI_BCRYPT_HANDLE_KEY key_handle_struct;

        public LSADecyptorKeyPattern key_pattern;

        public KIWI_BCRYPT_KEY81 key_struct;

        public LSA_x86_6()
        {
            key_pattern = new LSADecyptorKeyPattern();
            key_pattern.signature = new byte[] { 0x6a, 0x02, 0x6a, 0x10, 0x68 };
            key_pattern.IV_length = 16;
            key_pattern.offset_to_IV_ptr = 5;
            key_pattern.offset_to_DES_key_ptr = -79;
            key_pattern.offset_to_AES_key_ptr = -22;
            key_struct = new KIWI_BCRYPT_KEY81();
            key_handle_struct = new KIWI_BCRYPT_HANDLE_KEY();
        }
    }
}