using Minidump.Streams;
using System;
using System.Runtime.InteropServices;
using static Minidump.Helpers;

namespace Minidump.Templates
{
    public class credman
    {
        public struct CredmanTemplate
        {
            public byte[] signature;
            public int offset;
            public Type list_entry;
        }

        public static CredmanTemplate get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            CredmanTemplate template = new CredmanTemplate();
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    template.list_entry = typeof(KIWI_CREDMAN_LIST_ENTRY_5);
                    template.offset = 0;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_VISTA <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_7)
                {
                    template.list_entry = typeof(KIWI_CREDMAN_LIST_ENTRY_60);
                    template.offset = 0;
                }
                else
                {
                    template.list_entry = typeof(KIWI_CREDMAN_LIST_ENTRY);
                    template.offset = 0;
                }
            }
            else if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
            {
                template.list_entry = typeof(KIWI_CREDMAN_LIST_ENTRY_5_X86);
                template.offset = -32;
            }
            else if ((int)SystemInfo.WindowsMinBuild.WIN_VISTA <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_7)
            {
                template.list_entry = typeof(KIWI_CREDMAN_LIST_ENTRY_60_X86);
                template.offset = -32;
            }
            else
            {
                template.list_entry = typeof(KIWI_CREDMAN_LIST_ENTRY_X86);
                template.offset = -32;
            }
            return template;
        }
    }

    //x64
    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_CREDMAN_LIST_ENTRY
    {
        public uint cbEncPassword;
        public long encPassword;
        public uint unk0;
        public uint unk1;
        public IntPtr unk2;
        public IntPtr unk3;
        public IntPtr UserName;
        public uint cbUserName;
        public long Flink;
        public long Blink;
        public LIST_ENTRY unk4;
        public UNICODE_STRING type;
        public IntPtr unk5;
        public UNICODE_STRING server1;
        public IntPtr unk6;
        public IntPtr unk7;
        public IntPtr unk8;
        public IntPtr unk9;
        public IntPtr unk10;
        public UNICODE_STRING user;
        public uint unk11;
        public UNICODE_STRING server2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_CREDMAN_LIST_ENTRY_5
    {
        public uint cbEncPassword;
        public long encPassword;
        public uint unk0;
        public uint unk1;
        public IntPtr unk2;
        public IntPtr unk3;
        public IntPtr UserName;
        public uint cbUserName;
        public long Flink;
        public long Blink;
        public UNICODE_STRING server1;
        public IntPtr unk6;
        public IntPtr unk7;
        public UNICODE_STRING user;
        public IntPtr unk8;
        public UNICODE_STRING server2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_CREDMAN_LIST_ENTRY_60
    {
        public uint cbEncPassword;
        public long encPassword;
        public uint unk0;
        public uint unk1;
        public IntPtr unk2;
        public IntPtr unk3;
        public IntPtr UserName;
        public uint cbUserName;
        public long Flink;
        public long Blink;
        public UNICODE_STRING type;
        public IntPtr unk5;
        public UNICODE_STRING server1;
        public IntPtr unk6;
        public IntPtr unk7;
        public IntPtr unk8;
        public IntPtr unk9;
        public IntPtr unk10;
        public UNICODE_STRING user;
        public IntPtr unk11;
        public UNICODE_STRING server2;
    }

    //x86
    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_CREDMAN_LIST_ENTRY_X86
    {
        public uint cbEncPassword;
        public long encPassword;
        public uint unk0;
        public uint unk1;
        public IntPtr unk2;
        public IntPtr unk3;
        public IntPtr UserName;
        public uint cbUserName;
        public long Flink;
        public long Blink;
        public LIST_ENTRY unk4;
        public UNICODE_STRING type;
        public IntPtr unk5;
        public UNICODE_STRING server1;
        public IntPtr unk6;
        public IntPtr unk7;
        public IntPtr unk8;
        public IntPtr unk9;
        public IntPtr unk10;
        public UNICODE_STRING user;
        public uint unk11;
        public UNICODE_STRING server2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_CREDMAN_LIST_ENTRY_5_X86
    {
        public uint cbEncPassword;
        public long encPassword;
        public uint unk0;
        public uint unk1;
        public IntPtr unk2;
        public IntPtr unk3;
        public IntPtr UserName;
        public uint cbUserName;
        public long Flink;
        public long Blink;
        public UNICODE_STRING server1;
        public IntPtr unk6;
        public IntPtr unk7;
        public UNICODE_STRING user;
        public IntPtr unk8;
        public UNICODE_STRING server2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_CREDMAN_LIST_ENTRY_60_X86
    {
        public uint cbEncPassword;
        public long encPassword;
        public uint unk0;
        public uint unk1;
        public IntPtr unk2;
        public IntPtr unk3;
        public IntPtr UserName;
        public uint cbUserName;
        public long Flink;
        public long Blink;
        public UNICODE_STRING type;
        public IntPtr unk5;
        public UNICODE_STRING server1;
        public IntPtr unk6;
        public IntPtr unk7;
        public IntPtr unk8;
        public IntPtr unk9;
        public IntPtr unk10;
        public UNICODE_STRING user;
        public IntPtr unk11;
        public UNICODE_STRING server2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_CREDMAN_SET_LIST_ENTRY
    {
        public IntPtr Flink;
        public IntPtr Blink;
        public uint unk0;
        public IntPtr list1;
        public IntPtr list2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_CREDMAN_LIST_STARTER
    {
        private readonly uint unk0;
        public IntPtr start;
    }
}