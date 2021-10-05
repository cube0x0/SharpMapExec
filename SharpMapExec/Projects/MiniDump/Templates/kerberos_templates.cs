using Minidump.Streams;
using System;
using System.Runtime.InteropServices;
using static Minidump.Helpers;

namespace Minidump.Templates
{
    public class kerberos
    {
        public struct KerberosTemplate
        {
            public byte[] signature;
            public int first_entry_offset;
            public int LogonSessionTypeSize;
            public Type LogonSessionType;
            public Type PrimaryCredentialType;
            public int SessionCredentialOffset;
            public int SessionUserNameOffset;
            public int SessionDomainOffset;
            public int SessionPasswordOffset;
        }

        public static KerberosTemplate get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            KerberosTemplate template = new KerberosTemplate();
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                if ((int)SystemInfo.WindowsMinBuild.WIN_XP <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_2K3)
                {
                    template.signature = new byte[] { 0x48, 0x3b, 0xfe, 0x0f, 0x84 };
                    template.first_entry_offset = -4;
                    template.LogonSessionType = typeof(KIWI_KERBEROS_LOGON_SESSION_10);
                    template.LogonSessionTypeSize = Marshal.SizeOf(typeof(KIWI_KERBEROS_LOGON_SESSION_10));
                    template.PrimaryCredentialType = typeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL);
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_2K3 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    template.signature = new byte[] { 0x48, 0x3b, 0xfe, 0x0f, 0x84 };
                    template.first_entry_offset = -4;
                    template.LogonSessionType = typeof(KIWI_KERBEROS_LOGON_SESSION_10);
                    template.LogonSessionTypeSize = Marshal.SizeOf(typeof(KIWI_KERBEROS_LOGON_SESSION_10));
                    template.PrimaryCredentialType = typeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL);
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_VISTA <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_7)
                {
                    template.signature = new byte[] { 0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d };
                    template.first_entry_offset = 6;
                    template.LogonSessionType = typeof(KIWI_KERBEROS_LOGON_SESSION_10);
                    template.LogonSessionTypeSize = Marshal.SizeOf(typeof(KIWI_KERBEROS_LOGON_SESSION_10));
                    template.PrimaryCredentialType = typeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL);
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_7 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
                {
                    template.signature = new byte[] { 0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d };
                    template.first_entry_offset = 6;
                    template.LogonSessionType = typeof(KIWI_KERBEROS_LOGON_SESSION_10);
                    template.LogonSessionTypeSize = Marshal.SizeOf(typeof(KIWI_KERBEROS_LOGON_SESSION_10));
                    template.PrimaryCredentialType = typeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL);
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_8 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1507)
                {
                    template.signature = new byte[] { 0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d };
                    template.first_entry_offset = 6;
                    template.LogonSessionType = typeof(KIWI_KERBEROS_LOGON_SESSION_10);
                    template.LogonSessionTypeSize = Marshal.SizeOf(typeof(KIWI_KERBEROS_LOGON_SESSION_10));
                    template.PrimaryCredentialType = typeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL);
                }
                else if ((int)SystemInfo.WindowsBuild.WIN_10_1507 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1511)
                {
                    template.signature = new byte[] { 0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d };
                    template.first_entry_offset = 6;
                    template.LogonSessionType = typeof(KIWI_KERBEROS_LOGON_SESSION_10);
                    template.LogonSessionTypeSize = Marshal.SizeOf(typeof(KIWI_KERBEROS_LOGON_SESSION_10));
                    template.PrimaryCredentialType = typeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL);
                }
                else if ((int)SystemInfo.WindowsBuild.WIN_10_1511 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1607)
                {
                    template.signature = new byte[] { 0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d };
                    template.first_entry_offset = 6;
                    template.LogonSessionType = typeof(KIWI_KERBEROS_LOGON_SESSION_10);
                    template.LogonSessionTypeSize = Marshal.SizeOf(typeof(KIWI_KERBEROS_LOGON_SESSION_10));
                    template.PrimaryCredentialType = typeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL);
                }
                else if (sysinfo.BuildNumber >= (int)SystemInfo.WindowsBuild.WIN_10_1607)
                {
                    template.signature = new byte[] { 0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d };
                    template.first_entry_offset = 6;
                    template.LogonSessionType = typeof(KIWI_KERBEROS_LOGON_SESSION_10_1607);
                    template.LogonSessionTypeSize = Marshal.SizeOf(typeof(KIWI_KERBEROS_LOGON_SESSION_10_1607));
                    template.PrimaryCredentialType = typeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607);
                }
                else
                {
                    throw new Exception(String.Format("Could not identify template! Architecture: %s sysinfo.BuildNumber: %s", sysinfo.ProcessorArchitecture, sysinfo.BuildNumber));
                }
                template.SessionCredentialOffset = StructFieldOffset(template.LogonSessionType, "credentials");
                template.SessionUserNameOffset = StructFieldOffset(template.PrimaryCredentialType, "UserName");
                template.SessionDomainOffset = StructFieldOffset(template.PrimaryCredentialType, "Domain");
                template.SessionPasswordOffset = StructFieldOffset(template.PrimaryCredentialType, "Password");
            }
            else if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                if ((int)SystemInfo.WindowsMinBuild.WIN_XP <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_2K3)
                {
                    template.signature = new byte[] { 0x8B, 0x7D, 0x08, 0x8B, 0x17, 0x39, 0x50 };
                    template.first_entry_offset = -8;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_2K3 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    template.signature = new byte[] { 0x8B, 0x7D, 0x08, 0x8B, 0x17, 0x39, 0x50 };
                    template.first_entry_offset = -8;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_VISTA <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_7)
                {
                    template.signature = new byte[] { 0x53, 0x8b, 0x18, 0x50, 0x56 };
                    template.first_entry_offset = -11;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_7 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_8)
                {
                    template.signature = new byte[] { 0x53, 0x8b, 0x18, 0x50, 0x56 };
                    template.first_entry_offset = -11;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_8 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_BLUE)
                {
                    template.signature = new byte[] { 0x57, 0x8b, 0x38, 0x50, 0x68 };
                    template.first_entry_offset = -14;
                }
                else if ((int)SystemInfo.WindowsMinBuild.WIN_BLUE <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1507)
                {
                    template.signature = new byte[] { 0x56, 0x8b, 0x30, 0x50, 0x57 };
                    template.first_entry_offset = -15;
                }
                else if ((int)SystemInfo.WindowsBuild.WIN_10_1507 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1511)
                {
                    //###DOUBLE CHECK THE STRUCTURES BELOW LINE!!!!
                    //### kerbHelper[N] -> KerberosReferences... {-15,7}}, here N= 7
                    template.signature = new byte[] { 0x56, 0x8b, 0x30, 0x50, 0x57 };
                    template.first_entry_offset = -15;
                }
                else if ((int)SystemInfo.WindowsBuild.WIN_10_1511 <= sysinfo.BuildNumber && sysinfo.BuildNumber < (int)SystemInfo.WindowsBuild.WIN_10_1903)
                {
                    template.signature = new byte[] { 0x56, 0x8b, 0x30, 0x50, 0x57 };
                    template.first_entry_offset = -15;
                }
                else if ((int)SystemInfo.WindowsBuild.WIN_10_1903 <= sysinfo.BuildNumber)
                {
                    template.signature = new byte[] { 0x56, 0x8b, 0x30, 0x50, 0x53 };
                    template.first_entry_offset = -15;
                }
            }
            else
            {
                throw new Exception($"Unknown architecture! {sysinfo.ProcessorArchitecture}");
            }
            return template;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_AVL_TABLE
        {
            public RTL_BALANCED_LINKS BalancedRoot;
            public long OrderedPointer;
            public uint WhichOrderedElement;
            public uint NumberGenericTableElements;
            public uint DepthOfTree;
            public long RestartKey;
            public uint DeleteCount;
            public long CompareRoutine;
            public long AllocateRoutine;
            public long FreeRoutine;
            public long TableContext;
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
        public struct KIWI_KERBEROS_10_PRIMARY_CREDENTIAL
        {
            private readonly UNICODE_STRING UserName;
            private readonly UNICODE_STRING Domain;
            private readonly IntPtr unk0;
            private readonly UNICODE_STRING Password;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_KERBEROS_LOGON_SESSION_10
        {
            private readonly uint UsageCount;
            private readonly LIST_ENTRY unk0;
            private readonly IntPtr unk1;
            private readonly uint unk1b;
            private readonly FILETIME unk2;
            private readonly IntPtr unk4;
            private readonly IntPtr unk5;
            private readonly IntPtr unk6;
            private readonly LUID LocallyUniqueIdentifier;
            private readonly FILETIME unk7;
            private readonly IntPtr unk8;
            private readonly uint unk8b;
            private readonly FILETIME unk9;
            private readonly IntPtr unk11;
            private readonly IntPtr unk12;
            private readonly IntPtr unk13;
            private readonly KIWI_KERBEROS_10_PRIMARY_CREDENTIAL credentials;
            private readonly uint unk14;
            private readonly uint unk15;
            private readonly uint unk16;
            private readonly uint unk17;
            private readonly IntPtr unk19;
            private readonly IntPtr unk20;
            private readonly IntPtr unk21;
            private readonly IntPtr unk22;
            private readonly IntPtr unk23;
            private readonly IntPtr unk24;
            private readonly IntPtr unk25;
            private readonly IntPtr pKeyList;
            private readonly IntPtr unk26;
            private readonly LIST_ENTRY Tickets_1;
            private readonly FILETIME unk27;
            private readonly LIST_ENTRY Tickets_2;
            private readonly FILETIME unk28;
            private readonly LIST_ENTRY Tickets_3;
            private readonly FILETIME unk29;
            private readonly IntPtr SmartcardInfos;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO
        {
            public uint StructSize;
            public IntPtr isoBlob;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607
        {
            [FieldOffset(0)] public UNICODE_STRING UserName;

            [FieldOffset(16)] public UNICODE_STRING Domain;

            [FieldOffset(32)] public IntPtr unkFunction;

            [FieldOffset(40)] public uint type;
            [FieldOffset(48)] public UNICODE_STRING Password;

            [FieldOffset(48)] public KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO IsoPassword;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_KERBEROS_LOGON_SESSION_10_1607
        {
            public uint UsageCount;
            public LIST_ENTRY unk0;
            public IntPtr unk1;
            public uint unk1b;
            public FILETIME unk2;
            public IntPtr unk4;
            public IntPtr unk5;
            public IntPtr unk6;
            public LUID LocallyUniqueIdentifier;
            public FILETIME unk7;
            public IntPtr unk8;
            public uint unk8b;
            public FILETIME unk9;
            public IntPtr unk11;
            public IntPtr unk12;
            public IntPtr unk13;
            public KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607 credentials;
            public uint unk14;
            public uint unk15;
            public uint unk16;
            public uint unk17;
            public IntPtr unk18;
            public IntPtr unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public IntPtr unk22;
            public IntPtr unk23;
            public IntPtr unk24;
            public IntPtr unk25;
            public IntPtr pKeyList;
            public IntPtr unk26;
            public LIST_ENTRY Tickets_1;
            public FILETIME unk27;
            public LIST_ENTRY Tickets_2;
            public FILETIME unk28;
            public LIST_ENTRY Tickets_3;
            public FILETIME unk29;
            public IntPtr SmartcardInfos;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_HASHPASSWORD_6
        {
            private readonly UNICODE_STRING salt;
            private readonly IntPtr stringToKey;
            private readonly KERB_HASHPASSWORD_GENERIC generic;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_HASHPASSWORD_6_1607
        {
            private readonly UNICODE_STRING salt;
            private readonly IntPtr stringToKey;
            private readonly IntPtr unk0;
            private readonly KERB_HASHPASSWORD_GENERIC generic;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_HASHPASSWORD_GENERIC
        {
            public uint Type;
            public UIntPtr Size;
            public IntPtr Checksump;
        }
    }
}