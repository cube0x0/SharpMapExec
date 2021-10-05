using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Minidump.Streams
{
    public class SystemInfo
    {
        [Flags]
        public enum PROCESSOR_ARCHITECTURE
        {
            AMD64 = 9,
            ARM = 5,
            IA64 = 6,
            INTEL = 0,
            AARCH64 = 0x8003,
            UNKNOWN = 0xffff
        }

        [Flags]
        public enum PROCESSOR_LEVEL
        {
            INTEL_80386 = 3,
            INTEL_80486 = 4,
            INTEL_PENTIUM = 5,
            INTEL_PENTIUM_PRO = 6
        }

        [Flags]
        public enum PRODUCT_TYPE
        {
            VER_UNIDENTIFIED_PRODUCT = 0x0000000,
            VER_NT_WORKSTATION = 0x0000001,
            VER_NT_DOMAIN_CONTROLLER = 0x0000002,
            VER_NT_SERVER = 0x0000003
        }

        [Flags]
        public enum PLATFORM_ID
        {
            VER_PLATFORM_WIN32s = 0,
            VER_PLATFORM_WIN32_WINDOWS = 1,
            VER_PLATFORM_WIN32_NT = 2,
            VER_PLATFORM_CRASHPAD_MAC = 0x8101,
            VER_PLATFORM_CRASHPAD_IOS = 0x8102,
            VER_PLATFORM_CRASHPAD_LINUX = 0x8201,
            VER_PLATFORM_CRASHPAD_SOLARIS = 0x8202,
            VER_PLATFORM_CRASHPAD_ANDROID = 0x8203,
            VER_PLATFORM_CRASHPAD_PS3 = 0x8204,
            VER_PLATFORM_CRASHPAD_NACL = 0x8205,
            VER_PLATFORM_CRASHPAD_FUSCHIA = 0x8206,
            VER_PLATFORM_CRASHPAD_UNKNOWN = 0xfffffff
        }

        [Flags]
        public enum WindowsBuild
        {
            WIN_XP = 2600,
            WIN_2K3 = 3790,
            WIN_VISTA = 6000,
            WIN_7 = 7600,
            WIN_8 = 9200,
            WIN_BLUE = 9600,
            WIN_10_1507 = 10240,
            WIN_10_1511 = 10586,
            WIN_10_1607 = 14393,
            WIN_10_1703 = 15063,
            WIN_10_1709 = 16299,
            WIN_10_1803 = 17134,
            WIN_10_1809 = 17763,
            WIN_10_1903 = 18362
        }

        [Flags]
        public enum WindowsMinBuild
        {
            WIN_XP = 2500,
            WIN_2K3 = 3000,
            WIN_VISTA = 5000,
            WIN_7 = 7000,
            WIN_8 = 8000,
            WIN_BLUE = 9400,
            WIN_10 = 9800
        }

        [Flags]
        public enum SUITE_MASK
        {
            VER_SUITE_BACKOFFICE = 0x00000004,
            VER_SUITE_BLADE = 0x00000400,
            VER_SUITE_COMPUTE_SERVER = 0x00004000,
            VER_SUITE_DATACENTER = 0x00000080,
            VER_SUITE_ENTERPRISE = 0x00000002,
            VER_SUITE_EMBEDDEDNT = 0x00000040,
            VER_SUITE_PERSONAL = 0x00000200,
            VER_SUITE_SINGLEUSERTS = 0x00000100,
            VER_SUITE_SMALLBUSINESS = 0x00000001,
            VER_SUITE_SMALLBUSINESS_RESTRICTED = 0x00000020,
            VER_SUITE_STORAGE_SERVER = 0x00002000,
            VER_SUITE_TERMINAL = 0x00000010
        }

        public struct MINIDUMP_SYSTEM_INFO
        {
            public PROCESSOR_ARCHITECTURE ProcessorArchitecture;
            public uint ProcessorLevel;
            public uint ProcessorRevision;
            public uint Reserved0;
            public uint NumberOfProcessors;
            public PRODUCT_TYPE ProductType;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public PLATFORM_ID PlatformId;
            public uint CSDVersionRva;
            public int Reserved1;
            public SUITE_MASK SuiteMask;
            public int Reserved2;
            public List<uint> VendorId;
            public uint VersionInformation;
            public uint FeatureInformation;
            public uint AMDExtendedCpuFeatures;
            public List<UInt64> ProcessorFeatures;

            //for wrtier
            public uint CSDVersion;

            public int msv_dll_timestamp;
            public string OS;
        }

        public static MINIDUMP_SYSTEM_INFO Parse(BinaryReader fileBinaryReader)
        {
            MINIDUMP_SYSTEM_INFO msi = new MINIDUMP_SYSTEM_INFO();

            //msi.ProcessorArchitecture = Helpers.ReadUInt16(fileBinaryReader);
            msi.ProcessorArchitecture = (PROCESSOR_ARCHITECTURE)Enum.Parse(typeof(PROCESSOR_ARCHITECTURE),
                Enum.GetName(typeof(PROCESSOR_ARCHITECTURE), (int)Helpers.ReadUInt16(fileBinaryReader)));
            msi.ProcessorLevel = Helpers.ReadUInt16(fileBinaryReader);
            msi.ProcessorRevision = Helpers.ReadUInt16(fileBinaryReader);
            //the below field is present in the documentation from MSDN, however is not present in the actual dump
            //msi.Reserved0 = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
            msi.NumberOfProcessors = Helpers.ReadInt8(fileBinaryReader);
            //msi.ProductType = Helpers.ReadUInt8(fileBinaryReader);
            msi.ProductType = (PRODUCT_TYPE)Enum.Parse(typeof(PRODUCT_TYPE), Enum.GetName(typeof(PRODUCT_TYPE), (int)Helpers.ReadInt8(fileBinaryReader)));
            msi.MajorVersion = Helpers.ReadUInt32(fileBinaryReader);
            msi.MinorVersion = Helpers.ReadUInt32(fileBinaryReader);
            msi.BuildNumber = Helpers.ReadUInt32(fileBinaryReader);
            //msi.PlatformId = Helpers.ReadUInt32(fileBinaryReader);
            msi.PlatformId = (PLATFORM_ID)Enum.Parse(typeof(PLATFORM_ID), Enum.GetName(typeof(PLATFORM_ID), (int)Helpers.ReadUInt32(fileBinaryReader)));
            msi.CSDVersionRva = Helpers.ReadUInt32(fileBinaryReader);
            ////msi.Reserved1 = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
            ////msi.SuiteMask = Helpers.ReadUInt16(fileBinaryReader);
            int sm = Helpers.ReadUInt16(fileBinaryReader);
            try
            {
                msi.SuiteMask = (SUITE_MASK)Enum.Parse(typeof(SUITE_MASK), Enum.GetName(typeof(SUITE_MASK), sm));
            }
            catch (Exception e)
            { }
            msi.Reserved2 = Helpers.ReadUInt16(fileBinaryReader);
            if (msi.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL)
            {
                foreach (var _ in Enumerable.Range(0, 3))
                {
                    msi.VendorId.Add(Helpers.ReadUInt32(fileBinaryReader));
                }

                msi.VersionInformation = Helpers.ReadUInt32(fileBinaryReader);
                msi.FeatureInformation = Helpers.ReadUInt32(fileBinaryReader);
                msi.AMDExtendedCpuFeatures = Helpers.ReadUInt32(fileBinaryReader);
            }
            else
            {
                foreach (var _ in Enumerable.Range(0, 2))
                {
                    //fix this
                    //msi.ProcessorFeatures.Add(Helpers.ReadUInt64(fileBinaryReader));
                }
            }

            return msi;
        }

        public static string guess_os(uint MajorVersion, uint MinorVersion, PRODUCT_TYPE ProductType)
        {
            string OperatingSystem = "";

            if (MajorVersion == 10 && MinorVersion == 0 &&
                ProductType == PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows 10";
            }
            else if (MajorVersion == 10 && MinorVersion == 0 &&
                     ProductType != PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows Server 2016 Technical Preview";
            }
            else if (MajorVersion == 6 && MinorVersion == 3 &&
                     ProductType == PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows 8.1";
            }
            else if (MajorVersion == 6 && MinorVersion == 3 &&
                     ProductType != PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows Server 2012 R2";
            }
            else if (MajorVersion == 6 && MinorVersion == 2 &&
                     ProductType == PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows 8";
            }
            else if (MajorVersion == 6 && MinorVersion == 2 &&
                     ProductType != PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows Server 2012";
            }
            else if (MajorVersion == 6 && MinorVersion == 1 &&
                     ProductType == PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows 7";
            }
            else if (MajorVersion == 6 && MinorVersion == 1 &&
                     ProductType != PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows Server 2008 R2";
            }
            else if (MajorVersion == 6 && MinorVersion == 0 &&
                     ProductType == PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows Vista";
            }
            else if (MajorVersion == 6 && MinorVersion == 0 &&
                     ProductType != PRODUCT_TYPE.VER_NT_WORKSTATION)
            {
                OperatingSystem = "Windows Server 2008";
            }
            else if (MajorVersion == 5 && MinorVersion == 1)
            {
                // Can't accurately report on Windows Server 2003/R2
                // elif (MajorVersion == 5 and MinorVersion == 2 and ProductType == self.ProductType.VER_NT_WORKSTATION)
                //	self.OperatingSystem =  "Windows Vista"
                //elif (MajorVersion == 5 and MinorVersion == 2 and ProductType != self.ProductType.VER_NT_WORKSTATION)
                //	self.OperatingSystem =  "Windows Server 2008"
                OperatingSystem = "Windows XP";
            }
            else if (MajorVersion == 5 && MinorVersion == 0)
            {
                OperatingSystem = "Windows 2000";
            }

            return OperatingSystem;
        }

        public static MINIDUMP_SYSTEM_INFO parse(Directory.MINIDUMP_DIRECTORY dir, Program.MiniDump minidump)
        {
            minidump.fileBinaryReader.BaseStream.Seek(dir.Offset, 0);
            byte[] chunk = minidump.fileBinaryReader.ReadBytes((int)dir.Size);

            using (BinaryReader ChunkReader = new BinaryReader(new MemoryStream(chunk)))
            {
                MINIDUMP_SYSTEM_INFO si = Parse(ChunkReader);
                si.OS = guess_os(si.MajorVersion, si.MinorVersion, si.ProductType);
                return si;
            }
        }
    }
}