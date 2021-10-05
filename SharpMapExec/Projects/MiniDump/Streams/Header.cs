using System;

namespace Minidump.Streams
{
    public class Header
    {
        public struct MinidumpHeader
        {
            public String Signature;
            public UInt16 Version;
            public UInt16 ImplementationVersion;
            public UInt32 NumberOfStreams;
            public UInt32 StreamDirectoryRva;
            public UInt32 CheckSum;
            public UInt32 Reserved;
            public UInt32 TimeDateStamp;
            public string Flags;
        }

        [Flags]
        public enum MINIDUMP_TYPE
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000,
            MiniDumpWithoutAuxiliaryState = 0x00004000,
            MiniDumpWithFullAuxiliaryState = 0x00008000,
            MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
            MiniDumpIgnoreInaccessibleMemory = 0x00020000,
            MiniDumpWithTokenInformation = 0x00040000,
            MiniDumpWithModuleHeaders = 0x00080000,
            MiniDumpFilterTriage = 0x00100000,
            MiniDumpValidTypeFlags = 0x001fffff
        }

        public static MinidumpHeader ParseHeader(Program.MiniDump minidump)
        {
            MinidumpHeader Header = new MinidumpHeader();
            Header.Signature = Helpers.ReadString(minidump.fileBinaryReader, 4);
            Header.Version = Helpers.ReadUInt16(minidump.fileBinaryReader);
            Header.ImplementationVersion = Helpers.ReadUInt16(minidump.fileBinaryReader);
            Header.NumberOfStreams = Helpers.ReadUInt32(minidump.fileBinaryReader);
            Header.StreamDirectoryRva = Helpers.ReadUInt32(minidump.fileBinaryReader);
            Header.CheckSum = Helpers.ReadUInt32(minidump.fileBinaryReader);
            Header.Reserved = Helpers.ReadUInt32(minidump.fileBinaryReader);
            Header.TimeDateStamp = Helpers.ReadUInt32(minidump.fileBinaryReader);
            //Header.Flags = Helpers.ReadUInt32(fileBinaryReader);
            Header.Flags = Enum.GetName(typeof(MINIDUMP_TYPE), Helpers.ReadUInt32(minidump.fileBinaryReader));

            return Header;
        }
    }
}