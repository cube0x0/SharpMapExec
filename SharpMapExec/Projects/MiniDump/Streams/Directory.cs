using System;
using System.Collections.Generic;

namespace Minidump.Streams
{
    public class Directory
    {
        public struct MINIDUMP_DIRECTORY
        {
            public MINIDUMP_STREAM_TYPE StreamType;
            public uint Size;
            public uint Offset;
        }

        [Flags]
        public enum MINIDUMP_STREAM_TYPE
        {
            UnusedStream = 0,
            ReservedStream0 = 1,
            ReservedStream1 = 2,
            ThreadListStream = 3,
            ModuleListStream = 4,
            MemoryListStream = 5,
            ExceptionStream = 6,
            SystemInfoStream = 7,
            ThreadExListStream = 8,
            Memory64ListStream = 9,
            CommentStreamA = 10,
            CommentStreamW = 11,
            HandleDataStream = 12,
            FunctionTableStream = 13,
            UnloadedModuleListStream = 14,
            MiscInfoStream = 15,
            MemoryInfoListStream = 16,
            ThreadInfoListStream = 17,
            HandleOperationListStream = 18,
            TokenStream = 19,
            JavaScriptDataStream = 20,
            SystemMemoryInfoStream = 21,
            ProcessVmCountersStream = 22,
            ThreadNamesStream = 24,
            ceStreamNull = 25,
            ceStreamSystemInfo = 26,
            ceStreamException = 27,
            ceStreamModuleList = 28,
            ceStreamProcessList = 29,
            ceStreamThreadList = 30,
            ceStreamThreadContextList = 31,
            ceStreamThreadCallStackList = 32,
            ceStreamMemoryVirtualList = 33,
            ceStreamMemoryPhysicalList = 34,
            ceStreamBucketParameters = 35,
            ceStreamProcessModuleMap = 36,
            ceStreamDiagnosisList = 37,
            LastReservedStream = 0xffff,
        }

        public static List<MINIDUMP_DIRECTORY> ParseDirectory(Program.MiniDump minidump)
        {
            List<MINIDUMP_DIRECTORY> directories = new List<Directory.MINIDUMP_DIRECTORY>();

            for (int i = 0; i < (int)minidump.header.NumberOfStreams; i++)
            {
                minidump.fileBinaryReader.BaseStream.Seek(minidump.header.StreamDirectoryRva + i * 12, 0);
                UInt32 raw_stream_type_value = Helpers.ReadUInt32(minidump.fileBinaryReader);
                bool is_user_stream = (int)raw_stream_type_value > (int)MINIDUMP_STREAM_TYPE.LastReservedStream;
                bool is_stream_supported = Enum.IsDefined(typeof(MINIDUMP_STREAM_TYPE), (int)raw_stream_type_value);
                if (is_user_stream && !is_stream_supported)
                {
                    continue;
                }

                MINIDUMP_DIRECTORY md = new MINIDUMP_DIRECTORY();
                md.StreamType = (MINIDUMP_STREAM_TYPE)Enum.Parse(typeof(MINIDUMP_STREAM_TYPE),
                    Enum.GetName(typeof(MINIDUMP_STREAM_TYPE), (int)raw_stream_type_value)); // Enum.GetName(typeof(MINIDUMP_STREAM_TYPE), (int)raw_stream_type_value);
                md.Size = Helpers.ReadUInt32(minidump.fileBinaryReader);
                md.Offset = Helpers.ReadUInt32(minidump.fileBinaryReader);
                directories.Add(md);
            }

            return directories;
        }
    }
}