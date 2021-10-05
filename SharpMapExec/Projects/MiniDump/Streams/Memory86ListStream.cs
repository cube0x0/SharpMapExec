using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Minidump.Streams
{
    public class MINIDUMP_MEMORY86
    {
        public struct MINIDUMP_MEMORY_LIST
        {
            public UInt32 NumberOfMemoryRanges;
            public List<object> MemoryRanges;
        }

        public static MINIDUMP_MEMORY_LIST parse_mml(BinaryReader fileBinaryReader)
        {
            var mml = new MINIDUMP_MEMORY_LIST();
            mml.NumberOfMemoryRanges = Helpers.ReadUInt32(fileBinaryReader);
            foreach (var _ in Enumerable.Range(0, (int)mml.NumberOfMemoryRanges))
            {
                mml.MemoryRanges.Add(parse_mmd(fileBinaryReader));
            }
            return mml;
        }

        public struct MINIDUMP_MEMORY_DESCRIPTORx86
        {
            public UInt64 StartOfMemoryRange;
            public UInt32 MemoryLocation;

            //we do not use MemoryLocation but immediately store its fields in this object for easy access
            public UInt32 DataSize;

            public UInt32 Rva;
        }

        public static MINIDUMP_MEMORY_DESCRIPTORx86 parse_mmd(BinaryReader fileBinaryReader)
        {
            var md = new MINIDUMP_MEMORY_DESCRIPTORx86();
            md.StartOfMemoryRange = Helpers.ReadUInt64(fileBinaryReader);
            //MemoryLocation = parse_mld(fileBinaryReader);
            //md.DataSize = md.MemoryLocation.DataSize;
            //md.Rva = md.MemoryLocation.Rva;
            return md;
        }

        public struct MinidumpMemory86List
        {
            public List<MinidumpMemory.MinidumpMemorySegment> memory_segments;
        }

        public static MinidumpMemory86List parse(Directory.MINIDUMP_DIRECTORY dir, Program.MiniDump minidump)
        {
            List<MinidumpMemory.MinidumpMemorySegment> list = new List<MinidumpMemory.MinidumpMemorySegment>();
            MinidumpMemory86List mmlist = new MinidumpMemory86List();

            minidump.fileBinaryReader.BaseStream.Seek(dir.Offset, 0);
            byte[] chunk = minidump.fileBinaryReader.ReadBytes((int)dir.Size);

            using (BinaryReader ChunkReader = new BinaryReader(new MemoryStream(chunk)))
            {
                var mtl = parse_mml(ChunkReader);
                foreach (MINIDUMP_MEMORY_DESCRIPTORx86 mod in mtl.MemoryRanges)
                {
                    //list.Add(parse_mini(mod, fileBinaryReader));
                }
            }

            mmlist.memory_segments = list;
            return mmlist;
        }
    }
}