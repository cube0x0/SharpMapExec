using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Minidump.Streams
{
    public class MINIDUMP_MEMORY64
    {
        public struct MINIDUMP_MEMORY64_LIST
        {
            public long NumberOfMemoryRanges;
            public long BaseRva;
            public List<MINIDUMP_MEMORY_DESCRIPTOR64> MemoryRanges;
        }

        public static MINIDUMP_MEMORY64_LIST parse_mml(BinaryReader fileBinaryReader)
        {
            MINIDUMP_MEMORY64_LIST mml = new MINIDUMP_MEMORY64_LIST();
            mml.NumberOfMemoryRanges = Helpers.ReadInt64(fileBinaryReader);
            mml.BaseRva = Helpers.ReadInt64(fileBinaryReader);
            List<MINIDUMP_MEMORY_DESCRIPTOR64> list = new List<MINIDUMP_MEMORY_DESCRIPTOR64>();
            foreach (var _ in Enumerable.Range(0, (int)mml.NumberOfMemoryRanges))
            {
                list.Add(parse_mmd(fileBinaryReader));
            }

            mml.MemoryRanges = list;
            return mml;
        }

        public struct MINIDUMP_MEMORY_DESCRIPTOR64
        {
            public long StartOfMemoryRange;
            public long DataSize;
        }

        public static MINIDUMP_MEMORY_DESCRIPTOR64 parse_mmd(BinaryReader fileBinaryReader)
        {
            MINIDUMP_MEMORY_DESCRIPTOR64 md = new MINIDUMP_MEMORY_DESCRIPTOR64();
            md.StartOfMemoryRange = Helpers.ReadInt64(fileBinaryReader);
            md.DataSize = Helpers.ReadInt64(fileBinaryReader);
            return md;
        }

        public struct MinidumpMemory64List
        {
            public List<MinidumpMemory.MinidumpMemorySegment> memory_segments;
        }

        public static MinidumpMemory64List parse(Directory.MINIDUMP_DIRECTORY dir, Program.MiniDump minidump)
        {
            List<MinidumpMemory.MinidumpMemorySegment> list = new List<MinidumpMemory.MinidumpMemorySegment>();
            MinidumpMemory64List mmlist = new MinidumpMemory64List();

            minidump.fileBinaryReader.BaseStream.Seek(dir.Offset, 0);
            byte[] chunk = minidump.fileBinaryReader.ReadBytes((int)dir.Size);

            using (BinaryReader ChunkReader = new BinaryReader(new MemoryStream(chunk)))
            {
                var mtl = parse_mml(ChunkReader);
                var rva = mtl.BaseRva;
                foreach (MINIDUMP_MEMORY_DESCRIPTOR64 mod in mtl.MemoryRanges)
                {
                    list.Add(MinidumpMemory.parse_full(mod, rva));
                    rva += mod.DataSize;
                }
            }

            mmlist.memory_segments = list;
            return mmlist;
        }
    }
}