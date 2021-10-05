namespace Minidump.Streams
{
    public class MinidumpMemory
    {
        public struct MinidumpMemorySegment
        {
            public long start_virtual_address;
            public long size;
            public long end_virtual_address;
            public long start_file_address;
        }

        public static MinidumpMemorySegment parse_full(MINIDUMP_MEMORY64.MINIDUMP_MEMORY_DESCRIPTOR64 memory_decriptor, long rva)
        {
            MinidumpMemorySegment mms = new MinidumpMemorySegment();
            mms.start_virtual_address = memory_decriptor.StartOfMemoryRange;
            mms.size = memory_decriptor.DataSize;
            mms.start_file_address = rva;
            mms.end_virtual_address = mms.start_virtual_address + mms.size;

            return mms;
        }
    }
}