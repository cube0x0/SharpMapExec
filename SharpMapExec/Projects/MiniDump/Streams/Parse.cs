using System.Collections.Generic;

namespace Minidump.Streams
{
    internal class Parse
    {
        public static int parseMM(ref Program.MiniDump minidump, List<Directory.MINIDUMP_DIRECTORY> directories)
        {
            foreach (Directory.MINIDUMP_DIRECTORY dir in directories)
            {
                if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.UnusedStream)
                {
                    //Console.WriteLine($"Found UnusedStream {dir.Offset} {dir.Size} Size");
                    continue; //Reserved. Do not use this enumeration value.
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.ReservedStream0)
                {
                    //Console.WriteLine($"Found ReservedStream0 {dir.Offset} {dir.Size} Size");
                    continue; // Reserved. Do not use this enumeration value.
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.ReservedStream1)
                {
                    //Console.WriteLine($"Found ReservedStream1 {dir.Offset} {dir.Size} Size");
                    continue; // Reserved. Do not use this enumeration value.
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.ThreadListStream)
                {
                    //Console.WriteLine($"Found ThreadListStream {dir.Offset} {dir.Size} Size");
                    //threads = MinidumpThreadList.parse(dir, file_handle);
                    continue;
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.ModuleListStream)
                {
                    //Console.WriteLine($"Found ModuleListStream {dir.Offset} {dir.Size} Size");
                    minidump.modules = ModuleList.parse(dir, minidump);
                    continue; //Console.WriteLine(str(modules_list))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.MemoryListStream)
                {
                    //Console.WriteLine($"Found MemoryListStream {dir.Offset} {dir.Size} Size");
                    //memory_segments = MinidumpMemoryList.parse(dir, minidump);
                    continue; //Console.WriteLine(str(memory_segments))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.SystemInfoStream)
                {
                    //Console.WriteLine($"Found SystemInfoStream {dir.Offset} {dir.Size} Size");
                    minidump.sysinfo = SystemInfo.parse(dir, minidump);
                    continue; //Console.WriteLine(str(sysinfo))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.ThreadExListStream)
                {
                    //Console.WriteLine($"Found ThreadExListStream {dir.Offset} {dir.Size} Size");
                    //threads_ex = MinidumpThreadExList.parse(dir, file_handle);
                    continue; //Console.WriteLine(str(threads_ex))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.Memory64ListStream)
                {
                    //Console.WriteLine($"Found Memory64ListStream {dir.Offset} {dir.Size} Size");
                    minidump.memory_segments_64 = MINIDUMP_MEMORY64.parse(dir, minidump);
                    continue; //Console.WriteLine(str(memory_segments_64))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.CommentStreamA)
                {
                    //Console.WriteLine($"Found CommentStreamA {dir.Offset} {dir.Size} Size");
                    //comment_a = CommentStreamA.parse(dir, file_handle);
                    continue; //Console.WriteLine(str(comment_a))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.CommentStreamW)
                {
                    //Console.WriteLine($"Found CommentStreamW {dir.Offset} {dir.Size} Size");
                    //comment_w = CommentStreamW.parse(dir, file_handle);
                    continue; //Console.WriteLine(str(comment_w))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.ExceptionStream)
                {
                    //Console.WriteLine($"Found ExceptionStream {dir.Offset} {dir.Size} Size");
                    //exception = ExceptionList.parse(dir, file_handle);
                    continue; //Console.WriteLine(str(comment_w))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.HandleDataStream)
                {
                    //Console.WriteLine($"Found HandleDataStream {dir.Offset} {dir.Size} Size");
                    //handles = MinidumpHandleDataStream.parse(dir, file_handle);
                    continue; //Console.WriteLine(str(handles))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.FunctionTableStream)
                {
                    //Console.WriteLine($"Found FunctionTableStream {dir.Offset} {dir.Size} Size");
                    //Console.WriteLine($"Parsing of this stream type is not yet implemented!");
                    continue;
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.UnloadedModuleListStream)
                {
                    //Console.WriteLine($"Found UnloadedModuleListStream {dir.Offset} {dir.Size} Size");
                    //unloaded_modules = MinidumpUnloadedModuleList.parse(dir, file_handle);
                    continue; //Console.WriteLine(str(unloaded_modules))
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.MiscInfoStream)
                {
                    //Console.WriteLine($"Found MiscInfoStream {dir.Offset} {dir.Size} Size");
                    //misc_info = MinidumpMiscInfo.parse(dir, file_handle);
                    //Console.WriteLine(str(misc_info))
                    continue;
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.MemoryInfoListStream)
                {
                    //Console.WriteLine($"Found MemoryInfoListStream {dir.Offset} {dir.Size} Size");
                    //memory_info = MinidumpMemoryInfoList.parse(dir, file_handle);
                    //Console.WriteLine(str(memory_info))
                    continue;
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.ThreadInfoListStream)
                {
                    //Console.WriteLine($"Found ThreadInfoListStream {dir.Offset} {dir.Size} Size");
                    //thread_info = MinidumpThreadInfoList.parse(dir, file_handle);
                    //Console.WriteLine(thread_info);
                    continue;
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.SystemMemoryInfoStream)
                {
                    //Console.WriteLine($"Found SystemMemoryInfoStream {dir.Offset} {dir.Size} Size");
                    //Console.WriteLine($"SystemMemoryInfoStream parsing is not implemented (Missing documentation)");
                    continue;
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.JavaScriptDataStream)
                {
                    //Console.WriteLine($"Found JavaScriptDataStream {dir.Offset} {dir.Size} Size");
                    //Console.WriteLine($"JavaScriptDataStream parsing is not implemented (Missing documentation)");
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.ProcessVmCountersStream)
                {
                    //Console.WriteLine($"Found ProcessVmCountersStream {dir.Offset} {dir.Size} Size");
                    //Console.WriteLine($"ProcessVmCountersStream parsing is not implemented (Missing documentation)");
                }
                else if (dir.StreamType == Directory.MINIDUMP_STREAM_TYPE.TokenStream)
                {
                    //Console.WriteLine($"Found TokenStream {dir.Offset} {dir.Size} Size");
                    //Console.WriteLine($"TokenStream parsing is not implemented (Missing documentation)");
                }
                else
                {
                    //Console.WriteLine($"Found Unknown Stream! Type {dir.StreamType}, {dir.Offset}, {dir.Size})");
                }
            }
            return 0;
        }
    }
}