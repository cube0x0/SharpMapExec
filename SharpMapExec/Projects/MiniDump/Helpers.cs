using Minidump.Streams;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Minidump
{
    public class Helpers
    {
        public const int LM_NTLM_HASH_LENGTH = 16;
        public const int SHA_DIGEST_LENGTH = 20;

        [StructLayout(LayoutKind.Sequential)]
        public struct LARGE_INTEGER
        {
            public int LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public long Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool ConvertSidToStringSid(
            [MarshalAs(UnmanagedType.LPArray)] byte[] pSID, out IntPtr ptrSid);

        public static DateTime ToDateTime(FILETIME time)
        {
            var fileTime = ((long)time.dwHighDateTime << 32) | (uint)time.dwLowDateTime;

            try
            {
                return DateTime.FromFileTime(fileTime);
            }
            catch
            {
                return DateTime.FromFileTime(0xFFFFFFFF);
            }
        }

        public static List<long> find_all_global(BinaryReader fileBinaryReader, byte[] pattern, byte[] allocationprotect = null)
        {
            List<long> list = new List<long>();
            if (allocationprotect == null)
                allocationprotect = new byte[] { 0x04 };

            fileBinaryReader.BaseStream.Seek(0, 0);
            byte[] data = fileBinaryReader.ReadBytes((int)fileBinaryReader.BaseStream.Length);
            list = AllPatternAt(data, pattern);
            return list;
        }

        //https://github.com/skelsec/pypykatz/blob/bd1054d1aa948133a697a1dfcb57a5c6463be41a/pypykatz/lsadecryptor/package_commons.py#L64
        public static long find_signature(Program.MiniDump minidump, string module_name, byte[] signature)
        {
            return find_in_module(minidump, module_name, signature);
        }

        //https://github.com/skelsec/minidump/blob/96d6b64dba679df14f5f78c64c3a045be8c4f1f1/minidump/minidumpreader.py#L268
        public static long find_in_module(Program.MiniDump minidump, string module_name, byte[] pattern, bool find_first = false, bool reverse = false)
        {
            return search_module(minidump, module_name, pattern, find_first = find_first, reverse = reverse);
        }

        //https://github.com/skelsec/minidump/blob/96d6b64dba679df14f5f78c64c3a045be8c4f1f1/minidump/minidumpreader.py#L323
        public static long search_module(Program.MiniDump minidump, string module_name, byte[] pattern, bool find_first = false, bool reverse = false, int chunksize = (10 * 1024))
        {
            long pos = minidump.fileBinaryReader.BaseStream.Position;
            ModuleList.MinidumpModule mod = get_module_by_name(module_name, minidump.modules);
            List<MinidumpMemory.MinidumpMemorySegment> memory_segments = new List<MinidumpMemory.MinidumpMemorySegment>();
            bool is_fulldump;
            if (minidump.sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                memory_segments = minidump.memory_segments_64.memory_segments;
                is_fulldump = true;
            }
            else
            {
                memory_segments = minidump.memory_segments.memory_segments;
                is_fulldump = false;
            }

            byte[] needles = new byte[] { };
            foreach (MinidumpMemory.MinidumpMemorySegment ms in memory_segments)
            {
                if (mod.baseaddress <= ms.start_virtual_address && ms.start_virtual_address <= mod.endaddress)
                {
                    minidump.fileBinaryReader.BaseStream.Seek(ms.start_file_address, 0);
                    byte[] data = minidump.fileBinaryReader.ReadBytes((int)ms.size);
                    minidump.fileBinaryReader.BaseStream.Seek(pos, 0);
                    int offset = PatternAt(data, pattern);
                    if (offset != -1)
                    {
                        return (ms.start_file_address + offset);
                    }
                }
            }

            return 0;
        }

        public static long Rva2offset(Program.MiniDump minidump, long virutal_address)
        {
            List<MinidumpMemory.MinidumpMemorySegment> memory_segments = new List<MinidumpMemory.MinidumpMemorySegment>();
            bool is_fulldump;
            if (minidump.sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                memory_segments = minidump.memory_segments_64.memory_segments;
                is_fulldump = true;
            }
            else
            {
                memory_segments = minidump.memory_segments.memory_segments;
                is_fulldump = false;
            }

            foreach (MinidumpMemory.MinidumpMemorySegment ms in memory_segments)
            {
                if (ms.start_virtual_address <= (long)virutal_address && ms.end_virtual_address >= (long)virutal_address)
                {
                    if (ms.start_virtual_address < (long)virutal_address)
                    {
                        int offset = (int)(virutal_address - (long)ms.start_virtual_address);
                        return (long)(ms.start_file_address + (long)offset);
                    }
                    return (long)ms.start_file_address;
                }
            }

            return 0;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("0x{0:x2} ", b);
            return hex.ToString();
        }

        public static int PatternAt(byte[] src, byte[] pattern)
        {
            int maxFirstCharSlot = src.Length - pattern.Length + 1;
            for (int i = 0; i < maxFirstCharSlot; i++)
            {
                if (src[i] != pattern[0]) // compare only first byte
                    continue;

                // found a match on first byte, now try to match rest of the pattern
                for (int j = pattern.Length - 1; j >= 1; j--)
                {
                    if (src[i + j] != pattern[j]) break;
                    if (j == 1) return i;
                }
            }
            return -1;
        }

        public static List<long> AllPatternAt(byte[] src, byte[] pattern)
        {
            List<long> list = new List<long>();
            int maxFirstCharSlot = src.Length - pattern.Length + 1;
            for (int i = 0; i < maxFirstCharSlot; i++)
            {
                if (src[i] != pattern[0]) // compare only first byte
                    continue;

                // found a match on first byte, now try to match rest of the pattern
                for (int j = pattern.Length - 1; j >= 1; j--)
                {
                    if (src[i + j] != pattern[j]) break;
                    if (j == 1) list.Add(i);
                }
            }
            return list;
        }

        //https://github.com/skelsec/minidump/blob/96d6b64dba679df14f5f78c64c3a045be8c4f1f1/minidump/minidumpreader.py#L311
        public static ModuleList.MinidumpModule get_module_by_name(string module_name, List<ModuleList.MinidumpModule> modules)
        {
            return modules.FirstOrDefault(item => item.name.Contains(module_name));
        }

        //https://github.com/skelsec/pypykatz/blob/bd1054d1aa948133a697a1dfcb57a5c6463be41a/pypykatz/commons/common.py#L168
        public static ulong get_ptr_with_offset(BinaryReader fileBinaryReader, long pos, SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                fileBinaryReader.BaseStream.Seek(pos, SeekOrigin.Begin);
                UInt32 ptr = Minidump.Helpers.ReadUInt32(fileBinaryReader);
                return (ulong)(pos + 4 + ptr);
            }
            else
            {
                fileBinaryReader.BaseStream.Seek(pos, SeekOrigin.Begin);
                UInt16 ptr = Minidump.Helpers.ReadUInt16(fileBinaryReader);
                return ptr;
            }
        }

        //https://github.com/skelsec/pypykatz/blob/bd1054d1aa948133a697a1dfcb57a5c6463be41a/pypykatz/commons/common.py#L162
        public static ulong get_ptr(BinaryReader fileBinaryReader, long pos, SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            fileBinaryReader.BaseStream.Seek(pos, 0);
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                UInt32 ptr = Minidump.Helpers.ReadUInt32(fileBinaryReader);
                return (ulong)ptr;
            }
            else
            {
                UInt16 ptr = Minidump.Helpers.ReadUInt16(fileBinaryReader);
                return (ulong)ptr;
            }
        }

        public static T ReadStruct<T>(byte[] array) where T : struct
        {
            var handle = GCHandle.Alloc(array, GCHandleType.Pinned);
            var mystruct = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return mystruct;
        }

        public static string ExtractSid(Program.MiniDump minidump, long pSid)
        {
            byte nbAuth;
            int sizeSid;

            var pSidInt = Minidump.Helpers.ReadInt64(minidump.fileBinaryReader, pSid);
            minidump.fileBinaryReader.BaseStream.Seek(Rva2offset(minidump, pSidInt) + 8, 0);
            var nbAuth_b = minidump.fileBinaryReader.ReadBytes(1);
            nbAuth = nbAuth_b[0];
            sizeSid = 4 * nbAuth + 6 + 1 + 1;

            minidump.fileBinaryReader.BaseStream.Seek(Rva2offset(minidump, pSidInt), 0);
            var sid_b = minidump.fileBinaryReader.ReadBytes(sizeSid);

            ConvertSidToStringSid(sid_b, out IntPtr ptrSid);

            return Marshal.PtrToStringAuto(ptrSid);
        }

        public static UNICODE_STRING ExtractUnicodeString(BinaryReader fileStreamReader)
        {
            UNICODE_STRING str;

            byte[] strBytes = fileStreamReader.ReadBytes(Marshal.SizeOf(typeof(UNICODE_STRING)));
            str = ReadStruct<UNICODE_STRING>(strBytes);

            return str;
        }

        public static string ExtractUnicodeStringString(Program.MiniDump minidump, UNICODE_STRING str)
        {
            if (str.MaximumLength == 0) return null;

            minidump.fileBinaryReader.BaseStream.Seek(Helpers.Rva2offset(minidump, str.Buffer), 0);
            byte[] resultBytes = minidump.fileBinaryReader.ReadBytes(str.MaximumLength);

            var encoder = new UnicodeEncoding(false, false, true);
            try
            {
                return encoder.GetString(resultBytes);
            }
            catch (Exception)
            {
                return PrintHexBytes(resultBytes);
            }
        }

        public static string PrintHexBytes(byte[] byteArray)
        {
            var res = new StringBuilder(byteArray.Length * 3);
            for (var i = 0; i < byteArray.Length; i++)
                res.AppendFormat(NumberFormatInfo.InvariantInfo, "{0:x2} ", byteArray[i]);
            return res.ToString();
        }

        public static int FieldOffset<T>(string fieldName)
        {
            return Marshal.OffsetOf(typeof(T), fieldName).ToInt32();
        }

        public static int StructFieldOffset(Type s, string field)
        {
            var ex = typeof(Helpers);
            var mi = ex.GetMethod("FieldOffset");
            var miConstructed = mi.MakeGenericMethod(s);
            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        public static UNICODE_STRING ExtractUnicodeString(BinaryReader fileStreamReader, long offset)
        {
            UNICODE_STRING str;
            fileStreamReader.BaseStream.Seek(offset, 0);
            byte[] strBytes = fileStreamReader.ReadBytes(Marshal.SizeOf(typeof(UNICODE_STRING)));
            str = ReadStruct<UNICODE_STRING>(strBytes);

            return str;
        }

        public static byte[] GetBytes(byte[] source, long startindex, int lenght)
        {
            var resBytes = new byte[lenght];
            Array.Copy(source, startindex, resBytes, 0, resBytes.Length);
            return resBytes;
        }

        public static string PrintHashBytes(byte[] byteArray)
        {
            if (byteArray == null)
                return string.Empty;

            var res = new StringBuilder(byteArray.Length * 2);
            for (var i = 0; i < byteArray.Length; i++)
                res.AppendFormat(NumberFormatInfo.InvariantInfo, "{0:x2}", byteArray[i]);
            return res.ToString();
        }

        public static string ExtractANSIStringString(Program.MiniDump minidump, UNICODE_STRING str)
        {
            if (str.MaximumLength == 0) return null;

            minidump.fileBinaryReader.BaseStream.Seek(Helpers.Rva2offset(minidump, str.Buffer), 0);
            byte[] resultBytes = minidump.fileBinaryReader.ReadBytes(str.MaximumLength);
            var pinnedArray = GCHandle.Alloc(resultBytes, GCHandleType.Pinned);
            var tmp_p = pinnedArray.AddrOfPinnedObject();
            var result = Marshal.PtrToStringAnsi(tmp_p);
            pinnedArray.Free();

            return result;
        }

        public static string get_from_rva(int rva, BinaryReader fileBinaryReader)
        {
            long pos = fileBinaryReader.BaseStream.Position;
            fileBinaryReader.BaseStream.Seek(rva, 0);
            UInt32 length = ReadUInt32(fileBinaryReader);
            byte[] data = fileBinaryReader.ReadBytes((int)length);
            ////Array.Reverse(data);
            fileBinaryReader.BaseStream.Seek(pos, 0);
            string name = Encoding.Unicode.GetString(data);
            return name;
        }

        public static void PrintProperties(object myObj, string header = "", int offset = 0)
        {
            string trail = String.Concat(Enumerable.Repeat(" ", offset));

            if (!string.IsNullOrEmpty(header))
                Console.WriteLine(header);

            foreach (var prop in myObj.GetType().GetProperties())
            {
                try
                {
                    if (!string.IsNullOrEmpty((string)(prop.GetValue(myObj, null))))
                        Console.WriteLine(trail + prop.Name + ": " + prop.GetValue(myObj, null));
                }
                catch (Exception e)
                {
                    Console.WriteLine(trail + prop.Name + ": " + prop.GetValue(myObj, null));
                }
            }

            foreach (var field in myObj.GetType().GetFields())
            {
                try
                {
                    if (!string.IsNullOrEmpty((string)field.GetValue(myObj)))
                        Console.WriteLine(trail + field.Name + ": " + field.GetValue(myObj));
                }
                catch (Exception e)
                {
                    Console.WriteLine(trail + field.Name + ": " + field.GetValue(myObj));
                }
            }
        }

        public static string ReadString(BinaryReader fileBinaryReader, int Length)
        {
            var data = fileBinaryReader.ReadBytes(Length);
            Array.Reverse(data);
            return Encoding.Unicode.GetString(data);
        }

        public static Int16 ReadInt16(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(2);
            //Array.Reverse(data);
            return BitConverter.ToInt16(data, 0);
        }

        public static Int32 ReadInt32(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(4);
            //Array.Reverse(data);
            return BitConverter.ToInt32(data, 0);
        }

        public static Int64 ReadInt64(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(8);
            //Array.Reverse(data);
            return BitConverter.ToInt64(data, 0);
        }

        public static uint ReadInt8(BinaryReader fileBinaryReader)
        {
            byte data = fileBinaryReader.ReadBytes(1)[0];
            //Array.Reverse(data);
            return data;
        }

        public static UInt16 ReadUInt16(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(2);
            //Array.Reverse(data);
            return BitConverter.ToUInt16(data, 0);
        }

        public static UInt32 ReadUInt32(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(4);
            //Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
        }

        public static UInt64 ReadUInt64(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(8);
            //Array.Reverse(data);
            return BitConverter.ToUInt64(data, 0);
        }

        public static Int16 ReadInt16(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(2);
            //Array.Reverse(data);
            return BitConverter.ToInt16(data, 0);
        }

        public static Int32 ReadInt32(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(4);
            //Array.Reverse(data);
            return BitConverter.ToInt32(data, 0);
        }

        public static Int64 ReadInt64(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(8);
            //Array.Reverse(data);
            return BitConverter.ToInt64(data, 0);
        }

        public static uint ReadInt8(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            byte data = fileBinaryReader.ReadBytes(1)[0];
            //Array.Reverse(data);
            return data;
        }

        public static UInt16 ReadUInt16(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(2);
            //Array.Reverse(data);
            return BitConverter.ToUInt16(data, 0);
        }

        public static UInt32 ReadUInt32(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(4);
            //Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
        }

        public static UInt64 ReadUInt64(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(8);
            //Array.Reverse(data);
            return BitConverter.ToUInt64(data, 0);
        }

        public static byte[] ReadBytes(BinaryReader fileBinaryReader, long offset, int length)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(length);
            //Array.Reverse(data);
            return data;
        }
    }
}