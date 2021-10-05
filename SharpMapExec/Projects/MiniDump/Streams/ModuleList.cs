using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Minidump.Streams
{
    public class ModuleList
    {
        public struct MinidumpModule
        {
            public string name;
            public long baseaddress;
            public long size;
            public long endaddress;
            public VS_FIXEDFILEINFO versioninfo;
            public long checksum;
            public long timestamp;
        }

        public struct VS_FIXEDFILEINFO
        {
            public UInt32 dwSignature;
            public UInt32 dwStrucVersion;
            public UInt32 dwFileVersionMS;
            public UInt32 dwFileVersionLS;
            public UInt32 dwProductVersionMS;
            public UInt32 dwProductVersionLS;
            public UInt32 dwFileFlagsMask;
            public UInt32 dwFileFlags;
            public UInt32 dwFileOS;
            public UInt32 dwFileType;
            public UInt32 dwFileSubtype;
            public UInt32 dwFileDateMS;
            public UInt32 dwFileDateLS;
        }

        public struct MINIDUMP_MODULE
        {
            public long BaseOfImage;
            public long SizeOfImage;
            public long CheckSum;
            public long TimeDateStamp;
            public long ModuleNameRva;
            public VS_FIXEDFILEINFO VersionInfo;
            public MINIDUMP_LOCATION_DESCRIPTOR CvRecord;
            public MINIDUMP_LOCATION_DESCRIPTOR MiscRecord;
            public UInt64 Reserved0;
            public UInt64 Reserved1;
        }

        public struct MINIDUMP_MODULE_LIST
        {
            public int NumberOfModules;
            public List<MINIDUMP_MODULE> Modules;
        }

        public struct MINIDUMP_LOCATION_DESCRIPTOR
        {
            public UInt32 Size;
            public UInt32 Rva;
        }

        public static MinidumpModule parse_mod(MINIDUMP_MODULE mod, BinaryReader fileBinaryReader)
        {
            MinidumpModule mm = new MinidumpModule();
            mm.baseaddress = mod.BaseOfImage;
            mm.size = mod.SizeOfImage;
            mm.checksum = mod.CheckSum;
            mm.timestamp = mod.TimeDateStamp;
            mm.name = Helpers.get_from_rva((int)mod.ModuleNameRva, fileBinaryReader);
            mm.versioninfo = mod.VersionInfo;
            mm.endaddress = (mm.baseaddress + mod.SizeOfImage);
            return mm;
        }

        public static MINIDUMP_LOCATION_DESCRIPTOR parse_mld(BinaryReader fileBinaryReader)
        {
            MINIDUMP_LOCATION_DESCRIPTOR mld = new MINIDUMP_LOCATION_DESCRIPTOR();

            mld.Size = Helpers.ReadUInt32(fileBinaryReader);
            mld.Rva = Helpers.ReadUInt32(fileBinaryReader);

            return mld;
        }

        public static VS_FIXEDFILEINFO parse_vf(BinaryReader fileBinaryReader)
        {
            VS_FIXEDFILEINFO vf = new VS_FIXEDFILEINFO();
            vf.dwSignature = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwStrucVersion = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwFileVersionMS = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwFileVersionLS = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwProductVersionMS = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwProductVersionLS = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwFileFlagsMask = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwFileFlags = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwFileOS = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwFileType = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwFileSubtype = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwFileDateMS = Helpers.ReadUInt32(fileBinaryReader);
            vf.dwFileDateLS = Helpers.ReadUInt32(fileBinaryReader);
            return vf;
        }

        public static MINIDUMP_MODULE parse_mm(BinaryReader fileBinaryReader)
        {
            MINIDUMP_MODULE mm = new MINIDUMP_MODULE();
            mm.BaseOfImage = Helpers.ReadInt64(fileBinaryReader);
            mm.SizeOfImage = Helpers.ReadUInt32(fileBinaryReader);
            mm.CheckSum = Helpers.ReadUInt32(fileBinaryReader);
            mm.TimeDateStamp = Helpers.ReadUInt32(fileBinaryReader);
            mm.ModuleNameRva = Helpers.ReadUInt32(fileBinaryReader);
            mm.VersionInfo = parse_vf(fileBinaryReader);
            mm.CvRecord = parse_mld(fileBinaryReader);
            mm.MiscRecord = parse_mld(fileBinaryReader);
            mm.Reserved0 = Helpers.ReadUInt64(fileBinaryReader);
            mm.Reserved1 = Helpers.ReadUInt64(fileBinaryReader);
            return mm;
        }

        public static MINIDUMP_MODULE_LIST parse_mml(BinaryReader fileBinaryReader)
        {
            MINIDUMP_MODULE_LIST mml = new MINIDUMP_MODULE_LIST();
            List<MINIDUMP_MODULE> modules = new List<MINIDUMP_MODULE>();

            mml.NumberOfModules = Helpers.ReadInt32(fileBinaryReader);
            foreach (var _ in Enumerable.Range(0, mml.NumberOfModules))
            {
                MINIDUMP_MODULE module = parse_mm(fileBinaryReader);
                modules.Add(module);
            }

            mml.Modules = modules;
            return mml;
        }

        public static List<MinidumpModule> parse(Directory.MINIDUMP_DIRECTORY dir, Program.MiniDump minidump)
        {
            List<MinidumpModule> list = new List<MinidumpModule>();
            minidump.fileBinaryReader.BaseStream.Seek(dir.Offset, 0);
            byte[] chunk = minidump.fileBinaryReader.ReadBytes((int)dir.Size);

            using (BinaryReader ChunkReader = new BinaryReader(new MemoryStream(chunk)))
            {
                MINIDUMP_MODULE_LIST mtl = parse_mml(ChunkReader);
                foreach (MINIDUMP_MODULE mod in mtl.Modules)
                {
                    MinidumpModule module = parse_mod(mod, minidump.fileBinaryReader);
                    list.Add(module);
                }
            }
            return list;
        }
    }
}