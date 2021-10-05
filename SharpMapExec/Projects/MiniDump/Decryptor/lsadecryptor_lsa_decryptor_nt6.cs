using Minidump.Templates;
using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace Minidump.Decryptor
{
    public class LsaDecryptor_NT6
    {
        public static LsaDecryptor.LsaKeys LsaDecryptor(Program.MiniDump minidump, lsaTemplate_NT6.LsaTemplate_NT6 template)
        {
            LsaDecryptor.LsaKeys LsaKeys = new LsaDecryptor.LsaKeys();

            acquire_crypto_material(minidump, template, ref LsaKeys);

            return LsaKeys;
        }

        public static void acquire_crypto_material(Program.MiniDump minidump, lsaTemplate_NT6.LsaTemplate_NT6 template, ref LsaDecryptor.LsaKeys LsaKeys)
        {
            //Console.WriteLine("Acquireing crypto stuff...");

            long sigpos = find_signature(minidump, template);
            minidump.fileBinaryReader.BaseStream.Seek(sigpos, 0);

            LsaKeys.iv = get_IV(minidump, sigpos, template);
            LsaKeys.des_key = get_des_key(minidump, sigpos, template);
            LsaKeys.aes_key = get_aes_key(minidump, sigpos, template);
        }

        public static byte[] get_des_key(Program.MiniDump minidump, long pos, lsaTemplate_NT6.LsaTemplate_NT6 template)
        {
            ///Console.WriteLine("Acquireing DES key...");
            long offset = (pos + template.key_pattern.offset_to_DES_key_ptr);
            long ptr_iv = (long)Helpers.get_ptr_with_offset(minidump.fileBinaryReader, (long)offset, minidump.sysinfo);

            minidump.fileBinaryReader.BaseStream.Seek(ptr_iv, 0);
            ptr_iv = (long)Minidump.Helpers.ReadUInt64(minidump.fileBinaryReader);

            ptr_iv = Helpers.Rva2offset(minidump, ptr_iv);

            minidump.fileBinaryReader.BaseStream.Seek(ptr_iv, 0);

            byte[] h3DesKeyBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_BCRYPT_HANDLE_KEY)));
            KIWI_BCRYPT_HANDLE_KEY h3DesKey = Helpers.ReadStruct<KIWI_BCRYPT_HANDLE_KEY>(h3DesKeyBytes);

            byte[] extracted3DesKeyByte = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_BCRYPT_KEY81)));
            KIWI_BCRYPT_KEY81 extracted3DesKey = Helpers.ReadStruct<KIWI_BCRYPT_KEY81>(extracted3DesKeyByte);

            return extracted3DesKey.hardkey.data.Take(24).ToArray();
        }

        public static byte[] get_aes_key(Program.MiniDump minidump, long pos, lsaTemplate_NT6.LsaTemplate_NT6 template)
        {
            //Console.WriteLine("Acquireing AES key...");
            long offset = (pos + template.key_pattern.offset_to_AES_key_ptr);
            long ptr_iv = (long)Helpers.get_ptr_with_offset(minidump.fileBinaryReader, (long)offset, minidump.sysinfo);

            minidump.fileBinaryReader.BaseStream.Seek(ptr_iv, 0);
            ptr_iv = (long)Helpers.ReadUInt64(minidump.fileBinaryReader);
            ptr_iv = Helpers.Rva2offset(minidump, ptr_iv);

            minidump.fileBinaryReader.BaseStream.Seek(ptr_iv, 0);

            byte[] hAesKeyBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_BCRYPT_HANDLE_KEY)));
            KIWI_BCRYPT_HANDLE_KEY hAesKey = Helpers.ReadStruct<KIWI_BCRYPT_HANDLE_KEY>(hAesKeyBytes);

            ptr_iv = Helpers.Rva2offset(minidump, hAesKey.key);
            minidump.fileBinaryReader.BaseStream.Seek(ptr_iv, 0);
            byte[] extractedAesKeyBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_BCRYPT_KEY81)));
            KIWI_BCRYPT_KEY81 extractedAesKey = Helpers.ReadStruct<KIWI_BCRYPT_KEY81>(extractedAesKeyBytes);

            return extractedAesKey.hardkey.data.Take(16).ToArray();
        }

        public static long find_signature(Program.MiniDump minidump, lsaTemplate_NT6.LsaTemplate_NT6 template)
        {
            //Console.WriteLine("Looking for main struct signature in memory...");
            long fl = Helpers.find_in_module(minidump, "lsasrv.dll", template.key_pattern.signature);
            if (fl == 0)
            {
                throw new Exception("LSA signature not found!");
            }
            return fl;
        }

        public static byte[] get_IV(Program.MiniDump minidump, long pos, lsaTemplate_NT6.LsaTemplate_NT6 template)
        {
            //Console.WriteLine("Reading IV");
            long offset = (pos + template.key_pattern.offset_to_IV_ptr);

            long ptr_iv = (long)Helpers.get_ptr_with_offset(minidump.fileBinaryReader, (long)offset, minidump.sysinfo);

            minidump.fileBinaryReader.BaseStream.Seek(ptr_iv, 0);
            byte[] data = minidump.fileBinaryReader.ReadBytes(template.key_pattern.IV_length);

            return data.Take(16).ToArray();
        }
    }
}