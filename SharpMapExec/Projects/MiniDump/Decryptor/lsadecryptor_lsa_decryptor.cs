using Minidump.Templates;
using System;

namespace Minidump.Decryptor
{
    public class LsaDecryptor
    {
        public struct LsaKeys
        {
            public byte[] iv;
            public byte[] aes_key;
            public byte[] des_key;
        }

        public static LsaKeys choose(Program.MiniDump minidump, object template)
        {
            if (template.GetType() == typeof(lsaTemplate_NT6.LsaTemplate_NT6))
            {
                return LsaDecryptor_NT6.LsaDecryptor(minidump, (lsaTemplate_NT6.LsaTemplate_NT6)template);
            }
            else
            {
                throw new Exception($"NT5 not yet supported");
            }
        }
    }
}