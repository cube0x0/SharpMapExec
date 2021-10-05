using Minidump.Crypto;
using Minidump.Templates;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Minidump.Helpers;

namespace Minidump.Decryptor
{
    public class Tspkg_
    {
        private static readonly long max_search_size = 170000;

        public static int FindCredentials(Program.MiniDump minidump, tspkg.TspkgTemplate template)
        {
            RTL_AVL_TABLE entry;
            long llCurrent;

            long tsGlobalCredTableAddr = find_signature(minidump, "TSpkg.dll", template.signature);

            if (tsGlobalCredTableAddr != 0)
            {
                long ptr_entry_loc = (long)get_ptr_with_offset(minidump.fileBinaryReader, tsGlobalCredTableAddr + template.avl_offset, minidump.sysinfo);
                long ptr_entry = (long)Minidump.Helpers.ReadUInt64(minidump.fileBinaryReader, (long)ptr_entry_loc);
                //ptr_entry = Rva2offset(minidump, ptr_entry);
                //minidump.fileBinaryReader.BaseStream.Seek(ptr_entry, 0);
                //byte[] entryBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(RTL_AVL_TABLE)));
                //entry = ReadStruct<RTL_AVL_TABLE>(entryBytes);
                //
                //llCurrent = entry.BalancedRoot.RightChild;

                WalkAVLTables(minidump, template, ptr_entry);

                return 0;
            }

            return 1;
        }

        private static void WalkAVLTables(Program.MiniDump minidump, tspkg.TspkgTemplate template, long pElement)
        {
            pElement = Rva2offset(minidump, pElement);
            minidump.fileBinaryReader.BaseStream.Seek(pElement, 0);

            if (pElement == 0)
                return;

            var entryBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(RTL_AVL_TABLE)));
            var entry = ReadStruct<RTL_AVL_TABLE>(entryBytes);

            //Minidump.Helpers.PrintProperties(entry.BalancedRoot);

            if (entry.OrderedPointer != 0)
            {
                pElement = Rva2offset(minidump, entry.OrderedPointer);
                minidump.fileBinaryReader.BaseStream.Seek(pElement, 0);

                var krbrLogonSessionBytes = minidump.fileBinaryReader.ReadBytes(template.TSCredTypeSize);
                var luid = ReadStruct<LUID>(GetBytes(krbrLogonSessionBytes, template.TSCredLocallyUniqueIdentifierOffset, Marshal.SizeOf(typeof(LUID))));

                long pCredAddr = Rva2offset(minidump, BitConverter.ToInt64(krbrLogonSessionBytes, template.TSCredOffset));
                minidump.fileBinaryReader.BaseStream.Seek(pCredAddr, 0);

                var pCredBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_TS_PRIMARY_CREDENTIAL)));
                var pCred = ReadStruct<KIWI_TS_PRIMARY_CREDENTIAL>(pCredBytes);

                var usUserName = pCred.credentials.UserName;
                var usDomain = pCred.credentials.Domain;
                var usPassword = pCred.credentials.Password;

                var username = ExtractUnicodeStringString(minidump, usUserName);
                var domain = ExtractUnicodeStringString(minidump, usDomain);

                byte[] msvPasswordBytes = minidump.fileBinaryReader.ReadBytes(usPassword.MaximumLength);
                var msvDecryptedPasswordBytes = BCrypt.DecryptCredentials(msvPasswordBytes, minidump.lsakeys);

                var passDecrypted = "";
                var NT = "";
                var encoder = new UnicodeEncoding(false, false, true);
                try
                {
                    passDecrypted = encoder.GetString(msvDecryptedPasswordBytes);
                }
                catch (Exception)
                {
                    passDecrypted = PrintHexBytes(msvDecryptedPasswordBytes);
                }

                if (msvDecryptedPasswordBytes.Length > 0)
                {
                    try
                    {
                        NT = msvDecryptedPasswordBytes.MD4().AsHexString();
                    }
                    catch
                    {
                        NT = "NULL";
                    }
                }

                if (!string.IsNullOrEmpty(username) && username.Length > 1)
                {
                    Tspkg krbrentry = new Tspkg();
                    krbrentry.UserName = username;

                    if (!string.IsNullOrEmpty(domain))
                        krbrentry.DomainName = domain;
                    else
                        krbrentry.DomainName = "NULL";

                    if (!string.IsNullOrEmpty(passDecrypted))
                        krbrentry.Password = passDecrypted;
                    else
                        krbrentry.Password = "NULL";

                    krbrentry.NT = NT;

                    //Minidump.Helpers.PrintProperties(krbrentry);
                    if (krbrentry.Password != "NULL")
                    {
                        var currentlogon = minidump.logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                        if (currentlogon == null)
                        {
                            currentlogon = new Logon(luid);
                            currentlogon.UserName = username;
                            currentlogon.Tspkg = new List<Tspkg>();
                            currentlogon.Tspkg.Add(krbrentry);
                            minidump.logonlist.Add(currentlogon);
                        }
                        else
                        {
                            currentlogon.Tspkg = new List<Tspkg>();
                            currentlogon.Tspkg.Add(krbrentry);
                        }
                    }
                }
            }

            if (entry.BalancedRoot.RightChild != 0)
                WalkAVLTables(minidump, template, entry.BalancedRoot.RightChild);
            if (entry.BalancedRoot.LeftChild != 0)
                WalkAVLTables(minidump, template, entry.BalancedRoot.LeftChild);
        }
    }
}