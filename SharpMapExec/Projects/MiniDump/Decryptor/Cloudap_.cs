using Minidump.Crypto;
using Minidump.Templates;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static Minidump.Helpers;

namespace Minidump.Decryptor
{
    public class Cloudap_
    {
        public static int FindCredentials(Program.MiniDump minidump, cloudap.CloudapTemplate template)
        {
            wdigest.KIWI_WDIGEST_LIST_ENTRY entry;
            long logSessListAddr;
            long llCurrent;

            long position = find_signature(minidump, "cloudAP.dll", template.signature);
            if (position == 0)
                return 0;

            var ptr_entry_loc = get_ptr_with_offset(minidump.fileBinaryReader, (position + template.first_entry_offset), minidump.sysinfo);
            var ptr_entry = ReadUInt64(minidump.fileBinaryReader, (long)ptr_entry_loc);

            llCurrent = (long)ptr_entry;
            long stop = ReadInt64(minidump.fileBinaryReader, Rva2offset(minidump, llCurrent + 8));

            do
            {
                logSessListAddr = Rva2offset(minidump, llCurrent);
                byte[] Bytes = ReadBytes(minidump.fileBinaryReader, logSessListAddr, Marshal.SizeOf(typeof(KIWI_CLOUDAP_LOGON_LIST_ENTRY)));
                var log = ReadStruct<KIWI_CLOUDAP_LOGON_LIST_ENTRY>(Bytes);
                LUID luid = log.LocallyUniqueIdentifier;
                //PrintProperties(log);

                byte[] entryBytes = ReadBytes(minidump.fileBinaryReader, Rva2offset(minidump, log.cacheEntry), Marshal.SizeOf(typeof(KIWI_CLOUDAP_CACHE_LIST_ENTRY)));
                KIWI_CLOUDAP_CACHE_LIST_ENTRY cacheEntry = ReadStruct<KIWI_CLOUDAP_CACHE_LIST_ENTRY>(entryBytes);
                string cachedir = Encoding.Unicode.GetString(cacheEntry.toname);
                //PrintProperties(cacheEntry);

                Cloudap cloudapentry = new Cloudap();
                cloudapentry.cachedir = cachedir;

                if (cacheEntry.cbPRT != 0 && cacheEntry.PRT != 0)
                {
                    byte[] prtBytes = ReadBytes(minidump.fileBinaryReader, Rva2offset(minidump, (long)cacheEntry.PRT), (int)cacheEntry.cbPRT);
                    var DecryptedPRTBytes = BCrypt.DecryptCredentials(prtBytes, minidump.lsakeys);
                    string PRT = Encoding.ASCII.GetString(DecryptedPRTBytes.Skip(25).ToArray());
                    cloudapentry.PRT = PRT;


                    if (cacheEntry.toDetermine != 0)
                    {
                        byte[] cacheunkBytes = ReadBytes(minidump.fileBinaryReader, Rva2offset(minidump, (long)cacheEntry.toDetermine), Marshal.SizeOf(typeof(KIWI_CLOUDAP_CACHE_UNK)));
                        KIWI_CLOUDAP_CACHE_UNK cacheunk = ReadStruct<KIWI_CLOUDAP_CACHE_UNK>(cacheunkBytes);
                        var DecryptedDpapiBytes = BCrypt.DecryptCredentials(cacheunk.unk, minidump.lsakeys);

                        string key_guid = cacheunk.guid.ToString();
                        string dpapi_key = BitConverter.ToString(DecryptedDpapiBytes).Replace("-", "");
                        string dpapi_key_sha1 = BCrypt.GetHashSHA1(DecryptedDpapiBytes);

                        cloudapentry.key_guid = key_guid;
                        cloudapentry.dpapi_key = dpapi_key;
                        cloudapentry.dpapi_key_sha = dpapi_key_sha1;
                    }

                    var currentlogon = minidump.logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                    if (currentlogon == null)
                    {
                        currentlogon = new Logon(luid)
                        {
                            //UserName = username,
                            Cloudap = new List<Cloudap>()
                        };
                        currentlogon.Cloudap.Add(cloudapentry);
                        minidump.logonlist.Add(currentlogon);
                        //continue;
                    }
                    else
                    {
                        currentlogon.Cloudap = new List<Cloudap>();
                        currentlogon.Cloudap.Add(cloudapentry);
                    }
                }

                llCurrent = log.Flink;
            } while (llCurrent != stop);

            return 0;
        }
    }
}