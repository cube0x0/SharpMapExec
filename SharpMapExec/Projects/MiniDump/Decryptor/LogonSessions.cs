using Minidump.Templates;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static Minidump.Helpers;

namespace Minidump.Decryptor
{
    public class Logon
    {
        public Logon(LUID logonId)
        {
            LogonId = logonId;
        }

        public LUID LogonId { get; set; }
        public string LogonType { get; set; }
        public int Session { get; set; }
        public FILETIME LogonTime { get; set; }
        public string UserName { get; set; }
        public string LogonDomain { get; set; }
        public string LogonServer { get; set; }
        public string SID { get; set; }

        public Msv Msv { get; set; }
        public Kerberos Kerberos { get; set; }
        public List<Tspkg> Tspkg { get; set; }
        public List<WDigest> Wdigest { get; set; }
        public List<Ssp> Ssp { get; set; }
        public List<LiveSsp> LiveSsp { get; set; }
        public List<CredMan> Credman { get; set; }
        public List<KerberosKey> KerberosKeys { get; set; }
        public List<Cloudap> Cloudap { get; set; }
        public List<Dpapi> Dpapi { get; set; }
        public List<Rdp> Rdp { get; set; }

        public long pCredentials { get; set; }
        public long pCredentialManager { get; set; }
    }

    public class Cloudap
    {
        public string luid { get; set; }
        public string sid { get; set; }
        public string cachedir { get; set; }
        public string PRT { get; set; }
        public string key_guid { get; set; }
        public string dpapi_key { get; set; }
        public string dpapi_key_sha { get; set; }
    }

    public class Dpapi
    {
        public string luid { get; set; }
        public string key_guid { get; set; }
        public string masterkey { get; set; }
        public string masterkey_sha { get; set; }
        public string insertTime { get; set; }
        public string key_size { get; set; }
    }

    public class Msv
    {
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Lm { get; set; }
        public string NT { get; set; }
        public string Sha1 { get; set; }
        public string Dpapi { get; set; }
    }

    public class Ssp
    {
        //public int Reference { get; set; }
        public string DomainName { get; set; }

        public string UserName { get; set; }
        public string Password { get; set; }
        public string NT { get; set; }
    }

    public class Rdp
    {
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Password_raw { get; set; }
        public string NT { get; set; }
    }

    public class LiveSsp
    {
        public int Reference { get; set; }
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string NT { get; set; }
    }

    public class Tspkg
    {
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string NT { get; set; }
    }

    public class Kerberos
    {
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string NT { get; set; }
    }

    public class CredMan
    {
        public int Reference { get; set; }
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string NT { get; set; }
    }

    public class WDigest
    {
        public string HostName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string NT { get; set; }
    }

    public class KerberosKey
    {
        public string Type { get; set; }
        public string Key { get; set; }
    }

    internal class LogonSessions
    {
        private static readonly long max_search_size = 580000;

        private static readonly string[] KUHL_M_SEKURLSA_LOGON_TYPE =
        {
            "UndefinedLogonType",
            "Unknown !",
            "Interactive",
            "Network",
            "Batch",
            "Service",
            "Proxy",
            "Unlock",
            "NetworkCleartext",
            "NewCredentials",
            "RemoteInteractive",
            "CachedInteractive",
            "CachedRemoteInteractive",
            "CachedUnlock"
        };

        public static List<Logon> FindSessions(Program.MiniDump minidump, msv.MsvTemplate template, int ptr_entry_offset = 1)
        {
            //PrintProperties(template);

            List<Logon> logonlist = new List<Logon>();
            List<long> offsetlist = new List<long>();

            long logonSessionListSignOffset = find_signature(minidump, "lsasrv.dll", template.signature);
            if (logonSessionListSignOffset == 0)
            {
                Console.WriteLine("[x] Error: Could not find LogonSessionList signature\n");
                return logonlist;
            }

            ulong logonSessionOffset = get_ptr_with_offset(minidump.fileBinaryReader, (logonSessionListSignOffset + template.LogonSessionListCountOffset), minidump.sysinfo);
            uint logonSessionListCount = ReadInt8(minidump.fileBinaryReader, (long)logonSessionOffset);

            //Console.WriteLine($"logonSessionOffset {(Int32)logonSessionOffset}");
            //Console.WriteLine($"Parsing {logonSessionListCount} logon sessions");

            long offset = logonSessionListSignOffset + template.first_entry_offset;
            long listMemOffset = ReadInt32(minidump.fileBinaryReader, logonSessionListSignOffset + template.first_entry_offset);
            long ptr_entry_loc = offset + sizeof(int) + listMemOffset;

            for (var i = 0; i < logonSessionListCount; i++)
            {
                long listentry;
                long entry_ptr;
                long pos;
                //Console.WriteLine($"Parsing session {i}");

                entry_ptr = ptr_entry_loc + (16 * i);
                listentry = ReadInt64(minidump.fileBinaryReader, entry_ptr);
                //offsetlist.Add(listentry);
                if (entry_ptr == listentry)
                    continue;

                pos = entry_ptr;

                int count = 0;
                do
                {
                    listentry = Rva2offset(minidump, ReadInt64(minidump.fileBinaryReader, pos));
                    //Console.WriteLine($"listentry {listentry}");

                    count++;
                    if (count >= 255)
                        return null;

                    if (listentry == 0)
                        break;

                    if (offsetlist.Contains((listentry)))
                    {
                        break;
                    }
                    offsetlist.Add(listentry);


                    KIWI_BASIC_SECURITY_LOGON_SESSION_DATA logonsession = new KIWI_BASIC_SECURITY_LOGON_SESSION_DATA();
                    logonsession.LogonId = listentry + template.LocallyUniqueIdentifierOffset;
                    logonsession.LogonType = ReadInt32(minidump.fileBinaryReader, listentry + template.LogonTypeOffset);
                    logonsession.Session = ReadInt32(minidump.fileBinaryReader, listentry + template.SessionOffset);
                    logonsession.LogonTime = ReadStruct<FILETIME>(ReadBytes(minidump.fileBinaryReader, listentry + template.LogonTimeOffset + 4, 8));
                    //p* for pointers
                    logonsession.pCredentials = ReadInt64(minidump.fileBinaryReader, listentry + template.CredentialsOffset);
                    logonsession.pCredentialManager = ReadInt64(minidump.fileBinaryReader, listentry + template.CredentialManagerOffset);
                    logonsession.pSid = listentry + template.pSidOffset;

                    var luid = ReadStruct<LUID>(ReadBytes(minidump.fileBinaryReader, logonsession.LogonId, 4));

                    minidump.fileBinaryReader.BaseStream.Seek(listentry + template.UserNameListOffset, 0);
                    logonsession.UserName =
                        ExtractUnicodeStringString(minidump,
                            ExtractUnicodeString(minidump.fileBinaryReader));

                    minidump.fileBinaryReader.BaseStream.Seek(listentry + template.DomainOffset, 0);
                    logonsession.LogonDomain =
                        ExtractUnicodeStringString(minidump,
                            ExtractUnicodeString(minidump.fileBinaryReader));

                    minidump.fileBinaryReader.BaseStream.Seek(listentry + template.LogonServerOffset, 0);
                    logonsession.LogonServer =
                        ExtractUnicodeStringString(minidump,
                            ExtractUnicodeString(minidump.fileBinaryReader));

                    string stringSid = "";
                    stringSid = ExtractSid(minidump, logonsession.pSid);

                    var logon = new Logon(luid)
                    {
                        Session = logonsession.Session,
                        LogonType = KUHL_M_SEKURLSA_LOGON_TYPE[logonsession.LogonType],
                        LogonTime = logonsession.LogonTime,
                        UserName = logonsession.UserName,
                        LogonDomain = logonsession.LogonDomain,
                        LogonServer = logonsession.LogonServer,
                        SID = stringSid,
                        pCredentials = Rva2offset(minidump, logonsession.pCredentials),
                        pCredentialManager = Rva2offset(minidump, logonsession.pCredentialManager)
                    };
                    //Console.WriteLine("session " + logon.Session + " luid " + logon.LogonId.LowPart + " username " + logon.UserName + " pCredentials " + logonsession.pCredentials);
                    //PrintProperties(logon);
                    logonlist.Add(logon);
                    pos = Rva2offset(minidump, ReadInt64(minidump.fileBinaryReader, pos));
                    //Console.WriteLine(pos);
                } while (true);
            }

            return logonlist;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_BASIC_SECURITY_LOGON_SESSION_DATA
        {
            public long LogonId;
            public string UserName;
            public string LogonDomain;
            public int LogonType;
            public int Session;
            public long pCredentials;
            public long pSid;
            public long pCredentialManager;
            public FILETIME LogonTime;
            public string LogonServer;
        }
    }
}