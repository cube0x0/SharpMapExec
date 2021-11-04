using Microsoft.Management.Infrastructure;
using SharpMapExec.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static SharpMapExec.Helpers.SecurityContext;

namespace SharpMapExec.Lib
{
    public class ntlm
    {
        public static void Ntlm(string[] users, string domain, string[] passwords, string[] hashes, string[] computernames, string domainController, string module, string moduleargument,string path, string destination, List<string> flags, string protocol)
        {
            //StartJob(users, domain, passwords, hashes, computernames, module, moduleargument, path, destination, flags, protocol);
            var listOfTasks = new List<Task>();
            listOfTasks.Add(new Task(() => StartJob(users, domain, passwords, hashes, computernames, domainController, module, moduleargument, path, destination, flags, protocol)));
            Tasks.StartAndWaitAllThrottled(listOfTasks, 1);
        }

        public static void StartJob(string[] users, string domain, string[] passwords, string[] hashes, string[] computernames, string domainController, string module, string moduleargument, string path, string destination, List<string> flags, string protocol)
        {
            var secrets = hashes != null ? hashes : passwords;
 
            if (hashes != null)
            {
                foreach (string user in users)
                {
                    foreach (string password in secrets)
                    {
                        Console.WriteLine("------------------");
                        Console.WriteLine(string.Format("[*] User:   {0}", user));
                        Console.WriteLine(string.Format("[*] domain: {0}", domain));
                        Console.WriteLine(string.Format("[*] secret: {0}", password));
                        Console.WriteLine();
                        SetThreadToken(user, domain, password);
                        if (protocol.ToLower() == "smb")
                        {
                            Scan.SMB(computernames, module);
                        }
                        else if (protocol.ToLower() == "winrm")
                        {
                            Scan.WINRM(computernames, module, moduleargument, path, destination, flags);
                        }
                        else if (protocol.ToLower() == "reg32")
                        {
                            Scan.REG32(computernames, module);
                        }
                        else if (protocol.ToLower() == "domain")
                        {
                            Scan.LDAP(module, domain, domainController);
                        }
                    }
                }
            }
            else
            {
                foreach (string user in users)
                {
                    foreach (string password in secrets)
                    {
                        Console.WriteLine("------------------");
                        Console.WriteLine(string.Format("[*] User:   {0}", user));
                        Console.WriteLine(string.Format("[*] domain: {0}", domain));
                        Console.WriteLine(string.Format("[*] secret: {0}", password));
                        Console.WriteLine();
                        using (new Impersonator.Impersonation(domain, user, password))
                        {
                            if (protocol.ToLower() == "smb")
                            {
                                Scan.SMB(computernames, module);
                            }
                            else if (protocol.ToLower() == "winrm")
                            {
                                Scan.WINRM(computernames, module, moduleargument, path, destination, flags);
                            }
                            else if (protocol.ToLower() == "cim")
                            {
                                foreach (string computername in computernames)
                                {
                                    CimSession cimSession;
                                    cimSession = Cim.newSession(computername, domain, user, password, flags.Contains("impersonate"));
                                    Scan.CIM(cimSession, module);
                                }
                            }
                            else if (protocol.ToLower() == "reg32")
                            {
                                Scan.REG32(computernames, module);
                            }
                            else if (protocol.ToLower() == "domain")
                            {
                                Scan.LDAP(module, domain, domainController);
                            }
                        }
                    }
                }
            }
        }
    }
}