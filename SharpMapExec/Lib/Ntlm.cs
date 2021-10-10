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
        public static void Ntlm<T>(string[] users, string domain, T secrets, string[] computernames, string module, string moduleargument,string path, string destination, List<string> flags, string protocol)
        {
            StartJob(users, domain, secrets, computernames, module, moduleargument, path, destination, flags, protocol);
            //var listOfTasks = new List<Task>();
            //listOfTasks.Add(new Task(() => StartJob(users, domain, secrets, computernames, module, moduleargument, path, destination, flags, protocol)));
            //Tasks.StartAndWaitAllThrottled(listOfTasks, 1);
        }

        public static void StartJob<T>(string[] users, string domain, T secrets, string[] computernames, string module, string moduleargument, string path, string destination, List<string> flags, string protocol)
        {
            string[] passwords;
            if (typeof(T) == typeof(NTHash))
            {
                passwords = (string[])secrets.GetType().GetProperties().Single(pi => pi.Name == "Nthash").GetValue(secrets, null);
                foreach (string user in users)
                {
                    foreach (string password in passwords)
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
                    }
                }
            }
            else if (typeof(T) == typeof(ClearText))
            {
                passwords = (string[])secrets.GetType().GetProperties().Single(pi => pi.Name == "Cleartext").GetValue(secrets, null);
                foreach (string user in users)
                {
                    foreach (string password in passwords)
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
                        }
                    }
                }
            }
        }
    }
}