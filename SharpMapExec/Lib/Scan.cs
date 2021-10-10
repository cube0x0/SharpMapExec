using Microsoft.Management.Infrastructure;
using SharpMapExec.Helpers;
using System;
using System.Collections.Generic;
using System.IO;

namespace SharpMapExec.Lib
{
    internal class Scan
    {
        public static void SMB(string[] computernames, string module)
        {
            foreach (string computername in computernames)
            {
                try
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
                    Smb.CheckSMBVersion(computername);
                    Smb.CheckOsVersion(computername);
                    Smb.CheckLocalAdmin(computername, module);
                    Console.WriteLine("");
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}:445 - {1}", computername, e.ToString());
                }
            }
        }

        public static void WINRM(string[] computernames, string module, string moduleargument, string path, string destination, List<string> flags)
        {
            foreach (string computername in computernames)
            {
                try
                {
                    Console.WriteLine(String.Format("[*] Checking {0}", computername));
                    if (!Misc.CheckHostPort(computername, 5985))
                    {
                        Console.WriteLine(String.Format("[-] Could Not Reach {0}:5985", computername));
                        Console.WriteLine();
                        continue;
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
                    else if (module.Contains("upload"))
                    {
                        Wsman.UploadFile(computername, path, destination);
                    }
                    Console.WriteLine("");
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}:5985 - {1}", computername, e.ToString());
                }
            }
        }

        public static void CIM(CimSession cimSession, string module)
        {
            try
            {
                Console.WriteLine(String.Format("[*] Checking {0}", cimSession.ComputerName));
                if (!cimSession.TestConnection(out CimInstance instance, out CimException exception))
                {
                    Console.WriteLine(String.Format("[-] Could Not Reach {0} - {1}", cimSession.ComputerName, exception));
                    Console.WriteLine();
                    return;
                }
                if (module.Length == 0)
                {
                    Cim.CheckLocalAdmin(cimSession);
                }
                else if (module.Contains("enable_winrm"))
                {
                    Cim.enable_winrm(cimSession);
                }
                else if (module.Contains("disable_winrm"))
                {
                    Cim.disable_winrm(cimSession);
                }
                else if (module.Contains("check_pslockdown"))
                {
                    Cim.check_pslockdown(cimSession);
                }
                else if (module.Contains("check_pslogging"))
                {
                    Cim.check_pslogging(cimSession);
                }
                else if (module.Contains("disable_pslockdown"))
                {
                    Cim.disable_pslockdown(cimSession);
                }
                else if (module.Contains("disable_pslogging"))
                {
                    Cim.disable_pslogging(cimSession);
                }
                Console.WriteLine("");
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] {0} - {1}", cimSession.ComputerName, e.ToString());
            }
        }

        public static void REG32(string[] computernames, string module)
        {
            foreach (string computername in computernames)
            {
                Console.WriteLine(module);

                try
                {
                    Console.WriteLine(String.Format("[*] Checking {0}", computername));
                    if (!Misc.CheckHostPort(computername, 445))
                    {
                        Console.WriteLine(String.Format("[-] Could Not Reach {0}:135", computername));
                        Console.WriteLine();
                        continue;
                    }
                    if (!Reg32.CheckLocalAdmin(computername))
                    {
                        continue;
                    }
                    else if (module.Contains("check_pslockdown"))
                    {
                        Reg32.check_pslockdown(computername);
                    }
                    else if (module.Contains("check_pslogging"))
                    {
                        Reg32.check_pslogging(computername);
                    }
                    else if (module.Contains("disable_pslockdown"))
                    {
                        Reg32.disable_pslockdown(computername);
                    }
                    else if (module.Contains("disable_pslogging"))
                    {
                        Reg32.disable_pslogging(computername);
                    }
                    Console.WriteLine("");
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0} - {1}", computername, e.ToString());
                }
            }
        }
    }
}