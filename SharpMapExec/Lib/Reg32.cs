using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SharpMapExec.Lib
{
    class Reg32
    {

        public static bool CheckLocalAdmin(string computername)
        {
            try
            {
                RegistryKey environmentKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computername);
                string[] subkeys = environmentKey.OpenSubKey("SOFTWARE").GetValueNames();
                Console.WriteLine(String.Format("  [+] Local Admin on {0}", computername));
                return true;
            }
            catch (System.UnauthorizedAccessException e)
            {
                Console.WriteLine(String.Format("  [-] Failed to authenticate on {0}", computername));
                return false;
            }
        }

        public static bool regValueExists(string computername, RegistryHive hive, string subKeyName, string keyName)
        {
            try
            {
                RegistryKey environmentKey = RegistryKey.OpenRemoteBaseKey(hive, computername);
                string[] subkeys = environmentKey.OpenSubKey(subKeyName).GetValueNames();
                string value = subkeys.FirstOrDefault(item => item.Contains(keyName));
                environmentKey.Close();
                if (string.IsNullOrEmpty(value))
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
            catch (System.UnauthorizedAccessException e)
            {
                Console.WriteLine(String.Format("  [-] Failed to authenticate on {0}", computername));
                return false;
            }
            catch (Exception e)
            {
                //Console.WriteLine("[-] {0}", e.ToString());
                return false;
            }
        }

        public static string readRegValue(string computername, RegistryHive hive, string subKeyName, string keyName)
        {
            try
            {
                RegistryKey environmentKey = RegistryKey.OpenRemoteBaseKey(hive, computername);
                var value = environmentKey.OpenSubKey(subKeyName).GetValue(keyName);
                environmentKey.Close();
                return value.ToString();
            }
            catch (System.UnauthorizedAccessException e)
            {
                Console.WriteLine(String.Format("  [-] Failed to authenticate on {0}", computername));
                return "";
            }
            catch (Exception e)
            {
                //Console.WriteLine("[-] {0}", e.ToString());
                return "";
            }
        }

        public static bool setRegValue(string computername, RegistryHive hive, string subKeyName, string keyName, string valueName, RegistryValueKind valueKind)
        {
            try
            {
                RegistryKey environmentKey = RegistryKey.OpenRemoteBaseKey(hive, computername).OpenSubKey(subKeyName, true);
                environmentKey.SetValue(keyName, valueName, valueKind);
                environmentKey.Close();
                if (readRegValue(computername, hive, subKeyName, keyName) == valueName)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (System.UnauthorizedAccessException e)
            {
                Console.WriteLine(String.Format("  [-] Failed to authenticate on {0}", computername));
                return false;
            }
            catch (Exception e)
            {
                //Console.WriteLine("[-] {0}", e.ToString());
                return false;
            }
        }

        public static void disable_pslockdown(string computername)
        {
            if (!regValueExists(computername, RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy"))
            {
                Console.WriteLine("[*] CLM not enabled");
                return;
            }

            string value = readRegValue(computername, RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy");
            Console.WriteLine("  [*] __PSLockdownPolicy value: {0}", value);

            if(value == "8")
            {
                return;
            }

            bool result = setRegValue(computername, RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy", "8", RegistryValueKind.String);
            if (result)
            {
                Console.WriteLine("  [+] Constrained Language Mode Disabled");
            }
            else
            {
                Console.WriteLine("  [-] Failed To Disable Constrained Language Mode");
            }
        }

        public static void check_pslockdown(string computername)
        {
            if (!regValueExists(computername, RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy"))
            {
                Console.WriteLine("[*] CLM not enabled");
                return;
            }

            string value = readRegValue(computername, RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy");
            Console.WriteLine("  [*] __PSLockdownPolicy value: {0}", value);
        }

        public static void disable_pslogging(string computername)
        {
            Dictionary<string, string> keys = new Dictionary<string, string>
            {
                { "EnableModuleLogging", @"Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" },
                { "EnableTranscripting", @"Software\Policies\Microsoft\Windows\PowerShell\Transcription" },
                { "EnableScriptBlockLogging", @"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" },
                { "EnableScriptBlockInvocationLogging", @"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" },
            };
            foreach (var key in keys)
            {
                if (!regValueExists(computername, RegistryHive.LocalMachine, key.Value, key.Key))
                {
                    Console.WriteLine("[*] {0} not enabled", key.Key);
                    continue;
                }

                string value = readRegValue(computername, RegistryHive.LocalMachine, key.Value, key.Key);
                Console.WriteLine("  [*] {0} value: {1}", key.Key, value);

                if(value == "0")
                {
                    continue;
                }

                bool result = setRegValue(computername, RegistryHive.LocalMachine, key.Value, key.Key, "0", RegistryValueKind.DWord);
                if (result)
                {
                    Console.WriteLine("  [+] {0} Disabled", key.Key);
                }
                else
                {
                    Console.WriteLine("  [-] Failed To Disable {0}", key.Key);
                }
            }
        }

        public static void check_pslogging(string computername)
        {
            Dictionary<string, string> keys = new Dictionary<string, string>
            {
                { "EnableModuleLogging", @"Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" },
                { "EnableTranscripting", @"Software\Policies\Microsoft\Windows\PowerShell\Transcription" },
                { "EnableScriptBlockLogging", @"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" },
                { "EnableScriptBlockInvocationLogging", @"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" },
            };
            foreach (var key in keys)
            {
                if (!regValueExists(computername, RegistryHive.LocalMachine, key.Value, key.Key))
                {
                    Console.WriteLine("[*] {0} not enabled", key.Key);
                    continue;
                }

                string value = readRegValue(computername, RegistryHive.LocalMachine, key.Value, key.Key);
                Console.WriteLine("  [*] {0} value: {1}", key.Key, value);

            }
        }
    }
}
