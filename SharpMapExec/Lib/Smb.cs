using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpMapExec.Lib
{
    public class Smb
    {
        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(
            StringBuilder ServerName,
            int level,
            ref IntPtr bufPtr,
            uint prefmaxlen,
            ref int entriesread,
            ref int totalentries,
            ref int resume_handle
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;

            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }

            public override string ToString()
            {
                return shi1_netname;
            }
        }

        private const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
        private const int NERR_Success = 0;

        private enum NetError : uint
        {
            NERR_Success = 0,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23),
        }

        private enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
        }

        public static SHARE_INFO_1[] EnumNetShares(string Server)
        {
            List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            StringBuilder server = new StringBuilder(Server);
            int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == NERR_Success)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                    ShareInfos.Add(shi1);
                    currentPtr += nStructSize;
                }
                NetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }
            else
            {
                ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(), 10, string.Empty));
                return ShareInfos.ToArray();
            }
        }

        public static void CheckLocalAdmin(string computer, string module)
        {
            string[] errors = { "ERROR=53", "ERROR=5" };
            if (module.Length == 0)
            {
                try
                {
                    string path = String.Format("\\\\{0}\\{1}", computer, "C$");
                    DirectoryInfo di = new DirectoryInfo(path);
                    var dirs = di.GetDirectories();
                    Console.WriteLine(String.Format("  [+] Local Admin on {0}", computer));
                }
                catch
                {
                    SHARE_INFO_1[] computerShares = EnumNetShares(computer);
                    foreach (SHARE_INFO_1 share in computerShares)
                    {
                        if (share.shi1_netname.Contains("ERROR"))
                        {
                            Console.WriteLine(String.Format("  [-] Failed to authenticate on {0}", computer));
                            return;
                        }
                    }
                    Console.WriteLine(String.Format("  [+] Authenticated but not admin on {0}", computer));
                }
            }
            else
            {
                SHARE_INFO_1[] computerShares = EnumNetShares(computer);
                if (computerShares.Length > 0)
                {
                    if (module.Contains("shares"))
                    {
                        List<string> readableShares = new List<string>();
                        List<string> unauthorizedShares = new List<string>();
                        foreach (SHARE_INFO_1 share in computerShares)
                        {
                            try
                            {
                                string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
                                DirectoryInfo di = new DirectoryInfo(path);
                                var dirs = di.GetDirectories();
                                readableShares.Add(share.shi1_netname);
                            }
                            catch
                            {
                                if (!errors.Contains(share.shi1_netname))
                                {
                                    unauthorizedShares.Add(share.shi1_netname);
                                }
                            }
                        }
                        if (readableShares.Contains("C$") || readableShares.Contains("ADMIN$"))
                        {
                            Console.WriteLine(String.Format("  [+] Local Admin on {0}", computer));
                        }
                        else if (unauthorizedShares.Count > 0)
                        {
                            Console.WriteLine(String.Format("  [+] Authenticated but not admin on {0}", computer));
                        }
                        else
                        {
                            Console.WriteLine(String.Format("[-] Access is Denied on {0}", computer));
                        }
                        if (unauthorizedShares.Count > 0 || readableShares.Count > 0)
                        {
                            string output = string.Format("    [*] Listing shares on {0}", computer);
                            if (readableShares.Count > 0)
                            {
                                output += "\n--- Accessible Shares ---";
                                foreach (string share in readableShares)
                                {
                                    output += string.Format("\n    [+]{0}", share);
                                }
                            }
                            if (unauthorizedShares.Count > 0)
                            {
                                output += "\n--- No Access ---";
                                foreach (string share in unauthorizedShares)
                                {
                                    output += string.Format("\n    [-]{0}", share);
                                }
                            }
                            Console.WriteLine(output);
                        }
                    }
                }
                else
                {
                    Console.WriteLine(String.Format("[-] Access is Denied on {0}", computer));
                }
            }
        }
    }
}
