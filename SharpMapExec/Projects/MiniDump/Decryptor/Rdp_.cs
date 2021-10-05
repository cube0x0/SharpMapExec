using Minidump.Streams;
using Minidump.Templates;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static Minidump.Helpers;

namespace Minidump.Decryptor
{
    public class Rdp_
    {
        public static int FindCredentials(Program.MiniDump minidump, rdp.RdpTemplate template)
        {
            foreach (byte[] signature in template.signature)
            {
                rdp.WTS_KIWI cred = new rdp.WTS_KIWI();

                List<long> positions = find_all_global(minidump.fileBinaryReader, signature);
                foreach (long pos in positions)
                {
                    if (pos <= 0)
                        continue;

                    minidump.fileBinaryReader.BaseStream.Seek(pos + template.first_entry_offset, 0);
                    try
                    {
                        byte[] credBytes = minidump.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(rdp.WTS_KIWI)));
                        cred = ReadStruct<rdp.WTS_KIWI>(credBytes);
                    }
                    catch
                    {
                        continue;
                    }

                    if (cred.cbDomain <= 512 && cred.cbUsername <= 512 && cred.cbPassword <= 512 && cred.cbPassword > 0)
                    {
                        try
                        {
                            string domain = Encoding.ASCII.GetString(cred.Domain.Take(cred.cbDomain).ToArray());
                            string username = Encoding.ASCII.GetString(cred.UserName.Take(cred.cbUsername).ToArray());
                            byte[] password_raw = cred.Password.Take(cred.cbPassword).ToArray();

                            if (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(username))
                                continue;

                            //credentials are encrypted
                            if (minidump.sysinfo.BuildNumber >= (int)SystemInfo.WindowsMinBuild.WIN_10)
                                continue;

                            Console.WriteLine(username);
                            Console.WriteLine(domain);
                            Console.WriteLine(PrintHexBytes(password_raw));

                            PrintProperties(cred);
                        }
                        catch { }
                    }
                }
            }

            return 0;
        }
    }
}