using Minidump.Streams;
using System;

namespace Minidump.Templates
{
    public class lsaTemplate
    {
        public static object get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                throw new Exception($"X86 not yet supported");
            }
            else
            {
                if (sysinfo.BuildNumber < (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    //return lsaTemplate_NT5.get_template(sysinfo);
                    throw new Exception($"NT5 not yet supported");
                }
                else
                {
                    return lsaTemplate_NT6.get_template(sysinfo);
                }
            }
        }
    }
}