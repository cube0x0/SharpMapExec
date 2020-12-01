using SharpMapExec.HiveParser;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static SharpMapExec.HiveParser.Registry;

namespace SharpMapExec.Lib
{
    internal class Secrets
    {
        public static void ParseSecrets(string sampath, string systempath, string securitypath, List<byte[]> machineMasterKeys = null, List<byte[]> userMasterKeys = null, string credDirs = null, string vaultDirs = null, string certDirs = null)
        {
            StringBuilder sb = new StringBuilder();
            byte[] bootKey = new byte[16];

            RegistryHive system = RegistryHive.ImportHiveDump(systempath);
            if (system != null)
            {
                bootKey = GetBootKey(system);
                if (bootKey == null)
                {
                    sb.AppendLine("[-] Failed to parse bootkey");
                    return;
                }
            }
            else
            {
                sb.AppendLine("[-] Unable to access to SYSTEM dump file");
            }

            RegistryHive sam = RegistryHive.ImportHiveDump(sampath);
            if (sam != null)
            {
                ParseSam(bootKey, sam).ForEach(item => sb.Append(item + Environment.NewLine));
            }
            else
            {
                sb.AppendLine("[-] Unable to access to SAM dump file");
            }

            RegistryHive security = RegistryHive.ImportHiveDump(securitypath);
            if (security != null)
            {
                ParseLsa(security, bootKey, system).ForEach(item => sb.Append(item + Environment.NewLine));
            }
            else
            {
                sb.AppendLine("[-] Unable to access to SECURITY dump file");
            }

            if (machineMasterKeys != null || userMasterKeys != null)
            {
                List<byte[]> dpapikeys = new List<byte[]>();
                foreach (string line in sb.ToString().Split(new string[] { Environment.NewLine }, StringSplitOptions.None).ToList())
                {
                    if (line.Contains("dpapi_machinekey:") || line.Contains("dpapi_userkey:"))
                    {
                        byte[] bytes = Helpers.Misc.HexToByteArray(line.Split(':').Last());
                        dpapikeys.Add(bytes);
                    }
                }
                SharpDPAPI.SharpDPAPI.ParseDpapi(sb, dpapikeys, machineMasterKeys, userMasterKeys, credDirs, vaultDirs, certDirs);
            }
            Console.WriteLine(sb.ToString());
        }
    }
}