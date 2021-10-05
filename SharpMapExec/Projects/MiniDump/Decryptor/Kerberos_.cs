using Minidump.Crypto;
using Minidump.Templates;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Minidump.Helpers;

namespace Minidump.Decryptor
{
    internal class Kerberos_
    {
        public static void FindCredentials(Program.MiniDump minidump, kerberos.KerberosTemplate template)
        {
            foreach (KerberosSessions.KerberosLogonItem entry in minidump.klogonlist)
            {
                if (entry == null)
                    continue;

                var luid = ReadStruct<LUID>(GetBytes(entry.LogonSessionBytes, 72, Marshal.SizeOf(typeof(LUID))));

                var usUserName = ReadStruct<UNICODE_STRING>(GetBytes(entry.LogonSessionBytes, template.SessionCredentialOffset + template.SessionUserNameOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));
                var usDomain = ReadStruct<UNICODE_STRING>(GetBytes(entry.LogonSessionBytes, template.SessionCredentialOffset + template.SessionDomainOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));
                var usPassword = ReadStruct<UNICODE_STRING>(GetBytes(entry.LogonSessionBytes, template.SessionCredentialOffset + template.SessionPasswordOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));

                var username = ExtractUnicodeStringString(minidump, usUserName);
                var domain = ExtractUnicodeStringString(minidump, usDomain);

                minidump.fileBinaryReader.BaseStream.Seek(Rva2offset(minidump, usPassword.Buffer), 0);
                byte[] msvPasswordBytes = minidump.fileBinaryReader.ReadBytes(usPassword.MaximumLength);

                var msvDecryptedPasswordBytes = BCrypt.DecryptCredentials(msvPasswordBytes, minidump.lsakeys);

                var passDecrypted = "";
                var encoder = new UnicodeEncoding(false, false, true);
                try
                {
                    passDecrypted = encoder.GetString(msvDecryptedPasswordBytes);
                }
                catch (Exception)
                {
                    passDecrypted = PrintHexBytes(msvDecryptedPasswordBytes);
                }
                //passDecrypted = Convert.ToBase64String(msvDecryptedPasswordBytes);

                if (!string.IsNullOrEmpty(username) && username.Length > 1)
                {
                    if (msvDecryptedPasswordBytes.Length <= 1)
                        continue;

                    var krbrentry = new Kerberos();
                    krbrentry.UserName = username;

                    if (krbrentry.UserName.Contains("$"))
                    {
                        try
                        {
                            krbrentry.NT = msvDecryptedPasswordBytes.MD4().AsHexString();
                        }
                        catch
                        {
                            krbrentry.NT = "NULL";
                        }
                    }

                    if (!string.IsNullOrEmpty(domain))
                        krbrentry.DomainName = domain;
                    else
                        krbrentry.DomainName = "NULL";

                    if (!string.IsNullOrEmpty(passDecrypted))
                        krbrentry.Password = passDecrypted;
                    else
                        krbrentry.Password = "NULL";

                    var currentlogon = minidump.logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                    if (currentlogon == null)
                    {
                        currentlogon = new Logon(luid);
                        currentlogon.UserName = username;
                        currentlogon.Kerberos = krbrentry;
                        minidump.logonlist.Add(currentlogon);
                    }
                    else
                    {
                        currentlogon.Kerberos = krbrentry;
                    }
                }
            }
        }
    }
}