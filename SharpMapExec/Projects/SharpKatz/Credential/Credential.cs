//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using System;
using System.Collections.Generic;
using static SharpKatz.Win32.Natives;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace SharpKatz.Credential
{
    internal class Logon
    {
        public LUID LogonId { get; set; }
        public string LogonType { get; set; }
        public int Session { get; set; }
        public FILETIME LogonTime { get; set; }
        public string UserName { get; set; }
        public string LogonDomain { get; set; }
        public string LogonServer { get; set; }
        public string SID { get; set; }

        public Msv Msv { get; set; }
        public WDigest Wdigest { get; set; }
        public List<Ssp> Ssp { get; set; }
        public Tspkg Tspkg { get; set; }
        public Kerberos Kerberos { get; set; }
        public List<CredMan> Credman { get; set; }
        public List<KerberosKey> KerberosKeys { get; set; }

        public IntPtr pCredentials { get; set; }
        public IntPtr pCredentialManager { get; set; }

        public Logon(LUID logonId)
        {
            LogonId = logonId;
        }
    }

    internal class Msv
    {
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Lm { get; set; }
        public string Ntlm { get; set; }
        public string Sha1 { get; set; }
        public string Dpapi { get; set; }

        public Msv()
        {
        }
    }

    internal class Ssp
    {
        public int Reference { get; set; }
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

        public Ssp()
        {
        }
    }

    internal class Tspkg
    {
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

        public Tspkg()
        {
        }
    }

    internal class Kerberos
    {
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

        public Kerberos()
        {
        }
    }

    internal class CredMan
    {
        public int Reference { get; set; }
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

        public CredMan()
        {
        }
    }

    internal class WDigest
    {
        public string HostName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

        public WDigest()
        {
        }
    }

    internal class KerberosKey
    {
        public string Type { get; set; }
        public string Key { get; set; }

        public KerberosKey()
        {
        }
    }
}