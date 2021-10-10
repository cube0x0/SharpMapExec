using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Sockets;
using System.Security;
using System.Text;

namespace SharpMapExec.Helpers
{
    internal class Misc
    {
        public static string Compress(byte[] data)
        {
            using (var compressedStream = new MemoryStream())
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Compress))
            {
                zipStream.Write(data, 0, data.Length);
                zipStream.Close();
                return Convert.ToBase64String(compressedStream.ToArray());
            }
        }

        public static byte[] Decompress(byte[] data)
        {
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {
                zipStream.CopyTo(resultStream);
                return resultStream.ToArray();
            }
        }

        public static bool CheckHostPort(string hostname, int port, int PortScanTimeout = 2000)
        {
            using (var client = new TcpClient())
            {
                try
                {
                    var result = client.BeginConnect(hostname, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(PortScanTimeout);
                    if (!success) return false;
                    client.EndConnect(result);
                }
                catch
                {
                    return false;
                }
                return true;
            }
        }

        public static string CompressData(string data)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(data);
            using (var msi = new MemoryStream(bytes))
            using (var mso = new MemoryStream())
            {
                using (var gs = new GZipStream(mso, CompressionMode.Compress))
                {
                    msi.CopyTo(gs);
                }
                return Convert.ToBase64String(mso.ToArray());
            }
        }

        public static void PrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("new byte[] { ");
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("}");
            Console.WriteLine(sb.ToString());
        }

        public static byte[] HexToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static SecureString CreateSecuredString(string pw)
        {
            SecureString secureString = new SecureString();
            if (string.IsNullOrEmpty(pw))
                return null;
            foreach (char c in pw)
                secureString.AppendChar(c);
            return secureString;
        }
    }
}