using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;

namespace SharpMapExec.Lib
{
    public class Smb2Protocol
    {
        public enum SBM2_Command
        {
            SMB2_NEGOTIATE = 0,
            SMB2_SESSION_SETUP = 1,
            SMB2_TREE_CONNECT = 3,
            SMB2_IOCTL = 0x000B,
        }

        private static byte[] mechTypes = new byte[] { 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, };

        public const uint STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016;

        // https://msdn.microsoft.com/en-us/library/cc246529.aspx
        [StructLayout(LayoutKind.Explicit)]
        public struct SMB2_Header
        {
            [FieldOffset(0)]
            public UInt32 ProtocolId;

            [FieldOffset(4)]
            public UInt16 StructureSize;

            [FieldOffset(6)]
            public UInt16 CreditCharge;

            [FieldOffset(8)]
            public UInt32 Status; // to do SMB3

            [FieldOffset(12)]
            public UInt16 Command;

            [FieldOffset(14)]
            public UInt16 CreditRequest_Response;

            [FieldOffset(16)]
            public UInt32 Flags;

            [FieldOffset(20)]
            public UInt32 NextCommand;

            [FieldOffset(24)]
            public UInt64 MessageId;

            [FieldOffset(32)]
            public UInt32 Reserved;

            [FieldOffset(36)]
            public UInt32 TreeId;

            [FieldOffset(40)]
            public UInt64 SessionId;

            [FieldOffset(48)]
            public UInt64 Signature1;

            [FieldOffset(56)]
            public UInt64 Signature2;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_NegotiateRequest
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;

            [FieldOffset(2)]
            public UInt16 DialectCount;

            [FieldOffset(4)]
            public UInt16 SecurityMode;

            [FieldOffset(6)]
            public UInt16 Reserved;

            [FieldOffset(8)]
            public UInt32 Capabilities;

            [FieldOffset(12)]
            public Guid ClientGuid;

            [FieldOffset(28)]
            public UInt64 ClientStartTime;

            [FieldOffset(36)]
            public UInt16 DialectToTest;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_NegotiateResponse
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;

            [FieldOffset(2)]
            public byte SecurityMode;

            [FieldOffset(3)]
            public UInt16 Dialect;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_SessionSetupResponse
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;

            [FieldOffset(2)]
            public UInt16 SessionFlags;

            [FieldOffset(4)]
            public UInt16 SecurityBufferOffset;

            [FieldOffset(6)]
            public UInt16 SecurityBufferLength;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_SessionSetup
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;

            [FieldOffset(2)]
            public byte Flags;

            [FieldOffset(3)]
            public byte SecurityMode;

            [FieldOffset(4)]
            public UInt32 Capabilities;

            [FieldOffset(8)]
            public UInt32 Channel;

            [FieldOffset(12)]
            public UInt16 SecurityBufferOffset;

            [FieldOffset(14)]
            public UInt16 SecurityBufferLength;

            [FieldOffset(16)]
            public UInt64 PreviousSessionId;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_TreeConnect
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;

            [FieldOffset(2)]
            public UInt16 Flags;

            [FieldOffset(4)]
            public UInt16 PathOffset;

            [FieldOffset(6)]
            public UInt16 PathLength;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_TreeConnectResponse
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;

            [FieldOffset(2)]
            public byte ShareType;

            [FieldOffset(4)]
            public UInt32 ShareFlags;

            [FieldOffset(8)]
            public UInt32 Capabilities;

            [FieldOffset(12)]
            public UInt32 MaximalAccess;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_IOCTLRequest
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;

            [FieldOffset(4)]
            public UInt32 CtlCode;

            [FieldOffset(8)]
            public Guid FileId;

            [FieldOffset(24)]
            public UInt32 InputOffset;

            [FieldOffset(28)]
            public UInt32 InputCount;

            [FieldOffset(32)]
            public UInt32 MaxInputResponse;

            [FieldOffset(36)]
            public UInt32 OutputOffset;

            [FieldOffset(40)]
            public UInt32 OutputCount;

            [FieldOffset(44)]
            public UInt32 MaxOutputResponse;

            [FieldOffset(48)]
            public UInt32 Flags;

            [FieldOffset(52)]
            public UInt32 Reserved2;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
        public struct SMB2_IOCTLResponse
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;

            [FieldOffset(4)]
            public UInt32 CtlCode;

            [FieldOffset(8)]
            public Guid FileId;

            [FieldOffset(24)]
            public UInt32 InputOffset;

            [FieldOffset(28)]
            public UInt32 InputCount;

            [FieldOffset(32)]
            public UInt32 OutputOffset;

            [FieldOffset(36)]
            public UInt32 OutputCount;

            [FieldOffset(40)]
            public UInt32 Flags;

            [FieldOffset(44)]
            public UInt32 Reserved2;
        }

        [Flags]
        public enum SMB2_NETWORK_INTERFACE_INFO_Capability : uint
        {
            None = 0,
            RSS_CAPABLE = 1,
            RDMA_CAPABLE = 2,
        }

        public struct SMB2_NETWORK_INTERFACE_INFO
        {
            public int Next;
            public UInt32 IfIndex;
            public SMB2_NETWORK_INTERFACE_INFO_Capability Capability;
            public UInt32 Reserved;
            public UInt64 LinkSpeed;
            public UInt16 SockAddr_Storage_Family;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
            public byte[] SockAddr_Storage_Buffer;
        }

        public class NetworkInfo
        {
            public SMB2_NETWORK_INTERFACE_INFO_Capability Capability { get; set; }
            public ulong LinkSpeed { get; set; }
            public IPAddress IP { get; set; }

            public uint Index { get; set; }
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public byte[] GenerateSmb2HeaderFromCommand(SBM2_Command command)
        {
            SMB2_Header header = new SMB2_Header();
            header.ProtocolId = 0x424D53FE;
            header.Command = (byte)command;
            header.StructureSize = 64;
            header.MessageId = _messageId++;
            header.Reserved = 0xFEFF;
            header.SessionId = _sessionid;
            header.TreeId = _TreeId;
            return getBytes(header);
        }

        public static byte[] getBytes(object structure)
        {
            int size = Marshal.SizeOf(structure);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(structure, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        // MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static byte[] GetNegotiateMessageSmbv2(int DialectToTest)
        {
            SMB2_NegotiateRequest request = new SMB2_NegotiateRequest();
            request.StructureSize = 36;
            request.DialectCount = 1;
            request.SecurityMode = 1; // signing enabled
            request.ClientGuid = Guid.NewGuid();
            request.DialectToTest = (UInt16)DialectToTest;
            request.Capabilities = 1; //DFS
            return getBytes(request);
        }

        // MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static byte[] GetSessionSetupMessageSmbv2(int securityBufferLength)
        {
            var request = new SMB2_SessionSetup();
            request.StructureSize = 25;
            request.Flags = 0;
            request.SecurityMode = 1; // signing enabled
            request.Capabilities = 1; //DFS
            request.Channel = 0;
            request.PreviousSessionId = 0;
            request.SecurityBufferLength = (ushort)securityBufferLength;
            request.SecurityBufferOffset = (ushort)(Marshal.SizeOf(typeof(SMB2_SessionSetup)) + Marshal.SizeOf(typeof(SMB2_Header)));
            return getBytes(request);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static byte[] GetTreeConnectMessageSmbv2(int targetlen)
        {
            var request = new SMB2_TreeConnect();
            request.StructureSize = 9;
            request.Flags = 0;
            request.PathOffset = (ushort)(Marshal.SizeOf(typeof(SMB2_Header)) + Marshal.SizeOf(typeof(SMB2_TreeConnect)));
            request.PathLength = (ushort)(targetlen * 2);
            return getBytes(request);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static byte[] GetIOCTLRequest(uint CTLCode, bool IsFSCTL)
        {
            var request = new SMB2_IOCTLRequest();
            request.StructureSize = 57;
            request.CtlCode = CTLCode;
            request.FileId = new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff");
            request.InputOffset = (uint)(Marshal.SizeOf(typeof(SMB2_Header)) + Marshal.SizeOf(typeof(SMB2_IOCTLRequest)));
            request.OutputOffset = request.InputOffset;
            request.MaxOutputResponse = 0x10000;
            request.MaxInputResponse = 0;
            request.Flags = (uint)(IsFSCTL ? 1 : 0);
            return getBytes(request);
        }

        public static byte[] GetGSSSpNegoToken(int NTLMTokenLen)
        {
            // brutal ASN1 encoding - use https://lapo.it/asn1js to verify it
            return new byte[]
            {
                0x60, (byte) (NTLMTokenLen + 32),
                    0x06, 0x06,
                        0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
                    0xa0, (byte) (NTLMTokenLen + 22),
                        0x30, (byte) (NTLMTokenLen + 20),
                            0xa0, 0x0e,
                                0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
                            0xa2, (byte) (NTLMTokenLen + 2),
                                0x04, (byte) NTLMTokenLen
            };
        }

        public static byte[] GetGSSSpNegoToken2(int NTLMTokenLen, int MIClen)
        {
            // brutal ASN1 encoding - use https://lapo.it/asn1js to verify it
            return new byte[]
            {
                0xa1,0x82,HighByte(NTLMTokenLen+17+MIClen),LowByte(NTLMTokenLen+17+MIClen),
                    0x30,0x82,HighByte(NTLMTokenLen+13+MIClen),LowByte(NTLMTokenLen+13+MIClen),
                        0xa0,0x03,0x0a,0x01,0x01,
                        0xa2,0x82,HighByte(NTLMTokenLen+4),LowByte(NTLMTokenLen+4),
                            0x04,0x82,HighByte(NTLMTokenLen),LowByte(NTLMTokenLen)
            };
        }

        private static byte LowByte(int size)
        {
            return (byte)(size % 0x100);
        }

        private static byte HighByte(int size)
        {
            return (byte)(size / 0x100);
        }

        private static byte[] AESEncrypt(byte[] key, byte[] iv, byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                var aes = Rijndael.Create();

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }

        private static byte[] Rol(byte[] b)
        {
            byte[] r = new byte[b.Length];
            byte carry = 0;

            for (int i = b.Length - 1; i >= 0; i--)
            {
                ushort u = (ushort)(b[i] << 1);
                r[i] = (byte)((u & 0xff) + carry);
                carry = (byte)((u & 0xff00) >> 8);
            }

            return r;
        }

        private byte[] AESCMAC(byte[] key, byte[] data)
        {
            // SubKey generation
            // step 1, AES-128 with key K is applied to an all-zero input block.
            byte[] L = AESEncrypt(key, new byte[16], new byte[16]);

            // step 2, K1 is derived through the following operation:
            byte[] FirstSubkey = Rol(L); //If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
            if ((L[0] & 0x80) == 0x80)
                FirstSubkey[15] ^= 0x87; // Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.

            // step 3, K2 is derived through the following operation:
            byte[] SecondSubkey = Rol(FirstSubkey); // If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
            if ((FirstSubkey[0] & 0x80) == 0x80)
                SecondSubkey[15] ^= 0x87; // Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

            byte[] d = new byte[((int)data.Length / 16) * 16];
            Array.Copy(data, d, data.Length);

            // MAC computing
            if (((data.Length != 0) && (data.Length % 16 == 0)) == true)
            {
                // If the size of the input message block is equal to a positive multiple of the block size (namely, 128 bits),
                // the last block shall be exclusive-OR'ed with K1 before processing
                for (int j = 0; j < FirstSubkey.Length; j++)
                    d[d.Length - 16 + j] ^= FirstSubkey[j];
            }
            else
            {
                // Otherwise, the last block shall be padded with 10^i

                d[data.Length] = 0x80;

                for (int i = 1; i < 16 - data.Length % 16; i++)
                {
                    d[data.Length + i] = 0;
                }

                // and exclusive-OR'ed with K2
                for (int j = 0; j < SecondSubkey.Length; j++)
                    d[d.Length - 16 + j] ^= SecondSubkey[j];
            }

            // The result of the previous process will be the input of the last encryption.
            byte[] encResult = AESEncrypt(key, new byte[16], d);

            byte[] HashValue = new byte[16];
            Array.Copy(encResult, encResult.Length - HashValue.Length, HashValue, 0, HashValue.Length);

            return HashValue;
        }

        public byte[] BuildNegotiatePacket(int dialect)
        {
            byte[] header = GenerateSmb2HeaderFromCommand(SBM2_Command.SMB2_NEGOTIATE);
            byte[] negotiatemessage = GetNegotiateMessageSmbv2(dialect);
            return BuildPacket(header, negotiatemessage);
        }

        public byte[] BuildSessionSetupPacket(byte[] NTLMSSPMessage, byte[] MIC)
        {
            int MIClen = (MIC == null ? 0 : MIC.Length + 4);
            byte[] header = GenerateSmb2HeaderFromCommand(SBM2_Command.SMB2_SESSION_SETUP);
            byte[] SpNegoToken = _sessionid == 0 ? GetGSSSpNegoToken(NTLMSSPMessage.Length)
                : GetGSSSpNegoToken2(NTLMSSPMessage.Length, MIClen);
            byte[] message = GetSessionSetupMessageSmbv2(SpNegoToken.Length + NTLMSSPMessage.Length + MIClen);
            byte[] MICPrefix = null;
            if (MIC != null)
            {
                MICPrefix = new byte[] { 0xA3, LowByte(MIC.Length + 2), 0x04, LowByte(MIC.Length) };
            }
            return BuildPacket(header, message, SpNegoToken, NTLMSSPMessage, MICPrefix, MIC);
        }

        public byte[] BuildTreeConnectPacket(string target)
        {
            byte[] header = GenerateSmb2HeaderFromCommand(SBM2_Command.SMB2_TREE_CONNECT);
            byte[] data = Encoding.Unicode.GetBytes(target);
            byte[] message = GetTreeConnectMessageSmbv2(target.Length);
            return BuildPacket(header, message, data);
        }

        public byte[] BuildIOCTLRequestPacket(uint CTLCode, bool IsFSCTL)
        {
            byte[] header = GenerateSmb2HeaderFromCommand(SBM2_Command.SMB2_IOCTL);
            byte[] message = GetIOCTLRequest(CTLCode, IsFSCTL);
            return BuildPacket(header, message);
        }

        public byte[] ReadPacket()
        {
            byte[] netbios = new byte[4];
            if (_stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                throw new Exception("");
            int size = netbios[0] << 24 | netbios[1] << 16 | netbios[2] << 8 | netbios[3] << 0;
            byte[] output = new byte[size];
            _stream.Read(output, 0, size);
            return output;
        }

        private SMB2_Header ReadSMB2Header(byte[] packet)
        {
            GCHandle handle = GCHandle.Alloc(packet, GCHandleType.Pinned);
            SMB2_Header header = (SMB2_Header)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(SMB2_Header));
            handle.Free();
            return header;
        }

        public static T ReadResponse<T>(byte[] packet) where T : struct
        {
            GCHandle handle = GCHandle.Alloc(packet, GCHandleType.Pinned);
            T header = (T)Marshal.PtrToStructure(new IntPtr(handle.AddrOfPinnedObject().ToInt64() + Marshal.SizeOf(typeof(SMB2_Header))), typeof(T));
            handle.Free();
            return header;
        }

        public static byte[] BuildPacket(params byte[][] bytes)
        {
            int size = 0;
            foreach (var array in bytes)
            {
                if (array == null)
                    continue;
                size += array.Length;
            }
            byte[] output = new byte[size + 4];
            var byteSize = BitConverter.GetBytes(size);
            output[0] = byteSize[3];
            output[1] = byteSize[2];
            output[2] = byteSize[1];
            output[3] = byteSize[0];
            int offset = 4;
            foreach (var array in bytes)
            {
                if (array == null)
                    continue;
                Array.Copy(array, 0, output, offset, array.Length);
                offset += array.Length;
            }
            return output;
        }

        public static byte[] ExtractSSP(byte[] answer, SMB2_SessionSetupResponse sessionSetupResponse)
        {
            int offset;
            for (offset = sessionSetupResponse.SecurityBufferOffset;
                offset + 4 < sessionSetupResponse.SecurityBufferLength - sessionSetupResponse.SecurityBufferOffset;
                offset++)
            {
                if (answer[offset] == 0x4e
                    && answer[offset + 1] == 0x54
                    && answer[offset + 2] == 0x4c
                    && answer[offset + 3] == 0x4d
                    && answer[offset + 4] == 0x53
                    && answer[offset + 5] == 0x53
                    && answer[offset + 6] == 0x50
                    && answer[offset + 7] == 0x00)
                {
                    offset = offset - sessionSetupResponse.SecurityBufferOffset;
                    var NegoPacket2 = new byte[sessionSetupResponse.SecurityBufferLength - offset];
                    Array.Copy(answer, sessionSetupResponse.SecurityBufferOffset + offset, NegoPacket2, 0, sessionSetupResponse.SecurityBufferLength - offset);
                    return NegoPacket2;
                }
            }
            throw new ApplicationException("SSP answer not found");
        }

        private void SendPacket(byte[] packet)
        {
            _stream.Write(packet, 0, packet.Length);
            _stream.Flush();
        }

        private Stream _stream;
        private string _server;

        private ulong _sessionid = 0;
        private ulong _messageId = 0;
        private byte[] sessionkey;
        private uint _TreeId;

        public Smb2Protocol(Stream stream, string server)
        {
            _stream = stream;
            _server = server;
        }

        public SMB2_NegotiateResponse SendNegotiateRequest(int dialect)
        {
            byte[] packet = BuildNegotiatePacket(dialect);
            _stream.Write(packet, 0, packet.Length);
            _stream.Flush();
            Trace.WriteLine("Negotiate Packet sent");

            byte[] answer = ReadPacket();
            Trace.WriteLine("Negotiate Packet received");
            var header = ReadSMB2Header(answer);

            if (header.Status != 0)
            {
                Trace.WriteLine("Checking " + _server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
                throw new Win32Exception((int)header.Status);
            }

            return ReadResponse<SMB2_NegotiateResponse>(answer);
        }

        //public SMB2_SessionSetupResponse SendSessionSetupRequests(NetworkCredential optionalCredential = null)
        //{
        //    SSPIHelper MyHelper = new SSPIHelper(_server);
        //    if (optionalCredential != null)
        //    {
        //        MyHelper.LoginClient(optionalCredential);
        //    }
        //    byte[] ServerSSPIPacket = null;
        //    byte[] ClientSSPIPacket;
        //    byte[] MIC = null;
        //    bool bContinueProcessing = true;
        //    while (bContinueProcessing)
        //    {
        //        MyHelper.InitializeClient(out ClientSSPIPacket, ServerSSPIPacket, out bContinueProcessing);
        //        if (!bContinueProcessing)
        //        {
        //            byte[] temp;
        //            MyHelper.SignMessage(mechTypes, out temp);
        //            MIC = new byte[temp.Length - mechTypes.Length];
        //            Array.Copy(temp, mechTypes.Length, MIC, 0, temp.Length - mechTypes.Length);
        //            sessionkey = MyHelper.GetSessionKey();
        //        }
        //        var packet = BuildSessionSetupPacket(ClientSSPIPacket, MIC);
        //        SendPacket(packet);
        //
        //        Trace.WriteLine("SessionSetup Packet sent");
        //        var answer = ReadPacket();
        //        var header = ReadSMB2Header(answer);
        //        Trace.WriteLine("SessionSetup Packet received");
        //        if (header.Status == 0)
        //        {
        //            return ReadResponse<SMB2_SessionSetupResponse>(answer);
        //        }
        //        if (header.Status != STATUS_MORE_PROCESSING_REQUIRED)
        //        {
        //            Trace.WriteLine("Checking " + _server + "Error " + header.Status);
        //            throw new Win32Exception((int)header.Status);
        //        }
        //        if (!bContinueProcessing)
        //        {
        //            Trace.WriteLine("Checking " + _server + "Error " + header.Status + " when no processing needed");
        //            throw new Win32Exception((int)header.Status, "Unexpected SessionSetup error");
        //        }
        //
        //        var sessionSetupResponse = ReadResponse<SMB2_SessionSetupResponse>(answer);
        //
        //        _sessionid = header.SessionId;
        //        // extract SSP answer from GSSPAPI answer
        //        ServerSSPIPacket = ExtractSSP(answer, sessionSetupResponse);
        //    }
        //    throw new NotImplementedException("Not supposed to be here");
        //}

        public SMB2_TreeConnectResponse SendTreeConnect(string target)
        {
            var packet = BuildTreeConnectPacket(target);
            SendPacket(packet);

            Trace.WriteLine("TreeConnect Packet sent");
            var answer = ReadPacket();
            var header = ReadSMB2Header(answer);
            Trace.WriteLine("TreeConnect Packet received");
            if (header.Status != 0)
            {
                Trace.WriteLine("Checking " + _server + "Error " + header.Status);
                throw new Win32Exception((int)header.Status);
            }
            var r = ReadResponse<SMB2_TreeConnectResponse>(answer);
            _TreeId = header.TreeId;
            return r;
        }

        public byte[] SendIOCTLRequest(uint CTLCode, bool IsFSCTL)
        {
            var packet = BuildIOCTLRequestPacket(CTLCode, IsFSCTL);
            SendPacket(packet);

            Trace.WriteLine("IOCTLRequest Packet sent");
            var answer = ReadPacket();
            var header = ReadSMB2Header(answer);
            Trace.WriteLine("IOCTLRequest Packet received");
            if (header.Status != 0)
            {
                Trace.WriteLine("Checking " + _server + "Error " + header.Status);
                throw new Win32Exception((int)header.Status);
            }
            var response = ReadResponse<SMB2_IOCTLResponse>(answer);
            if (response.OutputCount == 0)
                return null;
            var output = new byte[response.OutputCount];
            Array.Copy(answer, response.OutputOffset, output, 0, response.OutputCount);
            return output;
        }

        public List<NetworkInfo> GetNetworkInterfaceInfo()
        {
            var output = new List<NetworkInfo>();
            var o = SendIOCTLRequest(0x001401FC, true);

            int size = Marshal.SizeOf(typeof(SMB2_NETWORK_INTERFACE_INFO));
            int offset = 0;
            do
            {
                IntPtr pt = Marshal.AllocHGlobal(size);
                Marshal.Copy(o, offset, pt, size);
                var n = (SMB2_NETWORK_INTERFACE_INFO)Marshal.PtrToStructure(pt, typeof(SMB2_NETWORK_INTERFACE_INFO));

                var ni = new NetworkInfo();
                ni.Index = n.IfIndex;
                ni.Capability = n.Capability;
                ni.LinkSpeed = n.LinkSpeed;
                if (n.SockAddr_Storage_Family == 0x2)
                {
                    var t = new byte[4];
                    Array.Copy(o, offset + Marshal.OffsetOf(typeof(SMB2_NETWORK_INTERFACE_INFO), "SockAddr_Storage_Buffer").ToInt32() + 2, t, 0, t.Length);
                    ni.IP = new IPAddress(t);
                }
                else if (n.SockAddr_Storage_Family == 0x17)
                {
                    var t = new byte[16];
                    Array.Copy(o, offset + Marshal.OffsetOf(typeof(SMB2_NETWORK_INTERFACE_INFO), "SockAddr_Storage_Buffer").ToInt32() + 6, t, 0, t.Length);
                    ni.IP = new IPAddress(t);
                }
                else throw new NotImplementedException("SockAddr_Storage_Family unknown: " + n.SockAddr_Storage_Family);

                output.Add(ni);
                Marshal.FreeHGlobal(pt);

                if (n.Next == 0)
                    break;

                offset += n.Next;
            } while (offset != 0);
            return output;
        }
    }

    public class Smb
    {
        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(
            StringBuilder ServerName,
            int level,
            ref IntPtr bufPtr,
            uint prefmaxlen,
            ref int entriesread,
            ref int totalentries,
            ref int resume_handle
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;

            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }

            public override string ToString()
            {
                return shi1_netname;
            }
        }

        private const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
        private const int NERR_Success = 0;

        private enum NetError : uint
        {
            NERR_Success = 0,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23),
        }

        private enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct SMB_Header
        {
            [FieldOffset(0)]
            public UInt32 Protocol;

            [FieldOffset(4)]
            public byte Command;

            [FieldOffset(5)]
            public int Status;

            [FieldOffset(9)]
            public byte Flags;

            [FieldOffset(10)]
            public UInt16 Flags2;

            [FieldOffset(12)]
            public UInt16 PIDHigh;

            [FieldOffset(14)]
            public UInt64 SecurityFeatures;

            [FieldOffset(22)]
            public UInt16 Reserved;

            [FieldOffset(24)]
            public UInt16 TID;

            [FieldOffset(26)]
            public UInt16 PIDLow;

            [FieldOffset(28)]
            public UInt16 UID;

            [FieldOffset(30)]
            public UInt16 MID;
        };

        // https://msdn.microsoft.com/en-us/library/cc246529.aspx
        [StructLayout(LayoutKind.Explicit)]
        private struct SMB2_Header
        {
            [FieldOffset(0)]
            public UInt32 ProtocolId;

            [FieldOffset(4)]
            public UInt16 StructureSize;

            [FieldOffset(6)]
            public UInt16 CreditCharge;

            [FieldOffset(8)]
            public UInt32 Status; // to do SMB3

            [FieldOffset(12)]
            public UInt16 Command;

            [FieldOffset(14)]
            public UInt16 CreditRequest_Response;

            [FieldOffset(16)]
            public UInt32 Flags;

            [FieldOffset(20)]
            public UInt32 NextCommand;

            [FieldOffset(24)]
            public UInt64 MessageId;

            [FieldOffset(32)]
            public UInt32 Reserved;

            [FieldOffset(36)]
            public UInt32 TreeId;

            [FieldOffset(40)]
            public UInt64 SessionId;

            [FieldOffset(48)]
            public UInt64 Signature1;

            [FieldOffset(56)]
            public UInt64 Signature2;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct SMB2_NegotiateRequest
        {
            [FieldOffset(0)]
            public UInt16 StructureSize;

            [FieldOffset(2)]
            public UInt16 DialectCount;

            [FieldOffset(4)]
            public UInt16 SecurityMode;

            [FieldOffset(6)]
            public UInt16 Reserved;

            [FieldOffset(8)]
            public UInt32 Capabilities;

            [FieldOffset(12)]
            public Guid ClientGuid;

            [FieldOffset(28)]
            public UInt64 ClientStartTime;

            [FieldOffset(36)]
            public UInt16 DialectToTest;
        }

        private const int SMB_COM_NEGOTIATE = 0x72;
        private const int SMB2_NEGOTIATE = 0;
        private const int SMB_FLAGS_CASE_INSENSITIVE = 0x08;
        private const int SMB_FLAGS_CANONICALIZED_PATHS = 0x10;
        private const int SMB_FLAGS2_LONG_NAMES = 0x0001;
        private const int SMB_FLAGS2_EAS = 0x0002;
        private const int SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED = 0x0010;
        private const int SMB_FLAGS2_IS_LONG_NAME = 0x0040;
        private const int SMB_FLAGS2_ESS = 0x0800;
        private const int SMB_FLAGS2_NT_STATUS = 0x4000;
        private const int SMB_FLAGS2_UNICODE = 0x8000;
        private const int SMB_DB_FORMAT_DIALECT = 0x02;

        private static byte[] GenerateSmbHeaderFromCommand(byte command)
        {
            SMB_Header header = new SMB_Header();
            header.Protocol = 0x424D53FF;
            header.Command = command;
            header.Status = 0;
            header.Flags = SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS;
            header.Flags2 = SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EAS | SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_ESS | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE;
            header.PIDHigh = 0;
            header.SecurityFeatures = 0;
            header.Reserved = 0;
            header.TID = 0xffff;
            header.PIDLow = 0xFEFF;
            header.UID = 0;
            header.MID = 0;
            return getBytes(header);
        }

        private static byte[] getBytes(object structure)
        {
            int size = Marshal.SizeOf(structure);
            byte[] arr = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(structure, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        private static byte[] getDialect(string dialect)
        {
            byte[] dialectBytes = Encoding.ASCII.GetBytes(dialect);
            byte[] output = new byte[dialectBytes.Length + 2];
            output[0] = 2;
            output[output.Length - 1] = 0;
            Array.Copy(dialectBytes, 0, output, 1, dialectBytes.Length);
            return output;
        }

        private static byte[] GetNegotiateMessage(byte[] dialect)
        {
            byte[] output = new byte[dialect.Length + 3];
            output[0] = 0;
            output[1] = (byte)dialect.Length;
            output[2] = 0;
            Array.Copy(dialect, 0, output, 3, dialect.Length);
            return output;
        }


        private static byte[] GetNegotiatePacket(byte[] header, byte[] smbPacket)
        {
            byte[] output = new byte[smbPacket.Length + header.Length + 4];
            output[0] = 0;
            output[1] = 0;
            output[2] = 0;
            output[3] = (byte)(smbPacket.Length + header.Length);
            Array.Copy(header, 0, output, 4, header.Length);
            Array.Copy(smbPacket, 0, output, 4 + header.Length, smbPacket.Length);
            return output;
        }

        public static bool DoesServerSupportDialect(string server, string dialect)
        {
            Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect);
            TcpClient client = new TcpClient();
            try
            {
                client.Connect(server, 445);
            }
            catch (Exception)
            {
                throw new Exception("port 445 is closed on " + server);
            }
            try
            {
                NetworkStream stream = client.GetStream();
                byte[] header = GenerateSmbHeaderFromCommand(SMB_COM_NEGOTIATE);
                byte[] dialectEncoding = getDialect(dialect);
                byte[] negotiatemessage = GetNegotiateMessage(dialectEncoding);
                byte[] packet = GetNegotiatePacket(header, negotiatemessage);
                stream.Write(packet, 0, packet.Length);
                stream.Flush();
                byte[] netbios = new byte[4];
                if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
                byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB_Header))];
                if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
                byte[] negotiateresponse = new byte[3];
                if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
                if (negotiateresponse[1] == 0 && negotiateresponse[2] == 0)
                {
                    Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Supported");
                    return true;
                }
                Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Not supported");
                return false;
            }
            catch (Exception)
            {
                throw new ApplicationException("Smb1 is not supported on " + server);
            }
        }

        public static bool DoesServerSupportDialect(string server, string dialect, out SMBSecurityModeEnum securityMode)
        {
            Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect);
            securityMode = SMBSecurityModeEnum.NotTested;
            TcpClient client = new TcpClient();
            client.ReceiveTimeout = 500;
            client.SendTimeout = 500;
            try
            {
                client.Connect(server, 445);
            }
            catch (Exception)
            {
                //throw new SmbPortClosedException(server);
            }
            try
            {
                NetworkStream stream = client.GetStream();
                byte[] header = GenerateSmbHeaderFromCommand(SMB_COM_NEGOTIATE);
                byte[] dialectEncoding = getDialect(dialect);
                byte[] negotiatemessage = GetNegotiateMessage(dialectEncoding);
                byte[] packet = GetNegotiatePacket(header, negotiatemessage);
                stream.Write(packet, 0, packet.Length);
                stream.Flush();
                byte[] netbios = new byte[4];
                if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
                byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB_Header))];
                if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
                byte[] negotiateresponse = new byte[4];
                if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
                if (negotiateresponse[1] == 0 && negotiateresponse[2] == 0)
                {
                    Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Supported");
                    byte SmbSecurityMode = negotiateresponse[3];
                    if (SmbSecurityMode == 4)
                    {
                        securityMode = SMBSecurityModeEnum.SmbSigningEnabled;
                    }
                    else if (SmbSecurityMode == 8)
                    {
                        securityMode = SMBSecurityModeEnum.SmbSigningEnabled | SMBSecurityModeEnum.SmbSigningRequired;
                    }
                    else
                    {
                        securityMode = SMBSecurityModeEnum.None;
                    }
                    return true;
                }
                Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Not supported");
                return false;
            }
            catch (Exception)
            {
                //throw new Smb1NotSupportedException(server);
                return false;
            }
        }

        public static bool DoesServerSupportDialectWithSmbV2(string server, int dialect, out SMBSecurityModeEnum securityMode)
        {
            Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2"));
            securityMode = SMBSecurityModeEnum.NotTested;
            TcpClient client = new TcpClient();
            client.ReceiveTimeout = 500;
            client.SendTimeout = 500;
            try
            {
                client.Connect(server, 445);
            }
            catch (Exception)
            {
                //throw new SmbPortClosedException(server);
            }
            try
            {
                NetworkStream stream = client.GetStream();

                var smb2 = new Smb2Protocol(stream, server);

                var negotiateresponse = smb2.SendNegotiateRequest(dialect);
                if ((negotiateresponse.SecurityMode & 1) != 0)
                {
                    securityMode = SMBSecurityModeEnum.SmbSigningEnabled;

                    if ((negotiateresponse.SecurityMode & 2) != 0)
                    {
                        securityMode |= SMBSecurityModeEnum.SmbSigningRequired;
                    }
                }
                else
                {
                    securityMode = SMBSecurityModeEnum.None;
                }

                Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Supported");
                return true;
            }
            catch (Exception)
            {
                //throw new Smb2NotSupportedException(server);
                return false;
            }
        }

        [Flags]
        public enum SMBSecurityModeEnum
        {
            NotTested = 0,
            None = 1,
            SmbSigningEnabled = 2,
            SmbSigningRequired = 4,
        }

        private static SMBSecurityModeEnum CombineSecurityMode(SMBSecurityModeEnum smbv2secmode, SMBSecurityModeEnum smbv2temp)
        {
            if (smbv2temp == SMBSecurityModeEnum.NotTested)
                return smbv2secmode;
            if (smbv2secmode == SMBSecurityModeEnum.NotTested)
                return smbv2temp;
            if (smbv2temp == SMBSecurityModeEnum.None || smbv2secmode == SMBSecurityModeEnum.None)
                return SMBSecurityModeEnum.None;
            if ((smbv2temp & SMBSecurityModeEnum.SmbSigningEnabled) != 0 && (smbv2secmode & SMBSecurityModeEnum.SmbSigningEnabled) != 0)
            {
                if ((smbv2temp & SMBSecurityModeEnum.SmbSigningRequired) != 0 && (smbv2secmode & SMBSecurityModeEnum.SmbSigningRequired) != 0)
                {
                    return SMBSecurityModeEnum.SmbSigningEnabled | SMBSecurityModeEnum.SmbSigningRequired;
                }
                return SMBSecurityModeEnum.SmbSigningEnabled;
            }
            // defensive programming
            return SMBSecurityModeEnum.NotTested;
        }

        public static void CheckSMBVersion(string computer)
        {
            bool isPortOpened = true;
            bool SMBv1 = false;
            bool SMBv2_0x0202 = false;
            bool SMBv2_0x0210 = false;
            bool SMBv2_0x0300 = false;
            bool SMBv2_0x0302 = false;
            bool SMBv2_0x0311 = false;
            SMBSecurityModeEnum smbv1secmode = SMBSecurityModeEnum.NotTested;
            SMBSecurityModeEnum smbv2secmode = SMBSecurityModeEnum.NotTested;
            SMBSecurityModeEnum smbv2temp;
            try
            {
                try
                {
                    SMBv1 = DoesServerSupportDialect(computer, "NT LM 0.12", out smbv1secmode);
                }
                catch (ApplicationException)
                {
                }
                try
                {
                    SMBv2_0x0202 = DoesServerSupportDialectWithSmbV2(computer, 0x0202, out smbv2secmode);
                    SMBv2_0x0210 = DoesServerSupportDialectWithSmbV2(computer, 0x0210, out smbv2temp);
                    smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
                    SMBv2_0x0300 = DoesServerSupportDialectWithSmbV2(computer, 0x0300, out smbv2temp);
                    smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
                    SMBv2_0x0302 = DoesServerSupportDialectWithSmbV2(computer, 0x0302, out smbv2temp);
                    smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
                    SMBv2_0x0311 = DoesServerSupportDialectWithSmbV2(computer, 0x0311, out smbv2temp);
                    smbv2secmode = CombineSecurityMode(smbv2secmode, smbv2temp);
                }
                catch (ApplicationException)
                {
                }
            }
            catch (Exception)
            {
                isPortOpened = false;
            }
            Console.WriteLine("[*] SMB Versions:   " + (SMBv1 ? "[+]SMBv1" : "[-]SMBv1")
                    + "\t" + (SMBv2_0x0202 ? "[+]SMBv2(0x0202)" : "[-]SMBv2(0x0202)")
                    + "\t" + (SMBv2_0x0210 ? "[+]SMBv2(0x0210)" : "[-]SMBv2(0x0210)")
                    + "\t" + (SMBv2_0x0300 ? "[+]SMBv3(0x0300)" : "[-]SMBv3(0x0300)")
                    + "\t" + (SMBv2_0x0302 ? "[+]SMBv3(0x0302)" : "[-]SMBv3(0x0302)")
                    + "\t" + (SMBv2_0x0311 ? "[+]SMBv3(0x0311)" : "[-]SMBv3(0x0311)"));
            Console.WriteLine("[*] SMBv1  Signing: " + ((smbv1secmode & SMBSecurityModeEnum.SmbSigningRequired) != 0 ? "[+]Signing Required" : "[-]Signing Not Required"));
            Console.WriteLine("[*] SMBv2+ Signing: " + ((smbv2secmode & SMBSecurityModeEnum.SmbSigningRequired) != 0 ? "[+]Signing Required" : "[-]Signing Not Required"));
        }

        public static SHARE_INFO_1[] EnumNetShares(string Server)
        {
            List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            StringBuilder server = new StringBuilder(Server);
            int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == NERR_Success)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                    ShareInfos.Add(shi1);
                    currentPtr += nStructSize;
                }
                NetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }
            else
            {
                ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(), 10, string.Empty));
                return ShareInfos.ToArray();
            }
        }

        // https://github.com/w1u0u1/smb2os/blob/main/smb2os/Program.cs
        public static void CheckOsVersion(string computername)
        {
            byte[] request1 = new byte[]
        {
0x00,0x00,0x00,0x45,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x53,0xc8,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xfe,
0x00,0x00,0x00,0x00,0x00,0x22,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,
0x31,0x32,0x00,0x02,0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00,0x02,0x53,
0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00
        };

            byte[] request2 = new byte[]
            {
0x00,0x00,0x00,0xe8,0xfe,0x53,0x4d,0x42,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0xff,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x24,0x00,0x05,0x00,0x01,0x00,0x00,0x00,0x7f,0x00,0x00,0x00,
0xa7,0x22,0x57,0x31,0xd9,0x03,0xec,0x11,0x92,0x65,0x3c,0x58,0xc2,0x75,0xac,0xfa,
0x70,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x02,0x02,0x10,0x02,0x00,0x03,0x02,0x03,
0x11,0x03,0x00,0x00,0x01,0x00,0x26,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x20,0x00,
0x01,0x00,0x06,0x41,0x15,0xa2,0x9b,0x6f,0x7a,0x8f,0xda,0xa7,0xe9,0xf3,0xed,0xa8,
0x10,0x31,0x88,0x74,0x9e,0x53,0xaf,0xf7,0x92,0x36,0x38,0x8d,0x99,0xe6,0x0a,0x27,
0x4b,0x84,0x00,0x00,0x02,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x02,0x00,
0x01,0x00,0x00,0x00,0x03,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,
0x01,0x00,0x00,0x00,0x04,0x00,0x02,0x00,0x03,0x00,0x01,0x00,0x05,0x00,0x18,0x00,
0x00,0x00,0x00,0x00,0x31,0x00,0x39,0x00,0x32,0x00,0x2e,0x00,0x31,0x00,0x36,0x00,
0x38,0x00,0x2e,0x00,0x36,0x00,0x2e,0x00,0x36,0x00,0x30,0x00
            };

            byte[] request3 = new byte[]
            {
0x00,0x00,0x00,0xa2,0xfe,0x53,0x4d,0x42,0x40,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
0x01,0x00,0x21,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0xff,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x19,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x58,0x00,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x48,0x06,0x06,
0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,
0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04,0x28,0x4e,0x54,
0x4c,0x4d,0x53,0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x97,0x82,0x08,0xe2,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,
0x61,0x4a,0x00,0x00,0x00,0x0f
            };
            try
            {
                using (TcpClient tcpClient = new TcpClient())
                {
                    var result = tcpClient.BeginConnect(computername, 445, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(1000));
                    if (!success)
                    {
                        Console.WriteLine(string.Format("{0}\t{1}", computername, "Failed to connect timeout."));
                        return;
                    }

                    tcpClient.EndConnect(result);

                    using (NetworkStream ns = tcpClient.GetStream())
                    {
                        byte[] temp = new byte[1024];

                        ns.Write(request1, 0, request1.Length);
                        int read = ns.Read(temp, 0, temp.Length);

                        ns.Write(request2, 0, request2.Length);
                        read = ns.Read(temp, 0, temp.Length);

                        ns.Write(request3, 0, request3.Length);
                        read = ns.Read(temp, 0, temp.Length);

                        int blob_offset = BitConverter.ToInt16(temp, 72);
                        blob_offset += 4;

                        int ntlm_provider_offset = blob_offset + 31;

                        int target_name_length = BitConverter.ToInt16(temp, ntlm_provider_offset + 12);
                        if (target_name_length == 0)
                        {
                            ntlm_provider_offset = blob_offset + 33;
                            target_name_length = BitConverter.ToInt16(temp, ntlm_provider_offset + 12);
                        }

                        int target_name_offset = BitConverter.ToInt32(temp, ntlm_provider_offset + 16);
                        string name = Encoding.Unicode.GetString(temp, ntlm_provider_offset + target_name_offset, target_name_length);

                        int version_offset = ntlm_provider_offset + 48;
                        int major = temp[version_offset++];
                        int minor = temp[version_offset++];
                        int build = BitConverter.ToInt16(temp, version_offset);

                        Console.WriteLine(string.Format("[*] OS Version:     {0} - {1}.{2}.{3}", name, major, minor, build));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public static void CheckLocalAdmin(string computer, string module)
        {
            string[] errors = { "ERROR=53", "ERROR=5" };
            if (module.Length == 0)
            {
                try
                {
                    string path = String.Format("\\\\{0}\\{1}", computer, "C$");
                    DirectoryInfo di = new DirectoryInfo(path);
                    var dirs = di.GetDirectories();
                    Console.WriteLine(String.Format("  [+] Local Admin on {0}", computer));
                }
                catch
                {
                    SHARE_INFO_1[] computerShares = EnumNetShares(computer);
                    foreach (SHARE_INFO_1 share in computerShares)
                    {
                        if (share.shi1_netname.Contains("ERROR"))
                        {
                            Console.WriteLine(String.Format("  [-] Failed to authenticate on {0}", computer));
                            return;
                        }
                    }
                    Console.WriteLine(String.Format("  [+] Authenticated but not admin on {0}", computer));
                }
            }
            else
            {
                SHARE_INFO_1[] computerShares = EnumNetShares(computer);
                if (computerShares.Length > 0)
                {
                    if (module.Contains("shares"))
                    {
                        List<string> readableShares = new List<string>();
                        List<string> unauthorizedShares = new List<string>();
                        foreach (SHARE_INFO_1 share in computerShares)
                        {
                            try
                            {
                                string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
                                DirectoryInfo di = new DirectoryInfo(path);
                                var dirs = di.GetDirectories();
                                readableShares.Add(share.shi1_netname);
                            }
                            catch
                            {
                                if (!errors.Contains(share.shi1_netname))
                                {
                                    unauthorizedShares.Add(share.shi1_netname);
                                }
                            }
                        }
                        if (readableShares.Contains("C$") || readableShares.Contains("ADMIN$"))
                        {
                            Console.WriteLine(String.Format("  [+] Local Admin on {0}", computer));
                        }
                        else if (unauthorizedShares.Count > 0)
                        {
                            Console.WriteLine(String.Format("  [+] Authenticated but not admin on {0}", computer));
                        }
                        else
                        {
                            Console.WriteLine(String.Format("[-] Access is Denied on {0}", computer));
                        }
                        if (unauthorizedShares.Count > 0 || readableShares.Count > 0)
                        {
                            string output = string.Format("    [*] Listing shares on {0}", computer);
                            if (readableShares.Count > 0)
                            {
                                output += "\n--- Accessible Shares ---";
                                foreach (string share in readableShares)
                                {
                                    output += string.Format("\n    [+]{0}", share);
                                }
                            }
                            if (unauthorizedShares.Count > 0)
                            {
                                output += "\n--- No Access ---";
                                foreach (string share in unauthorizedShares)
                                {
                                    output += string.Format("\n    [-]{0}", share);
                                }
                            }
                            Console.WriteLine(output);
                        }
                    }
                }
                else
                {
                    Console.WriteLine(String.Format("[-] Access is Denied on {0}", computer));
                }
            }
        }
    }
}