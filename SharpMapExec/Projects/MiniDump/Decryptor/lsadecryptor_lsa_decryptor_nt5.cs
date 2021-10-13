using System;

using System.Linq;

namespace Minidump.Decryptor
{

    public class LsaDecryptor_NT5

    public object decryptor_template;
        
        public object des_key;
        
        public object feedback;
        
        public object feedback_offset;
        
        public object random_key;
        
        public LsaDecryptor_NT5(object reader, object decryptor_template, object sysinfo)
            : base(null, sysinfo, reader) {
            decryptor_template = decryptor_template;
            feedback;
            feedback_offset;
            des_key;
            random_key;
            acquire_crypto_material();
        }
        
        public virtual object acquire_crypto_material() {
            Console.WriteLine("Acquireing crypto stuff...");
            var sigpos = find_signature();
            reader.move(sigpos);
            //data = self.reader.peek(0x50)
            //self.Console.WriteLine('Memory looks like this around the signature\n%s' % hexdump(data, start = sigpos))
            foreach (var x in new List<object> {
                decryptor_template.feedback_ptr_offset,
                decryptor_template.old_feedback_offset
            }) {
                feedback_offset = x;
                try {
                    feedback = get_feedback(sigpos);
                    //self.Console.WriteLine('Feedback bytes:\n%s' % hexdump(self.feedback, start = 0))
                    des_key = get_key(sigpos);
                    random_key = get_random(sigpos);
                    //self.Console.WriteLine('randomkey bytes:\n%s' % hexdump(self.random_key, start = 0))
                } catch {
                    traceback.print_exc();
                    input();
                }
            }
        }
        
        public virtual object get_feedback(object sigpos) {
            if (decryptor_template.arch == "x86") {
                var new_ptr = reader.get_ptr_with_offset(sigpos + feedback_offset);
                reader.move(new_ptr);
                return reader.read(8);
            } else {
                reader.move(sigpos + feedback_offset);
                var offset = LONG(reader).value;
                var newpos = sigpos + feedback_offset + 4 + offset;
                reader.move(newpos);
                return reader.read(8);
            }
        }
        
        public virtual object get_key(object sigpos) {
            object des_key;
            object des_key_ptr;
            if (decryptor_template.arch == "x86") {
                var new_ptr = reader.get_ptr_with_offset(sigpos + decryptor_template.desx_key_ptr_offset);
                reader.move(new_ptr);
                des_key_ptr = decryptor_template.key_struct_ptr(reader);
                des_key = des_key_ptr.read(reader);
            } else {
                reader.move(sigpos + decryptor_template.desx_key_ptr_offset);
                var offset = LONG(reader).value;
                var newpos = sigpos + decryptor_template.desx_key_ptr_offset + 4 + offset;
                reader.move(newpos);
                des_key_ptr = decryptor_template.key_struct_ptr(reader);
                des_key = des_key_ptr.read(reader);
            }
            return des_key;
        }
        
        public virtual object get_random(object sigpos) {
            if (decryptor_template.arch == "x86") {
                var random_key_ptr = reader.get_ptr_with_offset(sigpos + decryptor_template.randomkey_ptr_offset);
                random_key_ptr = reader.get_ptr_with_offset(random_key_ptr);
                reader.move(random_key_ptr);
            } else {
                reader.move(sigpos + decryptor_template.randomkey_ptr_offset);
                var offset = LONG(reader).value;
                var newpos = sigpos + decryptor_template.desx_key_ptr_offset + 4 + offset;
                reader.move(newpos);
            }
            return reader.read(256);
        }
        
        public virtual object find_signature() {
            Console.WriteLine("Looking for main struct signature in memory...");
            var fl = reader.find_in_module("lsasrv.dll", decryptor_template.signature);
            if (fl.Count == 0) {
                logging.debug(String.Format("signature not found! %s", decryptor_template.signature.hex()));
                throw new Exception("LSA signature not found!");
            }
            Console.WriteLine(String.Format("Found candidates on the following positions: %s", " ".join(from x in fl
                select hex(x))));
            Console.WriteLine(String.Format("Selecting first one @ 0x%08x", fl[0]));
            return fl[0];
        }
        
        public virtual object decrypt(object encrypted) {
            // TODO: NT version specific, move from here in subclasses.
            var cleartext = new byte[] {  };
            var size = encrypted.Count;
            if (size) {
                if (size % 8 != 0) {
                    var ctx = RC4(random_key);
                    cleartext = ctx.decrypt(encrypted);
                } else {
                    //print('Decryption not implemented!')
                    cleartext = @__desx_decrypt(encrypted);
                    //raise Exception('Not implemented!')
                }
            }
            return cleartext;
        }
        
        public virtual object dump() {
            Console.WriteLine("Recovered LSA encryption keys\n");
            Console.WriteLine("Feedback ({}): {}".format(feedback.Count, feedback.hex()));
            Console.WriteLine("Random Key ({}): {}".format(random_key.Count, random_key.hex()));
            Console.WriteLine("DESX inputwhitening Key ({}): {}".format(des_key.inputWhitening.Count, des_key.inputWhitening.hex()));
            Console.WriteLine("DESX outputwhitening Key ({}): {}".format(des_key.outputWhitening.Count, des_key.outputWhitening.hex()));
            //self.Console.WriteLine('DESX DES Expanded Key ({}): {}' % (self.des_key.desKey.roundKey))
        }
        
        public virtual void @__desx_decrypt_internal_block(object chunk) {
            chunk = xor(chunk, des_key.outputWhitening);
            chunk = @__desx_internal_block(chunk, encrypt: false);
            chunk = xor(chunk, des_key.inputWhitening);
            return chunk;
        }
        
        public virtual object @__desx_decrypt(object data) {
            var res = new byte[] {  };
            var i = 0;
            var IV = feedback;
            while (i != data.Count) {
                var chunk = @__desx_decrypt_internal_block(data[i::(i  +  8)]);
                res += xor(chunk, IV);
                IV = data[i::(i  +  8)];
                i += 8;
            }
            return res;
        }
        
        public virtual object @__desx_internal_block(object data, object encrypt = false) {
            var L = @int.from_bytes(data[4], "little", signed: false);
            var R = @int.from_bytes(data[::4], "little", signed: false);
            //t = 'ORIGINAL L: %s R: %s' % (L,R)
            //input(t)
            //print(hex(R))
            R = rol32(R, 4);
            //input(hex(R))
            var Ta = (L ^ R) & 0xf0f0f0f0;
            //input('Ta ' + hex(Ta))
            L = L ^ Ta;
            R = R ^ Ta;
            L = rol32(L, 20);
            Ta = (L ^ R) & 0xfff0000f;
            //input('Ta ' + hex(Ta))
            L = L ^ Ta;
            R = R ^ Ta;
            L = rol32(L, 14);
            Ta = (L ^ R) & 0x33333333;
            //input('Ta ' + hex(Ta))
            L = L ^ Ta;
            R = R ^ Ta;
            R = rol32(R, 22);
            Ta = (L ^ R) & 0x03fc03fc;
            //input('Ta ' + hex(Ta))
            L = L ^ Ta;
            R = R ^ Ta;
            R = rol32(R, 9);
            Ta = (L ^ R) & 0xaaaaaaaa;
            //input('Ta ' + hex(Ta))
            L = L ^ Ta;
            R = R ^ Ta;
            L = rol32(L, 1);
            //t = 'BEFORE F! L: %s R: %s' % (L,R)
            //input(t)
            if (encrypt) {
                foreach (var i in Enumerable.Range(0, Convert.ToInt32(Math.Ceiling(Convert.ToDouble(14 - 0) / 2))).Select(_x_1 => 0 + _x_1 * 2)) {
                    var _tup_1 = F(L, R, des_key.desKey.roundKey[i]);
                    L = _tup_1.Item1;
                    R = _tup_1.Item2;
                    var _tup_2 = F(R, L, des_key.desKey.roundKey[i + 1]);
                    R = _tup_2.Item1;
                    L = _tup_2.Item2;
                }
            } else {
                foreach (var i in Enumerable.Range(0, Convert.ToInt32(Math.Ceiling(Convert.ToDouble(-2 - 14) / -2))).Select(_x_2 => 14 + _x_2 * -2)) {
                    //print(i)
                    var _tup_3 = F(L, R, des_key.desKey.roundKey[i + 1]);
                    L = _tup_3.Item1;
                    R = _tup_3.Item2;
                    //t = 'F(%s) L: %s R: %s' % (i, L,R)
                    //input(t)
                    var _tup_4 = F(R, L, des_key.desKey.roundKey[i]);
                    R = _tup_4.Item1;
                    L = _tup_4.Item2;
                    //t = 'F(%s) L: %s R: %s' % (i, L,R)
                    //input(t)
                    //t = 'AFTER F! L: %s R: %s' % (L,R)
                    //input(t)
                }
            }
            R = ror32(R, 1);
            Ta = (L ^ R) & 0xaaaaaaaa;
            L = L ^ Ta;
            R = R ^ Ta;
            L = ror32(L, 9);
            Ta = (L ^ R) & 0x03fc03fc;
            L ^= Ta;
            R ^= Ta;
            L = ror32(L, 22);
            Ta = (L ^ R) & 0x33333333;
            L ^= Ta;
            R ^= Ta;
            R = ror32(R, 14);
            Ta = (L ^ R) & 0xfff0000f;
            L ^= Ta;
            R ^= Ta;
            R = ror32(R, 20);
            Ta = (L ^ R) & 0xf0f0f0f0;
            L ^= Ta;
            R ^= Ta;
            L = ror32(L, 4);
            return L.to_bytes(4, "little", signed: false) + R.to_bytes(4, "little", signed: false);
        }
    }
    
    public static List<List<int>> SymCryptDesSpbox = new List<List<int>> {
        new List<int> {
            0x02080800,
            0x00080000,
            0x02000002,
            0x02080802,
            0x02000000,
            0x00080802,
            0x00080002,
            0x02000002,
            0x00080802,
            0x02080800,
            0x02080000,
            0x00000802,
            0x02000802,
            0x02000000,
            0x00000000,
            0x00080002,
            0x00080000,
            0x00000002,
            0x02000800,
            0x00080800,
            0x02080802,
            0x02080000,
            0x00000802,
            0x02000800,
            0x00000002,
            0x00000800,
            0x00080800,
            0x02080002,
            0x00000800,
            0x02000802,
            0x02080002,
            0x00000000,
            0x00000000,
            0x02080802,
            0x02000800,
            0x00080002,
            0x02080800,
            0x00080000,
            0x00000802,
            0x02000800,
            0x02080002,
            0x00000800,
            0x00080800,
            0x02000002,
            0x00080802,
            0x00000002,
            0x02000002,
            0x02080000,
            0x02080802,
            0x00080800,
            0x02080000,
            0x02000802,
            0x02000000,
            0x00000802,
            0x00080002,
            0x00000000,
            0x00080000,
            0x02000000,
            0x02000802,
            0x02080800,
            0x00000002,
            0x02080002,
            0x00000800,
            0x00080802
        },
        new List<int> {
            0x40108010,
            0x00000000,
            0x00108000,
            0x40100000,
            0x40000010,
            0x00008010,
            0x40008000,
            0x00108000,
            0x00008000,
            0x40100010,
            0x00000010,
            0x40008000,
            0x00100010,
            0x40108000,
            0x40100000,
            0x00000010,
            0x00100000,
            0x40008010,
            0x40100010,
            0x00008000,
            0x00108010,
            0x40000000,
            0x00000000,
            0x00100010,
            0x40008010,
            0x00108010,
            0x40108000,
            0x40000010,
            0x40000000,
            0x00100000,
            0x00008010,
            0x40108010,
            0x00100010,
            0x40108000,
            0x40008000,
            0x00108010,
            0x40108010,
            0x00100010,
            0x40000010,
            0x00000000,
            0x40000000,
            0x00008010,
            0x00100000,
            0x40100010,
            0x00008000,
            0x40000000,
            0x00108010,
            0x40008010,
            0x40108000,
            0x00008000,
            0x00000000,
            0x40000010,
            0x00000010,
            0x40108010,
            0x00108000,
            0x40100000,
            0x40100010,
            0x00100000,
            0x00008010,
            0x40008000,
            0x40008010,
            0x00000010,
            0x40100000,
            0x00108000
        },
        new List<int> {
            0x04000001,
            0x04040100,
            0x00000100,
            0x04000101,
            0x00040001,
            0x04000000,
            0x04000101,
            0x00040100,
            0x04000100,
            0x00040000,
            0x04040000,
            0x00000001,
            0x04040101,
            0x00000101,
            0x00000001,
            0x04040001,
            0x00000000,
            0x00040001,
            0x04040100,
            0x00000100,
            0x00000101,
            0x04040101,
            0x00040000,
            0x04000001,
            0x04040001,
            0x04000100,
            0x00040101,
            0x04040000,
            0x00040100,
            0x00000000,
            0x04000000,
            0x00040101,
            0x04040100,
            0x00000100,
            0x00000001,
            0x00040000,
            0x00000101,
            0x00040001,
            0x04040000,
            0x04000101,
            0x00000000,
            0x04040100,
            0x00040100,
            0x04040001,
            0x00040001,
            0x04000000,
            0x04040101,
            0x00000001,
            0x00040101,
            0x04000001,
            0x04000000,
            0x04040101,
            0x00040000,
            0x04000100,
            0x04000101,
            0x00040100,
            0x04000100,
            0x00000000,
            0x04040001,
            0x00000101,
            0x04000001,
            0x00040101,
            0x00000100,
            0x04040000
        },
        new List<int> {
            0x00401008,
            0x10001000,
            0x00000008,
            0x10401008,
            0x00000000,
            0x10400000,
            0x10001008,
            0x00400008,
            0x10401000,
            0x10000008,
            0x10000000,
            0x00001008,
            0x10000008,
            0x00401008,
            0x00400000,
            0x10000000,
            0x10400008,
            0x00401000,
            0x00001000,
            0x00000008,
            0x00401000,
            0x10001008,
            0x10400000,
            0x00001000,
            0x00001008,
            0x00000000,
            0x00400008,
            0x10401000,
            0x10001000,
            0x10400008,
            0x10401008,
            0x00400000,
            0x10400008,
            0x00001008,
            0x00400000,
            0x10000008,
            0x00401000,
            0x10001000,
            0x00000008,
            0x10400000,
            0x10001008,
            0x00000000,
            0x00001000,
            0x00400008,
            0x00000000,
            0x10400008,
            0x10401000,
            0x00001000,
            0x10000000,
            0x10401008,
            0x00401008,
            0x00400000,
            0x10401008,
            0x00000008,
            0x10001000,
            0x00401008,
            0x00400008,
            0x00401000,
            0x10400000,
            0x10001008,
            0x00001008,
            0x10000000,
            0x10000008,
            0x10401000
        },
        new List<int> {
            0x08000000,
            0x00010000,
            0x00000400,
            0x08010420,
            0x08010020,
            0x08000400,
            0x00010420,
            0x08010000,
            0x00010000,
            0x00000020,
            0x08000020,
            0x00010400,
            0x08000420,
            0x08010020,
            0x08010400,
            0x00000000,
            0x00010400,
            0x08000000,
            0x00010020,
            0x00000420,
            0x08000400,
            0x00010420,
            0x00000000,
            0x08000020,
            0x00000020,
            0x08000420,
            0x08010420,
            0x00010020,
            0x08010000,
            0x00000400,
            0x00000420,
            0x08010400,
            0x08010400,
            0x08000420,
            0x00010020,
            0x08010000,
            0x00010000,
            0x00000020,
            0x08000020,
            0x08000400,
            0x08000000,
            0x00010400,
            0x08010420,
            0x00000000,
            0x00010420,
            0x08000000,
            0x00000400,
            0x00010020,
            0x08000420,
            0x00000400,
            0x00000000,
            0x08010420,
            0x08010020,
            0x08010400,
            0x00000420,
            0x00010000,
            0x00010400,
            0x08010020,
            0x08000400,
            0x00000420,
            0x00000020,
            0x00010420,
            0x08010000,
            0x08000020
        },
        new List<int> {
            0x80000040,
            0x00200040,
            0x00000000,
            0x80202000,
            0x00200040,
            0x00002000,
            0x80002040,
            0x00200000,
            0x00002040,
            0x80202040,
            0x00202000,
            0x80000000,
            0x80002000,
            0x80000040,
            0x80200000,
            0x00202040,
            0x00200000,
            0x80002040,
            0x80200040,
            0x00000000,
            0x00002000,
            0x00000040,
            0x80202000,
            0x80200040,
            0x80202040,
            0x80200000,
            0x80000000,
            0x00002040,
            0x00000040,
            0x00202000,
            0x00202040,
            0x80002000,
            0x00002040,
            0x80000000,
            0x80002000,
            0x00202040,
            0x80202000,
            0x00200040,
            0x00000000,
            0x80002000,
            0x80000000,
            0x00002000,
            0x80200040,
            0x00200000,
            0x00200040,
            0x80202040,
            0x00202000,
            0x00000040,
            0x80202040,
            0x00202000,
            0x00200000,
            0x80002040,
            0x80000040,
            0x80200000,
            0x00202040,
            0x00000000,
            0x00002000,
            0x80000040,
            0x80002040,
            0x80202000,
            0x80200000,
            0x00002040,
            0x00000040,
            0x80200040
        },
        new List<int> {
            0x00004000,
            0x00000200,
            0x01000200,
            0x01000004,
            0x01004204,
            0x00004004,
            0x00004200,
            0x00000000,
            0x01000000,
            0x01000204,
            0x00000204,
            0x01004000,
            0x00000004,
            0x01004200,
            0x01004000,
            0x00000204,
            0x01000204,
            0x00004000,
            0x00004004,
            0x01004204,
            0x00000000,
            0x01000200,
            0x01000004,
            0x00004200,
            0x01004004,
            0x00004204,
            0x01004200,
            0x00000004,
            0x00004204,
            0x01004004,
            0x00000200,
            0x01000000,
            0x00004204,
            0x01004000,
            0x01004004,
            0x00000204,
            0x00004000,
            0x00000200,
            0x01000000,
            0x01004004,
            0x01000204,
            0x00004204,
            0x00004200,
            0x00000000,
            0x00000200,
            0x01000004,
            0x00000004,
            0x01000200,
            0x00000000,
            0x01000204,
            0x01000200,
            0x00004200,
            0x00000204,
            0x00004000,
            0x01004204,
            0x01000000,
            0x01004200,
            0x00000004,
            0x00004004,
            0x01004204,
            0x01000004,
            0x01004200,
            0x01004000,
            0x00004004
        },
        new List<int> {
            0x20800080,
            0x20820000,
            0x00020080,
            0x00000000,
            0x20020000,
            0x00800080,
            0x20800000,
            0x20820080,
            0x00000080,
            0x20000000,
            0x00820000,
            0x00020080,
            0x00820080,
            0x20020080,
            0x20000080,
            0x20800000,
            0x00020000,
            0x00820080,
            0x00800080,
            0x20020000,
            0x20820080,
            0x20000080,
            0x00000000,
            0x00820000,
            0x20000000,
            0x00800000,
            0x20020080,
            0x20800080,
            0x00800000,
            0x00020000,
            0x20820000,
            0x00000080,
            0x00800000,
            0x00020000,
            0x20000080,
            0x20820080,
            0x00020080,
            0x20000000,
            0x00000000,
            0x00820000,
            0x20800080,
            0x20020080,
            0x20020000,
            0x00800080,
            0x20820000,
            0x00000080,
            0x00800080,
            0x20020000,
            0x20820080,
            0x00800000,
            0x20800000,
            0x20000080,
            0x00820000,
            0x00020080,
            0x20020080,
            0x20800000,
            0x00000080,
            0x20820000,
            0x00820080,
            0x00000000,
            0x20000000,
            0x20800080,
            0x00020000,
            0x00820080
        }
    };
    
    public static object F(object L, object R, object keya) {
        var Ta = keya[0] ^ R;
        var Tb = keya[1] ^ R;
        Tb = ror32(Tb, 4);
        L ^= SymCryptDesSpbox[0][(Ta & 0xfc) / 4];
        L ^= SymCryptDesSpbox[1][(Tb & 0xfc) / 4];
        L ^= SymCryptDesSpbox[2][(Ta >> 8 & 0xfc) / 4];
        L ^= SymCryptDesSpbox[3][(Tb >> 8 & 0xfc) / 4];
        L ^= SymCryptDesSpbox[4][(Ta >> 16 & 0xfc) / 4];
        L ^= SymCryptDesSpbox[5][(Tb >> 16 & 0xfc) / 4];
        L ^= SymCryptDesSpbox[6][(Ta >> 24 & 0xfc) / 4];
        L ^= SymCryptDesSpbox[7][(Tb >> 24 & 0xfc) / 4];
        return Tuple.Create(L, R);
    }
    
    public static object rol32(object n, object d) {
        return (n << d | n >> 32 - d) & 0xFFFFFFFF;
    }
    
    public static object ror32(object n, object d) {
        return (n >> d | n << 32 - d) & 0xFFFFFFFF;
    }
    
    public static object xor(object d1, object d2) {
        return bytes(from _tup_1 in zip(d1, d2).Chop((a,b) => (a, b))
            let a = _tup_1.Item1
            let b = _tup_1.Item2
            select a ^ b);
    }
}
