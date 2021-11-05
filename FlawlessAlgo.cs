using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Flawless2
{
    public class FlawlessAlgo
    {
        public string InitialKey = "flawless";
        public static Random rng = new Random();

        public MemoryStream Encrypt(byte[] contents)
        {
            MemoryStream output = new MemoryStream();
            MemoryStream blocks = new MemoryStream();

            byte[] block = new byte[8];
            MemoryStream ms = new MemoryStream(contents);
            int index = 0;
            for (int i = 0; i < contents.Length / 8 + 1; i++)
            {
                //here we make sure the vulnerability of last block being sometimes half empty doesn't exist.
                FillRandom(ref block);
                ms.Read(block);

                EncryptBlock(ref block, index++);
                blocks.Write(block);
            }

            blocks.Position = 0;

            output.Position = 2;
            byte[] lenBytes = BitConverter.GetBytes((ushort)contents.Length);
            LenEncAlgo(ref lenBytes, InitialKey); //encrypts the Length header

            output.Write(lenBytes);
            output.Write(blocks.ToArray());

            output.Position = 0;
            byte[] resultArr = output.ToArray(); resultArr = resultArr.TakeLast(resultArr.Length - 2).ToArray(); //this extracts the encrypted payload
            byte[] checksum = CRC16(resultArr); //checksum is used to determine if contents should be decrypted
            output.Position = 0;
            output.Write(checksum);
            output.Position = 0;

            return output;
        }

        public MemoryStream Decrypt(byte[] contents)
        {
            MemoryStream ms = new MemoryStream(contents);
            byte[] buffer = new byte[2];
            ms.Position = 2; //skipping first two bytes as we don't care about checksum.
            ms.Read(buffer); //reading two bytes (ushort) to buffer
            LenEncAlgo(ref buffer, InitialKey); //decrypts the Length header
            ushort textlen = BitConverter.ToUInt16(buffer);

            //now just reading the remaining blocks
            var blocks = new byte[ms.Length - 4];
            ms.Read(blocks);

            MemoryStream rms = new MemoryStream(blocks);
            MemoryStream output = new MemoryStream();
            int index = 0;
            for (int i = 0; i < blocks.Length / 8; i++)
            {
                byte[] block = new byte[8];
                rms.Read(block);
                //blockList.Add(block);
                EncryptBlock(ref block, index++);

                output.Write(block);
            }

            output.SetLength(textlen);
            output.Position = 0;

            return output;
        }

        private static void LenEncAlgo(ref byte[] lenBytes, string key)
        {
            byte[] lenBytesKey = sha256(key + "len"); //here we calculate a special key
            lenBytes[0] ^= lenBytesKey[0]; lenBytes[1] ^= lenBytesKey[1]; //and then use it to encrypt content length header.
        }

        public void EncryptBlock(ref byte[] block, int blockIndex)
        {
            //for every block we generate a key : sha256 of key concatted with block's index.
            byte[] encBlockKey = sha256(InitialKey + blockIndex);
            for (int z = 0; z < block.Length; z++)
            {
                //then we just XOR
                block[z] ^= encBlockKey[z];
            }
        }

        private static byte[] sha256(string text)
        {
            using (SHA256 s = SHA256.Create())
            {
                return s.ComputeHash(Encoding.UTF8.GetBytes(text));
            }
        }
        private static void FillRandom(ref byte[] block)
        {
            for (int i = 0; i < block.Length; i++)
            {
                block[i] = (byte)rng.Next(0, 256);
            }
        }
        public static byte[] CRC16(byte[] bytes)
        {
            const ushort poly = 4129;
            ushort[] table = new ushort[256];
            ushort initialValue = 0xffff;
            ushort temp, a;
            ushort crc = initialValue;
            for (int i = 0; i < table.Length; ++i)
            {
                temp = 0;
                a = (ushort)(i << 8);
                for (int j = 0; j < 8; ++j)
                {
                    if (((temp ^ a) & 0x8000) != 0)
                        temp = (ushort)((temp << 1) ^ poly);
                    else
                        temp <<= 1;
                    a <<= 1;
                }
                table[i] = temp;
            }
            for (int i = 0; i < bytes.Length; ++i)
            {
                crc = (ushort)((crc << 8) ^ table[((crc >> 8) ^ (0xff & bytes[i]))]);
            }
            return BitConverter.GetBytes(crc);
        }
    }
}
