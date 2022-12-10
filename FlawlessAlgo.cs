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
        public bool LastOperationSuccess = true;

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
                ms.Read(block, 0, block.Length);

                EncryptBlock(ref block, index++);
                blocks.Write(block, 0, block.Length);
            }

            blocks.Position = 0;

            output.Position = 4;
            byte[] lenBytes = BitConverter.GetBytes((uint)contents.Length);
            LenEncAlgo(ref lenBytes, InitialKey); //encrypts the Length header

            output.Write(lenBytes, 0, lenBytes.Length);
            var arr = blocks.ToArray();
            output.Write(arr, 0, arr.Length);

            output.Position = 0;
            byte[] resultArr = output.ToArray(); resultArr = resultArr.ToList().GetRange(4, resultArr.Length - 4).ToArray(); //this extracts the encrypted payload
            byte[] checksum1 = CRC16(resultArr); //this checksum is used to determine if contents should be decrypted
            byte[] checksum2 = CRC16(contents); //this checksum is used to check if contents were decrypted properly. It is encrypted in a way similar to LenEncAlgo encryption.
            CheckEncAlgo(ref checksum2, InitialKey); //encrypts content checksum
            output.Position = 0;
            output.Write(checksum1, 0, checksum1.Length);
            output.Write(checksum2, 0, checksum2.Length);
            output.Position = 0;

            LastOperationSuccess = true;
            
            return output;
        }

        public static bool IsEncrypted(byte[] content)
        {
            var ms = new MemoryStream(content);
            byte[] encChecksum = new byte[2];
            byte[] buffer = new byte[2];
            byte[] data = new byte[content.Length - 4]; //w/out checksums

            ms.Read(encChecksum, 0, encChecksum.Length);
            ms.Read(buffer, 0, buffer.Length);
            ms.Read(data, 0, data.Length);

            byte[] crc = CRC16(data);
            if (crc[0] == encChecksum[0] && crc[1] == encChecksum[1])
            {
                return true;
            }
            return false;
        }

        public MemoryStream Decrypt(byte[] contents)
        {
            MemoryStream ms = new MemoryStream(contents);
            byte[] buffer = new byte[4];
            byte[] contentCheck = new byte[2];
            ms.Position = 2; //skipping first two bytes as we don't care about encryption checksum.
            ms.Read(contentCheck, 0, contentCheck.Length); //taking next two bytes containing content checksum
            CheckEncAlgo(ref contentCheck, InitialKey); // decrypting content check checksum
            ms.Read(buffer, 0, buffer.Length); //reading two bytes (ushort) to buffer
            LenEncAlgo(ref buffer, InitialKey); //decrypts the Length header
            uint textlen = BitConverter.ToUInt32(buffer, 0);

            //now just reading the remaining blocks
            var blocks = new byte[ms.Length - 8]; // encryption checksum (2 bytes) + content checksum (2 bytes) + length (4 bytes)
            ms.Read(blocks, 0, blocks.Length);

            MemoryStream rms = new MemoryStream(blocks);
            MemoryStream output = new MemoryStream();
            int index = 0;
            for (int i = 0; i < blocks.Length / 8; i++)
            {
                byte[] block = new byte[8];
                rms.Read(block, 0, block.Length);
                //blockList.Add(block);
                EncryptBlock(ref block, index++);

                output.Write(block, 0, block.Length);
            }

            output.SetLength(textlen);
            output.Position = 0;

            //now we check
            var l = output.ToArray();
            var c = CRC16(l);
            if (c[0] != contentCheck[0] ||
                c[1] != contentCheck[1])
            {
                LastOperationSuccess = false;
            } else
            {
                LastOperationSuccess = true;
            }

            return output;
        }

        private static void LenEncAlgo(ref byte[] lenBytes, string key)
        {
            byte[] lenBytesKey = sha256(key + "len"); //here we calculate a special key
            lenBytes[0] ^= lenBytesKey[0]; lenBytes[1] ^= lenBytesKey[1]; //and then use it to encrypt content length header.
            lenBytes[2] ^= lenBytesKey[2]; lenBytes[3] ^= lenBytesKey[3];
        }

        private static void CheckEncAlgo(ref byte[] checkBytes, string key)
        {
            byte[] checkBytesKey = sha256(key + "check"); //here we calculate a special checksum key
            checkBytes[0] ^= checkBytesKey[0]; checkBytes[1] ^= checkBytesKey[1]; //and then use it to encrypt content checksum header.
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
