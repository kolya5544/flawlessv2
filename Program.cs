using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Flawless2
{
    class Program
    {
        public static Random rng = new Random();
        public static char[] inputAlpha = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
        static void Main(string[] args)
        {
            Console.WriteLine("Welcome to *F L A W L E S S* v2.0");
            Console.Write("Insert what you'd want to encode or decode:");
            string toEncrypt = Console.ReadLine();
            Console.Write("Insert the key (any string. empty for default, \"gen\" to generate):");
            string key = Console.ReadLine().Replace(" ", "");
            key = key.Length < 1 ? "flawless" : key;
            if (key == "gen")
            {
                string newKey = "";
                while (newKey.Length != 32)
                {
                    char pass = inputAlpha[rng.Next(0, inputAlpha.Length)];
                    newKey += pass;
                }
                key = newKey;
                Console.WriteLine("Your generated key: " + newKey);
            }

            //figuring out if we should encrypt or decrypt
            byte[] data = new byte[] { };
            bool doWeEncrypt = true;
            try
            {
                byte[] encBytes = Convert.FromBase64String(toEncrypt);
                //seperating the checksum from the data
                byte[] checksum = encBytes.Take(2).ToArray();
                data = encBytes.TakeLast(encBytes.Length - 2).ToArray();
                //calculating the data's checksum and checking if everything's fine
                byte[] dCheck = CRC16(data);
                if (bacmp(dCheck, checksum))
                {
                    Console.Write("We've detected encrypted contents! Do you wish to encrypt them (1) or decrypt them? (2):");
                    string choice = Console.ReadLine();
                    doWeEncrypt = choice != "2";
                }
            }
            catch { doWeEncrypt = true; }

            if (!doWeEncrypt) //decoding
            {
                //extract the data from base64 string
                byte[] contents = Convert.FromBase64String(toEncrypt);
                MemoryStream ms = new MemoryStream(contents);
                byte[] buffer = new byte[2];
                ms.Position = 2; //skipping first two bytes as we don't care about checksum.
                ms.Read(buffer); //reading two bytes (ushort) to buffer
                LenEncAlgo(ref buffer, key); //decrypts the Length header
                ushort textlen = BitConverter.ToUInt16(buffer);

                //now just reading the remaining blocks
                var blocks = new byte[ms.Length - 4];
                ms.Read(blocks);
                //forming the list of blocks
                List<byte[]> blockList = new List<byte[]>();
                MemoryStream rms = new MemoryStream(blocks);
                for (int i = 0; i<blocks.Length/8; i++)
                {
                    byte[] block = new byte[8];
                    rms.Read(block);
                    blockList.Add(block);
                }

                //decrypting the block list
                byte[] decrypted = Encrypt(blockList, key);
                byte[] resultString = new byte[textlen];
                var dms = new MemoryStream(decrypted);
                dms.Read(resultString);

                string str = Encoding.UTF8.GetString(resultString);
                Console.WriteLine($"Your output:{str}");
            }
            else //encoding
            {
                //we take the text and split it into 8 byte blocks
                byte[] contents = Encoding.UTF8.GetBytes(toEncrypt);
                MemoryStream ms = new MemoryStream(contents);
                List<byte[]> blocks = new List<byte[]>();
                for (int i = 0; i < contents.Length / 8 + 1; i++)
                {
                    byte[] block = new byte[8];
                    //here we make sure the vulnerability of last block being sometimes half empty doesn't exist.
                    FillRandom(ref block);
                    ms.Read(block);
                    blocks.Add(block);
                }

                //now we form the headers
                MemoryStream output = new MemoryStream();
                output.Position = 2; //dont forget to reserve two bytes for CRC16
                byte[] lenBytes = BitConverter.GetBytes((ushort)contents.Length);
                LenEncAlgo(ref lenBytes, key); //encrypts the Length header
                output.Write(lenBytes);

                //encrypt the blocks
                byte[] encoded = Encrypt(blocks, key);
                output.Write(encoded);

                //now we form the final headers
                output.Position = 0;
                byte[] resultArr = output.ToArray(); resultArr = resultArr.TakeLast(resultArr.Length - 2).ToArray(); //this extracts the encrypted payload
                byte[] checksum = CRC16(resultArr); //checksum is used to determine if contents should be decrypted
                output.Position = 0;
                output.Write(checksum);

                //well done, output the result in base64 to user
                byte[] encResult = output.ToArray();
                string base64 = Convert.ToBase64String(encResult);
                Console.WriteLine($"Your output:{base64}");
            }
        }

        public static byte[] Encrypt(List<byte[]> blocklist, string key)
        {
            //now we encrypt blocks one by one
            MemoryStream ms = new MemoryStream();
            for (int i = 0; i < blocklist.Count; i++)
            {
                byte[] block = blocklist[i];
                //for every block we generate a key : sha256 of key concatted with block's index.
                byte[] encBlockKey = sha256(key + i);
                for (int z = 0; z < block.Length; z++)
                {
                    //then we just XOR
                    block[z] ^= encBlockKey[z];
                }
                ms.Write(block);
            }
            ms.Position = 0;
            return ms.ToArray();
        }

        private static void LenEncAlgo(ref byte[] lenBytes, string key)
        {
            byte[] lenBytesKey = sha256(key + "len"); //here we calculate a special key
            lenBytes[0] ^= lenBytesKey[0]; lenBytes[1] ^= lenBytesKey[1]; //and then use it to encrypt content length header.
        }

        public static byte[] sha256(string text)
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

        public static bool bacmp(byte[] a1, byte[] a2)
        {
            if (a1 == a2)
            {
                return true;
            }
            if ((a1 != null) && (a2 != null))
            {
                if (a1.Length != a2.Length)
                {
                    return false;
                }
                for (int i = 0; i < a1.Length; i++)
                {
                    if (a1[i] != a2[i])
                    {
                        return false;
                    }
                }
                return true;
            }
            return false;
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
