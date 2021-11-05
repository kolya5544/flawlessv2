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

            var flawless = new FlawlessAlgo();
            flawless.InitialKey = key;

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
                byte[] dCheck = FlawlessAlgo.CRC16(data);
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

                byte[] decrypted = flawless.Decrypt(contents).ToArray();

                string str = Encoding.UTF8.GetString(decrypted);
                Console.WriteLine($"Your output:{str}");
            }
            else //encoding
            {
                byte[] encResult = flawless.Encrypt(Encoding.UTF8.GetBytes(toEncrypt)).ToArray();
                string base64 = Convert.ToBase64String(encResult);
                Console.WriteLine($"Your output:{base64}");
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
    }
}
