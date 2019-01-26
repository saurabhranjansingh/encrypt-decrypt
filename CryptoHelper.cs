using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptDecrypt
{
    public static class CryptoHelper
    {
        static byte[] KeyBytes;
        static byte[] IVBytes;

        static CryptoHelper()
        {
            //You can change the content of SecretKey & InitializationVector.
            //But don't change their length.
            string SecretKey = "zdf3kdf820nvk94dJsd7nsl29kslqTx8"; //Length must be 32
            string InitializationVector = "h82hmD9tmwNn2Xh4";      //Length must be 16

            KeyBytes = Encoding.ASCII.GetBytes(SecretKey);
            IVBytes = Encoding.ASCII.GetBytes(InitializationVector);
        }

        /// <summary>
        /// Returns the Encypted string in Base 64 encoded format.
        /// </summary>
        /// <param name="PlainText">Plain Text</param>
        /// <returns></returns>
        public static string EncryptText(string PlainText)
        {
            if (string.IsNullOrEmpty(PlainText))
                throw new ArgumentNullException("PlainText");

            byte[] encrypted = EncryptStringToBytes_Aes(PlainText, KeyBytes, IVBytes);
            return Convert.ToBase64String(encrypted);                      
        }

        /// <summary>
        /// Accepts a Base64 encoded and encypted string and returns the decryped text.
        /// </summary>
        /// <param name="EncryptedText"></param>
        /// <returns></returns>
        public static string DecryptText(string EncryptedText)
        {
            if (string.IsNullOrEmpty(EncryptedText))
                throw new ArgumentNullException("EncryptedText");

            byte[] decodedText = Convert.FromBase64String(EncryptedText);
            return DecryptStringFromBytes_Aes(decodedText, KeyBytes, IVBytes);
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {            
            byte[] encrypted;

            // Create an Aes object with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold the decrypted text.
            string plaintext = null;

            // Create an Aes object with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}
