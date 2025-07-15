using System.Security.Cryptography;
using ApiGateway.Model;

namespace ApiGateway.Helper.Cryptography
{
    public static class AESHelper
    {
        public static byte[] Encrypt(byte[] plainBytes, byte[] key, byte[] iv)
        {
            byte[]? encryptedBytes = null;

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                // aes.BlockSize = 128;
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // aes.GenerateKey();
                // aes.GenerateIV();

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                }
            }

            return encryptedBytes;
        }

        public static byte[] Decrypt(byte[] cipherBytes, byte[] key, byte[] iv)
        {
            byte[]? decryptedBytes = null;

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                // aes.BlockSize = 128;
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                }
            }

            return decryptedBytes;
        }

        public static AesKeyData GetIVAndEncryptedData(string cipherText)
        {
            var cipherByte = Convert.FromBase64String(cipherText);

            var iv = new byte[16];
            var encryptedData = new byte[cipherByte.Length - iv.Length];

            Array.Copy(cipherByte, 0, iv, 0, iv.Length);
            Array.Copy(cipherByte, iv.Length, encryptedData, 0, encryptedData.Length);

            return new AesKeyData
            {
                EncryptedData = encryptedData,
                IV = iv
            };
        }

        public static AesKeyData GetIVAndEncryptedData(byte[] cipherByte)
        {
            var iv = new byte[16];
            var encryptedData = new byte[cipherByte.Length - iv.Length];

            Array.Copy(cipherByte, 0, iv, 0, iv.Length);
            Array.Copy(cipherByte, iv.Length, encryptedData, 0, encryptedData.Length);

            return new AesKeyData
            {
                EncryptedData = encryptedData,
                IV = iv
            };
        }        
    }
}