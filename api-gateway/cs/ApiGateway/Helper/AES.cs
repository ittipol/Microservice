using System.Security.Cryptography;

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
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

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
    }
}