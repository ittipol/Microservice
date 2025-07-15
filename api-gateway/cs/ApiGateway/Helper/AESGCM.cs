using System.Security.Cryptography;
using System.Text;
using ApiGateway.Model;

namespace ApiGateway.Helper.Cryptography
{
    public static class AESGCMHelper
    {
        public static byte[] AesGcmEncrypt(byte[] plainBytes, byte[] key)
        {
            Console.WriteLine("AesGcm --> TagByteSizes: {0}", AesGcm.TagByteSizes.MaxSize.ToString());
            Console.WriteLine("AesGcm --> NonceByteSizes: {0}", AesGcm.NonceByteSizes.MaxSize.ToString());

            using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);

            // For AES-GCM, the nonce must be 96-bits (12-bytes) in length
            var nonce = Utils.RandomByte(AesGcm.NonceByteSizes.MaxSize);

            var ciphertext = new byte[plainBytes.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // tag size = 16
            // var associatedData = new byte[12];

            aes.Encrypt(nonce, plainBytes, ciphertext, tag);

            var mergedData = new byte[nonce.Length + tag.Length + ciphertext.Length];

            Array.Copy(nonce, 0, mergedData, 0, nonce.Length);
            Array.Copy(ciphertext, 0, mergedData, nonce.Length, ciphertext.Length);
            Array.Copy(tag, 0, mergedData, nonce.Length + ciphertext.Length, tag.Length);

            return mergedData;
        }

        public static string AesGcmDecrypt(byte[] ciphertext, byte[] key)
        {
            var aesGcmKeyData = GetNonceAndEncryptedData(ciphertext);

            using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);

            var plaintextBytes = new byte[aesGcmKeyData.EncryptedData.Length];

            aes.Decrypt(aesGcmKeyData.Nonce, aesGcmKeyData.EncryptedData, aesGcmKeyData.Tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        public static AesGcmKeyData GetNonceAndEncryptedData(byte[] cipherByte)
        {
            // Extract --> Nonce (12B) | Ciphertext (*B) | Tag (16B)

            var nonce = new byte[12];
            var tag = new byte[16];
            var encryptedData = new byte[cipherByte.Length - nonce.Length - tag.Length];

            Array.Copy(cipherByte, 0, nonce, 0, nonce.Length);
            Array.Copy(cipherByte, nonce.Length, encryptedData, 0, encryptedData.Length);
            Array.Copy(cipherByte, nonce.Length + encryptedData.Length, tag, 0, tag.Length);

            // Utils.PrintByteArray(nonce);
            // Utils.PrintByteArray(encryptedData);
            // Utils.PrintByteArray(tag);

            return new AesGcmKeyData
            {
                EncryptedData = encryptedData,
                Nonce = nonce,
                Tag = tag
            };
        }
    }
}