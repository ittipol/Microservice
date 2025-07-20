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

            var encryptedData = new byte[plainBytes.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // tag size = 16
            // var associatedData = new byte[12];

            aes.Encrypt(nonce, plainBytes, encryptedData, tag);                    

            var cipherText = new byte[nonce.Length + tag.Length + encryptedData.Length];

            Array.Copy(nonce, 0, cipherText, 0, nonce.Length);
            Array.Copy(encryptedData, 0, cipherText, nonce.Length, encryptedData.Length);
            Array.Copy(tag, 0, cipherText, nonce.Length + encryptedData.Length, tag.Length);

            // Utils.PrintByteArray(nonce);
            // Utils.PrintByteArray(encryptedData);
            // Utils.PrintByteArray(tag);
            // Console.WriteLine("cipherText length: {0}", cipherText.Length);

            return cipherText;
        }

        public static TResult? AesGcmDecrypt<TResult>(byte[] ciphertext, byte[] key) where TResult : notnull
        {
            var aesGcmKeyData = GetNonceAndEncryptedData(ciphertext);

            using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);

            var plaintextBytes = new byte[aesGcmKeyData.EncryptedData.Length];

            aes.Decrypt(aesGcmKeyData.Nonce, aesGcmKeyData.EncryptedData, aesGcmKeyData.Tag, plaintextBytes);

            if (typeof(TResult).IsAssignableTo(typeof(string)))
            {
                object value = Encoding.UTF8.GetString(plaintextBytes);
                return (TResult)Convert.ChangeType(value, typeof(TResult));
            }
            else if (typeof(TResult).IsAssignableTo(typeof(byte[])))
            {
                object value = plaintextBytes;
                return (TResult)Convert.ChangeType(value, typeof(TResult));
            }

            return default(TResult);  
        }

        public static string AesGcmDecrypt(byte[] ciphertext, byte[] key)
        {
            var aesGcmKeyData = GetNonceAndEncryptedData(ciphertext);

            using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);

            var plaintextBytes = new byte[aesGcmKeyData.EncryptedData.Length];

            aes.Decrypt(aesGcmKeyData.Nonce, aesGcmKeyData.EncryptedData, aesGcmKeyData.Tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        // public static byte[] AesGcmDecryptToByte(byte[] ciphertext, byte[] key)
        // {
        //     var aesGcmKeyData = GetNonceAndEncryptedData(ciphertext);

        //     using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);

        //     var plaintextBytes = new byte[aesGcmKeyData.EncryptedData.Length];

        //     aes.Decrypt(aesGcmKeyData.Nonce, aesGcmKeyData.EncryptedData, aesGcmKeyData.Tag, plaintextBytes);

        //     return plaintextBytes;
        // }

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