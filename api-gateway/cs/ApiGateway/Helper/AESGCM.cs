using System.Security.Cryptography;
using System.Text;
using ApiGateway.Model;

namespace ApiGateway.Helper.Cryptography
{
    public static class AESGCMHelper
    {
        public static byte[] AesGcmEncrypt(byte[] plaintext, byte[] key)
        {
            Console.WriteLine("AesGcm --> TagByteSizes: {0}", AesGcm.TagByteSizes.MaxSize.ToString());
            Console.WriteLine("AesGcm --> NonceByteSizes: {0}", AesGcm.NonceByteSizes.MaxSize.ToString());

            using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);

            // For AES-GCM, the nonce must be 96-bits (12-bytes) in length
            var nonce = Utils.RandomByte(AesGcm.NonceByteSizes.MaxSize); // Generate a new, random nonce

            var cipherText = new byte[plaintext.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // tag size = 16

            // Optional: Associated Data (authentication only, not encrypted)
            // byte[] associatedData = Encoding.UTF8.GetBytes("Additional authenticated data");

            aes.Encrypt(nonce, plaintext, cipherText, tag);

            var encryptedData = new byte[nonce.Length + tag.Length + cipherText.Length];

            // Returns a concatenation of [nonce], [cipherText] and [mac]
            Array.Copy(nonce, 0, encryptedData, 0, nonce.Length);
            Array.Copy(cipherText, 0, encryptedData, nonce.Length, cipherText.Length);
            Array.Copy(tag, 0, encryptedData, nonce.Length + cipherText.Length, tag.Length);

            // Utils.PrintByteArray(nonce);
            // Utils.PrintByteArray(cipherText);
            // Utils.PrintByteArray(tag);
            // Console.WriteLine("cipherText length: {0}", cipherText.Length);

            // Contains ciphertext, nonce, and MAC (tag)
            return encryptedData;
        }

        public static TResult? AesGcmDecrypt<TResult>(byte[] encryptedData, byte[] key) where TResult : notnull
        {
            var aesGcmKeyData = GetNonceAndEncryptedData(encryptedData);

            using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);

            var plaintextBytes = new byte[aesGcmKeyData.CipherText.Length];

            aes.Decrypt(aesGcmKeyData.Nonce, aesGcmKeyData.CipherText, aesGcmKeyData.Tag, plaintextBytes);

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

        public static string AesGcmDecrypt(byte[] encryptedData, byte[] key)
        {
            var aesGcmKeyData = GetNonceAndEncryptedData(encryptedData);

            using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);

            var plaintextBytes = new byte[aesGcmKeyData.CipherText.Length];

            aes.Decrypt(aesGcmKeyData.Nonce, aesGcmKeyData.CipherText, aesGcmKeyData.Tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        // return byte array
        // public static byte[] AesGcmDecryptToByte(byte[] ciphertext, byte[] key)
        // {
        //     var aesGcmKeyData = GetNonceAndEncryptedData(ciphertext);

        //     using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);

        //     var plaintextBytes = new byte[aesGcmKeyData.EncryptedData.Length];

        //     aes.Decrypt(aesGcmKeyData.Nonce, aesGcmKeyData.EncryptedData, aesGcmKeyData.Tag, plaintextBytes);

        //     return plaintextBytes;
        // }

        public static AesGcmKeyData GetNonceAndEncryptedData(byte[] encryptedData)
        {
            // Separate --> Nonce (12 Bytes) | Ciphertext (* Bytes) | Tag (16 Bytes)

            var nonce = new byte[12];
            var tag = new byte[16];
            var cipherText = new byte[encryptedData.Length - nonce.Length - tag.Length];

            Array.Copy(encryptedData, 0, nonce, 0, nonce.Length);
            Array.Copy(encryptedData, nonce.Length, cipherText, 0, cipherText.Length);
            Array.Copy(encryptedData, nonce.Length + cipherText.Length, tag, 0, tag.Length);

            Utils.PrintByteArray(nonce);
            Utils.PrintByteArray(cipherText);
            Utils.PrintByteArray(tag);

            return new AesGcmKeyData
            {
                CipherText = cipherText,
                Nonce = nonce,
                Tag = tag
            };
        }


        public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] nonce, byte[]? associatedData = null)
        {
            using (AesGcm aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
            {
                // Allocate space for ciphertext and tag
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize]; // Typically 16 bytes for AES-GCM

                if (nonce.Length == 0)
                {
                    nonce = Utils.RandomByte(AesGcm.NonceByteSizes.MaxSize); // Generate a new, random nonce
                }

                // Perform encryption
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

                // // Combine ciphertext and tag for storage/transmission
                // byte[] encryptedData = new byte[ciphertext.Length + tag.Length];
                // Buffer.BlockCopy(ciphertext, 0, encryptedData, 0, ciphertext.Length);
                // Buffer.BlockCopy(tag, 0, encryptedData, ciphertext.Length, tag.Length);

                // // Combine Nonce (12 Bytes) + Ciphertext (* Bytes) + Tag (16 Bytes)
                // byte[] combineData = new byte[nonce.Length + encryptedData.Length];
                // Buffer.BlockCopy(nonce, 0, combineData, 0, nonce.Length);
                // Buffer.BlockCopy(encryptedData, 0, combineData, nonce.Length, encryptedData.Length);

                byte[] encryptedData = new byte[nonce.Length + ciphertext.Length + tag.Length];
                Buffer.BlockCopy(nonce, 0, encryptedData, 0, nonce.Length);
                Buffer.BlockCopy(ciphertext, 0, encryptedData, nonce.Length, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, encryptedData, nonce.Length + ciphertext.Length, tag.Length);

                return encryptedData;
            }
        }

        // Decrypts ciphertext using AES-256 GCM
        public static byte[] Decrypt(byte[] encryptedData, byte[] key, byte[] nonce, byte[]? associatedData = null)
        {
            using (AesGcm aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
            {
                // // Separate ciphertext and tag
                // byte[] ciphertext = new byte[encryptedData.Length - AesGcm.TagByteSizes.MaxSize];
                // byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
                // Buffer.BlockCopy(encryptedData, 0, ciphertext, 0, ciphertext.Length);
                // Buffer.BlockCopy(encryptedData, ciphertext.Length, tag, 0, tag.Length);

                var secret = SeparateEncryptedData(encryptedData);

                // Allocate space for plaintext
                byte[] plaintext = new byte[secret.CipherText.Length];

                // Perform decryption and tag verification
                aesGcm.Decrypt(secret.Nonce, secret.CipherText, secret.Tag, plaintext, associatedData);

                return plaintext;
            }
        }

        public static AesGcmKeyData SeparateEncryptedData(byte[] encryptedData)
        {
            // Separate --> Nonce (12 Bytes) | Ciphertext (* Bytes) | Tag (16 Bytes)

            byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            byte[] ciphertext = new byte[encryptedData.Length - AesGcm.TagByteSizes.MaxSize - AesGcm.NonceByteSizes.MaxSize];
            byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
            
            Buffer.BlockCopy(encryptedData, 0, nonce, 0, nonce.Length);
            Buffer.BlockCopy(encryptedData, nonce.Length, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(encryptedData, nonce.Length + ciphertext.Length, tag, 0, tag.Length);

            Console.WriteLine("AesGcm --> nonce (length): {0} bytes", nonce.Length.ToString());
            Console.WriteLine("AesGcm --> ciphertext (length): {0} bytes", ciphertext.Length.ToString());
            Console.WriteLine("AesGcm --> tag (length): {0} bytes", tag.Length.ToString());

            return new AesGcmKeyData
            {
                CipherText = ciphertext,
                Nonce = nonce,
                Tag = tag
            };
        }
    }
}