using System.Security.Cryptography;
using System.Text;

namespace ApiGateway.Helper.Cryptography
{
    public static class Utils
    {
        public static byte[] RandomByte(int length = 32)
        {
            byte[] bytes = new byte[length];
            new Random().NextBytes(bytes);

            return bytes;
        }
        public static byte[] HexToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static RSA LoadRsaKey(string rsaKeyPath)
        {
            var rsa = RSA.Create();
            if (!File.Exists(rsaKeyPath))
            {
                throw new FileNotFoundException("RSA key file not found", rsaKeyPath);
            }
            var pemContents = File.ReadAllText(rsaKeyPath);
            rsa.ImportFromPem(pemContents.ToCharArray());

            return rsa;
        }

        public static ECDsa LoadEcdsaKey(string ecdsaKeyPath)
        {
            var ecdsa = ECDsa.Create();
            if (!File.Exists(ecdsaKeyPath))
            {
                throw new FileNotFoundException("ECDsa key file not found", ecdsaKeyPath);
            }
            var pemContents = File.ReadAllText(ecdsaKeyPath);
            ecdsa.ImportFromPem(pemContents.ToCharArray());

            return ecdsa;
        }

        public static bool RSAVerify(RSA rsa, byte[] data, byte[] signature)
        {
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        public static bool EcdsaVerify(ECDsa ecdsa, byte[] data, byte[] signature)
        {
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);
        }

        public static void PrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("print ---> byte[] { ");
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("}");
            Console.WriteLine(sb.ToString());
        }
    }
}