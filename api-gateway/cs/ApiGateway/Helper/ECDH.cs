using System.Security.Cryptography;
using System.Text;
using ApiGateway.Enum;

namespace ApiGateway.Helper.Cryptography
{
    public static class ECDHHelper
    {    
        public static byte[] MergeEcPoint(byte[] x, byte[] y)
        {
            var ecPoint = new byte[x.Length + y.Length + 1];

            var c = 0;

            ecPoint[c++] = 4;

            for (int i = 0; i < x.Length; i++)
            {
                ecPoint[c++] = x[i];
            }            

            for (int i = 0; i < y.Length; i++)
            {
                ecPoint[c++] = y[i];
            }

            // ecPoint[0] = 4;
            // Array.Copy(x, 0, ecPoint, 1, x.Length);
            // Array.Copy(y, 0, ecPoint, x.Length + 1, y.Length);

            return ecPoint;
        }

        public static byte[] ExportPublicKey(ECDiffieHellman ecdh)
        {
            var param = ecdh.ExportParameters(true);
            var ecPointX = param.Q.X ?? [];
            var ecPointY = param.Q.Y ?? [];

            var ecPoint = MergeEcPoint(ecPointX, ecPointY);

            Console.WriteLine("ecPointX length ---> [{0}]", ecPointX.Length);
            Console.WriteLine("ecPointY length ---> [{0}]", ecPointY.Length);
            Console.WriteLine("ecPoint (public key) length ---> [{0}]", ecPoint.Length);

            return ecPoint;
        }

        public static ECDiffieHellmanPublicKey ImportPublicKey(string publicKey)
        {
            var publicKeyBytes = Convert.FromHexString(publicKey);

            // P-256 --> Curve which implements NIST P-256 (FIPS 186-3, section D.2.3), also known as secp256r1 or prime256v1
            var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ecdh.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                // D = privateKeyBytes, // optional (private keys only)
                Q = new ECPoint
                {
                    X = publicKeyBytes.Skip(1).Take(32).ToArray(),
                    Y = publicKeyBytes.Skip(33).ToArray()
                }
            });

            return ecdh.PublicKey;
        }
    }
}