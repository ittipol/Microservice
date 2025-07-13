using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ApiGateway.Enum;
using Microsoft.IdentityModel.Tokens;

namespace ApiGateway.Helper
{
    public static class KeyId
    {        
        public static string GenKeyId(bool includeDateTime = false, KeyIdSigningType keyIdSigningType = KeyIdSigningType.None)
        {
            DateTime localDate = DateTime.Now;

            byte[] randomByte = new byte[32];
            new Random().NextBytes(randomByte);
            using SHA256 Hash = SHA256.Create();

            Console.WriteLine("Byte[0] ---> {0}", randomByte[0].ToString());
            Console.WriteLine(Hash.ComputeHash(randomByte).Length);

            // if (includeDateTime)
            // {
            //     Console.WriteLine(DateTime.Now.ToString("MMddyyyyHHmmss"));
            //     Console.WriteLine(Encoding.UTF8.GetBytes(DateTime.Now.ToString("MMddyyyyHHmmss")).Length);
            //     Console.WriteLine(Hash.ComputeHash(Encoding.UTF8.GetBytes(DateTime.Now.ToString("MMddyyyyHHmmss"))).Length);

            //     StringBuilder sb = new StringBuilder();
            //     sb.Append(Convert.ToHexString(Hash.ComputeHash(randomByte)));
            //     sb.Append(Convert.ToHexString(Hash.ComputeHash(Encoding.UTF8.GetBytes(DateTime.Now.ToString("MMddyyyyHHmmss")))));

            //     return sb.ToString();
            // }

            var keyId = Convert.ToHexString(Hash.ComputeHash(randomByte));
            
            var jwtSecretKey = Convert.FromBase64String("9PxBAw5rk3JqIQkV50VjX7Ek45YnmKoVmqutTs+GcH02Zs+d71tQEJJ0hMrUqsTnV71DYpGT4KQ40xrjATku2Q==");

            switch (keyIdSigningType)
            {
                case KeyIdSigningType.JWTWithHMAC:

                    var securityKey = new SymmetricSecurityKey(jwtSecretKey);
                    var creds = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                    var claims = new List<Claim> {
                        new("keyId", keyId),
                        new("keyId2", Convert.ToHexString(Hash.ComputeHash(Encoding.UTF8.GetBytes(localDate.ToString("MMddyyyyHHmmss"))))),
                        new(JwtRegisteredClaimNames.Sub, "Key id"),
                        new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };

                    var token = new JwtSecurityToken(
                        notBefore: localDate,
                        expires: localDate.AddMinutes(30),
                        signingCredentials: creds,
                        claims: claims
                    );

                    keyId = new JwtSecurityTokenHandler().WriteToken(token);

                    break;

                case KeyIdSigningType.JWSWithRSA:

                    var securityKey2 = new SymmetricSecurityKey(jwtSecretKey);
                    var creds2 = new SigningCredentials(securityKey2, SecurityAlgorithms.RsaSha256);

                    break;

                case KeyIdSigningType.ECDSA:

                    var encryptionKey = RSA.Create(3072); // public key for encryption, private key for decryption
                    var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // private key for signing, public key for validation

                    byte[] encryptionKidByte = new byte[32];
                    new Random().NextBytes(encryptionKidByte);

                    byte[] signingKidByte = new byte[32];
                    new Random().NextBytes(signingKidByte);

                    var encryptionKid = Encoding.ASCII.GetString(encryptionKidByte, 0, encryptionKidByte.Length);
                    var signingKid = Encoding.ASCII.GetString(signingKidByte, 0, signingKidByte.Length);

                    Console.WriteLine("l1 | {0}", encryptionKid.Length);
                    Console.WriteLine("l2 | {0}", signingKid.Length);

                    var privateEncryptionKey = new RsaSecurityKey(encryptionKey) { KeyId = encryptionKid };
                    var publicEncryptionKey = new RsaSecurityKey(encryptionKey.ExportParameters(false)) { KeyId = encryptionKid };
                    var privateSigningKey = new ECDsaSecurityKey(signingKey) { KeyId = signingKid };
                    var publicSigningKey = new ECDsaSecurityKey(ECDsa.Create(signingKey.ExportParameters(false))) { KeyId = signingKid };

                    break;

                    // default: 

            }

            return keyId;
        }
    }
}