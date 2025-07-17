using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ApiGateway.Enum;
using ApiGateway.Helper.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace ApiGateway.Helper
{
    public static class KeyId
    {
        public static string GenKeyId(KeyIdType keyIdType = KeyIdType.SHA256)
        {
            var keyId = string.Empty;  

            var randomByte = Utils.RandomByte();          

            switch (keyIdType)
            {
                case KeyIdType.SHA256:

                    using (SHA256 hash = SHA256.Create())
                    {
                        keyId = Convert.ToHexString(hash.ComputeHash(randomByte));
                    }

                    break;

                case KeyIdType.HmacSha256:

                    keyId = HmacSha256Helper.ComputeHmacSha256(Guid.NewGuid().ToString(), Convert.ToHexString(randomByte));

                    break;

                case KeyIdType.GUID:

                    keyId = Guid.NewGuid().ToString();

                    break;
            }

            return keyId;
        }        
        
        public static string SignKeyId(string keyId, KeyIdSigningType keyIdSigningType = KeyIdSigningType.None)
        {
            using SHA256 Hash = SHA256.Create();

            DateTime localDate = DateTime.Now;

            // var sb = new StringBuilder();
            // sb.Append(keyId);
            // sb.Append(Convert.ToHexString(Hash.ComputeHash(Encoding.UTF8.GetBytes(localDate.ToString("MMddyyyyHHmmss")))));
            // keyId = sb.ToString();

            switch (keyIdSigningType)
            {
                case KeyIdSigningType.JWTWithHMAC:

                    var jwtSecretKey = Convert.FromBase64String("9PxBAw5rk3JqIQkV50VjX7Ek45YnmKoVmqutTs+GcH02Zs+d71tQEJJ0hMrUqsTnV71DYpGT4KQ40xrjATku2Q==");

                    var securityKey = new SymmetricSecurityKey(jwtSecretKey);
                    var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                    var claims = new List<Claim> {
                        new("keyId", keyId),
                        // new("keyId2", Convert.ToHexString(Hash.ComputeHash(Encoding.UTF8.GetBytes(localDate.ToString("MMddyyyyHHmmss"))))),
                    };

                    keyId = GenJwtTokenWithClaim(signingCredentials, localDate, claims);

                    break;

                case KeyIdSigningType.JWTWithRS256:

                    var rsaKeyIdByte = Utils.RandomByte();

                    var rsaKeyId = Encoding.ASCII.GetString(rsaKeyIdByte, 0, rsaKeyIdByte.Length);

                    var rsa = Utils.LoadRsaKey("./key/rsa/private_key.pem");

                    var rsaPrivateEncryptionKey = new RsaSecurityKey(rsa) { KeyId = rsaKeyId };
                    var signingCredentialsRS256 = new SigningCredentials(rsaPrivateEncryptionKey, SecurityAlgorithms.RsaSha256);

                    var claims2 = new List<Claim> {
                        new("keyId", keyId),
                        // new("keyId2", Convert.ToHexString(Hash.ComputeHash(Encoding.UTF8.GetBytes(localDate.ToString("MMddyyyyHHmmss"))))),
                    };

                    keyId = GenJwtTokenWithClaim(signingCredentialsRS256, localDate, claims2);

                    break;

                case KeyIdSigningType.JWTWithEC256:

                    var ecdsaKeyIdByte = Utils.RandomByte();

                    var ecdsaKeyId = Encoding.ASCII.GetString(ecdsaKeyIdByte, 0, ecdsaKeyIdByte.Length);

                    var ecdsa = Utils.LoadEcdsaKey("./key/ecdsa/private_key.pem");

                    var ecdsaPrivateEncryptionKey = new ECDsaSecurityKey(ecdsa) { KeyId = ecdsaKeyId };
                    var signingCredentialsES256 = new SigningCredentials(ecdsaPrivateEncryptionKey, SecurityAlgorithms.EcdsaSha256);

                    var claims3 = new List<Claim> {
                        new("keyId", keyId),
                        // new("keyId2", Convert.ToHexString(Hash.ComputeHash(Encoding.UTF8.GetBytes(localDate.ToString("MMddyyyyHHmmss"))))),
                    };

                    keyId = keyId = GenJwtTokenWithClaim(signingCredentialsES256, localDate, claims3);

                    break;

                    // default: 

                    // Example ====================
                    // var encryptionKey = RSA.Create(3072); // public key for encryption, private key for decryption
                    // var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // private key for signing, public key for validation

                    // byte[] encryptionKidByte = new byte[32];
                    // new Random().NextBytes(encryptionKidByte);

                    // byte[] signingKidByte = new byte[32];
                    // new Random().NextBytes(signingKidByte);

                    // var encryptionKid = Encoding.ASCII.GetString(encryptionKidByte, 0, encryptionKidByte.Length);
                    // var signingKid = Encoding.ASCII.GetString(signingKidByte, 0, signingKidByte.Length);

                    // Console.WriteLine("l1 | {0}", encryptionKid.Length);
                    // Console.WriteLine("l2 | {0}", signingKid.Length);

                    // var privateEncryptionKey = new RsaSecurityKey(encryptionKey) { KeyId = encryptionKid };
                    // var publicEncryptionKey = new RsaSecurityKey(encryptionKey.ExportParameters(false)) { KeyId = encryptionKid };
                    // var privateSigningKey = new ECDsaSecurityKey(signingKey) { KeyId = signingKid };
                    // var publicSigningKey = new ECDsaSecurityKey(ECDsa.Create(signingKey.ExportParameters(false))) { KeyId = signingKid };

            }

            return keyId;
        }

        private static string GenJwtTokenWithClaim(SigningCredentials signingCredentials, DateTime localDate, List<Claim> claims)
        {
            claims.Add(new(JwtRegisteredClaimNames.Sub, "Key id"));
            claims.Add(new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

            var token2 = new JwtSecurityToken(
                notBefore: localDate,
                expires: localDate.AddMinutes(30),
                signingCredentials: signingCredentials,
                claims: claims
            );

            return new JwtSecurityTokenHandler().WriteToken(token2);
        }

        public static string SignPublicKey(byte[] data, ECDHPublicKeySigningType ecdhPublicKeySigningType = ECDHPublicKeySigningType.None)
        {
            string signature = string.Empty;

            switch (ecdhPublicKeySigningType)
            {
                case ECDHPublicKeySigningType.RSA:

                    var rsa = Utils.LoadRsaKey("./key/rsa/private_key.pem");

                    var rsaSignature = rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

                    signature = Convert.ToBase64String(rsaSignature);

                    break;

                case ECDHPublicKeySigningType.ECDSA:

                    var ecdsa = Utils.LoadEcdsaKey("./key/ecdsa/private_key.pem");

                    var ecdsaSignature = ecdsa.SignData(data, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);

                    signature = Convert.ToBase64String(ecdsaSignature);

                    break;
            }

            return signature;
        }        
    }
}