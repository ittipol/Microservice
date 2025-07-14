using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace ApiGateway.Helper.Cryptography
{
    public static class JwtHelper
    {
        public static bool IsValidToken(HttpContext context, byte[] secretKey)
        {
            var result = false;

            var bearerToken = context.Request.Headers.Authorization.ToString();

            var strVal = bearerToken.Split(' ');

            if (strVal.Length == 2)
            {
                var token = strVal[1];
                result = JwtHmacSha256Verify(token, secretKey);
            }

            return result;
        }

        public static string GetId(string token, byte[] secretKey)
        {
            var id = string.Empty;

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(secretKey),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                if (principal != null)
                {
                    id = principal.Claims.FirstOrDefault(c => c.Type.Equals("id"))?.Value ?? "";

                    Console.WriteLine($"id: {id}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"JWT Verify Type: {ex.GetType()}");
                Console.WriteLine($"JWT Verify error: {ex.Message}");
            }

            return id;
        }

        public static bool JwtHmacSha256Verify(string token, byte[] secretKey)
        {
            var result = false;
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(secretKey),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                if (principal != null)
                {
                    foreach (var item in principal.Claims)
                    {
                        Console.WriteLine($"Claims: {item.Type} : {item.Value}");
                    }
                }

                result = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"JWT Verify Type: {ex.GetType()}");
                Console.WriteLine($"JWT Verify error: {ex.Message}");
            }

            Console.WriteLine($"JwtHmacSha256Verify Verify: {result}");

            return result;
        }

        public static bool JwtRsaShaVerify(RSA rsa, string token)
        {
            var result = false;
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new RsaSecurityKey(rsa),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                if (principal != null)
                {
                    foreach (var item in principal.Claims)
                    {
                        Console.WriteLine($"Claims: {item.Type} : {item.Value}");
                    }
                }

                result = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"JWT Verify Type: {ex.GetType()}");
                Console.WriteLine($"JWT Verify error: {ex.Message}");
            }

            Console.WriteLine($"JwtRsaShaVerify Verify: {result}");

            return result;
        }

        public static bool JwtEcdsaShaVerify(ECDsa ecdsa, string token)
        {
            var result = false;
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new ECDsaSecurityKey(ecdsa),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                if (principal != null)
                {
                    foreach (var item in principal.Claims)
                    {
                        Console.WriteLine($"Claims: {item.Type} : {item.Value}");
                    }
                }

                result = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"JWT Verify Type: {ex.GetType()}");
                Console.WriteLine($"JWT Verify error: {ex.Message}");
            }

            Console.WriteLine($"JwtEcdsaShaVerify Verify: {result}");

            return result;
        }
    }
}