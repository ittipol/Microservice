using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
                result = Verify(token, secretKey);
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
                var x = ex.GetType();
                Console.WriteLine($"JWT Verify Type: {x}");
                Console.WriteLine($"JWT Verify error: {ex.Message}");
            }

            return id;
        }

        private static bool Verify(string token, byte[] secretKey)
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
                    var id = principal.Claims.FirstOrDefault(c => c.Type.Equals("id"))?.Value;

                    Console.WriteLine($"id: {id}");

                    // foreach (var claim in principal.Claims) {
                    //     Console.WriteLine($"claim: {claim}");
                    //     Console.WriteLine($"Type: {claim.Type}");
                    //     Console.WriteLine($"-----");
                    // }
                }

                // Console.WriteLine($"principal: {principal}");
                // Console.WriteLine($"validatedToken: {validatedToken}");

                result = true;
            }
            catch (Exception ex)
            {
                var x = ex.GetType();
                Console.WriteLine($"JWT Verify Type: {x}");
                Console.WriteLine($"JWT Verify error: {ex.Message}");
            }

            // var roleClaim = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            Console.WriteLine($"JWT Verify: {result}");

            return result;
        }
    }
}