using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using ApiGateway;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

var useEncryption = builder.Configuration.GetSection("UseEncryption").Get<bool>();
var key = Convert.FromBase64String(builder.Configuration.GetSection("AES:Secret").Get<string>() ?? "");
var iv = Convert.FromBase64String(builder.Configuration.GetSection("AES:IV").Get<string>() ?? "");
var jwtSecretKey = Convert.FromBase64String(builder.Configuration.GetSection("Jwt:Secret").Get<string>() ?? "");

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(transforms => {

        transforms.AddRequestTransform(async context =>
        {            
            if (context.HttpContext.User.Identity!.IsAuthenticated)
            {
                // Extract the JWT token from the incoming request
                var token = await context.HttpContext.GetTokenAsync("access_token");

                // Add the token to the outgoing request headers
                if (!string.IsNullOrEmpty(token))
                {
                    var id = JwtUtil.GetId(token, jwtSecretKey);

                    context.ProxyRequest.Headers.Add("id", id);

                    // context.ProxyRequest.Headers.Authorization =
                    //     new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                }
            }

            context.ProxyRequest.Headers.Remove("Authorization");

            using var reader = new StreamReader(context.HttpContext.Request.Body);
            
            var body = await reader.ReadToEndAsync();
            if (!string.IsNullOrEmpty(body))
            {                
                Console.WriteLine($"AddRequestTransform [origin]: {body}");

                byte[]? bytes = null;

                if(useEncryption)
                {
                    var cipherBytes = Convert.FromBase64String(body);
                    bytes = Cryptography.Decrypt(cipherBytes, key, iv);
                    Console.WriteLine($"AddRequestTransform [Decrypt]: {Encoding.UTF8.GetString(bytes)}");
                    // body = Encoding.UTF8.GetString(bytes);
                }
                else
                {
                    // body = body.Replace("Data", "value");
                    bytes = Encoding.UTF8.GetBytes(body);
                }

                // Change Content-Length to match the modified body, or remove it
                context.HttpContext.Request.Body = new MemoryStream(bytes);
                // Request headers are copied before transforms are invoked, update any
                // needed headers on the ProxyRequest
                context.ProxyRequest.Content!.Headers.ContentLength = bytes.Length;
            }
        });

        transforms.AddResponseTransform(async responseContext =>
        {
            responseContext.HttpContext.Response.Headers.Append("key", "value");
            responseContext.HttpContext.Response.Headers.Remove(HeaderNames.CacheControl);

            var stream = await responseContext.ProxyResponse!.Content.ReadAsStreamAsync();
            using var reader = new StreamReader(stream);
            
            var body = await reader.ReadToEndAsync();

            if (!string.IsNullOrEmpty(body))
            {            
                byte[]? bytes = null;

                if(useEncryption)
                {
                    var plaintextBytes = Encoding.UTF8.GetBytes(body);
                    var cipherBytes = Cryptography.Encrypt(plaintextBytes, key, iv);
                    var base64 = Convert.ToBase64String(cipherBytes);
                    Console.WriteLine($"AddResponseTransform [Encrypt]: {base64}");
                    bytes = Encoding.UTF8.GetBytes(base64);
                }
                else
                {
                    // body = body.Replace("Bravo", "Charlie");
                    bytes = Encoding.UTF8.GetBytes(body);
                }

                responseContext.SuppressResponseBody = true;
                
                // Change Content-Length to match the modified body, or remove it
                responseContext.HttpContext.Response.ContentLength = bytes.Length;
                // Response headers are copied before transforms are invoked, update
                // any needed headers on the HttpContext.Response
                await responseContext.HttpContext.Response.Body.WriteAsync(bytes);
            }            
        });
    });

// builder.Services.AddDataProtection().UseCryptographicAlgorithms(
//     new AuthenticatedEncryptorConfiguration
//     {
//         EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
//         ValidationAlgorithm = ValidationAlgorithm.HMACSHA256
//     });

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(jwtSecretKey),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            ValidTypes = ["JWT"]
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(options => {

    // options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.OnRejected = async (context, cancellationToken) =>
    {
        // Custom rejection handling logic
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.Headers["Retry-After"] = "300";

        await context.HttpContext.Response.WriteAsync("Rate limit exceeded. Please try again later.", cancellationToken);
    };

    // Policy #1 
    options.AddPolicy("FixedWindow", context => 
        RateLimitPartition.GetFixedWindowLimiter(
            // partitionKey: context.Request.Path,           
            // partitionKey: context.Connection.RemoteIpAddress?.ToString(), // By IP Address
            // partitionKey: httpContext.User.Identity?.Name ?? "anonymous", // By User Identity
            partitionKey: context.User.Identity?.Name ?? context.Request.Headers.Host.ToString(),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 10,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(5)
                // QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            }
        )
    );

    // Policy #2
    options.AddTokenBucketLimiter("token", options =>
    {
        options.TokenLimit = 10;
        options.ReplenishmentPeriod = TimeSpan.FromMinutes(1);
        options.TokensPerPeriod = 1;
        options.AutoReplenishment = true;
    });
});

var app = builder.Build();

app.UseRouting();

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapReverseProxy(proxyPipeline => {
    proxyPipeline.Use((context, next) =>
    {
        // Custom inline middleware

        // var x = context.Request.Path;
        // Console.WriteLine($"[middleware] Path: {x}");

        // if(!x.Equals("/auth/login")) {
        //     if(!ApiGateway.JwtUtil.IsValidToken(context, secretKey)) {
        //         context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        //         return context.Response.WriteAsync("Unauthorized");
        //     }
        // }                

        // context.Request.Headers.Append("id", "value");

        return next();
    });
})
.RequireAuthorization();

app.Map("/health", async context =>
{
    await context.Response.WriteAsync("OK");
});

if(app.Environment.IsDevelopment())
{
    app.Map("/encrypt", async context =>
    {
        using var reader = new StreamReader(context.Request.Body);
                
        var body = await reader.ReadToEndAsync();
        Console.WriteLine($"encrypt body: {body}");

        // byte[] key = new byte[32];  // 32-byte, 256bit
        // new Random().NextBytes(key);
        // byte[] iv = new byte[16];  // 16-byte initialization vector
        // new Random().NextBytes(iv); // randomize the IV

        byte[] plainBytes = Encoding.UTF8.GetBytes(body);

        var cipherBytes = Cryptography.Encrypt(plainBytes, key, iv);
        await context.Response.WriteAsync(Convert.ToBase64String(cipherBytes));
    });

    app.Map("/decrypt", async context =>
    {
        using var reader = new StreamReader(context.Request.Body);
                
        var body = await reader.ReadToEndAsync();
        Console.WriteLine($"decrypt body: {body}");

        var cipherBytes = Convert.FromBase64String(body);

        byte[] decryptedBytes = Cryptography.Decrypt(cipherBytes, key, iv);
        await context.Response.WriteAsync(Encoding.UTF8.GetString(decryptedBytes));
    });

    app.Map("/token", async context =>
    {
        DateTime localDate = DateTime.Now;
        // DateTime utcDate = DateTime.UtcNow;

        var securityKey = new SymmetricSecurityKey(jwtSecretKey);
        var creds = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        // var claims = new[] {
        //     new Claim("id", "1"),
        //     new Claim(JwtRegisteredClaimNames.Sub, "test"),            
        //     new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        // };

        var claims = new List<Claim> {
            new("id", "1"),
            new(JwtRegisteredClaimNames.Sub, "test"),            
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            notBefore: localDate,
            expires: localDate.AddMinutes(30),
            signingCredentials: creds,
            claims: claims
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        await context.Response.WriteAsync(tokenString);
    });
}

app.Run();

namespace ApiGateway
{
    public static class JwtUtil
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
                
                if (principal != null) {
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
                
                if (principal != null) {
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

    public static class Cryptography
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