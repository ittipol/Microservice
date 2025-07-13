using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using ApiGateway.Enum;
using ApiGateway.Helper;
using ApiGateway.Helper.Cryptography;
using ApiGateway.Model;
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
                    var id = JwtHelper.GetId(token, jwtSecretKey);

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
                    bytes = AESHelper.Decrypt(cipherBytes, key, iv);
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
                    var cipherBytes = AESHelper.Encrypt(plaintextBytes, key, iv);
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
    // app.Map("/ecdh", async context =>
    // {
    //     // ECCurve: NIST P-256 (FIPS 186-3, section D.2.3), also known as secp256r1 or prime256v1

    //     var headers = context.Request.Headers;

    //     var pubKeyFound = headers.ContainsKey("public-key");
    //     Console.WriteLine($"pubKeyFound: {pubKeyFound}");

    //     using var reader = new StreamReader(context.Request.Body);

    //     var body = await reader.ReadToEndAsync();
    //     Console.WriteLine($"body: {body}");

    //     // var c = new ECParameters
    //     // {
    //     //     Curve = ECCurve.NamedCurves.nistP256, // you'd need to know the curve before hand
    //     //     D = privateKeyBytes,
    //     //     Q = new ECPoint
    //     //     {
    //     //         X = publicKeyBytes.Skip(1).Take(32).ToArray(),
    //     //         Y = publicKeyBytes.Skip(33).ToArray()
    //     //     }
    //     // };

    //     // Client
    //     using var client = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    //     byte[] clientPublicKey = client.PublicKey.ExportSubjectPublicKeyInfo();

    //     // Server
    //     using var server = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    //     server.KeySize = 256;
    //     server.GenerateKey(ECCurve.NamedCurves.nistP256);

    //     var ecParamters = server.ExportParameters(true);

    //     // Private Key
    //     byte[] privateKey = ecParamters.D;
    //     Console.WriteLine("privateKey ---> {0}", privateKey.Length);

    //     // Public key params
    //     ECPoint publicKey = ecParamters.Q;

    //     byte[] publicKeyX = publicKey.X;
    //     byte[] publicKeyY = publicKey.Y;

    //     Console.WriteLine("publicKeyX ---> {0}", publicKeyX.Length);

    //     Console.WriteLine("publicKeyY ---> {0}", publicKeyY.Length);


    //     var x = server.PublicKey.ExportSubjectPublicKeyInfo();
    //     Console.WriteLine("xxxx ---> {0}", x.Length);
    //     Console.WriteLine("xxxx ---> {0}", server.PublicKey.ToString());

    //     // Fix for test
    //     // 04e33993f0210a4973a94c26667007d1b56fe886e8b3c2afdd66aa9e4937478ad20acfbdc666e3cec3510ce85d40365fc2045e5adb7e675198cf57c6638efa1bdb
    //     // 0403CEEFBFF158D68EFC150256E9694B20BE72FDC8B1971B0F6904B92C0D6765FEB5B6DA352CB71A95D4F00C527669E1EBE8CE5D9CDD8030F6EC9ABF76A9137C55
    //     // 04778aae16b613d212ddfc9d62cb5784d5c665746faea92d65b5699cd21b14fc75d4fd2e961d50e746334b1d5640700508fdda2a7658e266f4ec7ea53ea69d205a
    //     var clientPubKeyHex = "04e33993f0210a4973a94c26667007d1b56fe886e8b3c2afdd66aa9e4937478ad20acfbdc666e3cec3510ce85d40365fc2045e5adb7e675198cf57c6638efa1bdb";

    //     Console.WriteLine(Convert.ToHexString(clientPublicKey));
    //     Console.WriteLine(clientPubKeyHex);

    //     var b = Cryptography.HexToByteArray(clientPubKeyHex);

    //     Console.WriteLine("clientPublicKey: {0}", clientPublicKey.Length);
    //     Console.WriteLine("b: {0}", b.Length);

    //     // using var client2 = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    //     // client2.ImportSubjectPublicKeyInfo(clientPublicKey, out _);

    //     // // compute shared key
    //     // var sharedKey = server.DeriveKeyMaterial(client2.PublicKey);

    //     // Console.WriteLine(sharedKey.Length);
    //     // Console.WriteLine(Convert.ToBase64String(sharedKey));

    //     // // AES
    //     // byte[] plainBytes = Encoding.UTF8.GetBytes("Test");
    //     // var cipherBytes = Cryptography.Encrypt(plainBytes, sharedKey, iv);
    //     // await context.Response.WriteAsync(Convert.ToBase64String(cipherBytes));



    //     // ====================
    //     using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    //     server.KeySize = 256;
    //     server.GenerateKey(ECCurve.NamedCurves.nistP256);

    //     byte[] privatePkcs8Der = ecdsa.ExportPkcs8PrivateKey();
    //     byte[] privateSec1Der = ecdsa.ExportECPrivateKey();
    //     byte[] publicX509Der = ecdsa.ExportSubjectPublicKeyInfo();

    //     Console.WriteLine(privatePkcs8Der.Length);
    //     Console.WriteLine(privateSec1Der.Length);
    //     Console.WriteLine(publicX509Der.Length);
    //     // Console.WriteLine(p2.X.Length);

    //     await context.Response.WriteAsync("OK");
    // });

    app.Map("/ecdh", async context =>
    {
        // ECCurve: NIST P-256 (FIPS 186-3, section D.2.3), also known as secp256r1 or prime256v1

        var headers = context.Request.Headers;

        var pubKeyFound = headers.ContainsKey("public-key");
        Console.WriteLine($"pubKeyFound: {pubKeyFound}");

        using var reader = new StreamReader(context.Request.Body);

        var body = await reader.ReadToEndAsync();
        Console.WriteLine($"body: {body}");

        // Fix other party key pair for test
        var privateKey = "c711e5080f2b58260fe19741a7913e8301c1128ec8e80b8009406e5047e6e1ef";
        var publicKey = "04e33993f0210a4973a94c26667007d1b56fe886e8b3c2afdd66aa9e4937478ad20acfbdc666e3cec3510ce85d40365fc2045e5adb7e675198cf57c6638efa1bdb";

        var privateKeyBytes = Convert.FromHexString(privateKey);
        var publicKeyBytes = Convert.FromHexString(publicKey);

        Console.WriteLine("publicKeyBytes length ---> [{0}]", publicKeyBytes.Length);
        Console.WriteLine("publicKeyBytes first ---> [{0}]", publicKeyBytes[0]);

        // ===============================================================

        // Server
        var server = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        // server.KeySize = 256;
        // server.GenerateKey(ECCurve.NamedCurves.nistP256);

        var serverPublicKey = ECDHHelper.ExportPublicKey(server);

        // ===============================================================

        // Import client public (For test)
        var clientPublicKey = ECDHHelper.ImportPublicKey(publicKey);

        // ===============================================================

        // compute shared key
        var sharedKey = server.DeriveKeyMaterial(clientPublicKey);

        Console.WriteLine("sharedKey length {0}", sharedKey.Length);
        Console.WriteLine(Convert.ToBase64String(sharedKey));

        // AES (for test)
        // byte[] plainBytes = Encoding.UTF8.GetBytes("Test");
        // var cipherBytes = Cryptography.Encrypt(plainBytes, sharedKey, iv);
        // await context.Response.WriteAsync(Convert.ToBase64String(cipherBytes));

        // save SharedKey and KeyId in redis
        //

        // ===============================================================

        string jsonString = JsonSerializer.Serialize(new KeyMaterial
        {
            PublicKey = Convert.ToHexString(serverPublicKey),
            SharedKey = Convert.ToBase64String(sharedKey), // send to client for test key matching
            KeyId = KeyId.GenKeyId(true, KeyIdSigningType.JWSWithRSA)
        });

        await context.Response.WriteAsJsonAsync(jsonString);
    });

    app.Map("/encrypt", async context =>
    {
        using var reader = new StreamReader(context.Request.Body);
                
        var body = await reader.ReadToEndAsync();
        Console.WriteLine($"body (plain-text): {body}");

        // byte[] key = new byte[32];  // 32-byte, 256bit
        // new Random().NextBytes(key);
        // byte[] iv = new byte[16];  // 16-byte initialization vector
        // new Random().NextBytes(iv); // randomize the IV

        byte[] plainBytes = Encoding.UTF8.GetBytes(body);

        var cipherBytes = AESHelper.Encrypt(plainBytes, key, iv);
        await context.Response.WriteAsync(Convert.ToBase64String(cipherBytes));
    });

    app.Map("/decrypt", async context =>
    {
        using var reader = new StreamReader(context.Request.Body);
                
        var body = await reader.ReadToEndAsync();
        Console.WriteLine($"body (encrypted): {body}");

        var cipherBytes = Convert.FromBase64String(body);

        byte[] decryptedBytes = AESHelper.Decrypt(cipherBytes, key, iv);
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