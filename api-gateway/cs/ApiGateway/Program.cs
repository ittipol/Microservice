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
using StackExchange.Redis;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

var encryptionConfig = builder.Configuration.GetSection("Encryption").Get<EncryptionConfig>();
var jwtSecretKey = Convert.FromBase64String(builder.Configuration.GetSection("JwtHmacSha256:Secret").Get<string>() ?? "");

if (encryptionConfig == null)
{
    Environment.Exit(0);
}

var redisConn = new ConfigurationOptions
{
    AbortOnConnectFail = false,
    User = "",
    Password = Encoding.ASCII.GetString(Convert.FromBase64String("cGFzc3dvcmQ=")),
    Ssl = false,
    AsyncTimeout = 30000,
    SyncTimeout = 10000,
    ClientName = Environment.MachineName
};

redisConn.EndPoints.Add("localhost:6379");

IConnectionMultiplexer redis = ConnectionMultiplexer.Connect(redisConn);
IDatabase db = redis.GetDatabase();
// redis.Close();

var connected = db.Ping();
Console.WriteLine("Caching test: {0}", connected);

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(transforms => {

        transforms.AddRequestTransform(async context =>
        {
            Console.WriteLine("\n\n::::::::====================================================== request id, {0} ===============", context.HttpContext.Connection.Id);
            Console.WriteLine($"AddRequestTransform [Method]: {context.HttpContext.Request.Method}");
            Console.WriteLine($"AddRequestTransform [Path]: {context.HttpContext.Request.Path}");

            var session = context.HttpContext.Session;

            if (context.HttpContext.User.Identity!.IsAuthenticated)
            {
                // Extract the JWT token from the incoming request
                var token = await context.HttpContext.GetTokenAsync("access_token");

                // Add the token to the outgoing request headers
                if (!string.IsNullOrEmpty(token))
                {
                    var id = JwtHelper.GetId(token, jwtSecretKey);

                    // Add id to request header
                    context.ProxyRequest.Headers.Add("id", id);

                    // context.ProxyRequest.Headers.Authorization =
                    //     new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                }
            }

            // Remove Authorization from request header
            context.ProxyRequest.Headers.Remove("Authorization");

            using var reader = new StreamReader(context.HttpContext.Request.Body);
            var body = await reader.ReadToEndAsync();

            Console.WriteLine($"AddRequestTransform [origin]: {body}");

            byte[]? bytes = null;

            var sharedKey = session.GetString("key") ?? "";
            Console.WriteLine($"AddRequestTransform [sharedKey]: {sharedKey}");

            if (!string.IsNullOrEmpty(body))
            {
                try
                {
                    if (sharedKey != "")
                    {
                        var keyBytes = Convert.FromBase64String(sharedKey);
                        var cipherBytes = Convert.FromBase64String(body);

                        bytes = AESGCMHelper.AesGcmDecrypt<byte[]>(cipherBytes, keyBytes);
                        Console.WriteLine($"AddRequestTransform [Decrypt]: {Encoding.UTF8.GetString(bytes)}");
                    }
                    else if (!string.IsNullOrEmpty(body))
                    {
                        // body = body.Replace("Data", "value");
                        bytes = Encoding.UTF8.GetBytes(body);
                    }
                }
                catch (Exception)
                {
                    context.ProxyRequest.Dispose();
                    context.HttpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    await context.HttpContext.Response.WriteAsync(StatusCodes.Status500InternalServerError.ToString());
                    return;
                }
            }

            if (bytes != null)
            {
                // Change Content-Length to match the modified body, or remove it
                context.HttpContext.Request.Body = new MemoryStream(bytes);
                // Request headers are copied before transforms are invoked, update any
                // needed headers on the ProxyRequest
                context.ProxyRequest.Content!.Headers.ContentLength = bytes.Length;
            }            
            
        });

        transforms.AddResponseTransform(async context =>
        {
            Console.WriteLine("\n\n::::::::====================================================== response id, {0} ===============", context.HttpContext.Connection.Id);
            Console.WriteLine("response [CancellationToken], {0}", context.CancellationToken.IsCancellationRequested);
            
            var session = context.HttpContext.Session;

            // context.HttpContext.Response.Headers.Append("key", "value"); // example for adding header

            // Remove some header
            context.HttpContext.Response.Headers.Remove(HeaderNames.CacheControl);

            var stream = await context.ProxyResponse!.Content.ReadAsStreamAsync();
            using var reader = new StreamReader(stream);
            var body = await reader.ReadToEndAsync();

            Console.WriteLine($"AddResponseTransform [origin]: {body}");

            byte[]? bytes = null;

            var sharedKey = session.GetString("key") ?? "";
            Console.WriteLine($"AddResponseTransform [sharedKey]: {sharedKey}");

            if (!string.IsNullOrEmpty(body))
            {
                try
                {
                    if (sharedKey != "")
                    {
                        var keyBytes = Convert.FromBase64String(sharedKey);
                        var plaintextBytes = Encoding.UTF8.GetBytes(body);

                        var cipherBytes = AESGCMHelper.AesGcmEncrypt(plaintextBytes, keyBytes);

                        var base64 = Convert.ToBase64String(cipherBytes);
                        Console.WriteLine($"AddResponseTransform [Encrypted data]: {base64}");

                        bytes = Encoding.UTF8.GetBytes(base64);
                    }
                    else if (!string.IsNullOrEmpty(body))
                    {
                        // body = body.Replace("data", "new-data");
                        bytes = Encoding.UTF8.GetBytes(body);
                    }
                }
                catch (Exception)
                {
                    context.ProxyResponse.Dispose();
                    context.HttpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    await context.HttpContext.Response.WriteAsync(StatusCodes.Status500InternalServerError.ToString());
                    return;
                }                                    
            }

            if (bytes != null)
            {
                context.SuppressResponseBody = true;

                // Change Content-Length to match the modified body, or remove it
                context.HttpContext.Response.ContentLength = bytes.Length;
                // Response headers are copied before transforms are invoked, update
                // any needed headers on the HttpContext.Response
                await context.HttpContext.Response.Body.WriteAsync(bytes);
            }
        });
    }
);

builder.Services.AddRequestTimeouts(options =>
{
    options.AddPolicy("customPolicy", TimeSpan.FromSeconds(30));
});

builder.Services.AddOutputCache(options =>
{
    options.AddPolicy("customPolicy", builder => builder.Expire(TimeSpan.FromSeconds(20)));
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

builder.Services.AddRateLimiter(options =>
{
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

// Add to access session
builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(60);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

app.UseRouting();

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.UseOutputCache();

// Add to access session
app.UseSession();

app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use(async (context, next) =>
    {
        var session = context.Session;        

        Console.WriteLine("\n\n# >>>>>>>>>>>>>>>>>>>>>>>>>>\t\tCustom inline middleware [Before request]");
        Console.WriteLine($"#\t[Before request] Session: {context.Session.Id}\n");
        await next();
        Console.WriteLine("\n\n#\t\tCustom inline middleware [After response]");

        session.Clear();
    });

    proxyPipeline.Use((context, next) =>
    {
        var session = context.Session;   
        
        // Custom inline middleware
        Console.WriteLine("\n\n#\t\tCustom inline middleware");
        Console.WriteLine($"#\t[middleware] Connection: {context.Connection.Id}");
        Console.WriteLine($"#\t[middleware] Session: {context.Session.Id}");
        Console.WriteLine($"#\t[middleware] Path: {context.Request.Path}\n");

        if (ConfigHelper.IsUsingEncryption(encryptionConfig, context))
        {
            Console.WriteLine($"#\t[middleware] IsUsingEncryption");
            var isKeyIdFound = context.Request.Headers.TryGetValue("key-id", out var keyId);

            Console.WriteLine($"#\t[middleware] [isKeyIdFound]: {isKeyIdFound}");
            Console.WriteLine($"#\t[middleware] [keyId]: {keyId}");
            Console.WriteLine($"#\t[middleware] [KeyExists]: {db.KeyExists(keyId.ToString())}"); ;

            if (isKeyIdFound && db.KeyExists(keyId.ToString()))
            {
                var key = db.StringGet(keyId.ToString()).ToString();

                if (key != "")
                {
                    // Save temporary data
                    session.SetString("key", key);    
                }                
            }
            else
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return context.Response.WriteAsync("keyId not found");
            }
        }

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
    
    // proxyPipeline.UseSessionAffinity();
    // proxyPipeline.UseLoadBalancing();
    // proxyPipeline.UsePassiveHealthChecks();
})
.RequireAuthorization();

app.Map("/health", async context =>
{
    await context.Response.WriteAsync("ok");
});

if (app.Environment.IsDevelopment())
{
    // app.Map("/ecdh", async context =>
    // {
    //     // ECCurve: NIST P-256 (FIPS 186-3, section D.2.3), also known as secp256r1 or prime256v1
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

        // Fix other party key pair for test
        var privateKey = "c711e5080f2b58260fe19741a7913e8301c1128ec8e80b8009406e5047e6e1ef";
        var publicKey = "04e33993f0210a4973a94c26667007d1b56fe886e8b3c2afdd66aa9e4937478ad20acfbdc666e3cec3510ce85d40365fc2045e5adb7e675198cf57c6638efa1bdb";
        // ===

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
        var sharedKey = server.DeriveRawSecretAgreement(clientPublicKey);

        Console.WriteLine("sharedKey length {0}", sharedKey.Length);
        Console.WriteLine(Convert.ToBase64String(sharedKey));

        // AES (for test)
        // byte[] plainBytes = Encoding.UTF8.GetBytes("Test");
        // var cipherBytes = Cryptography.Encrypt(plainBytes, sharedKey, iv);
        // await context.Response.WriteAsync(Convert.ToBase64String(cipherBytes));

        // save SharedKey and KeyId in redis
        //

        // ===============================================================

        var keyId = KeyId.GenKeyId(KeyIdType.HmacSha256);

        string jsonString = JsonSerializer.Serialize(new KeyMaterial
        {
            PublicKey = Convert.ToHexString(serverPublicKey),
            SignedPublicKey = KeyId.SignPublicKey(serverPublicKey, ECDHPublicKeySigningType.ECDSA),
            // SharedKey = Convert.ToBase64String(sharedKey), // send to client for test key matching
            KeyId = keyId,
            SignedKeyId = KeyId.SignKeyId(keyId, KeyIdSigningType.JWTWithEC256)
        });

        await context.Response.WriteAsJsonAsync(jsonString);
    });

    app.Map("/gen-ecdh", async context =>
    {
        var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var privateKeyHex = Convert.ToHexString(ECDHHelper.ExportPrivateKey(ecdh));
        var publicKeyHex = Convert.ToHexString(ECDHHelper.ExportPublicKey(ecdh));

        Console.WriteLine("privateKeyHex: [{0}]\n", privateKeyHex);
        Console.WriteLine("publicKeyHex: [{0}]\n", publicKeyHex);

        await context.Response.WriteAsync("OK");
    });

    app.Map("/compare-ecdh", async context =>
    {
        // var clientPrivateKeyHex = "467807F7DF955D00C6B5F56E157657312933793D7E4D2262D0D05A2C89B31090"; // Gen From CS
        var clientPrivateKeyHex = "c3ef6732ef04061b5e9d7b1fe7c80ab3b75be2b82522ee5c8b7bf0f84a08f2d8"; // Gen From Go
        var clientPublicKeyHexTest = "04e5e251bbcf7a3826bfa1ff928218c12066320c71b5e74743821dfea709592328ceb2b2383dd60c2b266bcd3418c6b3d9730cf59fe34ad4ecb8bb51c7f37d50ae";

        // var serverPrivateKeyHex = "B1F53D13D670338594E8158817B371DB50FF29E33CD0BEA60DFD6CED82C4AE34"; // Gen From CS
        var serverPrivateKeyHex = "7cea6b94017e734867b9e5571ecd011a4a40d73f48c6f99f9ccc46633ad4dd75"; // Gen From Go
        var serverPublicKeyHexTest = "04aecb0c26b8479149dad3634a9233e13f151b335f6429cd250da07eae093b9ebdf907f9736bc97b25ab9c8c4461f958256bd2eeb2edcc748d93844bd3526064ec";

        var clientPrivateKey = ECDHHelper.ImportPrivateKey(clientPrivateKeyHex);
        var serverPrivateKey = ECDHHelper.ImportPrivateKey(serverPrivateKeyHex);

        // Test export public key
        var clientPublicKeyHex = Convert.ToHexString(ECDHHelper.ExportPublicKey(clientPrivateKey));
        var serverPublicKeyHex = Convert.ToHexString(ECDHHelper.ExportPublicKey(serverPrivateKey));

        Console.WriteLine("clientPublicKeyHex: [{0}]\n", clientPublicKeyHex);
        Console.WriteLine("serverPublicKeyHex: [{0}]\n", serverPublicKeyHex);

        Console.WriteLine("clientPublicKeyHex match: \t[{0}]\n", clientPublicKeyHex.Equals(clientPublicKeyHexTest.ToUpper()));
        Console.WriteLine("serverPublicKeyHex match: \t[{0}]\n", serverPublicKeyHex.Equals(serverPublicKeyHexTest.ToUpper()));

        // ========================================================
        
        var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var clientSharedKey = serverPrivateKey.DeriveRawSecretAgreement(clientPrivateKey.PublicKey);
        var serverSharedKey = serverPrivateKey.DeriveRawSecretAgreement(clientPrivateKey.PublicKey);

        Console.WriteLine("clientSharedKey: {0}", Convert.ToBase64String(clientSharedKey));
        Console.WriteLine("serverSharedKey: {0}", Convert.ToBase64String(serverSharedKey));

        await context.Response.WriteAsync("OK");
    });

    app.Map("/test-ecdh", async context =>
    {   
        Console.WriteLine("---------------------------------------------------------------------------------------------------------");     
        var headers = context.Request.Headers;
        headers.TryGetValue("private-key", out var clientPrivateKeyHex);
        headers.TryGetValue("public-key", out var clientPublicKeyHex);

        // var clientPrivateKeyHex = "3e5645ca777e60e57bc449f7699797d6df7923a20fdb9a981d91d1b7aa377b7c";
        // var clientPublicKeyHex = "0419206e599f95b8df90de88d82b6da1570eb40c3004482cb91aa30f07d9c1fabe6c620e5d1cc73f82296554563051c05d2fcf42afe6d11f7192bb3b3296eb5a9b";

        Console.WriteLine("\nclientPrivateKeyHex: [{0}]", clientPrivateKeyHex);
        Console.WriteLine("clientPublicKeyHex: [{0}]\n", clientPublicKeyHex);

        // ======================================================
        var serverEcdhInit = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var serverPrivateKeyHex = Convert.ToHexString(ECDHHelper.ExportPrivateKey(serverEcdhInit));
        var serverPrivateKey = ECDHHelper.ImportPrivateKey(serverPrivateKeyHex);
        // ======================================================

        // ======================================================
        var clientPublicKey = ECDHHelper.ImportPublicKey(clientPublicKeyHex);
        // ======================================================

        // ======================================================
        var serverSharedKey = serverPrivateKey.DeriveRawSecretAgreement(clientPublicKey);
        // ======================================================

        // ======================================================
        // #1
        // var clientPrivateKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        // #2
        // var clientPrivateKey = Utils.LoadEcdhKey("./key/ecdsa/private_key.pem");
        // #3        
        var clientPrivateKey = ECDHHelper.ImportPrivateKey(clientPrivateKeyHex);
        // clientPrivateKey.PublicKey
        // ======================================================

        // ======================================================
        var serverPublicKeyHex = Convert.ToHexString(ECDHHelper.ExportPublicKey(serverPrivateKey));
        var serverPublicKey = ECDHHelper.ImportPublicKey(serverPublicKeyHex);
        // ======================================================

        // ======================================================
        // var clientSharedKey = clientPrivateKey.DeriveRawSecretAgreement(serverPrivateKey.PublicKey);
        var clientSharedKey = clientPrivateKey.DeriveRawSecretAgreement(serverPublicKey);
        // ======================================================

        Console.WriteLine("\nserverSharedKey: {0}", Convert.ToBase64String(serverSharedKey));
        Console.WriteLine("clientSharedKey: {0}", Convert.ToBase64String(clientSharedKey));
        Console.WriteLine("is match: {0}\n", Convert.ToBase64String(serverSharedKey) == Convert.ToBase64String(clientSharedKey));

        Console.WriteLine("serverPrivateKeyHex: [{0}]\n", serverPrivateKeyHex);
        Console.WriteLine("serverPublicKeyHex: [{0}]\n", serverPublicKeyHex);

        var jsonString = JsonSerializer.Serialize(new TestEcdhResponse
        {
            ServerPrivateKey = serverPrivateKeyHex,
            ServerPublicKey = serverPublicKeyHex,
            ServerSharedKey = Convert.ToBase64String(serverSharedKey)
        });

        await context.Response.WriteAsJsonAsync(jsonString);
    });

    app.Map("/key-exchange", async context =>
    {
        var headers = context.Request.Headers;

        var pubKeyFound = headers.ContainsKey("public-key");
        Console.WriteLine($"pubKeyFound: {pubKeyFound}");

        var jsonString = string.Empty;

        if (headers.TryGetValue("public-key", out var clientPublicKeyHex))
        {
            try
            {
                Console.WriteLine($"=============> \tclientPublicKeyHex: {clientPublicKeyHex}");

                var serverPrivateKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                var clientPublicKey = ECDHHelper.ImportPublicKey(clientPublicKeyHex);
                var serverSharedKey = serverPrivateKey.DeriveRawSecretAgreement(clientPublicKey);

                Console.WriteLine("sharedKey: {0}", Convert.ToBase64String(serverSharedKey));

                var keyId = KeyId.GenKeyId(KeyIdType.HmacSha256);

                Console.WriteLine("KeyId: {0}", keyId);

                var serverPublicKey = ECDHHelper.ExportPublicKey(serverPrivateKey);
                Console.WriteLine("serverPublicKey: {0}", Convert.ToHexString(serverPublicKey));

                // save shared key to storage
                // key:value
                // keyId : sharedKey
                // ============================================

                // AES encrypt
                var signingKey = new KeyData
                {
                    SignedPublicKey = KeyId.SignPublicKey(serverPublicKey, ECDHPublicKeySigningType.ECDSA),                    
                    KeyId = keyId,
                    SignedKeyId = KeyId.SignKeyId(keyId, KeyIdSigningType.JWTWithEC256)
                };

                var jsonStringByte = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(signingKey));
                var encryptedKeyData = AESGCMHelper.AesGcmEncrypt(jsonStringByte, serverSharedKey);

                // Test decrypt
                // AESGCMHelper.AesGcmDecrypt(encryptedKeyData, serverSharedKey);

                jsonString = JsonSerializer.Serialize(new KeyExchangeResponse
                {
                    PublicKey = Convert.ToHexString(serverPublicKey),
                    EncryptedKeyData = Convert.ToBase64String(encryptedKeyData),
                    SharedKey = Convert.ToBase64String(serverSharedKey), // send to client for test key matching
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                jsonString = JsonSerializer.Serialize(new KeyExchangeResponse());
            }
        }
        
        await context.Response.WriteAsJsonAsync(jsonString);
    });

    // app.Map("/encrypt", async context =>
    // {
    //     using var reader = new StreamReader(context.Request.Body);
                
    //     var body = await reader.ReadToEndAsync();
    //     Console.WriteLine($"body (plain-text): {body}");

    //     // byte[] key = new byte[32];  // 32-byte, 256bit
    //     // new Random().NextBytes(key);
    //     // byte[] iv = new byte[16];  // 16-byte initialization vector
    //     // new Random().NextBytes(iv); // randomize the IV

    //     byte[] plainBytes = Encoding.UTF8.GetBytes(body);

    //     var cipherBytes = AESHelper.Encrypt(plainBytes, key, iv);
    //     await context.Response.WriteAsync(Convert.ToBase64String(cipherBytes));
    // });

    // app.Map("/decrypt", async context =>
    // {
    //     using var reader = new StreamReader(context.Request.Body);
                
    //     var body = await reader.ReadToEndAsync();
    //     Console.WriteLine($"body (encrypted): {body}");

    //     var cipherBytes = Convert.FromBase64String(body);

    //     byte[] decryptedBytes = AESHelper.Decrypt(cipherBytes, key, iv);
    //     await context.Response.WriteAsync(Encoding.UTF8.GetString(decryptedBytes));
    // });

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