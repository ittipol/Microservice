using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

// Console.WriteLine($"JWT: {builder.Configuration.GetSection("Jwt:Secret").Get<string>()}");

var secretKey = Convert.FromBase64String(builder.Configuration.GetSection("Jwt:Secret").Get<string>() ?? "");
// Console.WriteLine($"Key: {secretKey.Length}");

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(transforms => {
        transforms.AddRequestTransform(async context =>
        {            
            if (context.HttpContext.User.Identity!.IsAuthenticated)
            {
                // Extract the JWT token from the incoming request
                var token = await context.HttpContext.GetTokenAsync("access_token");
Console.WriteLine($"token: {token}");
                // Add the token to the outgoing request headers
                if (!string.IsNullOrEmpty(token))
                {
                    context.ProxyRequest.Headers.Authorization =
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                }
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
            IssuerSigningKey = new SymmetricSecurityKey(secretKey),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
        options.TokenValidationParameters.ValidTypes = ["JWT"];        
    });

builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(options => {

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy("FixedWindow", context => 
        RateLimitPartition.GetFixedWindowLimiter(
            // partitionKey: context.Request.Path,           
            partitionKey: context.Connection.RemoteIpAddress?.ToString(), 
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 5,
                Window = TimeSpan.FromSeconds(10),
                // QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                // QueueLimit = 2
            }
        )
    );

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

        // context.Request.Headers.Append("id", "XYZ");

        return next();
    });
})
.RequireAuthorization();

app.Map("/health", async context =>
{
    await context.Response.WriteAsync("OK");
});

app.Run();

// namespace ApiGateway
// {
//     public static class JwtUtil
//     {
//         public static bool IsValidToken(HttpContext context, byte[] secretKey)
//         {
//             var result = false;            

//             var bearerToken = context.Request.Headers.Authorization.ToString();
//             Console.WriteLine($"Header: {bearerToken}");     

//             var strVal = bearerToken.Split(' ');

//             if (strVal.Length == 2) 
//             {                
//                 var token = strVal[1];
//                 result = Verify(token, secretKey);
//             }

//             return result;
//         }

//         private static bool Verify(string token, byte[] secretKey)
//         {
//             var result = false;
//             try
//             {
//                 var tokenHandler = new JwtSecurityTokenHandler();
                
//                 var validationParameters = new TokenValidationParameters
//                 {
//                     ValidateIssuerSigningKey = true,
//                     IssuerSigningKey = new SymmetricSecurityKey(secretKey),
//                     ValidateIssuer = false,
//                     ValidateAudience = false,
//                     ValidateLifetime = true,
//                     ClockSkew = TimeSpan.Zero
//                 };

//                 ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                
//                 if (principal != null) {
//                     var id = principal.Claims.FirstOrDefault(c => c.Type.Equals("id"))?.Value;

//                     Console.WriteLine($"id: {id}");

//                     // foreach (var claim in principal.Claims) {
//                     //     Console.WriteLine($"claim: {claim}");
//                     //     Console.WriteLine($"Type: {claim.Type}");
//                     //     Console.WriteLine($"-----");
//                     // }
//                 }

//                 // Console.WriteLine($"principal: {principal}");
//                 // Console.WriteLine($"validatedToken: {validatedToken}");

//                 result = true;
//             }
//             catch (Exception ex)
//             {
//                 var x = ex.GetType();
//                 Console.WriteLine($"JWT Verify Type: {x}");
//                 Console.WriteLine($"JWT Verify error: {ex.Message}");
//             }
            
//             // var roleClaim = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

//             Console.WriteLine($"JWT Verify: {result}");

//             return result;
//         }
//     }
// }