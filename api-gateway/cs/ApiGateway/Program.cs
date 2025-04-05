using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

var secretKey = Convert.FromBase64String(builder.Configuration.GetSection("Jwt:Secret").Get<string>() ?? "");

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

                    var id = ApiGateway.JwtUtil.GetId(token, secretKey);

                    context.ProxyRequest.Headers.Add("id", id);

                    // context.ProxyRequest.Headers.Authorization =
                    //     new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                }
            }

            context.ProxyRequest.Headers.Remove("Authorization");
        });

        transforms.AddResponseTransform(async responseContext =>
        {
            responseContext.HttpContext.Response.Headers.Append("key", "value");
            responseContext.HttpContext.Response.Headers.Remove(HeaderNames.CacheControl);

            var stream = await responseContext.ProxyResponse!.Content.ReadAsStreamAsync();
            using var reader = new StreamReader(stream);
            // TODO: size limits, timeouts
            var body = await reader.ReadToEndAsync();

            if (!string.IsNullOrEmpty(body))
            {
                responseContext.SuppressResponseBody = true;

                // body = body.Replace("Bravo", "Charlie");
                var bytes = Encoding.UTF8.GetBytes(body);
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
            IssuerSigningKey = new SymmetricSecurityKey(secretKey),
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
}