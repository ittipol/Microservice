var builder = WebApplication.CreateBuilder(args);

builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

app.UseRouting();

// app.UseAuthentication();
// app.UseAuthorization();

app.MapReverseProxy(proxyPipeline => {
    proxyPipeline.Use((context, next) =>
    {
        // Custom inline middleware
        if(CheckAllowedRequest(context)) {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return context.Response.WriteAsync("!!!!");
        }

        return next();
    });
});

app.Map("/health", async context =>
{
    await context.Response.WriteAsync("OK");
});

app.Run();

static bool CheckAllowedRequest(HttpContext context) 
{

    // jwtAccessTokenSecretKey, _ := base64.StdEncoding.DecodeString("uDnF3+6uGj+tyvqRrzfCqc1czsKOnW8m+xv7lnOBDzuIGIkjphTa6aGjuQbbMQ79EAI22YU7bTfhTQzyqKMgBQ==")
    // jwtRefreshTokenSecretKey, _ := base64.StdEncoding.DecodeString("0Cf7yuCqusHqFW2N5eWZ88dy4bukCK19/jFdNIP1XvHR7zEiCDa04yf4JUqCX5TMRFaELd4ERLMcIFUB8aMXjg==")

    // foreach (string header in context.Request.Headers)
    // {
    //     string[] values = context.Request.Headers[header];
    //     headers += string.Format("{0}: {1}", header, string.Join(",", values));
    // }

    var x = context.Request.Headers.Authorization;
    Console.WriteLine($"Header: {x}");

    return false;
}