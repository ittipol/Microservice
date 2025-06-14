namespace RestApi.Utility;

public static class AppConfig
{
    public static IServiceCollection AddBackgroundTasks(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("backgroundTask") ?? "";

        Console.WriteLine(connectionString);      

        return services;
    }

    public static IApplicationBuilder UseBackgroundTasksDashboard(this IApplicationBuilder app)
    {        
        return app;
    }
}