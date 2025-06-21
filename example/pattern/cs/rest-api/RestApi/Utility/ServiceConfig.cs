namespace RestApi.Utility;

public static class ServiceConfig
{
    public static IServiceCollection AddConfig(this IServiceCollection services, IConfiguration config)
    {
        // services.Configure<DatabaseOptions>(config.GetSection(config.GetConnectionString("backgroundTask")));

        return services;
    }

    public static IServiceCollection AddMyDependencyGroup(this IServiceCollection services)
    {
        // services.AddScoped<IThreadTest, ThreadTest>();
        // services.AddScoped<IThreadTest2, ThreadTest2>();

        // services.AddTransient<IThreadTestTransient, ThreadTest>();
        // services.AddScoped<IThreadTestScoped, ThreadTest>();
        // services.AddSingleton<IThreadTestSingleton, ThreadTest>();

        return services;
    }
}