using Microsoft.FeatureManagement;

namespace RestApi.Utility;

public static class FeatureFlagConfig
{
    public static IServiceCollection AddFeatureFlag(this IServiceCollection services, IConfiguration configuration)
    {
        var config = configuration.GetSection("FeatureManagement");

        services.AddFeatureManagement(config)
        // .AddFeatureFilter<CustomFeatureFilter>();
        ;

        return services;
    }

    // public static IApplicationBuilder UseDashboard(this IApplicationBuilder app)
    // {        
    //     return app;
    // }
}