# API Gateway

## Run
dotnet run --project <path to .csproj file>

## YARP (Reverse Proxy)
- https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/yarp/config-files?view=aspnetcore-9.0
- https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/yarp/http-client-config?view=aspnetcore-9.0

**LoadBalancingPolicy**
``` json
// appsettings.json
"LoadBalancingPolicy" : "PowerOfTwoChoices", // Alternatively "FirstAlphabetical", "Random", "RoundRobin", "LeastRequests"
```

**AuthorizationPolicy**
- default: The route will require an authenticated user
- anonymous: The route will not require authorization regardless of any other configuration
``` json
// appsettings.json
"AuthorizationPolicy": "default", // default, anonymous, {custom authorization policy}
```

## Dependency Injection
Dependency Injection (DI) is a design pattern that allows a class to receive its dependencies from an external source rather than creating them internally. This approach promotes loose coupling, making your code more modular, testable, and maintainable

In .NET, DI is commonly implemented using a service container or service provider. This container holds a collection of services that can be injected into any class that needs them. Services can be registered with different lifetimes

- **Transient lifetime** a new instance is created every time it is requested
- **Scoped lifetime** a new instance is created once per request or scope
- **Singleton lifetime** a single instance is created and shared throughout the application’s lifetime

## Service Lifetimes in .NET

**1.Transient**
- A new instance of the service is created each time it is requested
- Best suited for lightweight, stateless services

**2. Scoped:**
- A new instance is created once per request or scope
- Useful for services that need to maintain state within a request but should not persist beyond it

**3. Singleton:**
- A single instance is created and shared across the entire application
- Ideal for services that hold shared state or perform expensive operations that should only be done once