# Commands

**dotnet command**
``` bash
// App publish
dotnet publish <path-to/*.csproj> -c Release -o <output-path> -p:UseAppHost=false
// ex.
dotnet publish ./services/order.service.csproj -c Release -o /build/published-order-service -p:UseAppHost=false

// Run debug (start local test)
// Open the launchSettings.json, profile-name will be in profiles property
dotnet run -c Debug --launch-profile <profile-name>

// list the local caches with this command:
dotnet nuget locals --list all

// You can clear all caches with this command:
dotnet nuget locals --clear all

// Restore package (same as dotnet restore command)
// The only difference: dotnet restore is a convenience wrapper to invoke dotnet msbuild /t:Restore which invokes an MSBuild-integrated restore
dotnet msbuild /t:Restore

// Clean a Solution
dotnet clean

// Build a Solution
dotnet build --no-incremental
```