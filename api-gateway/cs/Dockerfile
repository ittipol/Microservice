FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app

# Copy everything
COPY . ./

WORKDIR /app/ApiGateway

# Restore as distinct layers
RUN dotnet restore

# Build and publish a release
# -p:UseAppHost=false = do not use self-contained deployments, use dotnet command directly to run app
# This need .NET runtime installed on the target system
RUN dotnet publish ./ '-p:TargetFrameworks=net8.0' '-p:PackTargetFramework=net8.0' -c Release -o published -p:UseAppHost=false

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime

WORKDIR /app
COPY --from=build-env /app/ApiGateway/published .

ENV ASPNETCORE_HTTP_PORTS=3000
ENV ASPNETCORE_ENVIRONMENT=Production
# ENV ASPNETCORE_URLS=http://+:3000

EXPOSE 3000

USER 1000

ENTRYPOINT ["dotnet", "ApiGateway.dll"]