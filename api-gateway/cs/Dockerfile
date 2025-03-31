FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app

# Copy everything
COPY . ./

WORKDIR /app/TestProxy

# Restore as distinct layers
RUN dotnet restore
# Build and publish a release
RUN dotnet publish -c Release -o published

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime

WORKDIR /app
COPY --from=build-env /app/TestProxy/published .

ENV ASPNETCORE_HTTP_PORTS=3000
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:3000

EXPOSE 3000

USER 1000

ENTRYPOINT ["dotnet", "TestProxy.dll"]