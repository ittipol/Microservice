FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env

# RUN apt-get -y update && apt-get -y install iputils-ping curl

WORKDIR /app

# Copy everything
COPY . ./

RUN dotnet restore

# Linux RIDs
# linux-x64
# linux-arm64

# RUN dotnet publish ./ThreadExample/ThreadExample.csproj -c Release -r linux-arm64 -o published --self-contained
RUN dotnet publish ./ThreadExample/ThreadExample.csproj -c Release -r linux-arm64 -o published

FROM ubuntu:22.04 AS production

RUN apt-get update && apt-get install -y libc6 iputils-ping

WORKDIR /app

COPY --from=build-env /app/published ./

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
ENV PRODUCTION=1

ENTRYPOINT ["tail"]
CMD ["-f", "/dev/null"]