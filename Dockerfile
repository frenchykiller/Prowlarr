FROM node:20 AS build-frontend
WORKDIR /app
COPY package.json yarn.lock tsconfig.json ./
RUN yarn install --network-timeout 120000
COPY frontend ./frontend
RUN yarn build --env production

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-backend
WORKDIR /app
COPY . .
RUN dotnet publish src/NzbDrone.Console/Prowlarr.Console.csproj -c Release -r linux-x64 -f net8.0 --self-contained true -p:TreatWarningsAsErrors=false -p:EnableAnalyzers=false -p:EnforceCodeStyleInBuild=false -o _output/Prowlarr
RUN dotnet publish src/NzbDrone.Mono/Prowlarr.Mono.csproj -c Release -r linux-x64 -f net8.0 --self-contained true -p:TreatWarningsAsErrors=false -p:EnableAnalyzers=false -p:EnforceCodeStyleInBuild=false -o _output/Prowlarr

FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libicu-dev \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build-backend /app/_output/Prowlarr/ .
COPY --from=build-frontend /app/_output/UI/ /app/UI/
EXPOSE 9696
ENTRYPOINT ["./Prowlarr", "-nobrowser", "-data=/config"]
