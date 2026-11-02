ARG SVS15_TOOLCHAIN_IMAGE
FROM ${SVS15_TOOLCHAIN_IMAGE} AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_PROCESSOR_COUNT=4
WORKDIR /build/peer
COPY peer/ .
RUN dotnet restore treehammock.csproj --locked-mode --disable-parallel && dotnet publish treehammock.csproj -c Release --no-restore -m:1 -o /apps/treehammock
WORKDIR /build/current
COPY current/ .
WORKDIR /build/current/src
RUN dotnet restore Treehammock.SessionValidation.Api/Treehammock.SessionValidation.Api.csproj --locked-mode --disable-parallel && dotnet publish Treehammock.SessionValidation.Api/Treehammock.SessionValidation.Api.csproj -c Release --no-restore -m:1 -o /apps/svs
WORKDIR /build/current/tests
RUN dotnet restore Treehammock.SessionValidation.DisposableCaller/Treehammock.SessionValidation.DisposableCaller.csproj --locked-mode --disable-parallel && dotnet publish Treehammock.SessionValidation.DisposableCaller/Treehammock.SessionValidation.DisposableCaller.csproj -c Release --no-restore -m:1 -o /apps/caller
ARG SVS15_TOOLCHAIN_IMAGE
FROM ${SVS15_TOOLCHAIN_IMAGE}
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_PROCESSOR_COUNT=4 SSL_CERT_FILE=/run/fixture/trust.pem
COPY --from=build /apps /apps
COPY peer/ /peer/
COPY driver/ /driver/
COPY current/eng/session-validation/secure-exec.sh /apps/secure-exec.sh
USER 1654:1654
WORKDIR /apps/treehammock
ENTRYPOINT []
