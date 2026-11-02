# Supply an approved CPython 3.11/bookworm builder base by immutable digest.
# It must already contain curl, git, openssl, tar and .NET Linux prerequisites.
ARG SVS14_BASE_IMAGE
FROM ${SVS14_BASE_IMAGE}
ARG SVS14_BASE_IMAGE
RUN python3 -c 'import re,sys; assert re.fullmatch(r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}",sys.argv[1]); assert sys.version_info[:2]==(3,11)' "$SVS14_BASE_IMAGE" \
 && test "$(uname -m)" = x86_64 \
 && command -v curl && command -v git && command -v openssl && command -v tar
ENV DOTNET_ROOT=/opt/svs/dotnet \
    PATH=/opt/svs/dotnet:$PATH \
    DOTNET_CLI_TELEMETRY_OPTOUT=true \
    DOTNET_NOLOGO=true
RUN mkdir -p /opt/svs/dotnet \
 && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 https://dotnetcli.blob.core.windows.net/dotnet/Sdk/10.0.100/dotnet-sdk-10.0.100-linux-x64.tar.gz -o /tmp/sdk10.tar.gz \
 && echo 'f78dbac30c9af2230d67ff5c224de3a5dbf63f8a78d1c206594dedb80e6909d2cc8a9d865d5105c72c2fd2aa266fc0c6c77dedac60408cbccf272b116bd11b07  /tmp/sdk10.tar.gz' | sha512sum --check --status \
 && tar -xzf /tmp/sdk10.tar.gz -C /opt/svs/dotnet \
 && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 https://dotnetcli.blob.core.windows.net/dotnet/Sdk/8.0.415/dotnet-sdk-8.0.415-linux-x64.tar.gz -o /tmp/sdk8.tar.gz \
 && echo '0fc0499a857f161f7c35775bb3f50ac6f0333f02f5df21d21147d538eb26a9a87282d4ba3707181c46f3c09d22cdc984e77820a5953a773525d6f7b332deb7f2  /tmp/sdk8.tar.gz' | sha512sum --check --status \
 && tar -xzf /tmp/sdk8.tar.gz -C /opt/svs/dotnet \
 && rm /tmp/sdk10.tar.gz /tmp/sdk8.tar.gz
COPY deploy/session-validation/ci/requirements.txt /opt/svs/requirements.txt
RUN python3 -m pip install --no-cache-dir --require-hashes --only-binary=:all: --no-deps -r /opt/svs/requirements.txt \
 && dotnet --list-sdks
