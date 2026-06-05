FROM --platform=linux/amd64 ubuntu:22.04

ARG JUNOCASH_VERSION=0.9.12
ARG JUNOCASH_LINUX64_SHA256=41f74d61feb9a4284a4200b1fc163ecd072da3314a25db7222522f2e548ec386

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libnuma1 \
    tar \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN curl -fsSLo "junocash-${JUNOCASH_VERSION}-linux64.tar.gz" "https://github.com/juno-cash/junocash/releases/download/v${JUNOCASH_VERSION}/junocash-${JUNOCASH_VERSION}-linux64.tar.gz" \
 && echo "${JUNOCASH_LINUX64_SHA256}  junocash-${JUNOCASH_VERSION}-linux64.tar.gz" | sha256sum -c - \
 && tar -xzf "junocash-${JUNOCASH_VERSION}-linux64.tar.gz" \
 && install -m 0755 "junocash-${JUNOCASH_VERSION}/bin/junocashd" /usr/local/bin/junocashd \
 && install -m 0755 "junocash-${JUNOCASH_VERSION}/bin/junocash-cli" /usr/local/bin/junocash-cli \
 && rm -rf /tmp/*

VOLUME ["/data"]

ENTRYPOINT ["junocashd"]
