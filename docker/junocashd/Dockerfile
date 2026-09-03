FROM --platform=linux/amd64 ubuntu:24.04@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316

ARG JUNOCASH_VERSION=0.9.13
ARG JUNOCASH_LINUX64_SHA256=7e83b8c888344f33129ece2160d8b6434bc91ffb9cd992665aadd2c02c904f11

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libnuma1 \
    tar \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN curl -fsSLo "junocash-${JUNOCASH_VERSION}-linux64.tar.gz" "https://github.com/juno-cash/junocash/releases/download/v${JUNOCASH_VERSION}/junocash-${JUNOCASH_VERSION}-linux64.tar.gz" \
 && echo "${JUNOCASH_LINUX64_SHA256}  junocash-${JUNOCASH_VERSION}-linux64.tar.gz" | sha256sum -c - \
 && mkdir -p /tmp/junocash \
 && tar -xzf "junocash-${JUNOCASH_VERSION}-linux64.tar.gz" -C /tmp/junocash --strip-components=1 \
 && install -m 0755 "/tmp/junocash/bin/junocashd" /usr/local/bin/junocashd \
 && install -m 0755 "/tmp/junocash/bin/junocash-cli" /usr/local/bin/junocash-cli \
 && rm -rf /tmp/*

VOLUME ["/data"]

ENTRYPOINT ["junocashd"]
