FROM --platform=linux/amd64 ubuntu:22.04

ARG JUNOCASH_VERSION=0.9.8
ARG JUNOCASH_LINUX64_SHA256=67aca81b97644525aaa997024b15815202a0ea68f378d9d0213b4a3cb2ed6960

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
