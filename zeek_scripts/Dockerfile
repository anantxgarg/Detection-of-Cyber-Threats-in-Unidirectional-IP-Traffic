FROM zeek/zeek:7.0.0

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    pkg-config \
    autoconf \
    automake \
    libtool \
    git \
    curl \
    wget \
    ca-certificates \
    bison \
    flex \
    libfl-dev \
    swig \
    python3 \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    python3-git \
    python3-semantic-version \
    libpcap-dev \
    libssl-dev \
    zlib1g-dev \
    libzstd-dev \
    liblz4-dev \
    libcurl4-openssl-dev \
    libmaxminddb-dev \
    libgoogle-perftools-dev \
    libjemalloc-dev \
    libsystemd-dev \
    libsqlite3-dev \
    libkrb5-dev \
    libarchive-dev \
    libzmq3-dev \
    cppzmq-dev \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN command -v zkg && \
    zkg --version && \
    zeek --version

RUN zkg refresh

RUN zkg install --force --skiptests zeek/foxio/ja4

RUN echo '@load packages' >> /usr/local/zeek/share/zeek/site/local.zeek

# Verify installation
RUN zkg list && \
    zeek -b -e '@load packages'

WORKDIR /logs

CMD ["tail", "-f", "/dev/null"]