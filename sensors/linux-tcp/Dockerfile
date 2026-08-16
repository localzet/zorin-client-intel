FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bpftool \
        clang \
        gcc \
        libbpf-dev \
        libelf-dev \
        llvm \
        make \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sensor
COPY . .
COPY entrypoint.sh /usr/local/bin/zci-tcp-sensor-entrypoint
RUN chmod +x /usr/local/bin/zci-tcp-sensor-entrypoint

ENTRYPOINT ["/usr/local/bin/zci-tcp-sensor-entrypoint"]
