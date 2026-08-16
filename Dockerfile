FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p client-intel-collector

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/client-intel-collector /usr/local/bin/client-intel-collector
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/client-intel-collector"]
