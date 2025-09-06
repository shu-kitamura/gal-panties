FROM rust:1.89.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*

# ← これを追加
RUN rustup toolchain install nightly && rustup default nightly

WORKDIR /work
