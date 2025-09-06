FROM rust:1.89.0

# 基本ツール
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      clang llvm libelf-dev pkg-config make iproute2 tcpdump ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

# eBPF ビルドに必要なのは nightly + rust-src（ターゲット追加は不要）
# 必要なら llvm-tools-preview も入れておく
RUN rustup toolchain install nightly && \
    rustup default nightly && \
    rustup component add rust-src --toolchain nightly && \
    rustup component add llvm-tools-preview --toolchain nightly

WORKDIR /work