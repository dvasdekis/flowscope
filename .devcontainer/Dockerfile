FROM mcr.microsoft.com/devcontainers/javascript-node:1-20-bookworm

USER root

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/home/vscode/.cargo \
    PATH=/home/vscode/.cargo/bin:${PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        just \
        libssl-dev \
        llvm \
        ninja-build \
        pkg-config \
        python3 \
        chromium \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/local/rustup /home/vscode/.cargo /home/vscode/.cache/yarn \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none \
    && rustup toolchain install 1.95.0 \
        --profile minimal \
        --component clippy \
        --component rustfmt \
        --target wasm32-unknown-unknown \
    && rustup default 1.95.0 \
    && chown -R vscode:vscode /usr/local/rustup /home/vscode/.cargo /home/vscode/.cache

RUN corepack enable \
    && corepack prepare yarn@1.22.19 --activate

USER vscode
WORKDIR /workspaces/flowscope
