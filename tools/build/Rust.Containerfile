FROM docker.io/library/rust:1.98.0-bookworm@sha256:4e4a7e7939c17991ab35f2b8c2e67593980f771d28f6b1254b1850f860fd0c7f AS rust-toolchain

FROM docker.io/library/ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG DEBIAN_FRONTEND=noninteractive

COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN rustup component add clippy rustfmt

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        git \
        libgtk-3-dev \
        libcap2 \
        libevent-2.1-7t64 \
        liblzma5 \
        libseccomp2 \
        libssl-dev \
        libsystemd0 \
        libwebkit2gtk-4.1-dev \
        libzstd1 \
        pkg-config \
        dpkg-dev \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
