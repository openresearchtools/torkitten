# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/golang:1.26.3-bookworm@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b AS control
ENV GOTOOLCHAIN=local GOTELEMETRY=off
WORKDIR /src
COPY src/go.mod src/go.sum ./
RUN go mod download
COPY src/cmd ./cmd
COPY src/internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' -o /out/torkitten ./cmd/torkitten \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' -o /out/torkittenctl ./cmd/torkittenctl

FROM docker.io/library/ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libcap2 libevent-2.1-7t64 liblzma5 libseccomp2 libssl3t64 libsystemd0 libzstd1 zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 1000 -g 1000 -m 0700 /etc/torkitten/caddy /etc/torkitten/authelia /etc/torkitten/tor /run/torkitten /var/lib/torkitten /usr/share/torkitten/launcher
COPY --from=control /out/torkitten /out/torkittenctl /usr/bin/
COPY --from=control /usr/local/go/LICENSE /usr/share/doc/torkitten/go-LICENSE
COPY artifacts/tor/usr/bin/tor /usr/bin/tor
COPY artifacts/tor/usr/share/tor /usr/share/tor
COPY artifacts/tor/usr/share/doc/torkitten/third-party/tor /usr/share/doc/torkitten/third-party/tor
COPY artifacts/caddy/usr/bin/caddy /usr/bin/caddy
COPY artifacts/caddy/usr/share/doc/torkitten/third-party/caddy /usr/share/doc/torkitten/third-party/caddy
COPY artifacts/authelia/usr/bin/authelia /usr/bin/authelia
COPY artifacts/authelia/usr/share/doc/torkitten/third-party/authelia /usr/share/doc/torkitten/third-party/authelia
COPY LICENSE /usr/share/doc/torkitten/LICENSE
COPY licenses/ /usr/share/doc/torkitten/go-dependencies/
COPY runtime/launcher/ /usr/share/torkitten/launcher/
RUN chown -R 1000:1000 /etc/torkitten/caddy /etc/torkitten/authelia /etc/torkitten/tor /run/torkitten /var/lib/torkitten \
    && chown -R 0:0 /usr/share/torkitten /usr/share/doc/torkitten /usr/share/tor \
    && chown 0:0 /usr/bin/torkitten /usr/bin/torkittenctl /usr/bin/tor /usr/bin/caddy /usr/bin/authelia \
    && chmod 0555 /usr/bin/torkitten /usr/bin/torkittenctl /usr/bin/tor /usr/bin/caddy /usr/bin/authelia \
    && chmod 0755 /usr/share/torkitten /usr/share/torkitten/launcher \
    && chmod 0644 /usr/share/torkitten/launcher/* \
    && chmod -R go-w /usr/share/doc/torkitten /usr/share/tor
ENV HOME=/var/lib/torkitten DO_NOT_TRACK=1 GOTELEMETRY=off OTEL_SDK_DISABLED=true OTEL_METRICS_EXPORTER=none OTEL_TRACES_EXPORTER=none AUTHELIA_TELEMETRY_METRICS_ENABLED=false
USER 1000:1000
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/torkitten"]
