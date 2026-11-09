# syntax=docker/dockerfile:1.7

FROM ubuntu:24.04 AS builder

ARG BAZELISK_VERSION=v1.29.0
ARG BAZEL_VERSION=9.3.1
ARG TARGETARCH=amd64

ENV DEBIAN_FRONTEND=noninteractive \
    USE_BAZEL_VERSION=${BAZEL_VERSION}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        python3 \
        qt6-base-dev \
        libsodium-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /usr/local/bin/bazelisk \
        "https://github.com/bazelbuild/bazelisk/releases/download/${BAZELISK_VERSION}/bazelisk-linux-${TARGETARCH}" \
    && chmod +x /usr/local/bin/bazelisk

WORKDIR /src
COPY . .

# Bazel's GitHub release-asset URL is unreliable behind some HTTP proxies (504).
# codeload.github.com serves the same bytes (Bazel verifies the checksum), so
# fetch it explicitly and hand it to the build via --distdir.
ARG BAZEL_FEATURES_VERSION=1.47.0
RUN mkdir -p /tmp/bazel-distdir \
    && curl -fsSL \
        -o "/tmp/bazel-distdir/bazel_features-v${BAZEL_FEATURES_VERSION}.tar.gz" \
        "https://codeload.github.com/bazel-contrib/bazel_features/tar.gz/refs/tags/v${BAZEL_FEATURES_VERSION}"

# The flags below mirror the security-relevant parts of .bazelrc. They are
# passed explicitly because .bazelrc is gitignored and may be absent in CI.
# PM_CONTAINER_BUILD keeps core-dump/ptrace protection fail-closed but makes
# mlockall best-effort, since Docker's default RLIMIT_MEMLOCK is too small.
RUN --mount=type=cache,target=/root/.cache/bazel \
    --mount=type=cache,target=/root/.cache/bazelisk \
    bazelisk build -c opt //UI:UI \
        --distdir=/tmp/bazel-distdir \
        --enable_bzlmod \
        --noenable_workspace \
        --features=-layering_check \
        --spawn_strategy=local \
        --experimental_repository_downloader_retries=3 \
        --copt=-DPM_CONTAINER_BUILD \
        --copt=-D_FORTIFY_SOURCE=2 \
        --copt=-fstack-protector-strong \
        --copt=-fcf-protection=full \
        --copt=-fstack-clash-protection \
        --linkopt=-Wl,-z,relro \
        --linkopt=-Wl,-z,now \
        --linkopt=-Wl,-z,noexecstack \
    && mkdir -p /out \
    && cp -L bazel-bin/UI/UI /out/password-manager \
    && strip --strip-unneeded /out/password-manager

FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/home/app \
    QT_QPA_PLATFORM=xcb

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        fonts-dejavu-core \
        libsodium23 \
        libqt6core6t64 \
        libqt6dbus6t64 \
        libqt6gui6t64 \
        libqt6network6t64 \
        libqt6widgets6t64 \
        libxcb-cursor0 \
        libxkbcommon-x11-0 \
        qt6-wayland \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin app \
    && mkdir -p /home/app/Documents /data \
    && chown -R app:app /home/app /data

COPY --from=builder /out/password-manager /usr/local/bin/password-manager
COPY LICENSE.md /usr/share/doc/password-manager/LICENSE.md

LABEL org.opencontainers.image.title="Password Manager" \
      org.opencontainers.image.description="C++23 password manager with a Qt 6 UI and libsodium cryptography" \
      org.opencontainers.image.source="https://github.com/DemetrioII/Password-Manager" \
      org.opencontainers.image.licenses="LGPL-3.0" \
      com.password-manager.hardening-profile="container"

USER app
WORKDIR /home/app
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/password-manager"]
