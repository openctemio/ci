# syntax=docker/dockerfile:1.7
# ghcr.io/openctemio/ci-opengrep: opengrep + openctem-ci (capability sast).
# Build from the repository root: docker build -f images/opengrep/Dockerfile .
#
# The default sast rules are the OpenCTEM rules pack, a signed release
# verified at build (stage "rules").
# opengrep is the release's musl binary, pinned by version and SHA-256 per
# architecture; its keyless signature is verified with cosign against the
# opengrep release workflow of exactly that version before it is
# installed. No Python and no package installer in the image. Base images
# are pinned by digest (Dependabot docker).

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/openctem-ci ./cmd/openctem-ci

FROM ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d AS cosign

FROM docker.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS opengrep
ARG TARGETARCH
ARG OPENGREP_VERSION=1.31.0
ARG OPENGREP_SHA256_AMD64=02c9fba481611aa0664bc79ccf7ce59e9e334b76af8921c80b2f738d17fabf9b
ARG OPENGREP_SHA256_ARM64=b7cbedab0b6c9953ea27ce3baa006ad8b6fa1c50ee7433638b63f7fc731519d9
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates curl
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
RUN case "${TARGETARCH}" in \
    amd64) arch=x86; sum="${OPENGREP_SHA256_AMD64}" ;; \
    arm64) arch=aarch64; sum="${OPENGREP_SHA256_ARM64}" ;; \
    *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    f="opengrep_musllinux_${arch}"; \
    base="https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}"; \
    cd /tmp; \
    curl -fsSLo "$f" "$base/$f"; curl -fsSLo "$f.cert" "$base/$f.cert"; curl -fsSLo "$f.sig" "$base/$f.sig"; \
    echo "$sum  $f" | sha256sum -c -; \
    cosign verify-blob --cert "$f.cert" --signature "$f.sig" \
        --certificate-identity "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v${OPENGREP_VERSION}" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com "$f"; \
    install -m 0755 "$f" /opengrep; \
    # The binary unpacks its runtime into $XDG_CACHE_HOME/opengrep on first
    # run, owner-only: unpack it here and make it readable, not writable,
    # so the image runs it read-only as any user.
    XDG_CACHE_HOME=/opt/opengrep/cache HOME=/tmp /opengrep --version | grep -qx "${OPENGREP_VERSION}"; \
    chmod -R a+rX,go-w /opt/opengrep/cache

# The OpenCTEM rules pack (github.com/openctemio/sast-rules): a release
# bundle whose cosign keyless signature must verify for the pack's release
# workflow at exactly this tag. It is the image's default sast rules.
FROM docker.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS rules
ARG SAST_RULES_VERSION=0.1.0
ARG SAST_RULES_SHA256=6bcd18f7d6f65fbbccc0d965a86010e10da7d8f9e217a39597fe52e3fef4df6d
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates curl
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
RUN f="sast-rules-${SAST_RULES_VERSION}.tar.gz"; \
    base="https://github.com/openctemio/sast-rules/releases/download/v${SAST_RULES_VERSION}"; \
    cd /tmp; \
    curl -fsSLo "$f" "$base/$f"; curl -fsSLo "$f.sigstore.json" "$base/$f.sigstore.json"; \
    echo "${SAST_RULES_SHA256}  $f" | sha256sum -c -; \
    cosign verify-blob --bundle "$f.sigstore.json" \
        --certificate-identity "https://github.com/openctemio/sast-rules/.github/workflows/release.yml@refs/tags/v${SAST_RULES_VERSION}" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com "$f"; \
    mkdir -p /opt/openctem/sast-rules; \
    tar -xzf "$f" -C /opt/openctem/sast-rules --strip-components=1 --no-same-owner; \
    test -d /opt/openctem/sast-rules/rules; \
    grep -qx "${SAST_RULES_VERSION}" /opt/openctem/sast-rules/VERSION; \
    chmod -R a+rX,go-w /opt/openctem/sast-rules

FROM docker.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
LABEL org.opencontainers.image.title="openctem-ci-opengrep" \
      org.opencontainers.image.description="OpenCTEM CI scanning: opengrep (sast) and openctem-ci" \
      org.opencontainers.image.source="https://github.com/openctemio/ci" \
      org.opencontainers.image.licenses="GPL-3.0-only"
# git: opengrep lists the files to scan and finds the baseline with it.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates git \
    && addgroup -g 1001 openctem && adduser -D -u 1001 -G openctem -h /home/openctem openctem
COPY --from=opengrep /opengrep /usr/local/bin/opengrep
COPY --from=opengrep /opt/opengrep/cache /opt/opengrep/cache
COPY --from=rules /opt/openctem/sast-rules /opt/openctem/sast-rules
COPY --from=build /out/openctem-ci /usr/local/bin/openctem-ci
ENV HOME=/home/openctem \
    XDG_CACHE_HOME=/opt/opengrep/cache
# uid 1001 is the GitHub-hosted runner user that owns the checkout.
USER 1001:1001
WORKDIR /home/openctem
ENTRYPOINT ["openctem-ci"]
CMD ["--help"]
