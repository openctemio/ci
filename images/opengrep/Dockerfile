# syntax=docker/dockerfile:1.7
# ghcr.io/openctemio/ci-opengrep: opengrep + openctem-ci (capability sast).
# Build from the repository root: docker build -f images/opengrep/Dockerfile .
#
# opengrep is the release's musl binary, pinned by version and SHA-256 per
# architecture; its keyless signature is verified with cosign against the
# opengrep release workflow of exactly that version before it is
# installed. No Python and no package installer in the image. Base images
# are pinned by digest (Dependabot docker).

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
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

FROM ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 AS cosign

FROM docker.io/library/alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS opengrep
ARG TARGETARCH
ARG OPENGREP_VERSION=1.30.2
ARG OPENGREP_SHA256_AMD64=f757557fa23c217e54c140a9e609a46397e668518ca1394436eb76d83ba560fe
ARG OPENGREP_SHA256_ARM64=564211ffe4e932f89a3b4d5e04c4a8c6dc4fb1c4e61e9a830f3afbd9ab2e5f97
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

FROM docker.io/library/alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
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
COPY --from=build /out/openctem-ci /usr/local/bin/openctem-ci
ENV HOME=/home/openctem \
    XDG_CACHE_HOME=/opt/opengrep/cache
# uid 1001 is the GitHub-hosted runner user that owns the checkout.
USER 1001:1001
WORKDIR /home/openctem
ENTRYPOINT ["openctem-ci"]
CMD ["--help"]
