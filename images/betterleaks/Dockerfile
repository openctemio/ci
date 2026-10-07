# syntax=docker/dockerfile:1.7
# ghcr.io/openctemio/ci-betterleaks: betterleaks + openctem-ci (capability secrets).
# Build from the repository root: docker build -f images/betterleaks/Dockerfile .
#
# Every base image is pinned by digest; Dependabot (docker) bumps tag and
# digest together. The tool comes from its official image, copied by digest.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
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

# betterleaks v1: v2 changes the JSON report the importer reads.
FROM ghcr.io/betterleaks/betterleaks:v1.9.0@sha256:e3b95b0db6c2735db17165c009b0ad6d9cef34fb4578659232b98f69d7346cac AS betterleaks
RUN cp "$(command -v betterleaks)" /betterleaks && /betterleaks version

FROM docker.io/library/alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
LABEL org.opencontainers.image.title="openctem-ci-betterleaks" \
      org.opencontainers.image.description="OpenCTEM CI scanning: betterleaks (secrets) and openctem-ci" \
      org.opencontainers.image.source="https://github.com/openctemio/ci" \
      org.opencontainers.image.licenses="GPL-3.0-only"
# git: betterleaks reads history in git mode.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates git \
    && addgroup -g 1001 openctem && adduser -D -u 1001 -G openctem -h /home/openctem openctem
COPY --from=betterleaks /betterleaks /usr/local/bin/betterleaks
COPY --from=build /out/openctem-ci /usr/local/bin/openctem-ci
ENV HOME=/home/openctem
# uid 1001 is the GitHub-hosted runner user that owns the checkout.
USER 1001:1001
WORKDIR /home/openctem
ENTRYPOINT ["openctem-ci"]
CMD ["--help"]
