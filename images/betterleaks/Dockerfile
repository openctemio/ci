# syntax=docker/dockerfile:1.7
# ghcr.io/openctemio/ci-betterleaks: betterleaks + openctem-ci (capability secrets).
# Build from the repository root: docker build -f images/betterleaks/Dockerfile .
#
# Every base image is pinned by digest; Dependabot (docker) bumps tag and
# digest together. The tool comes from its official image, copied by digest.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
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
FROM ghcr.io/betterleaks/betterleaks:v1.10.0@sha256:c6dfa75145fe5b31fdaf02feff18a73f1e11df8ca04876522f87f857656c83ca AS betterleaks
RUN cp "$(command -v betterleaks)" /betterleaks && /betterleaks version

FROM docker.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
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
