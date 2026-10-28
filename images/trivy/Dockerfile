# syntax=docker/dockerfile:1.7
# ghcr.io/openctemio/ci-trivy: trivy + openctem-ci (capabilities sca, iac, container).
# Build from the repository root: docker build -f images/trivy/Dockerfile .
#
# Every base image is pinned by digest; Dependabot (docker) bumps tag and
# digest together. The tool comes from its official image, copied by digest.

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

FROM ghcr.io/aquasecurity/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c AS trivy
RUN cp "$(command -v trivy)" /trivy && /trivy --version

FROM docker.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
LABEL org.opencontainers.image.title="openctem-ci-trivy" \
      org.opencontainers.image.description="OpenCTEM CI scanning: trivy (sca, iac, container) and openctem-ci" \
      org.opencontainers.image.source="https://github.com/openctemio/ci" \
      org.opencontainers.image.licenses="GPL-3.0-only"
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates \
    && addgroup -g 1001 openctem && adduser -D -u 1001 -G openctem -h /home/openctem openctem
COPY --from=trivy /trivy /usr/local/bin/trivy
COPY --from=build /out/openctem-ci /usr/local/bin/openctem-ci
ENV HOME=/home/openctem \
    TRIVY_CACHE_DIR=/home/openctem/.cache/trivy \
    TRIVY_NO_PROGRESS=true
# uid 1001 is the GitHub-hosted runner user that owns the checkout.
USER 1001:1001
WORKDIR /home/openctem
ENTRYPOINT ["openctem-ci"]
CMD ["--help"]
