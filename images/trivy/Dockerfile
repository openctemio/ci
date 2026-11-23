# syntax=docker/dockerfile:1.7
# ghcr.io/openctemio/ci-trivy: trivy + openctem-ci (capabilities sca, iac, container).
# Build from the repository root: docker build -f images/trivy/Dockerfile .
#
# Every base image is pinned by digest; Dependabot (docker) bumps tag and
# digest together. The tool comes from its official image, copied by digest.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
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

FROM ghcr.io/aquasecurity/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb AS trivy
RUN cp "$(command -v trivy)" /trivy && /trivy --version

FROM docker.io/library/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
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
