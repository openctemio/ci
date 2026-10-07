# syntax=docker/dockerfile:1.7
# ghcr.io/openctemio/ci: every CI tool (semgrep, trivy, betterleaks) + openctem-ci.
# Build from the repository root: docker build -f images/all/Dockerfile .
#
# The same pins as the per-tool images (images/<tool>/Dockerfile); a CI
# check keeps them identical.

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

FROM ghcr.io/aquasecurity/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy
RUN cp "$(command -v trivy)" /trivy && /trivy --version

FROM ghcr.io/betterleaks/betterleaks:v1.9.0@sha256:e3b95b0db6c2735db17165c009b0ad6d9cef34fb4578659232b98f69d7346cac AS betterleaks
RUN cp "$(command -v betterleaks)" /betterleaks && /betterleaks version

FROM docker.io/library/python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
LABEL org.opencontainers.image.title="openctem-ci" \
      org.opencontainers.image.description="OpenCTEM CI scanning: semgrep, trivy, betterleaks and openctem-ci" \
      org.opencontainers.image.source="https://github.com/openctemio/ci" \
      org.opencontainers.image.licenses="GPL-3.0-only"
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY images/semgrep/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/requirements.txt \
    && semgrep --version \
    && rm -rf /tmp/requirements.txt /usr/local/lib/python3.12/site-packages/pip \
        /usr/local/lib/python3.12/site-packages/pip-*.dist-info /usr/local/lib/python3.12/ensurepip \
        /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
    && ! python3 -m pip --version >/dev/null 2>&1 \
    && groupadd -g 1001 openctem && useradd -u 1001 -g openctem -d /home/openctem -m openctem
COPY --from=trivy /trivy /usr/local/bin/trivy
COPY --from=betterleaks /betterleaks /usr/local/bin/betterleaks
COPY --from=build /out/openctem-ci /usr/local/bin/openctem-ci
ENV HOME=/home/openctem \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    TRIVY_CACHE_DIR=/home/openctem/.cache/trivy \
    TRIVY_NO_PROGRESS=true
# uid 1001 is the GitHub-hosted runner user that owns the checkout.
USER 1001:1001
WORKDIR /home/openctem
ENTRYPOINT ["openctem-ci"]
CMD ["--help"]
