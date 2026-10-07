# syntax=docker/dockerfile:1.7
# ghcr.io/openctemio/ci-semgrep: semgrep + openctem-ci (capability sast).
# Build from the repository root: docker build -f images/semgrep/Dockerfile .
#
# semgrep and its whole dependency set are pinned with hashes in
# images/semgrep/requirements.txt (pip --require-hashes; Dependabot pip
# bumps them). Base images are pinned by digest (Dependabot docker).

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

FROM docker.io/library/python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
LABEL org.opencontainers.image.title="openctem-ci-semgrep" \
      org.opencontainers.image.description="OpenCTEM CI scanning: semgrep (sast) and openctem-ci" \
      org.opencontainers.image.source="https://github.com/openctemio/ci" \
      org.opencontainers.image.licenses="GPL-3.0-only"
# git: semgrep lists the files to scan with it.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY images/semgrep/requirements.txt /tmp/requirements.txt
# Install exactly the hashed set, prove semgrep runs, then remove every
# package installer from the runtime image.
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/requirements.txt \
    && semgrep --version \
    && rm -rf /tmp/requirements.txt /usr/local/lib/python3.12/site-packages/pip \
        /usr/local/lib/python3.12/site-packages/pip-*.dist-info /usr/local/lib/python3.12/ensurepip \
        /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
    && ! python3 -m pip --version >/dev/null 2>&1 \
    && groupadd -g 1001 openctem && useradd -u 1001 -g openctem -d /home/openctem -m openctem
COPY --from=build /out/openctem-ci /usr/local/bin/openctem-ci
ENV HOME=/home/openctem \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0
# uid 1001 is the GitHub-hosted runner user that owns the checkout.
USER 1001:1001
WORKDIR /home/openctem
ENTRYPOINT ["openctem-ci"]
CMD ["--help"]
