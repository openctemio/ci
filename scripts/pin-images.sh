#!/usr/bin/env bash
# Pins the images the GitLab templates and the examples run to the digest a
# tag points at, after verifying each signature (cosign keyless, this
# repository's image workflow).
#
#   scripts/pin-images.sh <tag>        # e.g. v1.2.3 or edge
#
# A tag can be moved; a digest cannot. Pipelines that include a template
# then run exactly the images that were verified here.
set -euo pipefail
cd "$(dirname "$0")/.."

tag="${1:?usage: pin-images.sh <tag>}"
[[ "$tag" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || { echo "bad tag" >&2; exit 2; }
command -v cosign >/dev/null || { echo "cosign is required (https://docs.sigstore.dev)" >&2; exit 2; }

files=$(ls gitlab/templates/*.yml examples/*/* 2>/dev/null || true)
for name in ci ci-semgrep ci-trivy ci-betterleaks; do
  ref="ghcr.io/openctemio/${name}:${tag}"
  digest="$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' | jq -r .digest)"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "cannot resolve $ref" >&2; exit 1; }
  cosign verify "ghcr.io/openctemio/${name}@${digest}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/openctemio/ci/\.github/workflows/images\.yml@refs/(heads/main|tags/v[0-9.]+)$' \
    >/dev/null
  echo "verified ${ref} -> ${digest}"
  # Replace any tag and/or digest of this exact image name.
  for f in $files; do
    sed -i -E "s#ghcr\.io/openctemio/${name}(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?([^a-z0-9-]|\$)#ghcr.io/openctemio/${name}:${tag}@${digest}\3#g" "$f"
  done
done
echo "Pinned. Review: git diff -- gitlab examples"
