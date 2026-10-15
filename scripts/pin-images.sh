#!/usr/bin/env bash
# Pins the images the GitLab templates and the examples run, for the release
# named in VERSION, after verifying each signature (cosign keyless, this
# repository's image workflow) and that the binary inside reports that
# release.
#
#   scripts/pin-images.sh <source tag>   # sha-<commit> of the main build to release, or vX.Y.Z
#
# Each reference becomes ghcr.io/openctemio/<image>:<VERSION>@sha256:<digest>
# and images.lock records the five digests. When the release tag is pushed,
# the image workflow points vX.Y.Z and vX at exactly these digests (no
# rebuild), so the tag, the templates and the GitHub Action run one binary.
set -euo pipefail
cd "$(dirname "$0")/.."

src="${1:?usage: pin-images.sh <source tag: sha-<commit> or vX.Y.Z>}"
[[ "$src" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || { echo "bad tag" >&2; exit 2; }
version="$(tr -d '[:space:]' < VERSION)"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION must be vX.Y.Z" >&2; exit 2; }
command -v cosign >/dev/null || { echo "cosign is required (https://docs.sigstore.dev)" >&2; exit 2; }

files=$(ls gitlab/templates/*.yml examples/*/* 2>/dev/null || true)
lock=""
for name in ci ci-opengrep ci-semgrep ci-trivy ci-betterleaks; do
  ref="ghcr.io/openctemio/${name}:${src}"
  digest="$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' | jq -r .digest)"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "cannot resolve $ref" >&2; exit 1; }
  cosign verify "ghcr.io/openctemio/${name}@${digest}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/openctemio/ci/\.github/workflows/images\.yml@refs/(heads/main|tags/v[0-9.]+)$' \
    >/dev/null
  # The binary must report the release (exactly, or VERSION+<commit> for a
  # main build of the release commit): the platform reads the version from
  # the runner and refuses releases below its minimum.
  got="$(docker run --rm --pull always --entrypoint openctem-ci "ghcr.io/openctemio/${name}@${digest}" version | awk '{print $2}')"
  [[ "$got" == "$version" || "$got" == "${version}+"* ]] || {
    echo "${ref} reports ${got}, not ${version}: bump VERSION and build first" >&2
    exit 1
  }
  echo "verified ${ref} -> ${digest} (openctem-ci ${got})"
  lock+="${name} ${digest}"$'\n'
  # Replace any tag and/or digest of this exact image name.
  for f in $files; do
    sed -i -E "s#ghcr\.io/openctemio/${name}(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?([^a-z0-9-]|\$)#ghcr.io/openctemio/${name}:${version}@${digest}\3#g" "$f"
  done
done
{
  echo "# The images release ${version} runs (scripts/pin-images.sh). The release"
  echo "# tag points ${version} and its major tag at exactly these digests."
  echo "version ${version}"
  printf '%s' "$lock"
} > images.lock
echo "Pinned ${version}. Review: git diff -- gitlab examples images.lock"
