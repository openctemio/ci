#!/usr/bin/env bash
# Checks the release references a user copies:
# - every usage reference (openctemio/ci@vX.Y.Z, the reusable workflow,
#   raw template URLs) names one and the same full release version, never a
#   floating or unpublished tag such as @v1;
# - every image in the GitLab templates and the examples is pinned by digest,
#   tagged with the release in VERSION, and listed in images.lock.
# docs/images.md "Releasing" says when these change.
set -euo pipefail
cd "$(dirname "$0")/.."

files=(action.yml .github/workflows/scan.yml README.md docs/*.md gitlab/templates/*.yml examples/*/*)
fail=0

refs=$(grep -ohE 'openctemio/ci(/\.github/workflows/scan\.yml)?@v[0-9][0-9.]*|raw\.githubusercontent\.com/openctemio/ci/v[0-9][0-9.]*/' "${files[@]}" 2>/dev/null |
  sed -E 's#.*@(v[0-9.]*)$#\1#; s#.*/ci/(v[0-9.]*)/$#\1#' | sort -u || true)
for v in $refs; do
  if [[ ! "$v" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage reference $v is not a full release version (vX.Y.Z)" >&2
    fail=1
  fi
done
if [ "$(printf '%s\n' "$refs" | grep -c .)" -gt 1 ]; then
  echo "usage references name different versions: $(tr "\n" " " <<<"$refs")" >&2
  fail=1
fi

while IFS= read -r line; do
  echo "image not pinned by digest: $line" >&2
  fail=1
done < <(grep -nE 'ghcr\.io/openctemio/ci(-[a-z]+)?[:@ ]' gitlab/templates/*.yml examples/*/* | grep -v '@sha256:[0-9a-f]\{64\}' || true)

# VERSION names the release being prepared; the usage references follow it.
# The image tags in the templates and examples, and images.lock, name the
# release the pinned images report (VERSION once pinned with
# scripts/pin-images.sh; the previous release between the version bump and
# the pin). At the release tag (RELEASE_CHECK=true) all of them must agree.
version="$(tr -d '[:space:]' < VERSION)"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION is not vX.Y.Z: $version" >&2
  fail=1
fi
for v in $refs; do
  [ "$v" = "$version" ] || { echo "usage reference $v differs from VERSION $version" >&2; fail=1; }
done
pinned="$(awk '$1 == "version" {print $2}' images.lock)"
if [[ ! "$pinned" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "images.lock names no release (a 'version vX.Y.Z' line)" >&2
  fail=1
fi
if [ "${RELEASE_CHECK:-}" = true ] && [ "$pinned" != "$version" ]; then
  echo "images.lock pins ${pinned}, not ${version}: run scripts/pin-images.sh before tagging" >&2
  fail=1
fi
while IFS= read -r line; do
  echo "image tag is not the pinned release $pinned (pin with scripts/pin-images.sh): $line" >&2
  fail=1
done < <(grep -noE 'ghcr\.io/openctemio/ci(-[a-z]+)?:[A-Za-z0-9._-]+@' gitlab/templates/*.yml examples/*/* | grep -vF ":${pinned}@" || true)
while read -r name digest; do
  [[ -z "$name" || "$name" == \#* || "$name" == version ]] && continue
  if [[ ! "$name" =~ ^ci(-[a-z]+)?$ || ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "images.lock: bad line: $name $digest" >&2
    fail=1
    continue
  fi
  if grep -qhoE "ghcr\.io/openctemio/${name}:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}" gitlab/templates/*.yml examples/*/* &&
    grep -hoE "ghcr\.io/openctemio/${name}:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}" gitlab/templates/*.yml examples/*/* | grep -vqF "@${digest}"; then
    echo "${name} is pinned to another digest than images.lock" >&2
    fail=1
  fi
done < images.lock
[ "$(grep -cE '^ci(-[a-z]+)? sha256:' images.lock)" = 5 ] || { echo "images.lock must list the five images" >&2; fail=1; }

[ "$fail" = 0 ] && echo "release references: ${refs:-none}; images pinned to ${pinned}"
exit "$fail"
