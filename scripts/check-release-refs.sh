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

# VERSION names the release; the usage references, the image tags in the
# templates and examples, and images.lock all agree with it.
version="$(tr -d '[:space:]' < VERSION)"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION is not vX.Y.Z: $version" >&2
  fail=1
fi
for v in $refs; do
  [ "$v" = "$version" ] || { echo "usage reference $v differs from VERSION $version" >&2; fail=1; }
done
while IFS= read -r line; do
  echo "image tag is not the release $version (pin with scripts/pin-images.sh): $line" >&2
  fail=1
done < <(grep -noE 'ghcr\.io/openctemio/ci(-[a-z]+)?:[A-Za-z0-9._-]+@' gitlab/templates/*.yml examples/*/* | grep -vF ":${version}@" || true)
while read -r name digest; do
  [[ -z "$name" || "$name" == \#* ]] && continue
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

[ "$fail" = 0 ] && echo "release references: ${refs:-none}, images pinned"
exit "$fail"
