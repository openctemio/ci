#!/usr/bin/env bash
# Checks the release references a user copies:
# - every usage reference (openctemio/ci@vX.Y.Z, the reusable workflow,
#   raw template URLs) names one and the same full release version, never a
#   floating or unpublished tag such as @v1;
# - every image in the GitLab templates and the examples is pinned by digest.
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

[ "$fail" = 0 ] && echo "release references: ${refs:-none}, images pinned"
exit "$fail"
