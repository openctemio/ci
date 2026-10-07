#!/usr/bin/env bash
# Every FROM in images/*/Dockerfile is pinned by digest, and one image
# repository has one pin across all Dockerfiles: the per-tool images and the
# bundle then ship the same tool and base versions.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
froms=$(grep -hE '^FROM ' images/*/Dockerfile | sed -E 's/^FROM (--platform=[^ ]+ )?//; s/ AS .*$//I')
while read -r ref; do
  [ -z "$ref" ] && continue
  if [[ ! "$ref" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "FAIL not pinned by digest: $ref" >&2
    fail=1
  fi
done <<<"$froms"
while read -r repo; do
  [ -z "$repo" ] && continue
  n=$(printf '%s\n' "$froms" | awk -F'[:@]' -v r="$repo" '$1==r' | sort -u | wc -l)
  if [ "$n" -ne 1 ]; then
    echo "FAIL $repo is pinned differently across Dockerfiles:" >&2
    printf '%s\n' "$froms" | awk -F'[:@]' -v r="$repo" '$1==r' | sort -u >&2
    fail=1
  fi
done < <(printf '%s\n' "$froms" | cut -d: -f1 | cut -d@ -f1 | sort -u)
[ "$fail" -eq 0 ] && echo "All image pins are digests and consistent."
exit "$fail"
