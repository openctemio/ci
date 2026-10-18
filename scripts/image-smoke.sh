#!/usr/bin/env bash
# Smoke-test a built CI image: every bundled tool runs, the image runs as a
# non-root user, and openctem-ci scans the fixture repository for each
# capability the image carries (scan only, nothing uploaded) and writes a
# SARIF and a GitLab report. A tool that is shipped broken fails the build
# here instead of failing users' pipelines.
#
#   scripts/image-smoke.sh <opengrep|semgrep|trivy|betterleaks|all> <image>
set -euo pipefail

variant="${1:?usage: image-smoke.sh <variant> <image>}"
image="${2:?usage: image-smoke.sh <variant> <image>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
fixture="${root}/testdata/fixture"

case "$variant" in
  opengrep) tools="opengrep"; caps="sast" ;;
  semgrep) tools="semgrep"; caps="sast" ;;
  trivy) tools="trivy"; caps="sca iac" ;;
  betterleaks) tools="betterleaks"; caps="secrets" ;;
  all) tools="opengrep trivy betterleaks"; caps="sast sca iac secrets" ;;
  *) echo "unknown variant: $variant" >&2; exit 2 ;;
esac

fail=0
for tool in $tools; do
  args="--version"
  [ "$tool" = betterleaks ] && args="version"
  if out=$(docker run --rm --entrypoint "$tool" "$image" $args 2>&1); then
    echo "ok   $tool: $(printf '%s\n' "$out" | grep -m1 -iE 'version|[0-9]+\.[0-9]+' || true)"
  else
    echo "FAIL $tool does not run:" >&2
    printf '%s\n' "$out" | tail -n 10 >&2
    fail=1
  fi
done

uid=$(docker run --rm --entrypoint id "$image" -u)
if [ "$uid" = 0 ]; then
  echo "FAIL the image runs as root" >&2
  fail=1
else
  echo "ok   runs as uid $uid"
fi

work=$(mktemp -d)
trap 'rm -rf -- "${work:?}"' EXIT
cp -R "$fixture/." "$work/"
chmod -R a+rwX "$work"
for cap in $caps; do
  # Read-only root filesystem: only the workspace and a tmpfs are writable.
  if docker run --rm --read-only --tmpfs /tmp --tmpfs /home/openctem:uid=1001,gid=1001 \
      -v "$work:/src" -e OPENCTEM_WORKSPACE=/src -e OPENCTEM_REPOSITORY=github.com/openctemio/ci-fixture \
      "$image" scan --capability "$cap" --target /src \
      --sarif "/src/$cap.sarif" --gitlab-report "/src/gl-$cap.json" --status "/src/$cap.status.json" >"$work/$cap.log" 2>&1; then
    n=$(jq '[.runs[].results[]] | length' "$work/$cap.sarif")
    echo "ok   scan $cap: $n SARIF result(s)"
    if [ "$n" -eq 0 ]; then
      echo "FAIL scan $cap found nothing in the fixture" >&2
      fail=1
    fi
  else
    echo "FAIL scan $cap:" >&2
    tail -n 20 "$work/$cap.log" >&2
    fail=1
  fi
done

# Taint traces: with the self-test taint rule (testdata/rules/taint.yaml) the
# engine reports the fixture's request-to-command and request-to-query flows,
# and the CTIS report carries each one as a data flow with a source and a
# sink. opengrep writes the trace; semgrep's open-source engine no longer
# does (checked with 1.180.0), so the check is required for the opengrep
# images (ci-opengrep and ci) only.
if [ "$variant" = opengrep ] || [ "$variant" = all ]; then
  mkdir -p "$work/.openctem-selftest"
  cp "$root/testdata/rules/taint.yaml" "$work/.openctem-selftest/taint.yaml"
  chmod -R a+rwX "$work"
  if docker run --rm --read-only --tmpfs /tmp --tmpfs /home/openctem:uid=1001,gid=1001 \
      -v "$work:/src" -e OPENCTEM_WORKSPACE=/src -e OPENCTEM_REPOSITORY=github.com/openctemio/ci-fixture \
      "$image" scan --capability sast --target /src --sast-rules .openctem-selftest/taint.yaml \
      --ctis /src/taint.ctis.json >"$work/taint.log" 2>&1; then
    n=$(jq '[.findings[] | select((.data_flow.sources | length) > 0 and (.data_flow.sinks | length) > 0)] | length' "$work/taint.ctis.json")
    echo "ok   taint: $n finding(s) with a data flow"
    if [ "$n" -lt 2 ]; then
      echo "FAIL taint: want the 2 fixture flows with a source and a sink" >&2
      fail=1
    fi
  else
    echo "FAIL taint scan:" >&2
    tail -n 20 "$work/taint.log" >&2
    fail=1
  fi
fi
exit "$fail"
