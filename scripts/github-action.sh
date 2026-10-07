#!/usr/bin/env bash
# The body of the openctemio/ci GitHub Action (action.yml). Every input
# arrives through the environment (INPUT_*), never pasted into the script,
# and is validated here before use.
#
# It runs each capability in its image with `docker run`: the checkout is
# mounted at /src, outputs go to $RUNNER_TEMP/openctem, the root filesystem
# is read-only, and the job's OIDC request variables are passed only when
# results are reported (tenant set, not a fork).
set -euo pipefail

die() { echo "::error::$*"; exit 2; }

mode="${INPUT_COMMAND:-scan}"
caps_in="${INPUT_CAPABILITIES:-sast,sca,secrets}"
path_in="${INPUT_PATH:-.}"
target_in="${INPUT_TARGET:-.}"
fail_on="${INPUT_FAIL_ON:-}"
enforce="${INPUT_ENFORCE:-true}"
aggregate_in="${INPUT_AGGREGATE:-auto}"
image_override="${INPUT_SCANNER_IMAGE:-}"
tag="${INPUT_IMAGE_TAG:-}"
verify="${INPUT_VERIFY_SIGNATURE:-true}"
container_image="${INPUT_IMAGE:-}"
semgrep_config="${INPUT_SEMGREP_CONFIG:-}"
status_dir_in="${INPUT_STATUS_DIR:-}"

# ---- validation ------------------------------------------------------------
valid_caps="sast sca secrets iac container"
caps=()
for c in ${caps_in//,/ }; do
  c="$(printf '%s' "$c" | tr '[:upper:]' '[:lower:]')"
  if [ "$c" = all ]; then caps+=(sast sca secrets iac); continue; fi
  [[ " $valid_caps " == *" $c "* ]] || die "unknown capability '$c' (choose from: $valid_caps, all)"
  caps+=("$c")
done
# de-duplicate, keep order
mapfile -t caps < <(printf '%s\n' "${caps[@]}" | awk '!seen[$0]++')
[ "${#caps[@]}" -gt 0 ] || die "no capability given"

case "$mode" in scan | gate) ;; *) die "command must be scan or gate" ;; esac
case "$enforce" in true | false) ;; *) die "enforce must be true or false" ;; esac
case "$verify" in true | false) ;; *) die "verify-signature must be true or false" ;; esac
[ -z "$fail_on" ] || [[ "$fail_on" =~ ^(critical|high|medium|low|info)$ ]] || die "fail-on must be critical, high, medium, low or info"
for p in "$path_in" "$target_in"; do
  [[ "$p" != /* && "$p" != *..* ]] || die "path and target are relative paths inside the workspace without '..'"
done
[ -z "$container_image" ] || [[ "$container_image" =~ ^[a-z0-9./:@_-]+$ ]] || die "image is not an image reference"
[ -z "$semgrep_config" ] || [[ "$semgrep_config" =~ ^[A-Za-z0-9./_@:-]+$ && "$semgrep_config" != -* ]] || die "semgrep-config is not a rule pack or path"
[ -z "$tag" ] || [[ "$tag" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || die "image-tag is not a tag"
[ -z "$image_override" ] || [[ "$image_override" =~ ^[a-z0-9./:@_-]+$ ]] || die "scanner-image is not an image reference"

aggregate=false
case "$aggregate_in" in
  true) aggregate=true ;;
  false) ;;
  auto) [ "${#caps[@]}" -gt 1 ] && aggregate=true ;;
  *) die "aggregate must be auto, true or false" ;;
esac

src="${GITHUB_WORKSPACE:?}/${path_in}"
[ -d "$src" ] || die "path '$path_in' is not a directory in the workspace"
out="${RUNNER_TEMP:?}/openctem"
mkdir -p "$out/sarif" "$out/status" "$out/gitlab"
cache="${RUNNER_TEMP}/openctem-trivy-cache"
mkdir -p "$cache"

# ---- image per capability ----------------------------------------------------
if [ -z "$tag" ]; then
  # The action ref (v1, v1.2.3) names the matching image tag; any other ref
  # (a branch, a commit) uses the images built from main.
  if [[ "${ACTION_REF:-}" =~ ^v[0-9]+(\.[0-9]+\.[0-9]+)?$ ]]; then tag="$ACTION_REF"; else tag="edge"; fi
fi
image_for() {
  if [ -n "$image_override" ]; then echo "$image_override"; return; fi
  case "$1" in
    sast) echo "ghcr.io/openctemio/ci-semgrep:$tag" ;;
    secrets) echo "ghcr.io/openctemio/ci-betterleaks:$tag" ;;
    sca | iac | container) echo "ghcr.io/openctemio/ci-trivy:$tag" ;;
    gate) echo "ghcr.io/openctemio/ci-betterleaks:$tag" ;; # the smallest image
  esac
}

# Resolve a tag to its digest once, verify the signature (keyless, this
# repository's image workflow) and run exactly that digest.
declare -A resolved
pin() {
  local ref="$1"
  if [ -n "${resolved[$ref]:-}" ]; then echo "${resolved[$ref]}"; return; fi
  local pinned="$ref"
  if [ "$verify" = true ]; then
    local repo="${ref%:*}" digest
    [[ "$ref" == *@sha256:* ]] && repo="${ref%@*}"
    if [[ "$ref" == *@sha256:* ]]; then
      digest="${ref#*@}"
    else
      digest="$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' | jq -r .digest)"
    fi
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "could not resolve $ref to a digest"
    pinned="${repo}@${digest}"
    cosign verify "$pinned" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp '^https://github\.com/openctemio/ci/\.github/workflows/images\.yml@refs/(heads/main|tags/v[0-9.]+)$' \
      >/dev/null || die "the signature of $pinned does not verify"
    echo "Verified $pinned" >&2
  fi
  resolved[$ref]="$pinned"
  echo "$pinned"
}

# ---- reporting credentials ---------------------------------------------------
report_env=()
if [ -n "${OPENCTEM_TENANT_ID:-}" ]; then
  report_env+=(-e OPENCTEM_TENANT_ID -e OPENCTEM_API_URL -e OPENCTEM_OIDC_AUDIENCE)
  if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
    report_env+=(-e ACTIONS_ID_TOKEN_REQUEST_URL -e ACTIONS_ID_TOKEN_REQUEST_TOKEN)
  else
    echo "::warning::tenant-id is set but the job cannot request an OIDC token: grant 'permissions: id-token: write' (fork pull requests never get one). Scan only."
  fi
fi

run_ci() {
  local image="$1"
  shift
  # GitHub's event payload and summary are mounted read-only / append-only
  # paths; GITHUB_WORKSPACE is the mount point of the checkout.
  # Run as the runner user, which owns the checkout and the output directory.
  docker run --rm --read-only --tmpfs /tmp --tmpfs "/home/openctem:uid=${uid},gid=${gid}" \
    --user "${uid}:${gid}" --security-opt no-new-privileges --cap-drop ALL \
    -v "$src:/src" -v "$out:/out" -v "$cache:/home/openctem/.cache/trivy" \
    -v "${GITHUB_EVENT_PATH:?}:/github/event.json:ro" -v "${GITHUB_STEP_SUMMARY:?}:/github/summary" \
    -e GITHUB_ACTIONS -e GITHUB_REPOSITORY -e GITHUB_SHA -e GITHUB_REF -e GITHUB_HEAD_REF -e GITHUB_BASE_REF \
    -e GITHUB_EVENT_NAME -e GITHUB_SERVER_URL -e GITHUB_EVENT_PATH=/github/event.json \
    -e GITHUB_WORKSPACE=/src -e GITHUB_STEP_SUMMARY=/github/summary \
    -e OPENCTEM_FAIL_ON="$fail_on" -e OPENCTEM_SEMGREP_CONFIG="$semgrep_config" \
    "${report_env[@]}" \
    "$image" "$@"
}

uid="$(id -u)"
gid="$(id -g)"
rc=0
if [ "$mode" = scan ]; then
  for c in "${caps[@]}"; do
    image="$(pin "$(image_for "$c")")"
    args=(scan --capability "$c" --target "$target_in" --sarif "/out/sarif/openctem-$c.sarif"
      --gitlab-report "/out/gitlab/gl-$c-report.json" --status "/out/status/$c.status.json")
    [ "$c" = container ] && args+=(--image "$container_image")
    [ "$aggregate" = true ] && args+=(--aggregate)
    echo "::group::openctem-ci $c ($image)"
    set +e
    run_ci "$image" "${args[@]}"
    code=$?
    set -e
    echo "::endgroup::"
    echo "$c exit code: $code"
    [ "$code" -gt "$rc" ] && rc=$code
  done
  if [ "$aggregate" = true ] && [ "${INPUT_SKIP_GATE:-false}" != true ]; then
    image="$(pin "$(image_for gate)")"
    set +e
    run_ci "$image" gate --status-dir /out/status --expect "$(IFS=,; echo "${caps[*]}")"
    code=$?
    set -e
    # A failed scan (2) stays 2: the gate verdict never hides it.
    [ "$code" -gt "$rc" ] && rc=$code
  fi
else
  [ -n "$status_dir_in" ] || die "the gate command needs status-dir"
  sd="${GITHUB_WORKSPACE}/${status_dir_in}"
  [[ "$status_dir_in" != /* && "$status_dir_in" != *..* && -d "$sd" ]] || die "status-dir must be a directory in the workspace"
  cp -R "$sd/." "$out/status/"
  image="$(pin "$(image_for gate)")"
  set +e
  run_ci "$image" gate --status-dir /out/status --expect "$(IFS=,; echo "${caps[*]}")"
  rc=$?
  set -e
fi

{
  echo "exit-code=$rc"
  echo "sarif-dir=$out/sarif"
  echo "status-dir=$out/status"
  echo "gitlab-dir=$out/gitlab"
} >> "${GITHUB_OUTPUT:?}"

case "$rc" in
  0) exit 0 ;;
  1)
    if [ "$enforce" = true ]; then exit 1; fi
    echo "::warning::The OpenCTEM gate failed (enforce: false, the job passes)."
    exit 0
    ;;
  *) exit "$rc" ;; # a scan that cannot be trusted always fails
esac
