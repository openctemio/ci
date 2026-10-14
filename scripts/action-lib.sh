#!/usr/bin/env bash
# Helpers of scripts/github-action.sh, sourced by it and by
# .github/scripts/action-lib.test.sh. Pure functions: they print, never exit.

# signer_identity <tag> prints the certificate identity (a regexp) the
# signature of an image with that tag must carry: the image workflow of this
# repository, at the ref that built the tag. A release tag vX.Y.Z is only
# built from the git tag vX.Y.Z, a major tag vX from a vX.*.* release, edge
# and sha-* from main. Any other tag (an image-tag input naming something
# else) accepts main or a release, as before.
signer_identity() {
  local tag="$1" wf='^https://github\.com/openctemio/ci/\.github/workflows/images\.yml@refs/'
  if [[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    printf '%stags/v%s\\.%s\\.%s$\n' "$wf" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
  elif [[ "$tag" =~ ^v([0-9]+)$ ]]; then
    printf '%stags/v%s\\.[0-9]+\\.[0-9]+$\n' "$wf" "${BASH_REMATCH[1]}"
  elif [[ "$tag" == edge || "$tag" =~ ^sha-[0-9a-f]{7,40}$ ]]; then
    printf '%sheads/main$\n' "$wf"
  else
    printf '%s(heads/main|tags/v[0-9.]+)$\n' "$wf"
  fi
}

# proxy_env_args prints, one per line, the docker arguments that pass the
# job's proxy settings into a scanner container by name (-e NAME, so a proxy
# URL with credentials never appears on a command line).
proxy_env_args() {
  local v
  for v in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
    if [ -n "${!v:-}" ]; then
      printf -- '-e\n%s\n' "$v"
    fi
  done
}

# ca_bundle_args <workspace> <relative path> prints the docker arguments that
# mount a PEM bundle from the workspace read-only and point the tools at it,
# or fails (status 1, message on stderr) for a path outside the workspace or
# not a file. Empty path: nothing.
ca_bundle_args() {
  local ws="$1" rel="$2"
  [ -n "$rel" ] || return 0
  if [[ "$rel" == /* || "$rel" == *..* || ! -f "$ws/$rel" ]]; then
    echo "ca-bundle must be a file in the workspace (a relative path without '..')" >&2
    return 1
  fi
  printf -- '-v\n%s:/etc/openctem/ca.pem:ro\n-e\nSSL_CERT_FILE=/etc/openctem/ca.pem\n-e\nREQUESTS_CA_BUNDLE=/etc/openctem/ca.pem\n' "$ws/$rel"
}
