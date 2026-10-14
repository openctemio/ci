#!/usr/bin/env bash
# Tests for scripts/action-lib.sh. Run: bash .github/scripts/action-lib.test.sh
set -euo pipefail
lib="$(cd "$(dirname "$0")/../.." && pwd)/scripts/action-lib.sh"
# shellcheck disable=SC1090
. "$lib"
pass=0 failed=0
check() { # check <name> <got> <want>
  if [ "$2" = "$3" ]; then pass=$((pass + 1)); else failed=$((failed + 1)); printf 'FAIL %s\n  got:  %s\n  want: %s\n' "$1" "$2" "$3"; fi
}
matches() { # matches <name> <regexp> <identity> <0|1>
  local got=1
  if [[ "$3" =~ $2 ]]; then got=0; fi
  check "$1" "$got" "$4"
}
wf='https://github.com/openctemio/ci/.github/workflows/images.yml@refs/'

# Signer identity per tag.
id="$(signer_identity v0.3.0)"
matches "release accepts its own tag" "$id" "${wf}tags/v0.3.0" 0
matches "release refuses main" "$id" "${wf}heads/main" 1
matches "release refuses another release" "$id" "${wf}tags/v0.2.0" 1
matches "release refuses a look-alike" "$id" "${wf}tags/v0x3x0" 1
id="$(signer_identity v0)"
matches "major accepts its releases" "$id" "${wf}tags/v0.4.1" 0
matches "major refuses another major" "$id" "${wf}tags/v1.0.0" 1
matches "major refuses main" "$id" "${wf}heads/main" 1
id="$(signer_identity edge)"
matches "edge accepts main" "$id" "${wf}heads/main" 0
matches "edge refuses a tag" "$id" "${wf}tags/v0.3.0" 1
id="$(signer_identity sha-1234567)"
matches "sha accepts main" "$id" "${wf}heads/main" 0
id="$(signer_identity custom)"
matches "other accepts main" "$id" "${wf}heads/main" 0
matches "other accepts a release" "$id" "${wf}tags/v0.3.0" 0
matches "other refuses another workflow" "$id" "https://github.com/openctemio/ci/.github/workflows/evil.yml@refs/heads/main" 1

# Proxy variables pass by name, only when set.
got="$( (unset HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; export HTTPS_PROXY=http://u:p@proxy:3128 no_proxy=.corp; proxy_env_args) | tr '\n' ' ')"
check "proxy args by name" "$got" "-e HTTPS_PROXY -e no_proxy "
got="$( (unset HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; proxy_env_args) | tr '\n' ' ')"
check "no proxy, no args" "$got" ""

# CA bundle: a file in the workspace, mounted read-only.
ws="$(mktemp -d)"
mkdir -p "$ws/certs"; echo pem > "$ws/certs/ca.pem"
got="$(ca_bundle_args "$ws" certs/ca.pem | tr '\n' ' ')"
check "ca bundle mounted" "$got" "-v $ws/certs/ca.pem:/etc/openctem/ca.pem:ro -e SSL_CERT_FILE=/etc/openctem/ca.pem -e REQUESTS_CA_BUNDLE=/etc/openctem/ca.pem "
check "no ca bundle" "$(ca_bundle_args "$ws" "")" ""
for bad in /etc/ssl/cert.pem ../ca.pem certs/../../x certs/missing.pem certs; do
  rc=0; ca_bundle_args "$ws" "$bad" >/dev/null 2>&1 || rc=$?
  check "ca bundle refused: $bad" "$rc" 1
done
find "$ws" -delete

echo "action-lib: $pass passed, $failed failed"
[ "$failed" = 0 ]
