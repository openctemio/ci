#!/usr/bin/env bash
# Runs gitlab/templates/all.yml as a real GitLab pipeline with
# gitlab-ci-local (docker executor) on testdata/fixture, scan only (no
# platform), and checks what a GitLab user gets: every job ran, each
# gl-*-report.json validates against the published GitLab schema and has
# findings, the gate failed on the fixture's high findings (fail-on high),
# and no raw secret is in any artifact.
#
#   scripts/gitlab-local-test.sh            # the images the template pins
#   OPENCTEM_TEST_IMAGE=img:tag scripts/gitlab-local-test.sh   # one local image for every job
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
secret="Zq8vT3xK9mB2nR7wL4pY6sD1fH5jC0gA" # the fake credential in testdata/fixture
work="$(mktemp -d)"
trap 'rm -rf -- "${work:?}"' EXIT

cp -R "$root/testdata/fixture/." "$work/"
cp "$root/gitlab/templates/all.yml" "$work/openctem-all.yml"
if [ -n "${OPENCTEM_TEST_IMAGE:-}" ]; then
  sed -i -E "s#name: ghcr\.io/openctemio/ci[a-z-]*[:@][^ ]*#name: ${OPENCTEM_TEST_IMAGE}#" "$work/openctem-all.yml"
fi
cat > "$work/.gitlab-ci.yml" <<'EOF'
include:
  - local: openctem-all.yml
# The fixture has high findings: the gate must fail. Let the pipeline go on
# so the test can read every artifact.
openctem-gate:
  allow_failure: true
EOF
git -C "$work" init -q -b main
git -C "$work" remote add origin https://gitlab.com/openctemio/ci-fixture.git
git -C "$work" -c user.name=test -c user.email=test@example.invalid add -A
git -C "$work" -c user.name=test -c user.email=test@example.invalid commit -q -m fixture

pull=()
[ -n "${OPENCTEM_TEST_IMAGE:-}" ] && pull=(--pull-policy if-not-present)
(cd "$work" && npx -y gitlab-ci-local@4.76.1 --artifacts-to-source "${pull[@]}" \
  --variable OPENCTEM_FAIL_ON=high --variable CI_DEFAULT_BRANCH=main) | tee "$work/pipeline.log"

fail=0
for job in openctem-sast openctem-sca openctem-secrets openctem-iac; do
  grep -qE "$job .*(finished|Job succeeded)" "$work/pipeline.log" || { echo "FAIL $job did not succeed" >&2; fail=1; }
done
if ! grep -qE "openctem-gate .*(exit code 1|failed)|Local gate: FAIL" "$work/pipeline.log"; then
  echo "FAIL the gate did not fail on the fixture's high findings" >&2
  fail=1
fi

python3 -m venv "$work/.venv" >/dev/null
"$work/.venv/bin/pip" install -q jsonschema==4.25.1
"$work/.venv/bin/python" - "$work" "$root/internal/gitlab/testdata/schemas/v15.2.5" <<'EOF' || fail=1
import json, sys, jsonschema
work, schemas = sys.argv[1], sys.argv[2]
reports = {
    "gl-sast-report.json": "sast",
    "gl-dependency-scanning-report.json": "dependency-scanning",
    "gl-secret-detection-report.json": "secret-detection",
    "gl-iac-report.json": "sast",
}
bad = 0
for name, kind in reports.items():
    try:
        doc = json.load(open(f"{work}/{name}"))
        jsonschema.validate(doc, json.load(open(f"{schemas}/{kind}-report-format.json")))
    except Exception as e:  # noqa: BLE001
        print(f"FAIL {name}: {e}", file=sys.stderr)
        bad = 1
        continue
    n = len(doc["vulnerabilities"])
    print(f"ok   {name}: valid {kind} report (schema {doc['version']}), {n} vulnerabilities")
    if n == 0:
        print(f"FAIL {name} is empty", file=sys.stderr)
        bad = 1
sys.exit(bad)
EOF

if grep -rl --exclude-dir=.git --exclude-dir=.venv --exclude=settings.py --exclude=pipeline.log "$secret" "$work"; then
  echo "FAIL the raw fixture secret is in an artifact" >&2
  fail=1
fi
[ "$fail" -eq 0 ] && echo "GitLab pipeline test passed."
exit "$fail"
