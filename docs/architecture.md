# openctem-ci architecture

`openctem-ci` runs one scan capability in a CI job and reports it to
OpenCTEM. It is the CI half of the platform's scanning: the sensor daemon
runs long-lived, platform-dispatched scans; CI jobs run this binary in a
small per-tool image. Both produce the same CTIS reports.

## Flow of `openctem-ci scan`

```
CI job ── checkout ──▶ openctem-ci scan --capability sast
                         │ 1. read the CI environment (repository, branch, commit, PR/MR, fork)
                         │ 2. resolve the target inside the workspace (symlinks followed)
                         │ 3. run the tool (fixed argv, filtered env, private temp dir, timeout);
                         │    on a pull/merge request sast is diff-aware (opengrep --baseline-commit
                         │    at the merge base) and secrets scans only the change's commits
                         │    (betterleaks git --log-opts=<base>..HEAD) when the history is there,
                         │    else a full scan
                         │ 4. convert its native output to CTIS (ctis/importer)
                         │ 5. scope: one repository asset, repository-relative paths;
                         │    sast: the hash of each result's flagged lines (snippetHash/v1)
                         │    secrets: HMAC-SHA256 of each raw secret under the run's key (secretHMAC/v1)
                         │ 6. redact: mask secrets everywhere, then check every output
                         │ 7. exchange the job's OIDC token for a run token, upload every result
                         │ 8. leave out the results the platform says are already decided,
                         │    write SARIF / GitLab report / CTIS / status file
                         └ 9. ask the platform gate for the verdict (or the local gate)
```

### Known false positives

A false positive, duplicate, accepted risk or approved exception decided in
OpenCTEM is not shown again:

- The job uploads **every** result. The upload answers with `known`, the
  indexes of the results that already carry a decision. The job leaves those
  out of its summary, its SARIF (code scanning alerts) and its merge request
  report, and logs how many it left out and why. The CTIS file keeps every
  result.
- The platform decides, the job only displays: the gate does not count a
  decided finding whatever the job shows, and a job that hides more than it
  was told changes nothing in the verdict.
- Identity: a SAST result goes up with the hash of the lines it flags, read
  from the checked-out tree through an `os.Root` (never outside it), so the
  platform keys it on its code, not its line. Code inserted above a false
  positive keeps it one; editing the flagged code makes a new finding that is
  judged again. Only the hash leaves the job.
- Without the platform (`--no-push`, a fork, an upload failure) nothing is
  hidden: the job cannot know.
- Taint traces: sast runs with `--dataflow-traces`. A taint result goes up with
  the path from the source to the sink (the CTIS `data_flow`: file, line and
  code of each step, paths relative to the repository). The finding page
  shows it, and it never changes the finding's identity. opengrep writes the
  trace; semgrep's open-source engine no longer does, so `ci-semgrep` results
  carry none. The image smoke test scans the fixture with
  `testdata/rules/taint.yaml` and requires a data flow on both of its flows.

Exit codes: `0` pass (or no gate asked), `1` the gate failed, `2` the scan
cannot be trusted (tool, parse, upload, redaction or configuration error).
A broken scan never exits 0.

## Capabilities

Users choose capabilities, never images or tools. The one mapping is
`internal/capability/capability.go`; its ids are the platform capability
taxonomy ids (`ctis/capability`), checked by a test.

| Name | Capability id | Tool | Image | GitLab report |
|---|---|---|---|---|
| `sast` | `sast.code@1` | opengrep (semgrep in `ci-semgrep`) | `ghcr.io/openctemio/ci-opengrep` | `sast` |
| `sca` | `sca.deps@1` | trivy (`fs`, vulnerabilities) | `ghcr.io/openctemio/ci-trivy` | `dependency_scanning` |
| `secrets` | `secrets.code@1` | betterleaks | `ghcr.io/openctemio/ci-betterleaks` | `secret_detection` |
| `iac` | `iac.misconfig@1` | trivy (`config`) | `ghcr.io/openctemio/ci-trivy` | `sast` |
| `container` | `container.image@1` | trivy (`image`) | `ghcr.io/openctemio/ci-trivy` | `container_scanning` |

A `container` report carries the image reference (`metadata.properties.container_image`)
and its content digest (`image_digest`, from the registry digest trivy reports), so
the platform can relate the repository to the workloads running that exact image.

`all` selects every repository capability (`container` needs `--image` and is
never implied). `ghcr.io/openctemio/ci` carries every tool.

## Identity: OIDC only

A job proves who it is with its CI provider's OIDC token (GitHub Actions
`id-token: write`; GitLab `id_tokens` with the trust configuration's
audience, default `openctem:tenant:<tenant id>`; Azure Pipelines from
`System.OidcRequestUri`; Bitbucket `BITBUCKET_STEP_OIDC_TOKEN`; CircleCI and
Jenkins a token minted or bound into `OPENCTEM_ID_TOKEN`, see
[other-ci.md](other-ci.md)). `openctem-ci` exchanges it
at `POST /api/v1/ci/oidc/exchange` for a run token (`octci_`, at most 15
minutes) bound to one run on one repository. No API key is stored in CI.

- The run token stays inside `internal/platform`: never printed, logged or
  part of an error; `String()` redacts it.
- The platform URL must be https (plain http only for localhost); redirects
  are not followed, so the bearer cannot be sent to another host.
- The repository, branch and commit of a run come from the verified token
  on the platform, not from the report.
- Where the token signs no commit (CircleCI, Jenkins without a `sha`
  claim) or no repository name (Bitbucket), the exchange carries the job's
  own value; the platform uses it only then and marks it.
- GitHub and Azure mint a token on request, so a long job renews its run
  token with a fresh one. Elsewhere the job holds one token: once its run
  token nearly expires, the same token is exchanged again, which the
  platform answers with the same run only (at most five times per token).
- **One exchange per job.** The first `openctem-ci` step of a job stores the
  run token in the job's temp dir (`RUNNER_TEMP` on GitHub,
  `AGENT_TEMPDIRECTORY` on Azure, else `TMPDIR` or `/tmp`), in
  `openctem-ci-<uid>/<hash>.json`: directory 0700, file 0600, both owned by
  the user, never inside the job's workspace (artifacts and caches are taken
  from there). Later steps of the same job (a scan per capability, then the
  gate) reuse it until 30 seconds before it expires, so a job opens one run
  however many steps it has. The name hashes the API URL, tenant, provider,
  aggregate mode, the job id and, where the job holds one OIDC token, that
  token's digest: another job or another token never matches. The file holds
  the run id, run token, expiry, run details and secret hashing key, never
  the OIDC token; anything not private to the user (symlink, other owner,
  wider mode) is ignored. It is removed when the run gets its verdict, when
  the platform refuses the token (the step then exchanges its own) and when
  found expired; the runner removes the temp dir with the job.
  `OPENCTEM_TOKEN_CACHE=off` turns it off.
- A CI system without OIDC runs in scan-only mode: SARIF, reports and the
  local gate, no upload.

## Aggregate run

A pipeline that runs several capability jobs in parallel reports into one
platform run: each job calls `scan --aggregate`, and a final job calls
`gate`. The exchange carries `aggregate: true`; the platform finds or opens
the run shared by every job of the same pipeline run (same pipeline,
commit and attempt) and gives each job its own token for it. Only `gate`
asks for the verdict, on everything the jobs uploaded.

Scan jobs hand a status file (`<capability>.status.json`: ok, pushed, counts
per severity, no finding text) to the gate job as a CI artifact. A
capability that is expected but missing, failed or not uploaded counts as a
scan failure, and any scan failure fails the gate (fail closed).

A scan job whose upload fails never fails the pipeline on that alone: with
`--aggregate`, `--on-upload-error` defaults to `warn`. The job writes its
local reports as always, prints a loud warning, records `pushed: false` in
its status file and keeps its CTIS report beside it
(`<capability>.pending.ctis.json`, already checked for raw secrets, the same
content as the SARIF report). The gate job uploads every pending report with
its own token into the same aggregate run before it asks for the verdict;
only a report that still cannot be uploaded counts as not uploaded. A job
that is its own gate (no `--aggregate`) defaults to `fail`, and the gate job
stays fail closed when it gets no verdict. The gate reads a pending report
only under its fixed name beside its status file, as a plain file of at most
32 MiB; the platform refuses a report about another repository, so the
report adds nothing the scan job's own token could not upload.

A platform that does not answer `aggregate: true` is refused
(`ErrNoAggregate`): otherwise the gate job would judge an empty run and pass.

## Threat model

| Threat | Control |
|---|---|
| A fork pull/merge request exfiltrates the platform credential or uploads forged results | A fork is detected from the event (GitHub: head repository differs or is a fork; GitLab: source project differs) and never uploads or uses a credential; GitHub gives forks no OIDC token; the platform trust refuses forks by default |
| A long-lived key leaks from CI settings or logs | No key exists: OIDC per job, short-lived run token, never printed |
| A scanned repository runs code through the tool's environment | The tool gets an allow-listed environment (no OIDC request token, ID token, job token, platform or API key); the tool is resolved only from absolute PATH entries |
| A raw secret reaches the platform, an artifact or the log | Each secret goes up only as `HMAC-SHA256` of its raw value under the key the exchange hands the run (per organization and repository; CTIS partial fingerprint `secretHMAC/v1`), so the platform keys the finding on the secret without seeing it. Secret scanner output goes to a private 0700 temp dir, removed after the run; every finding is masked (`ctis.RedactSecretFinding` with the raw values); every output is checked for the raw values before it is written or sent, and the run stops instead (`ErrSecretInOutput`); SARIF and GitLab reports carry no snippet; the secret scanner is never run with `--verbose` |
| A report names another repository or a path outside the checkout | The target must resolve inside the workspace; the report keeps one repository asset; paths outside the repository are cleared; the platform re-validates (`ScopeReport`) |
| Hostile tool output (huge, deep, malformed) | Bounded reads (512 MB), `ctis/importer` limits; a parse error is a scan failure |
| Platform or scanner text forges CI log lines | Control characters and `::` workflow-command prefixes are removed before printing |
| A pull request changes scanner configuration committed in the tree to hide its own findings (a `trivy.yaml` severity threshold, a `.trivyignore`, a `.gitleaks.toml` allowlist, a `.betterleaksignore`) | Those files are not read: trivy runs with `--config ""` and `--ignorefile ""`, betterleaks with its built-in rules (unless the pipeline sets `BETTERLEAKS_CONFIG*`) and an ignore path outside the tree; configuration comes from the pipeline, exceptions are requested in `.openctem.yml` and approved in OpenCTEM. SAST runs with `--disable-nosem` and `--x-ignore-semgrepignore-files`: results under an inline ignore comment are reported (marked as in-source claims) and `.semgrepignore` patterns are sent as claims; OpenCTEM turns a default-branch run's claims into pending requests, and the gate counts the results until one is approved |
| Option injection through user input | Fixed argument lists, no shell; image references and sast rules that start with `-` are refused |
| A broken scan turns the pipeline green | Every failure exits 2 and is recorded as a scan failure on the run; the gate job counts missing statuses |

## Local gate

`--fail-on <severity>` is the offline fallback: it decides only when the
platform's verdict is unavailable (scan-only mode, platform unreachable).
Unknown severities block, and a finding that is actively exploited (KEV) or
has a known exploit blocks below the threshold.

## Dependencies

Only `github.com/openctemio/ctis` (CTIS types, importers, redaction,
capability taxonomy), pinned to a commit on its `main` branch
(`.github/scripts/check-deps-on-main.sh`).
