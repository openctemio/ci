# OpenCTEM CI

Security scanning for CI pipelines that reports to [OpenCTEM](https://openctem.io).
Product documentation: <https://docs.openctem.io>.

- `openctem-ci`: a one-shot binary that runs one scan capability on the
  checked-out repository, converts the result to CTIS, uploads it to an
  OpenCTEM CI run with the job's OIDC identity (no stored API key) and asks
  the platform gate for the verdict.
- Images: one per tool (`ghcr.io/openctemio/ci-<tool>`) and a bundle with
  every tool (`ghcr.io/openctemio/ci`).
- The GitHub Action, GitLab CI templates and examples for other CI systems.

## Capabilities

| Name | Does | Tool |
|---|---|---|
| `sast` | static analysis of the code | opengrep (the `ci-semgrep` image runs semgrep) |
| `sca` | vulnerable dependencies | trivy |
| `secrets` | committed credentials | betterleaks |
| `iac` | infrastructure-as-code misconfigurations | trivy |
| `container` | vulnerable packages in an image | trivy |

`openctem-ci capabilities` prints the full mapping.

## Usage

```sh
openctem-ci scan --capability sast \
  --sarif openctem-sast.sarif \
  --gitlab-report gl-sast-report.json
```

Commands: `scan` (run one capability), `gate` (judge the status files of
several capability jobs, the final job of a pipeline), `capabilities` (list
the capabilities, their tools and images) and `version`.
`openctem-ci <command> -h` prints the flags of a command.

`scan` flags:

| Flag | Default | Meaning |
|---|---|---|
| `--capability` | `$OPENCTEM_CAPABILITY` | the one capability to run |
| `--target` | `.` | directory to scan, inside the workspace |
| `--image` | | image reference to scan (`container`) |
| `--sast-rules` | `$OPENCTEM_SAST_RULES`, else `p/default` | sast rules: a path in the repository, or a registry pack the engine fetches on the runner (`--semgrep-config` / `$OPENCTEM_SEMGREP_CONFIG` still work, with a deprecation warning) |
| `--sarif`, `--gitlab-report`, `--ctis` | | write SARIF, a GitLab security report or the CTIS report to this file |
| `--status` | | write the job status for a later `gate` job to this file |
| `--fail-on` | `$OPENCTEM_FAIL_ON` | local gate threshold (`critical`, `high`, `medium`, `low`, `info`), used when the platform gate cannot decide |
| `--no-push` | `false` | scan and write files only; do not upload |
| `--aggregate` | `false` | report into the run shared by all capability jobs of this pipeline; a final `gate` job decides |
| `--timeout` | `30m` | tool timeout |
| `--diff` | `$OPENCTEM_DIFF`, else `auto` | on a pull or merge request, `auto`: `sast` reports only findings new since the merge base with the target branch, `secrets` scans only the commits after it (every commit of the change, so a secret added and removed again is still found); both need the history (`fetch-depth: 0`) and fall back to a full scan, saying why, without it. `off` scans in full. Default-branch runs always scan in full |

A registry pack (such as the default `p/default`) is fetched by the engine on your runner at scan time and is used under the registry's own rules licence; the images do not include registry rules. Point `--sast-rules` at a path in the repository to run your own rules without fetching anything.

`gate` flags: `--status-dir` (default `.`), `--expect` (capabilities that
must have reported, default `$OPENCTEM_CAPABILITIES`), `--fail-on`, and
`--no-push` (decide locally with `--fail-on`).

| Variable | Meaning |
|---|---|
| `OPENCTEM_API_URL` | OpenCTEM URL (https) |
| `OPENCTEM_TENANT_ID` | organization id; turns on reporting with the job's OIDC identity |
| `OPENCTEM_OIDC_AUDIENCE` | audience, when the trust configuration does not use `openctem:tenant:<id>` |
| `OPENCTEM_ID_TOKEN_VAR` | the variable holding the job's token on GitLab (`id_tokens`), CircleCI and Jenkins (default `OPENCTEM_ID_TOKEN`) |
| `OPENCTEM_RETRIES` | repeats after a transient failure, 0 to 10 (default 3): a network error, 429 (honouring `Retry-After`) or 5xx on upload and verdict; the token exchange only when nothing reached the platform (no connection, 429, 503), since the job's token is single use |
| `OPENCTEM_UPLOAD_TIMEOUT` | time limit of one results upload, 10s to 1h (default `5m`); reports of 4 KiB and more are sent gzip-compressed |

Without `OPENCTEM_TENANT_ID`, or in a fork pull request, the scan runs in
scan-only mode: files and the local gate (`--fail-on`), no upload.

Exit codes: `0` pass, `1` the gate failed, `2` the scan cannot be trusted.

Design, identity and threat model: [docs/architecture.md](docs/architecture.md).
Repository gate settings: [docs/repository-file.md](docs/repository-file.md).

- GitHub Actions: [docs/github.md](docs/github.md)
- GitLab CI: [docs/gitlab.md](docs/gitlab.md)
- Images, signatures and SBOMs: [docs/images.md](docs/images.md)
- Local scans and pre-commit hooks: [docs/local.md](docs/local.md)
- Azure Pipelines, Bitbucket Pipelines, CircleCI, Jenkins: [docs/other-ci.md](docs/other-ci.md) and [examples/](examples/)

## Development

```sh
go test ./...
go build -o openctem-ci ./cmd/openctem-ci
```

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

GPL-3.0. See [LICENSE](LICENSE).
