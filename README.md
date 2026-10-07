# OpenCTEM CI

Security scanning for CI pipelines that reports to [OpenCTEM](https://github.com/openctemio).

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
| `sast` | static analysis of the code | semgrep |
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

| Variable | Meaning |
|---|---|
| `OPENCTEM_API_URL` | OpenCTEM URL (https) |
| `OPENCTEM_TENANT_ID` | organization id; turns on reporting with the job's OIDC identity |
| `OPENCTEM_OIDC_AUDIENCE` | audience, when the trust configuration does not use `openctem:tenant:<id>` |
| `OPENCTEM_ID_TOKEN_VAR` | GitLab `id_tokens` variable (default `OPENCTEM_ID_TOKEN`) |

Without `OPENCTEM_TENANT_ID`, or in a fork pull request, the scan runs in
scan-only mode: files and the local gate (`--fail-on`), no upload.

Exit codes: `0` pass, `1` the gate failed, `2` the scan cannot be trusted.

Design, identity and threat model: [docs/architecture.md](docs/architecture.md).

- GitHub Actions: [docs/github.md](docs/github.md)
- GitLab CI: [docs/gitlab.md](docs/gitlab.md)
- Images, signatures and SBOMs: [docs/images.md](docs/images.md)

## Development

```sh
go test ./...
go build -o openctem-ci ./cmd/openctem-ci
```

## License

GPL-3.0. See [LICENSE](LICENSE).
