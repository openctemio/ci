### Added: `openctem-ci upload`, for scanner reports a pipeline already has

- `openctem-ci upload [--format F] [--gate] [--aggregate] [--receipt FILE] <file or directory>...` sends SARIF, trivy, grype, osv-scanner, ZAP, nuclei, CycloneDX, SPDX, CSAF, OpenVEX, Nessus, Qualys, semgrep, opengrep, vuls or DefectDojo files, or a ZIP of them, to the job's OpenCTEM CI run as they are; the platform detects and converts them.
- Same identity as `scan`: the job's OIDC token for a 15-minute run token; the repository, branch and commit come from the verified token.
- Every file is checked before anything is sent (format via the importers' detection, at most 50 MiB, at most 50 files); the file is streamed from disk.
- Each file carries an `Idempotency-Key` derived from the run id and the file's SHA-256, so a retried request, step or job never imports it twice.
- Partial: an upload never closes findings. The receipt lists new, still detected, resolved, reopened, skipped and failed per file. Exit 2 when a file is not stored (or `--on-upload-error warn`); `--gate` asks for the verdict and counts files not stored as failed scans.
- Secret scanner reports (gitleaks, betterleaks) are refused: they hold raw secret values; use `scan --capability secrets`.

### Upgrade notes

- Additive. Needs OpenCTEM v0.11.0 or later (tool files on `POST /api/v1/ci/runs/{id}/results`).
