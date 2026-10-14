# Local scans and pre-commit

The CI images run on a laptop too. Nothing is uploaded with `--no-push`; the
local gate (`--fail-on`) decides the exit code (`0` pass, `1` a finding at or
above the threshold, `2` the scan failed).

## One command

From the repository root, as your own user, with the checkout mounted
read-only:

```sh
docker run --rm --read-only --tmpfs /tmp \
  --user "$(id -u):$(id -g)" --tmpfs "/home/openctem:uid=$(id -u),gid=$(id -g)" \
  -e OPENCTEM_WORKSPACE=/src -v "$PWD:/src:ro" \
  ghcr.io/openctemio/ci:v0.3.0 scan --capability secrets --no-push --fail-on high
```

- `--capability` is one of `sast`, `sca`, `secrets`, `iac` (one per run; the
  `ci` image has every tool, the `ci-opengrep`, `ci-semgrep`, `ci-trivy` and `ci-betterleaks`
  images one each).
- `--user` and the `/home/openctem` tmpfs let the tools write their caches as
  you; without them a uid other than 1001 gets "permission denied".
- To keep a SARIF file for your editor, `mkdir -p .openctem` first (so the
  directory is yours) and add `-v "$PWD/.openctem:/out"` before the image and
  `--sarif /out/secrets.sarif` after `scan`.
- The scanners do not read configuration or ignore files from the tree
  (`trivy.yaml`, `.trivyignore`, `.gitleaks.toml`, ...); request exceptions in
  [`.openctem.yml`](repository-file.md).

## pre-commit

This repository publishes [pre-commit](https://pre-commit.com) hooks. They run
on the working tree as pre-commit leaves it (your staged changes; unstaged
ones are stashed) and need Docker:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/openctemio/ci
    rev: v0.3.0
    hooks:
      - id: openctem-secrets   # any secret blocks the commit
      - id: openctem-sast      # high or critical static analysis findings block it
```

`pre-commit install`, then commit as usual. The hooks are a convenience for
the developer: the gate that counts is the platform's, on the pull request.
