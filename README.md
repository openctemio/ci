# OpenCTEM CI

Security scanning for CI pipelines that reports to [OpenCTEM](https://github.com/openctemio).

This repository builds:

- `openctem-ci`, a one-shot binary that runs one scanner capability on the
  checked-out repository, converts the result to CTIS, uploads it to an
  OpenCTEM CI run with the job's OIDC identity (no stored API key) and asks
  the platform gate for the verdict;
- one container image per tool (`ghcr.io/openctemio/ci-<tool>`) and a bundle
  with every tool (`ghcr.io/openctemio/ci`);
- the GitHub Action, the GitLab CI templates and examples for other CI systems.

Work in progress: see the open pull requests.

## License

GPL-3.0. See [LICENSE](LICENSE).
