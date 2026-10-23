### Added: `openctem-ci upload --format mapping:<name>[@<version>]`

- Sends a CSV, JSON or XML file through an import mapping saved in your OpenCTEM organization: the value goes to the platform as the `format` query parameter of the run upload. Without `--format mapping:...`, detection is unchanged.
- The value is checked before anything is sent (name `[a-z0-9][a-z0-9._-]{0,63}`, positive integer version); an archive cannot go through a mapping.
- Still partial coverage: a mapped upload never closes findings. The idempotency key covers the mapping, so the same file through another mapping is a separate import.

### Upgrade notes

- Additive. Needs an OpenCTEM release with import mappings.
