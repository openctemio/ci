### Changed: CTIS 2.0

- Reports are CTIS 2.0 (`github.com/openctemio/ctis/v2`, `github.com/openctemio/contract` for the capability taxonomy). A scan result goes up as the document itself with the media type `application/vnd.ctis+json; version=2.0`; a report an older openctem-ci left pending for the gate is refused with the upgrade message.
- `metadata.id` is a producer UUIDv7, the same for every part of a large report; the parts carry `metadata.segment`. A part the platform refuses as too large is sent as two documents with new ids and partial coverage.
- No document carries a platform id: asset, finding and dependency references are document-local and never UUID-shaped.
- The repository is a `repository` asset in its canonical form. A scanned container image is a `container_image` asset with the canonical value `<registry>/<repository>@sha256:<digest>` when the digest is known, and its findings are filed on it. An image given by tag alone has no image asset.
- The capability is `metadata.extensions["io.openctem"].capability`; the scanner ignore-file patterns are `metadata.extensions["io.openctem"].ignore_file_paths` (at most 20 patterns of at most 500 characters, none with a control character). `metadata.properties` carries nothing.
- A scan of the whole repository on the default branch states its outcome in `metadata.targets`; a tool that failed after writing a partial report is a target in state `failed`.
- Secret findings get the `ctis-fp/2` fingerprint over an HMAC of the raw value under the run's key; without the key a report carries no secret fingerprint.
- SAST results without an advisory id are type `weakness`; rule text is written once in the report's `rules[]`, and SARIF output reads it from there. The SARIF partial fingerprint key is `openctem/v2`.

### Upgrade notes

- Breaking, with no compatibility layer: merge right after the OpenCTEM CTIS 2.0 switch and upgrade the platform and openctem-ci together.
