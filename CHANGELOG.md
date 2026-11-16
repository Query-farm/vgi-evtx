# Changelog

## 0.4.2 (2026-11-16)

- Bump the vgi Rust SDK to 0.51.1.
- CI: a release reuses the passing CI run of its commit; container images build on release tags only.

## 0.4.1 — 2026-11-14

### Fixed

- Example queries now show real output for any user, not only inside this repo
  (vgi-lint-check 2.7.0 VGI913/VGI516). They previously read `Security.evtx` or
  `test/sql/data/sample-security.evtx`, which exist only in the repo checkout, so
  outside it the scalars returned NULL and `evtx_records` returned no rows. The
  examples now read the committed sample Security log through a release-tag-pinned
  URL (`raw.githubusercontent.com/Query-farm/vgi-evtx/v0.4.0/test/sql/data/sample-security.evtx`);
  `evtx_records` examples load it with `SET VARIABLE` + `getvariable(...)`, since
  table-function arguments must be constants. The folder-triage example reads two
  pinned URLs instead of a local glob. README examples updated to match.
