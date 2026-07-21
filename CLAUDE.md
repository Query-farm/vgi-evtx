# CLAUDE.md — vgi-evtx

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion.

## What this is

A [VGI](https://query.farm) worker (Rust, compiled binary) exposing **Windows
Event Log (`.evtx`) parsing** to DuckDB/SQL over Arrow IPC. Built on the `vgi`
crate (crates.io), modeled on `vgi-ioc` / `vgi-image`. Catalog name `evtx`
(single `main` schema). **Defensive DFIR tool** — it parses event-log files (from
potentially compromised hosts) into rows; it does not touch the network. Pairs
with `vgi-sigma`: `evtx_records(...).event_json` feeds `sigma_match(event_json,
rule)`.

## Layout

```
Cargo.toml                          workspace; pins vgi = "0.5.0", evtx = "0.8.5", serde_json
crates/evtx-worker/
  src/main.rs                       Worker::new(); registers scalars + table fn
  src/evtx_parse.rs                 PURE logic (no Arrow): parse_records / record_count / is_valid + unit tests
  src/arrow_io.rs                   BLOB-or-VARCHAR-path input reads + in-process scalar test harness
  src/scalar/{inspect,mod}.rs         thin Arrow scalar adapters (evtx_record_count, is_valid_evtx)
  src/table/{evtx_records,mod}.rs   thin Arrow table-producer adapter (8 typed columns incl. TIMESTAMP)
  tests/parse.rs                    integration tests (include evtx_parse.rs by #[path], like vgi-ioc)
test/sql/*.test                     haybarn-unittest sqllogictest — authoritative E2E
test/sql/data/sample-security.evtx  clean 68 KB fixture (+ README.md attribution)
Makefile                            test / test-unit / test-sql / lint / fmt / build / clean
```

Pattern: keep parsing in `evtx_parse.rs` (pure, unit-tested), keep Arrow
marshalling in `arrow_io.rs` + `scalar/*.rs` + `table/*.rs` (thin,
harness-tested).

## MSRV pin (the load-bearing dependency decision)

The workspace `rust-version` is `1.86`. `evtx >= 0.10` is **edition 2024** and
uses let-chains → needs rustc ≥ 1.88. We therefore pin **`evtx = "0.8.5"`**
(edition 2021, builds on 1.86) with `default-features = false` to drop the
optional `simplelog` feature, which transitively pulls a `time` that *also*
needs rustc 1.88. If you ever bump the workspace MSRV to ≥ 1.88 you can move to a
newer evtx. Do not enable evtx default features without re-checking the `time`
MSRV.

## Input: BLOB or VARCHAR path

Both the scalars and the table function accept the `.evtx` either inline as a
**BLOB** or as a **VARCHAR path** to open. `arrow_io::input_bytes` (scalars,
row column) and `arrow_io::const_input_bytes` (table, bind-time constant)
centralize the path-vs-bytes decision. A path that can't be read (missing, too
large, not a file) resolves to "no usable input" → NULL/false/no rows, never an
error.

## Hostile input (the core requirement)

`.evtx` comes from compromised hosts. `evtx_parse.rs` is written so **no input
can panic or crash the worker**:

1. Input bounded to `MAX_INPUT_BYTES` (256 MiB) and output to `MAX_RECORDS`
   (5,000,000) before any parsing.
2. `ElfFile\0` magic pre-check rejects non-evtx up front.
3. Parser construction + record iteration run under `catch_unwind` — a panic in
   the third-party parser over hostile bytes becomes "no rows / invalid".
4. Per-record errors are skipped (one bad record ≠ whole-file failure).
   Garbage-beside-good is tested at both the pure and Arrow layers.

## Field extraction

Convenience columns come from `Event.System`: `EventID` (handles both the bare
integer form and the `{ "#text": …, "#attributes": {Qualifiers} }` object form),
`Provider/@Name`, `Channel`, `Computer`, `Level`. `time_created` is the record
header timestamp (`chrono::DateTime<Utc>`) as microseconds since epoch →
`Timestamp(Microsecond, None)`. The full event stays in `event_json`.

## Sharp edges (learned from the templates)

1. **`haybarn-unittest` skips `require vgi`** — `.test` files use explicit
   `statement ok` + `LOAD vgi;`. Functions live under the `evtx` catalog, so each
   file does `SET search_path = 'evtx.main'`, then `USE memory` before `DETACH`.
2. **Table functions take *constant* args, bound positionally** by the Rust SDK
   (no `name :=`). `evtx_records('path')` or `evtx_records(blob_literal)` — read
   via `arguments.const_str(0)` / `arguments.const_bytes(0)`.
3. **TIMESTAMP column** is `Timestamp(Microsecond, None)` (no timezone =
   DuckDB `TIMESTAMP`); the builder is `TimestampMicrosecondBuilder`. The declared
   `on_bind` schema must match the array built in `next_batch`.
4. **Determinism in SQL tests:** `evtx_records` rows are emitted in file order;
   tests still `ORDER BY record_id` (or `rowsort`) for stable comparison.
5. **Scalars are positional-only**, arity-1. The worker build version is not a
   scalar function (VGI328): it is published as the catalog's
   `implementation_version` and read from `vgi_catalogs()`.

## Tests

- `cargo test --workspace` — `evtx_parse.rs` unit tests (clean parse, truncation,
  garbage, EventID object form, bounding) + the in-process Arrow-boundary tests
  in `scalar/inspect.rs` + `tests/parse.rs`.
- `make test-sql` — the DuckDB E2E suite in `test/sql/*.test` over the committed
  fixture.
