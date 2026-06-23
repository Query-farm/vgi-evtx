# vgi-evtx

A [VGI](https://query.farm) worker (Rust, a compiled binary) that parses
**Windows Event Log (`.evtx`) files** into rows for DuckDB / SQL over Apache
Arrow. DuckDB launches the worker and talks to it over Arrow IPC; the functions
appear under the catalog `evtx`, schema `main`.

This is a **defensive DFIR tool**: it turns a `.evtx` file (which often comes
from a *compromised* host and must be treated as hostile input) into structured
rows you can query, and it preserves the full normalized event JSON so the
output composes with [`vgi-sigma`](../vgi-sigma)'s
`sigma_match(event_json, rule)`. It is pure parsing — no network access.

```sql
LOAD vgi;
ATTACH 'evtx' (TYPE vgi, LOCATION './target/release/evtx-worker');
SET search_path = 'evtx.main';

-- One row per event record. Input is the .evtx file as a BLOB …
SELECT record_id, event_id, provider, channel, time_created
FROM evtx_records((SELECT content FROM read_blob('Security.evtx')))
ORDER BY record_id;

-- … or as a VARCHAR path to open directly.
SELECT count(*) FROM evtx_records('Security.evtx');

-- How many records? Is it a real .evtx?
SELECT evtx_record_count((SELECT content FROM read_blob('Security.evtx')));  -- BIGINT
SELECT is_valid_evtx((SELECT content FROM read_blob('Security.evtx')));      -- BOOLEAN

-- Compose with vgi-sigma over the preserved full event JSON:
--   SELECT * FROM evtx_records('Security.evtx')
--   WHERE sigma_match(event_json, '<rule yaml>');
```

## Functions

### Table

| Function | Columns | Description |
| --- | --- | --- |
| `evtx_records(input)` | `record_id BIGINT, event_id INT, provider VARCHAR, channel VARCHAR, computer VARCHAR, level INT, time_created TIMESTAMP, event_json VARCHAR` | One row per event record. `event_json` carries the full normalized event JSON. |

`input` is a **constant** (DuckDB table functions take constant arguments): a
`.evtx` file as a **BLOB** (inline bytes) or a **VARCHAR** path to a `.evtx`
file. The convenience columns are lifted from the `Event.System` block; anything
else (e.g. `EventData`) is available in `event_json`.

### Scalar

| Function | Returns | Description |
| --- | --- | --- |
| `evtx_record_count(input)` | `BIGINT` | Number of event records (`0` for malformed/garbage input). |
| `is_valid_evtx(input)` | `BOOLEAN` | True if the input has the `ElfFile` magic and the parser constructs. |
| `evtx_version()` | `VARCHAR` | Worker version string. |

For the scalars, `input` is a BLOB or a VARCHAR path, taken from a row column.

## Hostile-input handling

`.evtx` files handed to a DFIR tool routinely come from compromised hosts and may
be truncated, corrupted, or deliberately malformed to crash the parser. Every
entry point is hardened:

- **Never panics / crashes.** Parser construction and per-record iteration run
  under `catch_unwind`; a caught panic is downgraded to "no rows / invalid".
- **Bounded work.** Input is capped at 256 MiB and per-file output at 5,000,000
  records before parsing begins.
- **Magic pre-check.** A file without the `ElfFile\0` header is rejected up front.
- **Skips bad records.** A single unparseable record never aborts the rest of the
  file; an unreadable VARCHAR path yields no usable input.
- **NULL semantics.** `NULL` input → `NULL` (scalars) / no rows (`evtx_records`).
  A garbage BLOB beside a good one in the same batch does not affect the good
  result.

## NULL handling

`NULL` input yields `NULL` for the scalars and zero rows for `evtx_records`.
Malformed / truncated / garbage input yields `0` / `false` / no rows.

## Building & testing

```sh
cargo build --release            # produces target/release/evtx-worker
cargo test --workspace           # pure-Rust + Arrow-boundary unit/integration tests
make test-sql                    # DuckDB sqllogictest E2E (needs haybarn-unittest)
make lint                        # clippy -D warnings + rustfmt --check
```

The SQL E2E suite uses [`haybarn-unittest`](https://pypi.org/project/haybarn-unittest/)
(`uv tool install haybarn-unittest`).

## The `.evtx` parser

Parsing is delegated to the pure-Rust [`evtx`](https://crates.io/crates/evtx)
crate (omerbenamram/evtx), dual-licensed **MIT / Apache-2.0**. We pin `evtx =
"0.8.5"` deliberately: evtx ≥ 0.10 is edition 2024 (uses let-chains) and requires
rustc ≥ 1.88, which would bump the workspace MSRV above the pinned 1.86. 0.8.5 is
edition 2021 and builds cleanly on 1.86. We build it with `default-features =
false` to drop its optional logging feature (which transitively pulls a `time`
that also requires rustc 1.88).

## Test fixture

`test/sql/data/sample-security.evtx` is a small (68 KB) clean Windows Security
event log from the `evtx` crate's own test corpus. See
`test/sql/data/README.md` for source and attribution.

## License

MIT © Query Farm LLC. The bundled `.evtx` parser (`evtx` crate) is MIT/Apache-2.0.
