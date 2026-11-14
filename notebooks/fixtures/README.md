# Test fixtures

## `sample-security.evtx`

A small (68 KB, 7 records) **clean** Windows **Security** event log, used by the
Rust unit/integration tests and the DuckDB SQL E2E suite.

- **Source:** the `evtx` crate's own test corpus —
  <https://github.com/omerbenamram/evtx>, file `samples/Security_short_selected.evtx`
  (renamed here to `sample-security.evtx`).
- **Obtained:** downloaded from
  `https://raw.githubusercontent.com/omerbenamram/evtx/master/samples/Security_short_selected.evtx`.
- **License / attribution:** the `evtx` crate is dual-licensed **MIT /
  Apache-2.0**; its `samples/` files are the project's test data. This file is a
  benign, publicly distributed Windows event-log sample (events from
  provider `Microsoft-Windows-Security-Auditing`, channel `Security`,
  recorded 2016-06-29).

### What it contains

7 event records (record ids 1..7), all on the `Security` channel from the
`Microsoft-Windows-Security-Auditing` provider:

| record_id | event_id |
| --- | --- |
| 1 | 5152 |
| 2 | 4611 |
| 3 | 4776 |
| 4 | 4625 |
| 5 | 5152 |
| 6 | 5157 |
| 7 | 4673 |

The file begins with the `ElfFile\0` header magic and is a single in-use chunk.
