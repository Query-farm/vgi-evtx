# EVTX notebooks

[01 · Keep unlabeled events when summarizing an EVTX timeline](01_keep_unlabeled_events_in_the_timeline.ipynb) distinguishes input states, parses a public seven-record Windows Security sample, and preserves records missing from the worker's reference table. The experiment changes display bins from 10 to 30 seconds.

## Run

Requirements: [uv](https://docs.astral.sh/uv/), Python 3.13+ (uv can install it), and internet access for the first dependency/native-worker download. No Windows machine, private logs, Rust build or surrounding worker checkout is needed.

```sh
cd notebooks
uv sync --locked
uv run --locked python execute.py --timeout 300
```

The locked environment uses Haybarn 2.0.0rc11. Visible SQL attaches `github-auto://Query-farm/vgi-evtx@v0.4.0`, release commit `3024d7503fdcfed1f7c00a97f56cf9fe3a57284d`. VGI downloads the platform-native binary, verifies the published SHA-256 and caches it. The parser itself reads local fixture bytes without calling a remote service. Upgrade the release deliberately and rerun defaults and the experiment.

Optional editor kernel:

```sh
uv run --locked python -m ipykernel install --user --name vgi-evtx-notebooks --display-name "Python (vgi-evtx notebooks)"
```

Use this directory as working directory, then Restart Kernel → Run All. The runner creates a temporary kernel registration and replaces saved outputs only on complete success.

## Separate experiment

```sh
uv run --locked python execute.py --parameters '{"BIN_SECONDS":30}' --output-dir artifacts/bin-30
```

Overrides require a separate destination. Branding, fixture, docs, runner and environment files accompany the copy. Restore 10 for defaults. Generated artifacts, charts and virtual environments are ignored.

## Fixture and interpretation

`fixtures/sample-security.evtx` is copied unchanged from this repository's `test/sql/data/sample-security.evtx` at source commit `e34c90ba0ef80c1167d45f7166299c5412b39a98`. Its upstream origin is the public [evtx parser corpus](https://github.com/omerbenamram/evtx), `samples/Security_short_selected.evtx`, distributed as parser test data under the project's MIT/Apache-2.0 attribution. [Original fixture attribution](fixtures/README.md) is retained.

SHA-256: `50c87926d2dfed9776906ffbcc77e61577940910a71fb1c1871860a4e2213456`. The notebook verifies these exact bytes. This is a real selected EVTX sample recorded June 29, 2016, not a live collection or synthesized event timeline. Deliberate non-EVTX bytes are separately labeled diagnostic controls. No local Windows logs are searched or collected.

`time_created` is the record-header UTC instant carried in a timezone-free SQL TIMESTAMP; the notebook labels it UTC according to the worker contract. Bins are Unix-epoch-aligned half-open intervals `[start,end)`. Zero counts mean no parsed sample records in a displayed bin, not no activity on an actual host. Full normalized event JSON remains in memory while displayed outputs use timing and classification metadata.

The reference table is deliberately incomplete. The notebook verifies unique `(event_id,channel)` reference keys and the sample's Microsoft-Windows-Security-Auditing provider before joining. All parsed records remain through a left join; missing names do not mean benign behavior or nonexistent Windows events. [Microsoft documents Security event 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) as a failed logon, but the label alone establishes no attack.

A parseable header is not a guarantee of intact, authentic or complete records. The worker skips per-record parser errors and caps input at 256 MiB/output at 5,000,000 records. Unreadable paths and NULL inputs yield NULL scalar diagnostics; malformed byte inputs yield false/zero. Counts describe successfully parsed records. No compromise decision, production event-rate estimate or host-completeness claim is made.
