# Windows Event Log Parser examples

[01 · Keep unlabeled events when summarizing an EVTX timeline](01_keep_unlabeled_events_in_the_timeline.ipynb) distinguishes malformed, absent and missing inputs, parses a public seven-record Security-log sample, and preserves records missing from the worker's reference view. The experiment changes display bins from 10 to 30 seconds.

[Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-evtx/blob/main/notebooks/01_keep_unlabeled_events_in_the_timeline.ipynb) and run the install cell, then Run All. A single downloaded notebook works too: shared `prepare("evtx")` retrieves and verifies the public fixture and attribution at immutable commit `6b3aad7d9c4426ff1afaf16d4a43809343908e9d`. No Windows machine, private logs, Rust build, worker checkout or account is needed. Actual hosted Colab execution has not been tested; a fresh Python 3.12 notebook-only run with compatible libraries already imported verifies the bootstrap and preservation behavior.

## Run locally

Requirements: [uv](https://docs.astral.sh/uv/), Python 3.11+ (uv can install it), and internet access for initial package/native-worker downloads. Run from this directory:

```sh
uv sync --locked --extra runner
uv run --locked --extra runner vgi-notebooks
```

The notebook uses shared [VGI example tools v0.3.11](https://github.com/Query-farm/vgi-example-notebooks/tree/v0.3.11) for branding, the SVG theme, credential-isolated SQL setup and the atomic runner. Colab installs only the core; `[runner]` adds local execution dependencies. `connect(globals())` creates an in-memory Haybarn database with empty temporary SQL-secret storage and persistence disabled; cleanup closes the connection and removes that storage.

Visible SQL attaches `github-auto://Query-farm/vgi-evtx@v0.4.0`, release commit `3024d7503fdcfed1f7c00a97f56cf9fe3a57284d`, through Haybarn 2.0.0rc11. VGI downloads the platform-native binary, verifies the published SHA-256 and caches it. The parser reads local fixture bytes without contacting a service. Upgrade the release deliberately and rerun the example and experiment.

The shared runner replaces the saved notebook only after successful execution. Defaults retain native SVG MIME and content-addressed `charts/` assets with ordinary GitHub image links; optional local SVG/PNG review exports go under ignored `artifacts/review/`. Existing saved outputs can be read directly on GitHub.

Optional local kernel:

```sh
uv run --locked --extra runner python -m ipykernel install --user --name vgi-evtx-notebooks --display-name "Python (vgi-evtx notebooks)"
```

## Separate experiment

```sh
uv run --locked --extra runner vgi-notebooks --parameters '{"BIN_SECONDS":30}' --output-dir artifacts/bin-30
```

Overrides require a separate destination and never replace the default. Experiment copies include the fixture, attribution, docs and environment files. Bins change from four to two, with the largest bin growing from four to five records; the seven underlying events and one reference-labeled record stay fixed. A wider count bin is not an event-rate estimate. Restore 10 for the default.

## Coverage and evidence

The actual v0.4.0 catalog contains **four logical (schema, name) surfaces**: `evtx_record_count`, `is_valid_evtx`, `evtx_records` and the `windows_event_id_reference` view. The two `evtx_records` overloads count once. All four have visible executed SQL, interpreted results and mappings in [coverage.json](coverage.json), with complete function/table/view exports and a successful raw-JSON execution receipt under [coverage/](coverage/).

Current public main at `6b3aad7d9c4426ff1afaf16d4a43809343908e9d` registers the same four surfaces and signatures. The release-to-main source changes add metadata/examples, not parser behavior or reference values. Current-interface coverage is explicitly compatibility-reviewed against the release: **4/4 released, 4/4 current interface; four exact released-runtime examples, zero exact current-runtime examples**. A supplementary probe of the pre-existing local binary agrees, but its build provenance is not asserted. No source rebuild or test rerun is needed for this notebook-only migration; the existing successful CI run [43567283707](https://github.com/Query-farm/vgi-evtx/actions/runs/43567283707) and the previous rollout's source/metadata results remain the baseline.

## Fixture and interpretation

`fixtures/sample-security.evtx` is copied unchanged from this repository's `test/sql/data/sample-security.evtx` at source commit `e34c90ba0ef80c1167d45f7166299c5412b39a98`. Its upstream origin is the public [evtx parser corpus](https://github.com/omerbenamram/evtx), `samples/Security_short_selected.evtx`, distributed as parser test data under the project's MIT/Apache-2.0 attribution. [Original fixture attribution](fixtures/README.md) is retained.

SHA-256: `50c87926d2dfed9776906ffbcc77e61577940910a71fb1c1871860a4e2213456`. The notebook verifies these exact bytes. This is a real selected EVTX sample recorded June 29, 2016, not a live collection or synthesized event timeline. Deliberate non-EVTX bytes are separately labeled diagnostic controls. No local Windows logs are searched or collected.

`time_created` is the record-header UTC instant carried in a timezone-free SQL TIMESTAMP; the notebook labels it UTC according to the worker contract. Bins are Unix-epoch-aligned half-open intervals `[start,end)`. Zero counts mean no parsed sample records in a displayed bin, not no activity on an actual host. Full normalized event JSON remains in memory while displayed outputs use timing and classification metadata.

The reference table is deliberately incomplete. The notebook verifies unique `(event_id,channel)` reference keys and the sample's Microsoft-Windows-Security-Auditing provider before joining. All parsed records remain through a left join; missing names do not mean benign behavior or nonexistent Windows events. [Microsoft documents Security event 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) as a failed logon, but the label alone establishes no attack.

A parseable header is not a guarantee of intact, authentic or complete records. The worker skips per-record parser errors and caps input at 256 MiB/output at 5,000,000 records. Unreadable paths and NULL inputs yield NULL scalar diagnostics; malformed byte inputs yield false/zero. Counts describe successfully parsed records. No compromise decision, production event-rate estimate or host-completeness claim is made.
