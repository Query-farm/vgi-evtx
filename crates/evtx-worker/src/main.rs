//! The `evtx` VGI worker — defensive DFIR tooling.
//!
//! A standalone binary that DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'evtx' (TYPE vgi, LOCATION '…')`). It parses Windows Event Log
//! (`.evtx`) files into rows under the catalog `evtx`, schema `main`, so they can
//! be queried in SQL and fed to detection tooling such as `vgi-sigma`:
//!
//! ```sql
//! ATTACH 'evtx' (TYPE vgi, LOCATION './target/release/evtx-worker');
//! SET search_path = 'evtx.main';
//!
//! -- One row per event record (input: BLOB bytes or a VARCHAR path).
//! SELECT record_id, event_id, provider, time_created
//! FROM evtx_records((SELECT content FROM read_blob('Security.evtx')))
//! ORDER BY record_id;
//!
//! SELECT evtx_record_count((SELECT content FROM read_blob('Security.evtx')));
//! SELECT is_valid_evtx((SELECT content FROM read_blob('Security.evtx')));
//!
//! -- Compose with vgi-sigma over the preserved full event JSON:
//! --   sigma_match(event_json, rule)
//! ```
//!
//! Pure `.evtx` parsing logic lives in `evtx_parse.rs`; the `scalar/` and
//! `table/` modules are thin Arrow adapters over it. Input is untrusted (`.evtx`
//! files come from potentially compromised hosts): every entry point is hardened
//! against malformed/truncated/garbage files — it yields NULL / no rows / false
//! and never panics.

mod arrow_io;
mod evtx_parse;
mod meta;
mod scalar;
mod table;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Worker version string, surfaced by `evtx_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Catalog + schema metadata (description, provenance) surfaced to DuckDB and
/// the `vgi-lint` metadata-quality linter. The function objects themselves are
/// served from the registered scalars/table; this only adds catalog/schema-level
/// comments and tags.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Windows Event Log (.evtx) parsing for defensive DFIR — turn event-log files into \
             queryable rows."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "Windows Event Log (.evtx) Parsing for DFIR".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                serde_json::to_string(&[
                    "evtx",
                    "windows event log",
                    "event log",
                    "dfir",
                    "forensics",
                    "incident response",
                    "security log",
                    "eventlog",
                    "elffile",
                    "windows logs",
                    "log parsing",
                    "sigma",
                    "detection",
                    "event id",
                    "provider",
                    "channel",
                ])
                .expect("keywords serialize to JSON"),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Parse Windows Event Log (.evtx) files into SQL rows for digital-forensics and \
                 incident-response (DFIR) work. Accepts a .evtx file as inline BLOB bytes or a \
                 VARCHAR path. Use to count records in a log, test whether bytes are a valid \
                 .evtx, and explode a log into one row per event record (record_id, event_id, \
                 provider, channel, computer, level, time_created, and the full event_json). The \
                 preserved event_json composes with vgi-sigma's sigma_match(event_json, rule) for \
                 detection. Hardened against hostile input: malformed/truncated/garbage files \
                 yield NULL/false/no rows and never crash. Does not touch the network."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# Windows Event Log (.evtx) Parsing in SQL\n\n\
                 Query Windows Event Logs directly in DuckDB: this VGI extension turns binary \
                 `.evtx` files into Apache Arrow rows so you can run digital-forensics and \
                 incident-response (DFIR) analysis, threat hunting, and log triage entirely in \
                 SQL — no external tooling, no network access, no scripting.\n\n\
                 ## What it does\n\n\
                 The Windows Event Log (`.evtx`, the binary `ElfFile` format that backs the \
                 Security, System, Application, PowerShell, and Sysmon channels) is the primary \
                 evidence source for Windows DFIR. This extension reads those files — including \
                 logs pulled from potentially compromised hosts — and exposes every event record \
                 as a queryable row, with convenience columns for the event id, provider, channel, \
                 source computer, severity level, and creation time, plus the complete original \
                 event preserved as JSON. It is built for incident responders, threat hunters, \
                 detection engineers, SOC analysts, and anyone who would rather join, filter, and \
                 aggregate event logs in SQL than wrangle them in a GUI.\n\n\
                 ## How it works\n\n\
                 Parsing is powered by the battle-tested [`evtx`](https://github.com/omerbenamram/evtx) \
                 Rust crate (API docs on [docs.rs](https://docs.rs/evtx)), which decodes the \
                 BinXML chunks of the \
                 [Windows event-logging](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging) \
                 format. Everything runs offline inside the worker — it never touches the network \
                 — and every entry point is hardened against hostile input: malformed, truncated, \
                 or deliberately corrupted files yield `NULL` / `false` / no rows and never crash \
                 the worker. Input may be supplied either inline as a `BLOB` (for example from \
                 `read_blob()`) or as a `VARCHAR` filesystem path.\n\n\
                 ## Working in SQL\n\n\
                 Because every event becomes an ordinary row, you build timelines by filtering on \
                 provider and creation time, surface the noisiest activity by grouping and \
                 counting, and pivot from triage to detection: the preserved event JSON composes \
                 with the companion `vgi-sigma` worker to run Sigma detection rules straight \
                 against your logs. A typical triage query that surfaces the busiest event IDs \
                 looks like:\n\n\
                 ```sql\n\
                 SELECT event_id, count(*) AS n\n\
                 FROM evtx.main.evtx_records('Security.evtx')\n\
                 GROUP BY event_id\n\
                 ORDER BY n DESC;\n\
                 ```"
                    .to_string(),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-evtx/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-evtx/blob/main/README.md".to_string(),
            ),
            // VGI152 / VGI920: an analyst-task suite so `vgi-lint simulate` can
            // measure how well an agent actually uses this worker. Each task's
            // reference_sql is self-contained and runs against the committed
            // fixture (test/sql/data/sample-security.evtx, 7 records) or the
            // hardened hostile-input path, so it executes without any external
            // .evtx file.
            (
                "vgi.agent_test_tasks".to_string(),
                serde_json::to_string(&[
                    serde_json::json!({
                        "name": "worker_version",
                        "prompt": "Report the version string of the attached evtx worker.",
                        "reference_sql": "SELECT evtx.main.evtx_version();",
                        // Value-only compare: the analyst may alias the column.
                        "ignore_column_names": true,
                    }),
                    serde_json::json!({
                        "name": "validate_bad_bytes",
                        "prompt": "Is the byte string 'this is not an event log' a valid, \
                                   parseable Windows Event Log (.evtx)? Answer with the boolean \
                                   the worker returns.",
                        "reference_sql": "SELECT evtx.main.is_valid_evtx('this is not an event log'::BLOB);",
                        "ignore_column_names": true,
                    }),
                    serde_json::json!({
                        "name": "validate_file",
                        "prompt": "Using the evtx worker, check whether the file at the path \
                                   'test/sql/data/sample-security.evtx' is a valid, parseable \
                                   Windows Event Log. Pass the path string to the validation \
                                   function.",
                        "reference_sql": "SELECT evtx.main.is_valid_evtx('test/sql/data/sample-security.evtx');",
                        "ignore_column_names": true,
                    }),
                    serde_json::json!({
                        "name": "count_records",
                        "prompt": "Using the evtx worker, count how many event records are in the \
                                   Windows Event Log file at the path \
                                   'test/sql/data/sample-security.evtx'. Pass the path string to \
                                   the record-count function.",
                        "reference_sql": "SELECT evtx.main.evtx_record_count('test/sql/data/sample-security.evtx');",
                        "ignore_column_names": true,
                    }),
                    serde_json::json!({
                        "name": "top_event_ids",
                        "prompt": "Parse the event log at the path \
                                   'test/sql/data/sample-security.evtx' with the evtx worker and \
                                   list each distinct event id together with how many records \
                                   have that id.",
                        "reference_sql": "SELECT event_id, count(*) AS n FROM evtx.main.evtx_records('test/sql/data/sample-security.evtx') GROUP BY event_id;",
                        // Set-of-rows compare: any row order and any column aliases pass.
                        "unordered": true,
                        "ignore_column_names": true,
                    }),
                    serde_json::json!({
                        "name": "distinct_providers",
                        "prompt": "Parse the event log at the path \
                                   'test/sql/data/sample-security.evtx' with the evtx worker and \
                                   list the distinct event provider names that appear in it.",
                        "reference_sql": "SELECT DISTINCT provider FROM evtx.main.evtx_records('test/sql/data/sample-security.evtx');",
                        "unordered": true,
                        "ignore_column_names": true,
                    }),
                ])
                .expect("agent test tasks serialize to JSON"),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-evtx".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "Windows Event Log (.evtx) parsing and inspection functions.".to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "evtx — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    serde_json::to_string(&[
                        "evtx",
                        "windows event log",
                        "event log",
                        "evtx_records",
                        "evtx_record_count",
                        "is_valid_evtx",
                        "dfir",
                        "forensics",
                        "incident response",
                        "sigma",
                        "event id",
                        "provider",
                        "channel",
                        "log parsing",
                    ])
                    .expect("keywords serialize to JSON"),
                ),
                // VGI123 classifying tags (bare keys: domain/category/topic) for faceting.
                ("domain".to_string(), "security".to_string()),
                ("category".to_string(), "parsing".to_string()),
                ("topic".to_string(), "windows-event-log".to_string()),
                // VGI506 representative example queries for the schema (display).
                (
                    "vgi.example_queries".to_string(),
                    "SELECT evtx.main.evtx_version();\n\
                     SELECT evtx.main.is_valid_evtx((SELECT content FROM read_blob('Security.evtx')));\n\
                     SELECT evtx.main.evtx_record_count((SELECT content FROM read_blob('Security.evtx')));\n\
                     SELECT record_id, event_id, provider, time_created FROM evtx.main.evtx_records('Security.evtx') ORDER BY record_id;\n\
                     SELECT event_id, count(*) AS n FROM evtx.main.evtx_records('Security.evtx') GROUP BY event_id ORDER BY n DESC;"
                        .to_string(),
                ),
                (
                    "vgi.doc_llm".to_string(),
                    "Windows Event Log (.evtx) parsing and inspection functions: count event \
                     records, validate that bytes are a parseable .evtx, and explode a .evtx \
                     file into one row per event record with the full event JSON preserved for \
                     downstream detection. All functions accept the file as inline BLOB bytes or \
                     a VARCHAR path and tolerate hostile input without erroring."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "## evtx.main\n\nWindows Event Log (`.evtx`) parsing and inspection over Apache \
                     Arrow. This schema turns a `.evtx` file — supplied as inline `BLOB` bytes or a \
                     `VARCHAR` filesystem path — into queryable event rows so a whole log can be \
                     joined, filtered, and aggregated in SQL.\n\n\
                     Alongside parsing, it lets you validate and size a log before loading it, and \
                     each event's full JSON is preserved so results compose with downstream \
                     detection tooling such as `vgi-sigma`.\n\n\
                     Everything runs offline. All entry points tolerate hostile input — malformed, \
                     truncated, or non-evtx data yields empty or false results rather than an \
                     error — because event logs are routinely pulled from potentially compromised \
                     hosts."
                        .to_string(),
                ),
                // VGI413 category registry: an ordered list of the navigation
                // categories that every object in this schema tags itself with
                // via `vgi.category`.
                (
                    "vgi.categories".to_string(),
                    serde_json::to_string(&[
                        serde_json::json!({
                            "name": "Event Record Parsing",
                            "description": "Explode a .evtx file into one queryable row per event \
                                            record, preserving the full event JSON.",
                        }),
                        serde_json::json!({
                            "name": "Inspection & Diagnostics",
                            "description": "Validate and size .evtx files before loading them, and \
                                            report the worker version.",
                        }),
                    ])
                    .expect("categories serialize to JSON"),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    // The catalog name DuckDB sees in `ATTACH 'evtx' (TYPE vgi, …)`. Default to
    // `evtx`, but honor an explicit override so a test harness can rename.
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "evtx");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "evtx".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
