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
                 as a queryable row, with convenience columns for `record_id`, `event_id`, \
                 `provider`, `channel`, `computer`, `level`, and `time_created`, plus the complete \
                 original event preserved as `event_json`. It is built for incident responders, \
                 threat hunters, detection engineers, SOC analysts, and anyone who would rather \
                 join, filter, and aggregate event logs in SQL than wrangle them in a GUI.\n\n\
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
                 ## SQL use cases\n\n\
                 Explode a log into rows with the `evtx_records(input)` table function, then use \
                 ordinary SQL to find anomalies — for example `SELECT event_id, count(*) FROM \
                 evtx.main.evtx_records('Security.evtx') GROUP BY event_id ORDER BY 2 DESC` to \
                 surface the noisiest event IDs, or filter on `provider` and `time_created` to \
                 build a timeline. Use the scalar `evtx_record_count(input)` to size a log before \
                 loading it, `is_valid_evtx(input)` to verify that a byte stream really is a \
                 parseable `.evtx`, and `evtx_version()` to report the worker version. The \
                 preserved `event_json` column composes with the companion `vgi-sigma` worker's \
                 `sigma_match(event_json, rule)` to run Sigma detection rules straight against \
                 your event logs in SQL."
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
                    "## evtx.main\n\nWindows Event Log (`.evtx`) parsing and inspection functions \
                     over Apache Arrow.\n\n- `evtx_records(input)` — one row per event record.\n\
                     - `evtx_record_count(input)` — number of records.\n- `is_valid_evtx(input)` \
                     — whether bytes parse as `.evtx`.\n- `evtx_version()` — worker version.\n\n\
                     Input is a `.evtx` BLOB or a VARCHAR path."
                        .to_string(),
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
