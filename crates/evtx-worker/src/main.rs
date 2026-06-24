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
                "evtx, windows event log, event log, dfir, forensics, incident response, \
                 security log, eventlog, elffile, windows logs, log parsing, sigma, detection, \
                 event id, provider, channel"
                    .to_string(),
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
                "# evtx\n\nWindows Event Log (`.evtx`) parsing for defensive DFIR over Apache \
                 Arrow.\n\n## Overview\n\nThis worker turns binary `.evtx` event-log files — \
                 including ones recovered from potentially compromised hosts — into queryable SQL \
                 rows. Parsing happens entirely offline; the worker never touches the network.\n\n\
                 ## Surface\n\n- Scalars: `evtx_record_count`, `is_valid_evtx`, `evtx_version`.\n\
                 - Table: `evtx_records`.\n\n## Usage\n\nInput is a `.evtx` file supplied as a \
                 BLOB or as a VARCHAR path. The `event_json` column emitted by `evtx_records(...)` \
                 feeds `vgi-sigma`'s `sigma_match(event_json, rule)` for detection-rule matching.\n\n\
                 ## Notes\n\nEvery entry point is hardened against hostile input: malformed, \
                 truncated, or garbage files yield NULL / false / no rows and never crash."
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
                    "evtx, windows event log, event log, evtx_records, evtx_record_count, \
                     is_valid_evtx, dfir, forensics, incident response, sigma, event id, \
                     provider, channel, log parsing"
                        .to_string(),
                ),
                // VGI123 classifying tags (bare keys: domain/category/topic) for faceting.
                ("domain".to_string(), "security".to_string()),
                ("category".to_string(), "parsing".to_string()),
                ("topic".to_string(), "windows-event-log".to_string()),
                (
                    "vgi.source_url".to_string(),
                    "https://github.com/Query-farm/vgi-evtx/blob/main/crates/evtx-worker/src/main.rs"
                        .to_string(),
                ),
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
