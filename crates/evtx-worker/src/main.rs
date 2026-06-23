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
mod scalar;
mod table;

use vgi::Worker;

/// Worker version string, surfaced by `evtx_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.run();
}
