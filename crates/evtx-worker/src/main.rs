//! Native `evtx` VGI worker binary.
//!
//! A standalone executable DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'evtx' (TYPE vgi, LOCATION '…')`). All function registration and
//! catalog metadata live in the library crate (`evtx_worker::build_worker`) so
//! the wasm build serves an identical worker over a SharedArrayBuffer channel.

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    evtx_worker::build_worker().run();
}
