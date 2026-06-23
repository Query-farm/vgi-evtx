//! Table functions exposed by the evtx worker, registered under `evtx.main`.

mod evtx_records;

use vgi::Worker;

/// Register every table function on the worker.
pub fn register(worker: &mut Worker) {
    // Two overloads of the same name so the DuckDB binder accepts both a BLOB
    // (inline bytes) and a VARCHAR (path) input — it does not implicitly cast
    // between them for a table-function argument.
    worker.register_table(evtx_records::EvtxRecords::blob());
    worker.register_table(evtx_records::EvtxRecords::path());
}
