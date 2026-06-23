//! Scalar functions exposed by the evtx worker, registered under `evtx.main`.

mod inspect;
mod version;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(version::EvtxVersion);
    worker.register_scalar(inspect::EvtxRecordCount);
    worker.register_scalar(inspect::IsValidEvtx);
}
