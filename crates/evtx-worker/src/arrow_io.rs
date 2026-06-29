//! Small Arrow helpers shared across the worker: reading the `.evtx` input cell
//! (BLOB bytes *or* a VARCHAR path to open) and an in-process scalar test
//! harness. Keeping this thin and centralized means the scalar/table adapters
//! never duplicate input-marshalling or path-vs-bytes logic.

use std::borrow::Cow;

use arrow_array::ArrayRef;
use arrow_schema::DataType;
use vgi_rpc::{Result, RpcError};

use crate::evtx_parse::MAX_INPUT_BYTES;

/// Resolve an input cell at `row` to the raw `.evtx` bytes.
///
/// The input may be:
/// * a **BLOB** (`Binary`/`LargeBinary`) — the `.evtx` file bytes inline; or
/// * a **VARCHAR** (`Utf8`/`LargeUtf8`) — a filesystem **path** to a `.evtx`
///   file, which we read (bounded to [`MAX_INPUT_BYTES`]).
///
/// Returns `None` for a NULL cell. A path that cannot be read, or a file larger
/// than the bound, resolves to `None` as well (treated as "no usable input" —
/// the caller surfaces that as invalid / no rows, never an error or panic).
/// Errors only if the column is neither binary nor string typed.
pub fn input_bytes(col: &ArrayRef, row: usize) -> Result<Option<Cow<'_, [u8]>>> {
    use arrow_array::cast::AsArray;
    use arrow_array::Array;

    if col.is_null(row) {
        return Ok(None);
    }
    Ok(match col.data_type() {
        DataType::Binary => Some(Cow::Borrowed(col.as_binary::<i32>().value(row))),
        DataType::LargeBinary => Some(Cow::Borrowed(col.as_binary::<i64>().value(row))),
        DataType::Utf8 => read_path(col.as_string::<i32>().value(row)),
        DataType::LargeUtf8 => read_path(col.as_string::<i64>().value(row)),
        other => {
            return Err(RpcError::value_error(format!(
                "evtx input must be a BLOB (file bytes) or VARCHAR (path), got {other:?}"
            )))
        }
    })
}

/// Read a `.evtx` file from `path`, bounded to [`MAX_INPUT_BYTES`]. Any error
/// (missing file, permission, too large) yields `None` rather than propagating —
/// a path pointing at nothing is "no usable input", not a worker failure.
fn read_path(path: &str) -> Option<Cow<'static, [u8]>> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() as usize > MAX_INPUT_BYTES {
        return None;
    }
    std::fs::read(path).ok().map(Cow::Owned)
}

/// Resolve a *constant* (bind-time) argument to raw `.evtx` bytes, for table
/// functions whose single argument is the file bytes/path. `bytes_arg` is the
/// BLOB constant (if any) and `str_arg` the VARCHAR-path constant (if any);
/// exactly one is generally present depending on how the user called the
/// function. Returns `None` (→ no rows) when neither yields usable bytes.
pub fn const_input_bytes(bytes_arg: Option<Vec<u8>>, str_arg: Option<String>) -> Option<Vec<u8>> {
    if let Some(b) = bytes_arg {
        return Some(b);
    }
    let path = str_arg?;
    read_path(&path).map(|c| c.into_owned())
}

/// Test-only helpers shared by the scalar Arrow-boundary unit tests: build a
/// one-column input `RecordBatch`, run `on_bind` + `process`, and inspect the
/// result — all in-process, no RPC/IPC.
#[cfg(test)]
pub mod test_support {
    use std::sync::Arc;

    use arrow_array::builder::BinaryBuilder;
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{Field, Schema, SchemaRef};
    use vgi::arguments::Arguments;
    use vgi::{BindParams, ProcessParams, ScalarFunction};
    use vgi_rpc::Result;

    /// A single-column `Binary` (BLOB) input batch. `None` entries become NULLs.
    pub fn blob_batch(rows: &[Option<&[u8]>]) -> RecordBatch {
        let mut b = BinaryBuilder::new();
        for r in rows {
            match r {
                Some(bytes) => b.append_value(bytes),
                None => b.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(b.finish());
        let schema = Arc::new(Schema::new(vec![Field::new(
            "blob",
            arr.data_type().clone(),
            true,
        )]));
        RecordBatch::try_new(schema, vec![arr]).unwrap()
    }

    /// Build a `ProcessParams` carrying the given output schema and arguments.
    pub fn process_params(output_schema: SchemaRef, arguments: Arguments) -> ProcessParams {
        ProcessParams {
            output_schema,
            input_schema: None,
            execution_id: Vec::new(),
            init_opaque_data: Vec::new(),
            arguments,
            settings: Default::default(),
            secrets: Default::default(),
            auth_principal: None,
            projection_ids: None,
            pushdown_filters: None,
            join_keys: Vec::new(),
            storage: None,
            order_by_column: None,
            order_by_direction: None,
            order_by_null_order: None,
            order_by_limit: None,
            tablesample_percentage: None,
            tablesample_seed: None,
            attach_opaque_data: None,
            at_unit: None,
            at_value: None,
            copy_from: None,
        }
    }

    /// Run a scalar function over a `Binary` input batch: call `on_bind` to
    /// obtain the declared output schema, then `process`, returning the single
    /// result column.
    pub fn run_scalar<F: ScalarFunction>(
        f: &F,
        rows: &[Option<&[u8]>],
        arguments: Arguments,
    ) -> Result<ArrayRef> {
        let batch = blob_batch(rows);
        let bind = BindParams {
            input_schema: Some(batch.schema()),
            arguments: arguments.clone(),
            ..Default::default()
        };
        let bound = f.on_bind(&bind)?;
        let params = process_params(bound.output_schema.clone(), arguments);
        let out = f.process(&params, &batch)?;
        Ok(out.column(0).clone())
    }

    /// The declared output `DataType` from `on_bind` for a scalar with no
    /// bind-time argument requirements.
    pub fn bound_type<F: ScalarFunction>(f: &F) -> arrow_schema::DataType {
        let bind = BindParams::default();
        let bound = f.on_bind(&bind).unwrap();
        bound.output_schema.field(0).data_type().clone()
    }
}
