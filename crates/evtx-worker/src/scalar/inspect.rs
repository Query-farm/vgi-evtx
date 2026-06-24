//! `evtx_record_count(input) -> BIGINT` and `is_valid_evtx(input) -> BOOLEAN`.
//!
//! `input` is a `.evtx` file as a BLOB (inline bytes) or a VARCHAR path to open.
//! Both functions are hardened against hostile input: malformed/truncated/garbage
//! files yield `0` / `false` and never panic. NULL in → NULL out.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, Int64Builder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::input_bytes;
use crate::evtx_parse;

// ---------------------------------------------------------------------------
// evtx_record_count(input) -> BIGINT
// ---------------------------------------------------------------------------

pub struct EvtxRecordCount;

impl ScalarFunction for EvtxRecordCount {
    fn name(&self) -> &str {
        "evtx_record_count"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Number of event records in a .evtx file (BLOB bytes or VARCHAR path); \
                          0 for malformed/garbage input"
                .into(),
            return_type: Some(DataType::Int64),
            examples: vec![FunctionExample {
                sql: "SELECT evtx.main.evtx_record_count((SELECT content FROM \
                      read_blob('Security.evtx')));"
                    .into(),
                description: "Count the event records in a .evtx file read as a BLOB.".into(),
                expected_output: None,
            }],
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "input",
            0,
            ".evtx file BLOB or VARCHAR path",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Int64))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = Int64Builder::new();
        for i in 0..rows {
            match input_bytes(col, i)? {
                None => out.append_null(),
                Some(bytes) => out.append_value(evtx_parse::record_count(&bytes)),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// is_valid_evtx(input) -> BOOLEAN
// ---------------------------------------------------------------------------

pub struct IsValidEvtx;

impl ScalarFunction for IsValidEvtx {
    fn name(&self) -> &str {
        "is_valid_evtx"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "True if the input is a parseable .evtx (has the ElfFile magic and the \
                          parser constructs); false for malformed/garbage input"
                .into(),
            return_type: Some(DataType::Boolean),
            examples: vec![FunctionExample {
                sql: "SELECT evtx.main.is_valid_evtx((SELECT content FROM \
                      read_blob('Security.evtx')));"
                    .into(),
                description:
                    "Check whether a file's bytes are a parseable .evtx before processing.".into(),
                expected_output: None,
            }],
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "input",
            0,
            ".evtx file BLOB or VARCHAR path",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Boolean))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = BooleanBuilder::new();
        for i in 0..rows {
            match input_bytes(col, i)? {
                None => out.append_null(),
                Some(bytes) => out.append_value(evtx_parse::is_valid(&bytes)),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::{bound_type, run_scalar};
    use arrow_array::cast::AsArray;
    use arrow_array::Array;
    use vgi::arguments::Arguments;

    fn sample() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/sql/data/sample-security.evtx"
        ))
        .unwrap()
    }

    #[test]
    fn record_count_over_blob() {
        assert_eq!(bound_type(&EvtxRecordCount), DataType::Int64);
        let s = sample();
        let out = run_scalar(
            &EvtxRecordCount,
            &[Some(s.as_slice()), Some(b"garbage"), None],
            Arguments::default(),
        )
        .unwrap();
        let a = out.as_primitive::<arrow_array::types::Int64Type>();
        assert_eq!(a.value(0), 7);
        assert_eq!(a.value(1), 0);
        assert!(out.is_null(2));
    }

    #[test]
    fn is_valid_over_blob() {
        assert_eq!(bound_type(&IsValidEvtx), DataType::Boolean);
        let s = sample();
        let mut truncated = s.clone();
        truncated.truncate(200);
        let out = run_scalar(
            &IsValidEvtx,
            &[
                Some(s.as_slice()),
                Some(b"not an evtx"),
                Some(truncated.as_slice()),
                None,
            ],
            Arguments::default(),
        )
        .unwrap();
        let b = out.as_boolean();
        assert!(b.value(0), "clean sample is valid");
        assert!(!b.value(1), "garbage is invalid");
        // truncated header-only must not panic; value is allowed either way but
        // typically false.
        let _ = b.value(2);
        assert!(out.is_null(3));
    }

    #[test]
    fn bad_blob_beside_good_survives() {
        // A garbage cell adjacent to a good one must not corrupt the good
        // result, and must not panic.
        let s = sample();
        let out = run_scalar(
            &EvtxRecordCount,
            &[
                Some(b"\x00\x01\x02bad"),
                Some(s.as_slice()),
                Some(&[0xFFu8; 1000]),
                Some(s.as_slice()),
            ],
            Arguments::default(),
        )
        .unwrap();
        let a = out.as_primitive::<arrow_array::types::Int64Type>();
        assert_eq!(a.value(0), 0);
        assert_eq!(a.value(1), 7);
        assert_eq!(a.value(2), 0);
        assert_eq!(a.value(3), 7);
    }
}
