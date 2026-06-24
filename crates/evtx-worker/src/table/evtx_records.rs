//! `evtx_records(input) -> (record_id BIGINT, event_id INT, provider VARCHAR,
//! channel VARCHAR, computer VARCHAR, level INT, time_created TIMESTAMP,
//! event_json VARCHAR)` — one row per event record in a `.evtx` file.
//!
//! `input` is a bind-time constant (DuckDB table functions take constant
//! arguments, bound positionally by the Rust SDK): either a **BLOB** of the
//! `.evtx` file bytes, or a **VARCHAR** path to a `.evtx` file to open. The
//! `event_json` column carries the full normalized event JSON so the result
//! composes with `vgi-sigma`'s `sigma_match(event_json, rule)`.
//!
//! A NULL / absent / malformed / garbage input yields zero rows — never a panic.

use std::sync::Arc;

use arrow_array::builder::{
    Int32Builder, Int64Builder, StringBuilder, TimestampMicrosecondBuilder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io::const_input_bytes;
use crate::evtx_parse::{self, EvtxRow};

/// `evtx_records` is registered twice — once with a BLOB-typed input arg and
/// once with a VARCHAR-typed (path) input arg — so DuckDB's binder accepts both
/// `evtx_records(<blob>)` and `evtx_records('path')` (it does not implicitly cast
/// VARCHAR→BLOB for a table-function argument). The two registrations share all
/// behavior; only the declared argument Arrow type differs.
pub struct EvtxRecords {
    input_type: &'static str,
}

impl EvtxRecords {
    /// The BLOB-input overload: `evtx_records(<.evtx bytes>)`.
    pub fn blob() -> Self {
        EvtxRecords { input_type: "blob" }
    }

    /// The VARCHAR-path overload: `evtx_records('path/to/file.evtx')`.
    pub fn path() -> Self {
        EvtxRecords {
            input_type: "varchar",
        }
    }
}

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("record_id", DataType::Int64, true),
        Field::new("event_id", DataType::Int32, true),
        Field::new("provider", DataType::Utf8, true),
        Field::new("channel", DataType::Utf8, true),
        Field::new("computer", DataType::Utf8, true),
        Field::new("level", DataType::Int32, true),
        // TIMESTAMP without a timezone (DuckDB TIMESTAMP), microsecond unit.
        Field::new(
            "time_created",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            true,
        ),
        Field::new("event_json", DataType::Utf8, true),
    ]))
}

impl TableFunction for EvtxRecords {
    fn name(&self) -> &str {
        "evtx_records"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Parse a .evtx file (BLOB bytes or VARCHAR path) into one row per event \
                          record; event_json carries the full normalized event JSON"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT record_id, event_id, provider, time_created \
                      FROM evtx.main.evtx_records('Security.evtx') ORDER BY record_id;"
                    .into(),
                description: "Explode a .evtx file at the given path into one row per event \
                              record, ordered by record id."
                    .into(),
                expected_output: None,
            }],
            tags: vec![(
                "vgi.columns_md".into(),
                "| column | type | description |\n\
                 |---|---|---|\n\
                 | `record_id` | BIGINT | The event record's identifier (file order). |\n\
                 | `event_id` | INTEGER | The Windows Event ID from `Event.System.EventID`. |\n\
                 | `provider` | VARCHAR | Event provider name (`Event.System.Provider/@Name`). |\n\
                 | `channel` | VARCHAR | Log channel, e.g. `Security`, `System`. |\n\
                 | `computer` | VARCHAR | Source computer name (`Event.System.Computer`). |\n\
                 | `level` | INTEGER | Severity level from `Event.System.Level`. |\n\
                 | `time_created` | TIMESTAMP | Record header timestamp (UTC, microsecond). |\n\
                 | `event_json` | VARCHAR | Full normalized event JSON; feeds `sigma_match`. |"
                    .into(),
            )],
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        // A single constant input. DuckDB will pass either a BLOB or a VARCHAR
        // depending on the call site; we read both at producer time.
        vec![ArgSpec::const_arg(
            "input",
            0,
            self.input_type,
            ".evtx file bytes (BLOB) or a path to a .evtx file (VARCHAR)",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: output_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        // Accept either a BLOB constant or a VARCHAR path constant.
        let bytes = const_input_bytes(
            params.arguments.const_bytes(0),
            params.arguments.const_str(0),
        );
        let rows = match bytes {
            Some(b) => evtx_parse::parse_records(&b),
            None => Vec::new(),
        };
        Ok(Box::new(RecordsProducer {
            schema: params.output_schema.clone(),
            rows,
            done: false,
        }))
    }
}

struct RecordsProducer {
    schema: SchemaRef,
    rows: Vec<EvtxRow>,
    done: bool,
}

impl TableProducer for RecordsProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;

        let mut record_id = Int64Builder::new();
        let mut event_id = Int32Builder::new();
        let mut provider = StringBuilder::new();
        let mut channel = StringBuilder::new();
        let mut computer = StringBuilder::new();
        let mut level = Int32Builder::new();
        let mut time_created = TimestampMicrosecondBuilder::new();
        let mut event_json = StringBuilder::new();

        for r in &self.rows {
            record_id.append_value(r.record_id);
            event_id.append_option(r.event_id);
            provider.append_option(r.provider.as_deref());
            channel.append_option(r.channel.as_deref());
            computer.append_option(r.computer.as_deref());
            level.append_option(r.level);
            time_created.append_option(r.time_created_micros);
            event_json.append_value(&r.event_json);
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(record_id.finish()),
            Arc::new(event_id.finish()),
            Arc::new(provider.finish()),
            Arc::new(channel.finish()),
            Arc::new(computer.finish()),
            Arc::new(level.finish()),
            Arc::new(time_created.finish()),
            Arc::new(event_json.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
