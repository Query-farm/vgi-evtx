//! Composed example queries: realistic SQL that combines two or more of this
//! worker's own objects (`evtx_records`, `windows_event_id_reference`,
//! `is_valid_evtx`, `evtx_record_count`) in one query.
//!
//! Each SQL is defined exactly once here and referenced from (a) the schema-level
//! `vgi.example_queries` list and (b) the example list of the object that drives
//! the query, inside its first five entries (the `vgi-lint` agent simulator only
//! shows agents per-object examples, first five each). Every query runs offline
//! against the committed fixture `test/sql/data/sample-security.evtx` (paths are
//! relative to the repo root) and is exercised by `test/sql/compose.test`.

use vgi::FunctionExample;

/// One described example query.
pub struct Example {
    pub description: &'static str,
    pub sql: &'static str,
}

/// `evtx_records` LEFT JOIN `windows_event_id_reference`: a readable timeline.
/// On the fixture only record 4 (4625) is catalogued; the rest show NULL.
pub const LABEL_TIMELINE: Example = Example {
    description: "Label each parsed record with its human-readable meaning by LEFT JOINing the \
                  event id reference onto evtx_records (meaning is NULL for ids the reference \
                  does not catalogue).",
    sql: "SELECT r.record_id, r.event_id, ref.name AS meaning, r.time_created FROM \
          evtx.main.evtx_records('test/sql/data/sample-security.evtx') AS r LEFT JOIN \
          evtx.main.windows_event_id_reference AS ref ON ref.event_id = r.event_id AND \
          ref.channel = r.channel ORDER BY r.record_id;",
};

/// `windows_event_id_reference` picks the event ids by name; `evtx_records`
/// supplies the matching records, whose `event_json` yields account + source IP.
pub const FAILED_LOGON_HUNT: Example = Example {
    description: "Hunt failed logons and lockouts: select the event ids from the reference by \
                  name, then pull the targeted account and source IP address out of each \
                  matching record's event_json.",
    sql: "SELECT r.record_id, r.time_created, ref.name, \
          r.event_json->>'$.Event.EventData.TargetUserName' AS target_user, \
          r.event_json->>'$.Event.EventData.IpAddress' AS source_ip FROM \
          evtx.main.evtx_records('test/sql/data/sample-security.evtx') AS r JOIN \
          evtx.main.windows_event_id_reference AS ref ON ref.event_id = r.event_id AND \
          ref.channel = r.channel WHERE ref.name IN ('Failed logon', 'Account locked out') \
          ORDER BY r.time_created, r.record_id;",
};

/// `is_valid_evtx` + `evtx_record_count` over every file `read_blob` globs.
pub const TRIAGE_FOLDER: Example = Example {
    description: "Triage a folder of collected files: flag which ones are parseable .evtx logs \
                  and how many event records each holds (non-evtx files show valid = false and \
                  0 records).",
    sql: "SELECT filename, evtx.main.is_valid_evtx(content) AS valid, \
          evtx.main.evtx_record_count(content) AS records FROM read_blob('test/sql/data/*') \
          ORDER BY filename;",
};

/// Every composed example, in the order the schema-level list shows them.
pub const COMPOSED: [&Example; 3] = [&LABEL_TIMELINE, &FAILED_LOGON_HUNT, &TRIAGE_FOLDER];

impl Example {
    /// The native `FunctionExample` carrier (same SQL as the described list).
    pub fn native(&self) -> FunctionExample {
        FunctionExample {
            sql: self.sql.into(),
            description: self.description.into(),
            expected_output: None,
        }
    }
}

/// Insert `examples` into a described `vgi.example_queries` JSON list at
/// position `at` (clamped to the list length) and re-serialize it.
pub fn insert_into(list_json: &str, at: usize, examples: &[&Example]) -> String {
    let mut list: Vec<serde_json::Value> =
        serde_json::from_str(list_json).expect("example list is a JSON array");
    let at = at.min(list.len());
    for (i, e) in examples.iter().enumerate() {
        list.insert(
            at + i,
            serde_json::json!({"description": e.description, "sql": e.sql}),
        );
    }
    serde_json::to_string_pretty(&list).expect("example list serializes to JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_into_places_examples_at_position() {
        let out = insert_into(
            r#"[{"description":"a","sql":"SELECT 1"}]"#,
            1,
            &[&TRIAGE_FOLDER],
        );
        let v: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[1]["sql"], TRIAGE_FOLDER.sql);
    }

    #[test]
    fn composed_sql_is_single_line_and_catalog_qualified() {
        for e in COMPOSED {
            assert!(!e.sql.contains('\n'));
            assert!(e.sql.contains("evtx.main."));
            assert!(e.sql.contains("ORDER BY"));
        }
    }
}
