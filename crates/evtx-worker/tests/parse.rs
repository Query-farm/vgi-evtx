//! Integration tests: black-box exercise of the worker's pure `.evtx` parsing
//! over the committed clean fixture and over hostile inputs, the same way the
//! SQL E2E suite drives it but without the Arrow/RPC layer.
//!
//! The pure logic lives in a private module of the binary crate, so we include
//! it by path — the same trick `vgi-ioc` / `vgi-barcode` use for their
//! integration tests.

#[path = "../src/evtx_parse.rs"]
#[allow(dead_code)]
mod evtx_parse;

use evtx_parse::{is_valid, parse_records, record_count, EvtxRow};

fn sample() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/sql/data/sample-security.evtx"
    ))
    .expect("clean fixture must be present")
}

#[test]
fn clean_sample_yields_expected_rows() {
    let bytes = sample();
    let rows: Vec<EvtxRow> = parse_records(&bytes);

    assert_eq!(rows.len(), 7);
    assert_eq!(record_count(&bytes), 7);
    assert!(is_valid(&bytes));

    // All lifted typed columns populated on every row.
    for r in &rows {
        assert!(r.event_id.is_some());
        assert!(r.provider.is_some());
        assert!(r.time_created_micros.is_some());
        assert!(!r.event_json.is_empty());
    }

    // record_ids are 1..=7 in order.
    let ids: Vec<i64> = rows.iter().map(|r| r.record_id).collect();
    assert_eq!(ids, (1..=7).collect::<Vec<_>>());

    // First event: EventID 5152, the Security-Auditing provider on the Security
    // channel.
    let first = &rows[0];
    assert_eq!(first.event_id, Some(5152));
    assert_eq!(
        first.provider.as_deref(),
        Some("Microsoft-Windows-Security-Auditing")
    );
    assert_eq!(first.channel.as_deref(), Some("Security"));

    // event_json round-trips as valid JSON containing the System block.
    let v: serde_json::Value = serde_json::from_str(&first.event_json).unwrap();
    assert!(v["Event"]["System"]["EventID"].is_number());
}

#[test]
fn truncated_and_garbage_never_panic() {
    let full = sample();
    for cut in [0usize, 1, 8, 64, 4096, 65535, full.len() - 1] {
        let trunc = &full[..cut.min(full.len())];
        // None of these may panic.
        let _ = parse_records(trunc);
        let _ = record_count(trunc);
        let _ = is_valid(trunc);
    }

    for garbage in [
        &b""[..],
        &b"ElfFile"[..], // magic-1 byte: not enough for magic
        &b"random non-evtx bytes"[..],
        &[0u8; 70_000][..],
        &[0xFFu8; 70_000][..],
    ] {
        assert!(parse_records(garbage).is_empty());
        assert_eq!(record_count(garbage), 0);
        assert!(!is_valid(garbage));
    }
}

#[test]
fn bad_blob_beside_good_survives() {
    // Concatenating the magic onto garbage must not crash, and the genuine
    // sample must still parse to 7 records right after a bad parse attempt.
    let mut fake = b"ElfFile\0".to_vec();
    fake.extend_from_slice(&[0xAB; 65_536]);
    assert!(parse_records(&fake).is_empty());

    let good = sample();
    assert_eq!(parse_records(&good).len(), 7);
}
