//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function and table.
//!
//! Each function/table surfaces these in its `FunctionMetadata.tags`:
//! - `vgi.title` (VGI124)           — human-friendly display name
//! - `vgi.doc_llm` (VGI112)         — Markdown narrative aimed at LLMs/agents
//! - `vgi.doc_md` (VGI113)          — Markdown narrative for human docs
//! - `vgi.keywords` (VGI126/VGI138) — JSON array of search terms/synonyms
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted: VGI139 wants the
//! `source_url` only on the catalog object, so provenance lives there.

/// Encode a list of keyword strings as a JSON array literal (VGI138 requires
/// `vgi.keywords` to be a JSON array of strings, not a comma-separated string).
fn keywords_json(keywords: &[&str]) -> String {
    serde_json::to_string(keywords).expect("keyword list serializes to JSON")
}

/// Build the four standard per-object discovery/description tags.
///
/// `keywords` is a list of search terms/synonyms; it is serialized as a JSON
/// array for the `vgi.keywords` tag.
pub fn object_tags(
    title: &str,
    doc_llm: &str,
    doc_md: &str,
    keywords: &[&str],
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), doc_llm.to_string()),
        ("vgi.doc_md".to_string(), doc_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
    ]
}
