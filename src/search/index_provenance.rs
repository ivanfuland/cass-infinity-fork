//! W2-6 Task2 (R2-X1 pre-step): source/origin identity normalization shared
//! by both the lexical and semantic indexing paths. Moved out of
//! `search::tantivy` before that module's tantivy engine internals retire,
//! since these three functions carry no tantivy-crate dependency at all --
//! pure string normalization consumed by `indexer::semantic` too.

use crate::sources::provenance::LOCAL_SOURCE_ID;

pub(crate) fn normalized_index_source_id(
    source_id: Option<&str>,
    origin_kind: Option<&str>,
    origin_host: Option<&str>,
) -> String {
    let trimmed_source_id = source_id.unwrap_or_default().trim();
    if !trimmed_source_id.is_empty() {
        if trimmed_source_id.eq_ignore_ascii_case(LOCAL_SOURCE_ID) {
            return LOCAL_SOURCE_ID.to_string();
        }
        return trimmed_source_id.to_string();
    }

    let trimmed_origin_host = origin_host.map(str::trim).filter(|value| !value.is_empty());
    let trimmed_origin_kind = origin_kind.unwrap_or_default().trim();
    if trimmed_origin_kind.eq_ignore_ascii_case("ssh")
        || trimmed_origin_kind.eq_ignore_ascii_case("remote")
    {
        return trimmed_origin_host.unwrap_or("remote").to_string();
    }
    if let Some(origin_host) = trimmed_origin_host {
        return origin_host.to_string();
    }

    LOCAL_SOURCE_ID.to_string()
}

pub(crate) fn normalized_index_origin_kind(source_id: &str, origin_kind: Option<&str>) -> String {
    if let Some(kind) = origin_kind.map(str::trim).filter(|value| !value.is_empty()) {
        if kind.eq_ignore_ascii_case("local") {
            return LOCAL_SOURCE_ID.to_string();
        }
        if kind.eq_ignore_ascii_case("ssh") || kind.eq_ignore_ascii_case("remote") {
            return "remote".to_string();
        }
        return kind.to_ascii_lowercase();
    }

    if source_id == LOCAL_SOURCE_ID {
        LOCAL_SOURCE_ID.to_string()
    } else {
        "remote".to_string()
    }
}

pub(crate) fn normalized_index_origin_host(origin_host: Option<&str>) -> Option<String> {
    origin_host
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_index_source_id_infers_remote_from_origin_host_without_kind() {
        let source_id = normalized_index_source_id(Some("   "), None, Some("dev@laptop"));
        assert_eq!(source_id, "dev@laptop");
        assert_eq!(normalized_index_origin_kind(&source_id, None), "remote");
    }
}
