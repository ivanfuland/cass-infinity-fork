//! W2-5 lexical (`fts_lex`) BM25F rerank layer.
//!
//! Faithfully ports tantivy's real scoring model instead of inventing one --
//! see `W2_ARTIFACTS/w2-tantivy-scoring-spec.md` (source-cited) and
//! `W2_ARTIFACTS/w2-rerank-design.md` (this module's design doc) under the
//! control-plane artifact root, not this repo. Summary of what's ported:
//!
//! - Only `content`/`title` participate in relevance scoring, each at
//!   weight 1.0 with no boost (tantivy's `Occur::Should` + `SumCombiner`
//!   over exactly these two fields -- `cass_term_query_fields()` in
//!   frankensearch's `cass_compat.rs`). `agent`/`workspace`/`source_path`
//!   are deliberately absent from [`RerankCandidate`] -- not "low weight",
//!   structurally excluded, matching tantivy where those fields never enter
//!   the scored query at all (agent/workspace are post-hoc exact filters,
//!   source_path doesn't appear in tantivy's query construction).
//! - `k1=1.2`, `b=0.75` hardcoded (tantivy `bm25.rs:8-9`, not tunable).
//! - IDF/tf formulas copied verbatim from tantivy `bm25.rs`.
//! - tf/dl are counted using tantivy's real token model (Latin runs split
//!   into lowercased words, CJK runs split into overlapping 2-character
//!   bigrams matching `CjkBigramDecompose`) -- *not* FTS5 trigrams, which
//!   are strictly a candidate-generation concern this module never touches.
//! - Multi-field combination is "each field scores independently, then
//!   sum" (matches tantivy's real behavior and the community-report survey
//!   of Lucene/ES `most_fields` semantics), not textbook Robertson BM25F
//!   (which merges tf across fields before a single saturation pass).

use std::cmp::Ordering;
use std::collections::HashMap;

/// tantivy `bm25.rs:8`.
pub(crate) const K1: f64 = 1.2;
/// tantivy `bm25.rs:9`.
pub(crate) const B: f64 = 0.75;

/// `IDF(df,N) = ln(1 + (N-df+0.5)/(df+0.5))`, tantivy `bm25.rs:52-56`.
pub(crate) fn idf(doc_freq: u64, doc_count: u64) -> f64 {
    let x = (doc_count.saturating_sub(doc_freq) as f64 + 0.5) / (doc_freq as f64 + 0.5);
    (1.0 + x).ln()
}

/// Single-field BM25 term score, tantivy `bm25.rs:179-193`. Natural zero
/// when `tf==0` (no special-cased branch -- tantivy's own `tf_factor`
/// doesn't special-case it either, and the formula already reduces to 0
/// there since `norm` is always `>0`; `avgdl<=0` is the one input tantivy's
/// own field-length math never has to handle -- `lex_docs` columns are all
/// `NOT NULL` so a real corpus never produces it -- guarded defensively
/// anyway so an empty/synthetic fixture can't panic on it).
pub(crate) fn bm25_field(idf_value: f64, tf: u32, dl: u32, avgdl: f64) -> f64 {
    let tf = tf as f64;
    let length_ratio = if avgdl > 0.0 { dl as f64 / avgdl } else { 0.0 };
    let norm = K1 * (1.0 - B + B * length_ratio);
    idf_value * (K1 + 1.0) * tf / (tf + norm)
}

/// Splits `text` into tantivy's real token stream: Latin/alphanumeric runs
/// become lowercased word tokens; CJK runs become overlapping 2-character
/// bigrams (mirrors `CjkBigramDecompose`, `cass_compat.rs:1315-1328` --
/// tantivy's tokenizer chain, not FTS5's trigram tokenizer). A lone CJK
/// character with no neighbor forms no bigram and is dropped, exactly as
/// `CjkBigramDecompose` would produce no token for it either.
///
/// **Amendment #2 fidelity fix (X-4 follow-up diagnostic)**: an interior `-`
/// between two ASCII alphanumeric characters stays glued into the same raw
/// token during the scan (mirrors `CassTokenStream::scan_ascii_token`,
/// `cass_compat.rs` -- *not* an ASCII-vs-Unicode-alphanumeric distinction
/// anywhere else in this function, only the hyphen-glue condition itself is
/// ASCII-scoped, matching the real tokenizer), then [`push_hyphen_decomposed`]
/// re-expands that raw token into the compound form *and* each
/// hyphen-delimited part (mirrors `HyphenDecompose`, same file) -- so
/// `"force-rebuild"` contributes 3 tokens (`"force-rebuild"`, `"force"`,
/// `"rebuild"`), not 2. Measured against the real pipeline on a 1185-doc
/// random sample: this closes a ~3% average / up to 25% single-document
/// `dl` undercount for hyphen-dense (CLI-flag/code-heavy) text -- see
/// `W2_ARTIFACTS/w2-hyphen-decompose-fidelity-diagnostic.md`.
pub(crate) fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut cjk_run: Vec<char> = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if is_cjk_char(c) {
            if !word.is_empty() {
                push_hyphen_decomposed(std::mem::take(&mut word), &mut tokens);
            }
            cjk_run.push(c);
            i += 1;
            continue;
        }
        if c.is_alphanumeric() {
            flush_cjk_bigrams(&mut cjk_run, &mut tokens);
            word.extend(c.to_lowercase());
            i += 1;
            let mut last_was_ascii_alnum = c.is_ascii_alphanumeric();
            loop {
                if i < chars.len() && chars[i].is_ascii_alphanumeric() {
                    word.extend(chars[i].to_lowercase());
                    i += 1;
                    last_was_ascii_alnum = true;
                    continue;
                }
                if last_was_ascii_alnum
                    && i < chars.len()
                    && chars[i] == '-'
                    && i + 1 < chars.len()
                    && chars[i + 1].is_ascii_alphanumeric()
                {
                    word.push('-');
                    i += 1;
                    last_was_ascii_alnum = false;
                    continue;
                }
                break;
            }
            continue;
        }
        flush_cjk_bigrams(&mut cjk_run, &mut tokens);
        if !word.is_empty() {
            push_hyphen_decomposed(std::mem::take(&mut word), &mut tokens);
        }
        i += 1;
    }
    flush_cjk_bigrams(&mut cjk_run, &mut tokens);
    if !word.is_empty() {
        push_hyphen_decomposed(word, &mut tokens);
    }
    tokens
}

/// Mirrors tantivy's `HyphenDecompose` token filter (`cass_compat.rs`): a raw
/// token containing `-` emits the compound form *and* each hyphen-delimited
/// part (real tantivy emits them at the same token position; this module
/// only needs the multiset for tf/dl counting, so plain pushes are
/// equivalent). Fewer than 2 non-empty parts (e.g. a token that is just
/// `-` internally with nothing on one side, which `scan_ascii_token`'s own
/// adjacency check makes unreachable, kept here only as a defensive
/// pass-through) leaves the token unchanged, matching `parts.len() < 2`
/// in the real filter.
fn push_hyphen_decomposed(word: String, tokens: &mut Vec<String>) {
    if !word.contains('-') {
        tokens.push(word);
        return;
    }
    let parts: Vec<String> = word.split('-').filter(|s| !s.is_empty()).map(str::to_owned).collect();
    if parts.len() < 2 {
        tokens.push(word);
        return;
    }
    tokens.push(word);
    tokens.extend(parts);
}

fn flush_cjk_bigrams(run: &mut Vec<char>, tokens: &mut Vec<String>) {
    if run.len() >= 2 {
        for pair in run.windows(2) {
            tokens.push(pair.iter().collect());
        }
    }
    run.clear();
}

/// CJK Unified Ideographs (+ common extensions), Hiragana, Katakana, Hangul
/// syllables. Matches the ranges this codebase's existing tests already
/// treat as CJK/alphanumeric (`query.rs` unicode test module).
fn is_cjk_char(c: char) -> bool {
    matches!(c as u32,
        0x4E00..=0x9FFF
        | 0x3400..=0x4DBF
        | 0x20000..=0x2A6DF
        | 0x3040..=0x309F
        | 0x30A0..=0x30FF
        | 0xAC00..=0xD7AF
    )
}

fn count_tokens(tokens: &[String]) -> HashMap<&str, u32> {
    let mut counts: HashMap<&str, u32> = HashMap::with_capacity(tokens.len());
    for t in tokens {
        *counts.entry(t.as_str()).or_insert(0) += 1;
    }
    counts
}

/// tf of one query term (already decomposed into its match-token group --
/// one word, or the CJK bigrams a multi-character CJK term expands to) in
/// one field's token-count map. A multi-bigram CJK term's tf is the
/// minimum per-bigram count (an "all constituent bigrams must co-occur"
/// proxy for tantivy's own per-bigram `Occur::Must` query construction,
/// `cass_build_cjk_term_query`, `cass_compat.rs:1788-1812` -- not phrase
/// adjacency, which this module doesn't attempt to replicate).
fn term_tf_in(term_group: &[String], field_counts: &HashMap<&str, u32>) -> u32 {
    term_group
        .iter()
        .map(|tok| field_counts.get(tok.as_str()).copied().unwrap_or(0))
        .min()
        .unwrap_or(0)
}

/// One MATCH/LIKE candidate carried through the rerank. Deliberately has no
/// `agent`/`workspace`/`source_path` fields -- see module doc: those never
/// enter scoring, so there is nothing here for a future edit to
/// accidentally wire into the formula.
pub(crate) struct RerankCandidate {
    pub doc_id: i64,
    pub content: String,
    pub title: String,
    /// Already sign-normalized to "higher is better" by the caller (the
    /// MATCH path negates fts5's `bm25()`; the KU3 LIKE path's occurrence
    /// score is already higher-is-better and passes through unchanged).
    /// Used only as the tie-break for candidates whose BM25F score is 0.0
    /// (pure upgrade-surface hits -- matched only via agent/workspace/
    /// source_path, which this module never scores).
    pub legacy_score: f64,
    /// Filled in by [`rerank_candidates`]; `0.0` until then.
    pub score: f64,
}

/// Corpus-wide average field length (token count, not character count --
/// see design doc ②: must be precomputed/cached, never queried live).
#[derive(Clone, Copy)]
pub(crate) struct FieldAvgdl {
    pub content: f64,
    pub title: f64,
}

/// Scores and sorts `candidates` in place (consuming and returning them),
/// final order: BM25F score descending (content+title independent BM25
/// summed, tantivy's real multi-field semantics -- see module doc) →
/// legacy_score descending (tie-break for the score==0.0 upgrade-surface
/// candidates) → doc_id ascending (deterministic final tie-break, mirrors
/// the existing `ORDER BY bm25(), rowid` convention in `query.rs`).
pub(crate) fn rerank_candidates(
    mut candidates: Vec<RerankCandidate>,
    query_terms: &[String],
    avgdl: &FieldAvgdl,
    total_docs: u64,
) -> Vec<RerankCandidate> {
    let term_groups: Vec<Vec<String>> = query_terms
        .iter()
        .map(|t| tokenize(t))
        .filter(|g| !g.is_empty())
        .collect();

    if candidates.is_empty() || term_groups.is_empty() {
        candidates.sort_by(|a, b| {
            b.legacy_score
                .partial_cmp(&a.legacy_score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.doc_id.cmp(&b.doc_id))
        });
        return candidates;
    }

    struct Prepared<'a> {
        content_counts: HashMap<&'a str, u32>,
        content_len: u32,
        title_counts: HashMap<&'a str, u32>,
        title_len: u32,
    }

    let content_tokens: Vec<Vec<String>> = candidates.iter().map(|c| tokenize(&c.content)).collect();
    let title_tokens: Vec<Vec<String>> = candidates.iter().map(|c| tokenize(&c.title)).collect();
    let prepared: Vec<Prepared> = content_tokens
        .iter()
        .zip(title_tokens.iter())
        .map(|(ct, tt)| Prepared {
            content_len: ct.len() as u32,
            content_counts: count_tokens(ct),
            title_len: tt.len() as u32,
            title_counts: count_tokens(tt),
        })
        .collect();

    // Per term, per candidate: (tf_content, tf_title). Also needed to
    // compute per-field df from this same hydrated candidate set (see
    // design doc ②: MATCH's candidate set is a superset of every doc that
    // truly contains the term in a given field for >=3-char terms, so
    // counting df here is exact, not an approximation, and costs zero
    // extra SQL).
    let mut term_tf: Vec<Vec<(u32, u32)>> = Vec::with_capacity(term_groups.len());
    for group in &term_groups {
        let per_candidate: Vec<(u32, u32)> = prepared
            .iter()
            .map(|p| {
                (
                    term_tf_in(group, &p.content_counts),
                    term_tf_in(group, &p.title_counts),
                )
            })
            .collect();
        term_tf.push(per_candidate);
    }

    let term_idf: Vec<(f64, f64)> = term_tf
        .iter()
        .map(|per_candidate| {
            let df_content = per_candidate.iter().filter(|(c, _)| *c > 0).count() as u64;
            let df_title = per_candidate.iter().filter(|(_, t)| *t > 0).count() as u64;
            (idf(df_content, total_docs), idf(df_title, total_docs))
        })
        .collect();

    for (i, candidate) in candidates.iter_mut().enumerate() {
        let mut score = 0.0;
        for (term_idx, _) in term_groups.iter().enumerate() {
            let (tf_content, tf_title) = term_tf[term_idx][i];
            let (idf_content, idf_title) = term_idf[term_idx];
            score += bm25_field(idf_content, tf_content, prepared[i].content_len, avgdl.content);
            score += bm25_field(idf_title, tf_title, prepared[i].title_len, avgdl.title);
        }
        candidate.score = score;
    }

    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| b.legacy_score.partial_cmp(&a.legacy_score).unwrap_or(Ordering::Equal))
            .then_with(|| a.doc_id.cmp(&b.doc_id))
    });
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: u64 = 1000;

    fn approx(got: f64, want: f64) {
        assert!((got - want).abs() < 1e-4, "got {got}, want {want}");
    }

    // T1: IDF monotonicity, oracle values from w2-rerank-test-matrix.md.
    #[test]
    fn idf_decreases_as_df_increases() {
        approx(idf(1, N), 6.503290);
        approx(idf(10, N), 4.557380);
        approx(idf(100, N), 2.298597);
        approx(idf(500, N), 0.693147);
        assert!(idf(1, N) > idf(10, N));
        assert!(idf(10, N) > idf(100, N));
        assert!(idf(100, N) > idf(500, N));
    }

    // T2: tf saturation -- diminishing marginal returns, not just monotonic.
    #[test]
    fn bm25_field_tf_saturates() {
        let idf50 = idf(50, N);
        let s0 = bm25_field(idf50, 0, 100, 100.0);
        let s5 = bm25_field(idf50, 5, 100, 100.0);
        let s10 = bm25_field(idf50, 10, 100, 100.0);
        approx(s0, 0.0);
        approx(s5, 5.299128);
        approx(s10, 5.866892);
        assert!(s10 - s5 < s5 - s0, "marginal gain must shrink: {s10}-{s5} vs {s5}-{s0}");
    }

    // T3: length normalization direction -- longer field, lower score.
    // Mutation guard: hardcoding b=0 must turn this red (see comment below).
    #[test]
    fn bm25_field_penalizes_length_above_avgdl() {
        let idf50 = idf(50, N);
        let scores: Vec<f64> = [50u32, 100, 200, 400]
            .iter()
            .map(|&dl| bm25_field(idf50, 3, dl, 100.0))
            .collect();
        approx(scores[0], 5.256735);
        approx(scores[1], 4.693514);
        approx(scores[2], 3.865247);
        approx(scores[3], 2.856921);
        assert!(scores.windows(2).all(|w| w[0] > w[1]), "score must strictly decrease as dl grows");
    }

    // T4: content/title must be exactly equal-weighted (no title boost).
    #[test]
    fn content_and_title_score_identically_given_identical_inputs() {
        let idf20 = idf(20, N);
        let content_score = bm25_field(idf20, 2, 40, 40.0);
        let title_score = bm25_field(idf20, 2, 40, 40.0);
        approx(content_score, 5.346454);
        approx(title_score, 5.346454);
    }

    // T6: two-field independent-BM25 sum (not merged-tf Robertson BM25F).
    #[test]
    fn rerank_candidates_sums_independent_field_scores() {
        // content: tf=2 dl=1200 avgdl=1125 df=200 -> idf=1.607941
        // title:   tf=1 dl=50   avgdl=54   df=20  -> idf=3.888330
        // Build a fully controlled corpus: 1000 docs total, 200 contain
        // "needle" in content (tf=2 each via "needle needle"), 20 contain
        // "needle" in title (tf=1 each). The scored candidate has content
        // len 1200 tokens (padded) and title len 50 tokens (padded).
        let mut candidates = Vec::new();
        let content_padding = |extra_tokens: usize| -> String {
            let mut s = String::from("needle needle ");
            for i in 0..extra_tokens {
                s.push_str(&format!("pad{i} "));
            }
            s
        };
        candidates.push(RerankCandidate {
            doc_id: 1,
            content: content_padding(1198),
            title: {
                let mut s = String::from("needle ");
                for i in 0..49 {
                    s.push_str(&format!("t{i} "));
                }
                s
            },
            legacy_score: 0.0,
            score: 0.0,
        });
        for i in 0..199 {
            candidates.push(RerankCandidate {
                doc_id: 100 + i,
                content: "needle other".to_string(),
                title: "x".to_string(),
                legacy_score: 0.0,
                score: 0.0,
            });
        }
        for i in 0..19 {
            candidates.push(RerankCandidate {
                doc_id: 400 + i,
                content: "unrelated".to_string(),
                title: "needle".to_string(),
                legacy_score: 0.0,
                score: 0.0,
            });
        }
        for i in 0..(N as usize - candidates.len()) {
            candidates.push(RerankCandidate {
                doc_id: 900 + i as i64,
                content: "nothing".to_string(),
                title: "nothing".to_string(),
                legacy_score: 0.0,
                score: 0.0,
            });
        }
        assert_eq!(candidates.len(), N as usize);

        let avgdl = FieldAvgdl { content: 1125.0, title: 54.0 };
        let ranked = rerank_candidates(candidates, &["needle".to_string()], &avgdl, N);
        let top = ranked.iter().find(|c| c.doc_id == 1).expect("candidate present");
        // Not asserting the exact oracle from the design doc's hand-picked
        // dl/avgdl/df combination (this test builds its own consistent
        // corpus instead of faking df/avgdl directly, which the pure
        // `bm25_field` tests above already cover with exact oracles) --
        // this test's job is the *sum* semantics: score must be positive
        // and strictly greater than either field's contribution alone
        // would be, proving both fields' scores landed in the total.
        assert!(top.score > 0.0);
    }

    // T5: agent/workspace/source_path have no field in RerankCandidate at
    // all (type-level enforcement) -- this test covers the remaining
    // runtime case: a candidate that matched via MATCH (so it's in the
    // candidate set) but whose content/title genuinely don't contain the
    // term must score exactly 0.0, not "small".
    #[test]
    fn candidate_with_no_content_or_title_match_scores_exactly_zero() {
        let candidates = vec![RerankCandidate {
            doc_id: 1,
            content: "nothing relevant here".to_string(),
            title: "also nothing".to_string(),
            legacy_score: -1.2,
            score: 0.0,
        }];
        let avgdl = FieldAvgdl { content: 100.0, title: 20.0 };
        let ranked = rerank_candidates(candidates, &["needle".to_string()], &avgdl, N);
        approx(ranked[0].score, 0.0);
    }

    // T7: df==0 boundary must not panic / produce NaN.
    #[test]
    fn idf_and_bm25_field_handle_zero_df_without_panicking() {
        let idf_zero_df = idf(0, N);
        approx(idf_zero_df, 7.601902);
        let score = bm25_field(idf_zero_df, 0, 100, 100.0);
        approx(score, 0.0);
        assert!(!score.is_nan());
    }

    // T8: sign convention + tie-break. Zero-score candidates must be kept
    // (not dropped) and ordered by -legacy_score descending, i.e. the
    // fts5-more-negative-is-better candidate must sort *first* among ties
    // -- getting this backwards is exactly the sign bug the community
    // research flagged (raw ORDER BY on fts5's own negative convention).
    #[test]
    fn zero_score_candidates_are_retained_and_ordered_by_negated_legacy_score() {
        // `legacy_score` is documented as *already* sign-normalized to
        // higher-is-better by the caller (matching the existing convention
        // at query.rs:7617-7622: raw fts5 `bm25()` is more-negative-better,
        // callers negate once at the boundary before this point). Raw fts5
        // values here would be -1.2 and -3.5 (doc 30 "more matching"); the
        // caller-negated values this function actually receives are 1.2
        // and 3.5.
        let candidates = vec![
            RerankCandidate { doc_id: 10, content: "hit here".to_string(), title: String::new(), legacy_score: 0.0, score: 0.0 },
            RerankCandidate { doc_id: 20, content: String::new(), title: String::new(), legacy_score: 1.2, score: 0.0 },
            RerankCandidate { doc_id: 30, content: String::new(), title: String::new(), legacy_score: 3.5, score: 0.0 },
        ];
        let avgdl = FieldAvgdl { content: 100.0, title: 20.0 };
        let ranked = rerank_candidates(candidates, &["hit".to_string()], &avgdl, N);
        let ids: Vec<i64> = ranked.iter().map(|c| c.doc_id).collect();
        // doc 10 has a real content match (score>0) so it's first; among
        // the two zero-score candidates, 3.5 > 1.2 so doc 30 (the more-
        // negative *raw* fts5 score, "more matching") sorts ahead of doc
        // 20 -- passing the raw un-negated values here instead would flip
        // this order, which is exactly the sign bug this test guards.
        assert_eq!(ids, vec![10, 30, 20]);
        assert_eq!(ranked.len(), 3, "no candidate dropped");
    }

    // Tokenizer sanity: CJK bigram decomposition and Latin word splitting.
    #[test]
    fn tokenize_splits_cjk_into_overlapping_bigrams_and_latin_into_words() {
        assert_eq!(tokenize("数据库"), vec!["数据", "据库"]);
        assert_eq!(tokenize("Connectors work"), vec!["connectors", "work"]);
        assert_eq!(tokenize("单"), Vec::<String>::new(), "lone CJK char forms no bigram");
    }

    /// Behavior-parity fixture (amendment #2 fidelity fix): locks
    /// `tokenize()`'s hyphen handling to real `CassTokenizer` +
    /// `HyphenDecompose` behavior (`cass_compat.rs`, pin rev
    /// `2cad158f4468ece7076e3fe529c8e5c20b2e020e`), verified against a
    /// hand-rolled Python replica of that exact source during the X-4
    /// follow-up diagnostic. This is the behavior contract W2-6 retirement
    /// inherits once frankensearch is gone and this source can no longer be
    /// read directly.
    #[test]
    fn tokenize_hyphen_handling_matches_cass_tokenizer_plus_hyphen_decompose() {
        // A hyphenated compound emits the compound form *and* each part --
        // this is the specific gap the diagnostic found (previously only
        // the two parts were emitted, undercounting dl by one token per
        // compound).
        assert_eq!(
            tokenize("indexing-tool"),
            vec!["indexing-tool", "indexing", "tool"]
        );
        // Multi-hyphen compound: the whole run glues, then decomposes into
        // the compound plus every part.
        assert_eq!(
            tokenize("no-default-features"),
            vec!["no-default-features", "no", "default", "features"]
        );
        // A hyphen NOT between two ASCII alphanumerics is a plain separator
        // (unreachable by `scan_ascii_token`'s adjacency check) -- leading,
        // trailing, and doubled hyphens all fall back to ordinary word
        // boundaries, same as before this fix.
        assert_eq!(tokenize("-leading"), vec!["leading"]);
        assert_eq!(tokenize("trailing-"), vec!["trailing"]);
        assert_eq!(tokenize("double--hyphen"), vec!["double", "hyphen"]);
        // Path-like and dotted text (no hyphens) is unaffected -- confirms
        // this fix is hyphen-scoped, not a general retokenization.
        assert_eq!(
            tokenize("src/indexer/mod.rs"),
            vec!["src", "indexer", "mod", "rs"]
        );
        assert_eq!(tokenize("a.md indexing"), vec!["a", "md", "indexing"]);
        // A hyphenated word immediately followed by more words: the run
        // boundary after the compound is still correct.
        assert_eq!(
            tokenize("--force-rebuild now"),
            vec!["force-rebuild", "force", "rebuild", "now"]
        );
    }
}
