//! Model-independent generation fingerprints. The frozen sentinel text and
//! comparison threshold preserve existing database identities.
//!
//! The per-sentinel cosine tolerance is `0.999`, not `0.9999`. The same model
//! served by two backends does not return byte-identical embeddings: measured
//! cross-backend cosines bottom out around `0.99969` (lowest sample), while a
//! genuinely different model lands far below `0.999`. The tolerance therefore
//! has to admit backend noise without admitting a model change. Three call
//! sites share this one function and inherit the tolerance together: API
//! generation reuse (`find_or_create_api_generation`), reuse on the legacy
//! Infinity path, and activation audit item ⑪.
use crate::search::frankensearch_types::cosine_similarity;
use crate::storage::schema::le_blob_to_f32_vector;

/// Three fixed sentinel sentences (English / Chinese / code) whose embeddings
/// form a generation's fingerprint. Frozen wording per plan v5.1 参数冻结
/// "代际身份" row -- changing any sentence changes what every stored
/// fingerprint means, so this is not meant to ever be edited casually.
pub const FINGERPRINT_SENTINELS: [&str; 3] = [
    "The quick brown fox jumps over the lazy dog.",
    "今天天气不错，我们去公园散步吧。",
    "fn main() { println!(\"hello\"); }",
];

/// Whether a `stored` fingerprint still matches a `fresh` one for a served
/// model of dimension `dim`: both must be exactly `3 * dim * 4` bytes long
/// (3 sentinels, LE f32), and each of the 3 corresponding sentinel vectors
/// must cosine-match at `>= 0.999`. The tolerance is deliberately looser
/// than the original `0.9999`: measured cross-backend cosines for the same
/// model reach as low as `0.99969`, and a different model stays far below
/// `0.999`. Tightening it again re-breaks any generation reached through a
/// different backend. A length mismatch or a malformed blob (not decodable
/// as f32s) is treated as a non-match, not a panic.
pub fn fingerprint_matches(stored: &[u8], fresh: &[u8], dim: usize) -> bool {
    let expected_len = 3 * dim * 4;
    if stored.len() != expected_len || fresh.len() != expected_len {
        return false;
    }
    let segment = dim * 4;
    for i in 0..3 {
        let s = &stored[i * segment..(i + 1) * segment];
        let f = &fresh[i * segment..(i + 1) * segment];
        let Ok(sv) = le_blob_to_f32_vector(s) else {
            return false;
        };
        let Ok(fv) = le_blob_to_f32_vector(f) else {
            return false;
        };
        if cosine_similarity(&sv, &fv) < 0.999 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::schema::f32_vector_to_le_blob;

    #[test]
    fn fingerprint_matches_rejects_length_mismatch_and_low_cosine() {
        let dim = 2usize;
        let identical: Vec<f32> = vec![1.0, 0.0];
        // Segment 0 deliberately sits at cosine ~0.95: below the real 0.999
        // threshold (must reject), but above a mutated 0.9 threshold -- the
        // fixture that makes the T7 cosine-threshold mutation step flip this
        // assertion to red.
        let low_stored: Vec<f32> = vec![1.0, 0.0];
        let low_fresh: Vec<f32> = vec![0.95, 0.312_249_9];
        let low_cosine = cosine_similarity(&low_stored, &low_fresh);
        assert!(
            (0.9..0.999).contains(&low_cosine),
            "fixture cosine {low_cosine} must sit strictly between 0.9 and 0.999 to be mutation-sensitive"
        );

        let mut stored = Vec::new();
        stored.extend_from_slice(&f32_vector_to_le_blob(&low_stored));
        stored.extend_from_slice(&f32_vector_to_le_blob(&identical));
        stored.extend_from_slice(&f32_vector_to_le_blob(&identical));

        let mut fresh = Vec::new();
        fresh.extend_from_slice(&f32_vector_to_le_blob(&low_fresh));
        fresh.extend_from_slice(&f32_vector_to_le_blob(&identical));
        fresh.extend_from_slice(&f32_vector_to_le_blob(&identical));

        assert!(
            !fingerprint_matches(&stored, &fresh, dim),
            "a below-threshold cosine on any one sentinel must fail the whole fingerprint"
        );

        // Length mismatch (independent of cosine): truncate `fresh` by a byte.
        let truncated = &fresh[..fresh.len() - 1];
        assert!(
            !fingerprint_matches(&stored, truncated, dim),
            "a length mismatch must fail before any cosine is even computed"
        );
    }

    /// Same model served by two backends returns near-identical, not
    /// byte-identical, embeddings: measured cross-backend cosines bottom out
    /// around 0.99969. Every sentinel must clear the shared tolerance on its
    /// own, so each of the three positions is walked separately.
    #[test]
    fn fingerprint_matches_accepts_cross_backend_tolerance() {
        let dim = 2usize;
        let stored_sentinel: Vec<f32> = vec![1.0, 0.0];
        let approximate: Vec<f32> = vec![1.0, 0.03];

        // Assert the fixture's real cosine against the literal vectors before
        // asking the product function anything -- otherwise a change to the
        // cosine implementation could silently move the fixture too.
        let cosine = cosine_similarity(&stored_sentinel, &approximate);
        assert!(
            (0.999..0.9999).contains(&cosine),
            "fixture cosine {cosine} must sit strictly between 0.999 and 0.9999"
        );

        for position in 0..3 {
            let mut stored = Vec::new();
            let mut fresh = Vec::new();
            for index in 0..3 {
                stored.extend_from_slice(&f32_vector_to_le_blob(&stored_sentinel));
                if index == position {
                    fresh.extend_from_slice(&f32_vector_to_le_blob(&approximate));
                } else {
                    fresh.extend_from_slice(&f32_vector_to_le_blob(&stored_sentinel));
                }
            }
            assert!(
                fingerprint_matches(&stored, &fresh, dim),
                "sentinel position {position} at cosine {cosine} must match a cross-backend re-embedding"
            );
        }
    }

    /// The other side of the tolerance: a cosine below `0.999` must be
    /// rejected at every sentinel position, not only the first one.
    #[test]
    fn fingerprint_matches_rejects_below_tolerance_at_every_position() {
        let dim = 2usize;
        let stored_sentinel: Vec<f32> = vec![1.0, 0.0];
        let drift: Vec<f32> = vec![1.0, 0.05];

        let cosine = cosine_similarity(&stored_sentinel, &drift);
        assert!(
            (0.99..0.999).contains(&cosine),
            "fixture cosine {cosine} must sit strictly between 0.99 and 0.999"
        );

        for position in 0..3 {
            let mut stored = Vec::new();
            let mut fresh = Vec::new();
            for index in 0..3 {
                stored.extend_from_slice(&f32_vector_to_le_blob(&stored_sentinel));
                if index == position {
                    fresh.extend_from_slice(&f32_vector_to_le_blob(&drift));
                } else {
                    fresh.extend_from_slice(&f32_vector_to_le_blob(&stored_sentinel));
                }
            }
            assert!(
                !fingerprint_matches(&stored, &fresh, dim),
                "sentinel position {position} at cosine {cosine} is below the tolerance and must not match"
            );
        }
    }

    #[test]
    fn fingerprint_matches_accepts_identical() {
        let dim = 3usize;
        let sentinel_vectors: [Vec<f32>; 3] = [
            vec![1.0, 2.0, 3.0],
            vec![-0.5, 4.25, 0.0],
            vec![7.0, -7.0, 0.001],
        ];
        let mut blob = Vec::new();
        for v in &sentinel_vectors {
            blob.extend_from_slice(&f32_vector_to_le_blob(v));
        }
        assert!(
            fingerprint_matches(&blob, &blob, dim),
            "byte-identical fingerprints must match (cosine of a vector with itself is 1.0)"
        );
    }

}
