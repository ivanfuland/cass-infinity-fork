//! Numerical gates for cross-endpoint embedding evidence.
//!
//! These calculations cannot grant runtime admission on their own. Admission
//! also requires pinned input bytes, model declarations, complete captures and
//! direct coverage of every stored contributor.
use super::Normalization;

pub(crate) const MIN_COSINE: f64 = 0.9999;
pub(crate) const MAX_COMPONENT_DELTA: f64 = 0.001;
pub(crate) const MAX_RELATIVE_NORM_DELTA: f64 = 0.001;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CompatibilityError {
    #[error("CompatibilityInvalidVector")]
    InvalidVector,
    #[error("CompatibilityDimensionMismatch")]
    DimensionMismatch,
    #[error("CompatibilityInvalidFixture")]
    InvalidFixture,
    #[error("CompatibilityNumericalMismatch")]
    NumericalMismatch,
    #[error("CompatibilityRetrievalMismatch")]
    RetrievalMismatch,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub(crate) struct VectorComparison {
    pub cosine: f64,
    pub max_component_delta: f64,
    pub relative_norm_delta: f64,
    pub passed: bool,
}

fn norm(vector: &[f32]) -> Result<f64, CompatibilityError> {
    if vector.is_empty() || vector.iter().any(|v| !v.is_finite()) {
        return Err(CompatibilityError::InvalidVector);
    }
    let norm = vector.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>().sqrt();
    if !norm.is_finite() || norm == 0.0 { return Err(CompatibilityError::InvalidVector); }
    Ok(norm)
}

/// Compare final vectors in f64, avoiding f32 norm overflow and underflow.
/// Norm error uses the larger norm as a symmetric relative-error denominator.
pub(crate) fn compare_vectors(left: &[f32], right: &[f32], normalization: Normalization)
    -> Result<VectorComparison, CompatibilityError> {
    if left.len() != right.len() { return Err(CompatibilityError::DimensionMismatch); }
    let (ln, rn) = (norm(left)?, norm(right)?);
    let mut cosine = 0.0;
    let mut max_component_delta = 0.0_f64;
    for (&l, &r) in left.iter().zip(right) {
        let (l, r) = (f64::from(l) / ln, f64::from(r) / rn);
        cosine += l * r;
        max_component_delta = max_component_delta.max((l-r).abs());
    }
    let cosine = cosine.clamp(-1.0, 1.0);
    let relative_norm_delta = (ln-rn).abs() / ln.max(rn);
    Ok(VectorComparison { cosine, max_component_delta, relative_norm_delta,
        passed: cosine >= MIN_COSINE && max_component_delta <= MAX_COMPONENT_DELTA
            && (normalization != Normalization::None || relative_norm_delta <= MAX_RELATIVE_NORM_DELTA),
    })
}

/// Both rounds at both endpoints must agree directly, including repeatability.
/// No averaging and no transitive inference can turn one failed row into a pass.
pub(crate) fn verify_four_observations(observations: [&[f32]; 4], normalization: Normalization)
    -> Result<Vec<VectorComparison>, CompatibilityError> {
    let mut comparisons = Vec::with_capacity(6);
    for left in 0..4 {
        for right in left+1..4 {
            let result = compare_vectors(observations[left], observations[right], normalization)?;
            if !result.passed { return Err(CompatibilityError::NumericalMismatch); }
            comparisons.push(result);
        }
    }
    Ok(comparisons)
}

/// One endpoint's two complete sets of query and document vectors.
pub(crate) struct RetrievalVectors<'a> {
    pub query_rounds: [&'a [Vec<f32>]; 2],
    pub document_rounds: [&'a [Vec<f32>]; 2],
}

/// The independently frozen expected top document for each query. Inputs here
/// are the fixture's selected queries/documents, not all probe texts together.
/// Two distinct targets prevent a constant-vector fixture from passing by ties.
pub(crate) fn verify_cross_retrieval(endpoints: [RetrievalVectors<'_>; 2], labels: &[usize])
    -> Result<(), CompatibilityError> {
    let documents = endpoints[0].document_rounds[0].len();
    if labels.len() < 2 || documents < 2 || labels.iter().any(|i| *i >= documents)
        || labels.iter().all(|i| *i == labels[0]) {
        return Err(CompatibilityError::InvalidFixture);
    }
    for endpoint in &endpoints {
        if endpoint.query_rounds.iter().any(|r| r.len() != labels.len())
            || endpoint.document_rounds.iter().any(|r| r.len() != documents) {
            return Err(CompatibilityError::InvalidFixture);
        }
    }
    // Four endpoint combinations, each covering all four round combinations.
    for queries in &endpoints {
        for docs in &endpoints {
            for query_round in queries.query_rounds {
                for doc_round in docs.document_rounds {
                    for (query, &expected) in query_round.iter().zip(labels) {
                        let mut best: Option<(usize, f64)> = None;
                        for (index, doc) in doc_round.iter().enumerate() {
                            let score = compare_vectors(query, doc, Normalization::L2)?.cosine;
                            // Strictly greater retains fixture order on an exact tie.
                            if best.is_none_or(|(_, previous)| score > previous) { best = Some((index, score)); }
                        }
                        if best.map(|(index, _)| index) != Some(expected) {
                            return Err(CompatibilityError::RetrievalMismatch);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_gate_is_additional_to_direction_and_uses_final_vectors() {
        assert!(compare_vectors(&[1.0,0.0], &[2.0,0.0], Normalization::L2).unwrap().passed);
        assert!(!compare_vectors(&[1.0,0.0], &[2.0,0.0], Normalization::None).unwrap().passed);
        assert!(compare_vectors(&[1.0,0.0], &[1.0005,0.0], Normalization::None).unwrap().passed);
    }

    #[test]
    fn component_gate_can_fail_despite_a_passing_cosine() {
        let result = compare_vectors(&[1.0,0.0], &[1.0,0.002], Normalization::L2).unwrap();
        assert!(result.cosine >= MIN_COSINE);
        assert!(!result.passed);
        assert!(result.max_component_delta > MAX_COMPONENT_DELTA);
        assert!(compare_vectors(&[1.0,0.0], &[1.0,0.0005], Normalization::L2).unwrap().passed);
    }

    #[test]
    fn malformed_vectors_are_not_numerical_evidence() {
        for vector in [vec![], vec![0.0,0.0], vec![f32::NAN,1.0], vec![f32::INFINITY,1.0]] {
            assert_eq!(compare_vectors(&vector, &vector, Normalization::L2).unwrap_err(), CompatibilityError::InvalidVector);
        }
        assert_eq!(compare_vectors(&[1.0], &[1.0,0.0], Normalization::L2).unwrap_err(), CompatibilityError::DimensionMismatch);
        for v in [f32::MAX, f32::MIN_POSITIVE, f32::from_bits(1)] {
            assert!(compare_vectors(&[v,v], &[v,v], Normalization::None).unwrap().passed);
        }
    }

    #[test]
    fn near_equality_is_not_transitive() {
        let (a,b,c) = ([1.0,0.0], [1.0,0.0008], [1.0,0.0016]);
        assert!(compare_vectors(&a,&b,Normalization::L2).unwrap().passed);
        assert!(compare_vectors(&b,&c,Normalization::L2).unwrap().passed);
        assert!(!compare_vectors(&a,&c,Normalization::L2).unwrap().passed);
        assert_eq!(verify_four_observations([&a,&b,&b,&c],Normalization::L2).unwrap_err(), CompatibilityError::NumericalMismatch);
    }

    #[test]
    fn all_rounds_and_all_cross_retrieval_directions_are_checked() {
        let good = vec![vec![1.0,0.0], vec![0.0,1.0]];
        let swapped = vec![vec![0.0,1.0], vec![1.0,0.0]];
        let endpoints = || [RetrievalVectors{query_rounds:[&good,&good], document_rounds:[&good,&good]},
            RetrievalVectors{query_rounds:[&good,&good], document_rounds:[&good,&good]}];
        verify_cross_retrieval(endpoints(), &[0,1]).unwrap();
        let mut changed = endpoints(); changed[1].document_rounds[1] = &swapped;
        assert_eq!(verify_cross_retrieval(changed, &[0,1]).unwrap_err(), CompatibilityError::RetrievalMismatch);
        let mut changed = endpoints(); changed[1].query_rounds[1] = &swapped;
        assert_eq!(verify_cross_retrieval(changed, &[0,1]).unwrap_err(), CompatibilityError::RetrievalMismatch);
        assert_eq!(verify_cross_retrieval(endpoints(), &[0,0]).unwrap_err(), CompatibilityError::InvalidFixture);
    }
}
