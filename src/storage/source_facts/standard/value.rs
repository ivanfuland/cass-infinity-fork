//! Public scalar primitives for standard facts (Task28).
//!
//! These functions compose the frozen Task10 DTOs from a lossless source
//! value. They implement the count, time, value and alias rules only: no
//! database access, no source-event mapping, no export and no recovery. Source
//! numbers stay in decimal text; the count domain never goes through `f64`
//! and never expands a large power of ten.

use std::cmp::Ordering;

use franken_agent_detection::{LosslessSourceValue, ValidatedJsonNumberText};

use super::{CandidateFact, FactStatus, FactUnit, FactValue, FactValueKind, FieldFact};

/// Build one count fact from an already located source node.
///
/// `None` means the field is absent; `Some(Null)` means it is present and
/// null. Both missing shapes keep `unit = count`.
#[must_use]
pub fn count_fact(field: &str, node: Option<&LosslessSourceValue>, raw_ref: &str) -> FieldFact {
    let missing_unit = Some(FactUnit::Count);
    match node {
        None => missing_absent(field, raw_ref, missing_unit),
        Some(LosslessSourceValue::Null) => missing_null(field, raw_ref, missing_unit),
        Some(LosslessSourceValue::Number(text)) => count_number(field, text.as_str(), raw_ref),
        Some(_) => invalid(field, raw_ref, "not_a_number", missing_unit),
    }
}

/// Build the single time fact. Its field is always `time`.
#[must_use]
pub fn time_fact(node: Option<&LosslessSourceValue>, raw_ref: &str) -> FieldFact {
    const FIELD: &str = "time";
    match node {
        None => missing_absent(FIELD, raw_ref, None),
        Some(LosslessSourceValue::Null) => missing_null(FIELD, raw_ref, None),
        Some(LosslessSourceValue::Number(_)) => invalid(FIELD, raw_ref, "unit_unproven", None),
        Some(LosslessSourceValue::String(text)) => time_string(text, raw_ref),
        Some(LosslessSourceValue::Bool(_) | LosslessSourceValue::Array(_)) => {
            invalid(FIELD, raw_ref, "bad_type", None)
        }
        Some(LosslessSourceValue::Object(_)) => invalid(FIELD, raw_ref, "bad_type", None),
    }
}

/// Build one generic value fact.
#[must_use]
pub fn value_fact(field: &str, node: Option<&LosslessSourceValue>, raw_ref: &str) -> FieldFact {
    match node {
        None => missing_absent(field, raw_ref, None),
        Some(LosslessSourceValue::Null) => missing_null(field, raw_ref, None),
        Some(LosslessSourceValue::String(text)) => FieldFact {
            field: field.to_owned(),
            status: FactStatus::Present,
            value: Some(FactValue::String(text.clone())),
            value_kind: None,
            raw_ref: Some(raw_ref.to_owned()),
            presence_ref: None,
            reason: None,
            refs: None,
            unit: None,
        },
        Some(LosslessSourceValue::Bool(value)) => FieldFact {
            field: field.to_owned(),
            status: FactStatus::Present,
            value: Some(FactValue::Boolean(*value)),
            value_kind: None,
            raw_ref: Some(raw_ref.to_owned()),
            presence_ref: None,
            reason: None,
            refs: None,
            unit: None,
        },
        Some(LosslessSourceValue::Number(text)) => FieldFact {
            field: field.to_owned(),
            status: FactStatus::Present,
            value: Some(FactValue::String(text.as_str().to_owned())),
            value_kind: None,
            raw_ref: Some(raw_ref.to_owned()),
            presence_ref: None,
            reason: None,
            refs: None,
            unit: Some(FactUnit::NumberText),
        },
        Some(node @ LosslessSourceValue::Array(_)) => FieldFact {
            field: field.to_owned(),
            status: FactStatus::Present,
            value: Some(FactValue::Tree(node.clone())),
            value_kind: Some(FactValueKind::Array),
            raw_ref: Some(raw_ref.to_owned()),
            presence_ref: None,
            reason: None,
            refs: None,
            unit: None,
        },
        Some(node @ LosslessSourceValue::Object(_)) => FieldFact {
            field: field.to_owned(),
            status: FactStatus::Present,
            value: Some(FactValue::Tree(node.clone())),
            value_kind: Some(FactValueKind::Object),
            raw_ref: Some(raw_ref.to_owned()),
            presence_ref: None,
            reason: None,
            refs: None,
            unit: None,
        },
    }
}

/// Aggregate already built candidates for one standard field.
///
/// The caller guarantees that every candidate belongs to the same event and
/// scope. An empty slice is an internal call error: it returns
/// `invalid/invalid_alias` and no location.
#[must_use]
pub fn alias_fact(field: &str, candidates: &[FieldFact]) -> FieldFact {
    if candidates.is_empty() {
        return FieldFact {
            field: field.to_owned(),
            status: FactStatus::Invalid,
            value: None,
            value_kind: None,
            raw_ref: None,
            presence_ref: None,
            reason: Some("invalid_alias".to_owned()),
            refs: None,
            unit: None,
        };
    }

    let refs: Vec<CandidateFact> = candidates.iter().map(candidate_of).collect();
    let malformed = candidates
        .iter()
        .any(|candidate| candidate.field != field || candidate.status == FactStatus::Conflict);
    if malformed {
        return FieldFact {
            field: field.to_owned(),
            status: FactStatus::Invalid,
            value: None,
            value_kind: None,
            raw_ref: None,
            presence_ref: None,
            reason: Some("invalid_alias".to_owned()),
            refs: Some(refs),
            unit: None,
        };
    }

    if candidates.len() == 1 {
        return candidates[0].clone();
    }

    let presents: Vec<&FieldFact> = candidates
        .iter()
        .filter(|candidate| candidate.status == FactStatus::Present)
        .collect();
    let mut distinct = presents
        .iter()
        .map(|candidate| (&candidate.value_kind, &candidate.unit, &candidate.value));
    let first = distinct.next();
    let disagree = first.is_some_and(|first| distinct.any(|other| other != first));

    if disagree {
        return FieldFact {
            field: field.to_owned(),
            status: FactStatus::Conflict,
            value: None,
            value_kind: None,
            raw_ref: None,
            presence_ref: None,
            reason: None,
            refs: Some(refs),
            unit: None,
        };
    }

    if candidates
        .iter()
        .any(|candidate| candidate.status == FactStatus::Invalid)
    {
        return FieldFact {
            field: field.to_owned(),
            status: FactStatus::Invalid,
            value: None,
            value_kind: None,
            raw_ref: None,
            presence_ref: None,
            reason: Some("invalid_alias".to_owned()),
            refs: Some(refs),
            unit: None,
        };
    }

    if let Some(first) = presents.first() {
        return FieldFact {
            field: field.to_owned(),
            status: FactStatus::Present,
            value: first.value.clone(),
            value_kind: first.value_kind,
            raw_ref: first.raw_ref.clone(),
            presence_ref: first.presence_ref.clone(),
            reason: first.reason.clone(),
            refs: Some(refs),
            unit: first.unit,
        };
    }

    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Missing,
        value: None,
        value_kind: None,
        raw_ref: None,
        presence_ref: None,
        reason: Some("null".to_owned()),
        refs: Some(refs),
        unit: None,
    }
}

fn candidate_of(fact: &FieldFact) -> CandidateFact {
    CandidateFact {
        status: fact.status,
        value: fact.value.clone(),
        value_kind: fact.value_kind,
        raw_ref: fact.raw_ref.clone(),
        presence_ref: fact.presence_ref.clone(),
        reason: fact.reason.clone(),
        refs: fact.refs.clone(),
        unit: fact.unit,
    }
}

fn missing_absent(field: &str, raw_ref: &str, unit: Option<FactUnit>) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Missing,
        value: None,
        value_kind: None,
        raw_ref: None,
        presence_ref: Some(raw_ref.to_owned()),
        reason: Some("absent".to_owned()),
        refs: None,
        unit,
    }
}

fn missing_null(field: &str, raw_ref: &str, unit: Option<FactUnit>) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Missing,
        value: None,
        value_kind: None,
        raw_ref: Some(raw_ref.to_owned()),
        presence_ref: None,
        reason: Some("null".to_owned()),
        refs: None,
        unit,
    }
}

fn invalid(field: &str, raw_ref: &str, reason: &str, unit: Option<FactUnit>) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Invalid,
        value: None,
        value_kind: None,
        raw_ref: Some(raw_ref.to_owned()),
        presence_ref: None,
        reason: Some(reason.to_owned()),
        refs: None,
        unit,
    }
}

/// The u64 decimal domain upper bound, as the fixed 20-digit text.
const U64_MAX_DECIMAL: &str = "18446744073709551615";
/// Width of the u64 decimal domain.
const U64_DECIMAL_DIGITS: usize = 20;

fn count_number(field: &str, text: &str, raw_ref: &str) -> FieldFact {
    let unit = Some(FactUnit::Count);
    let Some(parts) = split_number(text) else {
        return invalid(field, raw_ref, "not_a_number", unit);
    };

    let mut all_digits = String::with_capacity(parts.integer_digits.len() + parts.fraction.len());
    all_digits.push_str(parts.integer_digits);
    all_digits.push_str(parts.fraction);
    let significant = match all_digits.find(|character| character != '0') {
        Some(start) => &all_digits[start..],
        None => "",
    };
    if significant.is_empty() {
        return present(field, raw_ref, "0", unit);
    }

    let coefficient = significant.trim_end_matches('0');
    let trailing_zeros = significant.len() - coefficient.len();
    let shift_base = parts.fraction.len() as i128 - trailing_zeros as i128;
    let length = coefficient.len() as i128;

    if parts.exponent.is_less_than(shift_base) {
        return invalid(field, raw_ref, "not_an_integer", unit);
    }
    if coefficient.len() > U64_DECIMAL_DIGITS {
        return invalid(field, raw_ref, "out_of_domain", unit);
    }
    let upper = shift_base + (U64_DECIMAL_DIGITS as i128 - length);
    if parts.exponent.is_greater_than(upper) {
        return invalid(field, raw_ref, "out_of_domain", unit);
    }

    let exponent = match parts.exponent.to_i128() {
        Some(value) => value,
        None => return invalid(field, raw_ref, "out_of_domain", unit),
    };
    let zeros = exponent - shift_base;
    debug_assert!((0..U64_DECIMAL_DIGITS as i128).contains(&zeros));
    let mut canonical = String::with_capacity(coefficient.len() + zeros.max(0) as usize);
    canonical.push_str(coefficient);
    for _ in 0..zeros.max(0) {
        canonical.push('0');
    }

    if parts.negative {
        return invalid(field, raw_ref, "negative_nonzero", unit);
    }
    if canonical.len() == U64_DECIMAL_DIGITS && canonical.as_str() > U64_MAX_DECIMAL {
        return invalid(field, raw_ref, "out_of_domain", unit);
    }
    present(field, raw_ref, &canonical, unit)
}

fn present(field: &str, raw_ref: &str, value: &str, unit: Option<FactUnit>) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Present,
        value: Some(FactValue::String(value.to_owned())),
        value_kind: None,
        raw_ref: Some(raw_ref.to_owned()),
        presence_ref: None,
        reason: None,
        refs: None,
        unit,
    }
}

struct NumberParts<'a> {
    negative: bool,
    integer_digits: &'a str,
    fraction: &'a str,
    exponent: SignedDecimal<'a>,
}

struct SignedDecimal<'a> {
    negative: bool,
    /// Decimal digits without leading zeros. Zero is stored as `"0"` and is
    /// always non-negative.
    digits: &'a str,
}

impl SignedDecimal<'_> {
    fn is_less_than(&self, value: i128) -> bool {
        compare_decimal(self.negative, self.digits, value) == Ordering::Less
    }

    fn is_greater_than(&self, value: i128) -> bool {
        compare_decimal(self.negative, self.digits, value) == Ordering::Greater
    }

    /// Only call this after the value is proven to sit in a bounded window.
    fn to_i128(&self) -> Option<i128> {
        let mut value: i128 = 0;
        for byte in self.digits.bytes() {
            value = value
                .checked_mul(10)?
                .checked_add(i128::from(byte - b'0'))?;
        }
        Some(if self.negative { -value } else { value })
    }
}

fn split_number(text: &str) -> Option<NumberParts<'_>> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        index += 1;
    }

    let integer_start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == integer_start {
        return None;
    }
    let integer_digits = &text[integer_start..index];

    let mut fraction = "";
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        let fraction_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == fraction_start {
            return None;
        }
        fraction = &text[fraction_start..index];
    }

    let mut exponent_negative = false;
    let mut exponent_digits = "0";
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        index += 1;
        if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
            exponent_negative = bytes[index] == b'-';
            index += 1;
        }
        let exponent_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == exponent_start {
            return None;
        }
        exponent_digits = &text[exponent_start..index];
    }
    if index != bytes.len() {
        return None;
    }

    let exponent_digits = exponent_digits.trim_start_matches('0');
    let (exponent_negative, exponent_digits) = if exponent_digits.is_empty() {
        (false, "0")
    } else {
        (exponent_negative, exponent_digits)
    };

    Some(NumberParts {
        negative,
        integer_digits,
        fraction,
        exponent: SignedDecimal {
            negative: exponent_negative,
            digits: exponent_digits,
        },
    })
}

fn compare_decimal(negative: bool, digits: &str, value: i128) -> Ordering {
    let (negative, digits) = if digits == "0" {
        (false, "0")
    } else {
        (negative, digits)
    };
    if value >= 0 {
        if negative {
            Ordering::Less
        } else {
            compare_magnitude(digits, &value.to_string())
        }
    } else if !negative {
        Ordering::Greater
    } else {
        compare_magnitude(digits, &value.unsigned_abs().to_string()).reverse()
    }
}

fn compare_magnitude(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn time_string(text: &str, raw_ref: &str) -> FieldFact {
    if ValidatedJsonNumberText::new(text.to_owned()).is_ok() {
        return invalid("time", raw_ref, "unit_unproven", None);
    }
    match parse_rfc3339(text) {
        Ok((epoch_seconds, fraction)) => FieldFact {
            field: "time".to_owned(),
            status: FactStatus::Present,
            value: Some(FactValue::String(format_epoch(
                epoch_seconds,
                fraction.as_deref(),
            ))),
            value_kind: None,
            raw_ref: Some(raw_ref.to_owned()),
            presence_ref: None,
            reason: None,
            refs: None,
            unit: Some(FactUnit::Epoch),
        },
        Err(TimeError::UnitUnproven) => invalid("time", raw_ref, "unit_unproven", None),
        Err(TimeError::Format) => invalid("time", raw_ref, "unproven_format", None),
    }
}

enum TimeError {
    Format,
    UnitUnproven,
}

/// Parse one RFC3339 text with an explicit zone. Returns exact UTC whole
/// seconds and the original fractional digits.
fn parse_rfc3339(text: &str) -> Result<(i64, Option<String>), TimeError> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return Err(TimeError::Format);
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
        return Err(TimeError::Format);
    }
    if bytes[10] != b'T' && bytes[10] != b't' {
        return Err(TimeError::Format);
    }

    let year = fixed_digits(text, 0, 4)?;
    let month = fixed_digits(text, 5, 2)?;
    let day = fixed_digits(text, 8, 2)?;
    let hour = fixed_digits(text, 11, 2)?;
    let minute = fixed_digits(text, 14, 2)?;
    let second = fixed_digits(text, 17, 2)?;

    let mut index = 19;
    let fraction = if index < bytes.len() && bytes[index] == b'.' {
        let start = index + 1;
        index = start;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start {
            return Err(TimeError::Format);
        }
        Some(text[start..index].to_owned())
    } else {
        None
    };

    let (offset_seconds, unknown_zone) =
        if index < bytes.len() && (bytes[index] == b'Z' || bytes[index] == b'z') {
            if index + 1 != bytes.len() {
                return Err(TimeError::Format);
            }
            (0_i64, false)
        } else if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
            if index + 6 != bytes.len() || bytes[index + 3] != b':' {
                return Err(TimeError::Format);
            }
            let offset_hour = fixed_digits(text, index + 1, 2)?;
            let offset_minute = fixed_digits(text, index + 4, 2)?;
            if offset_hour > 23 || offset_minute > 59 {
                return Err(TimeError::Format);
            }
            let negative = bytes[index] == b'-';
            let unknown = negative && offset_hour == 0 && offset_minute == 0;
            let seconds = i64::from(offset_hour) * 3600 + i64::from(offset_minute) * 60;
            (if negative { -seconds } else { seconds }, unknown)
        } else {
            return Err(TimeError::Format);
        };
    if unknown_zone {
        return Err(TimeError::UnitUnproven);
    }

    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(TimeError::Format);
    }

    let days = days_from_civil(i64::from(year), i64::from(month), i64::from(day));
    let epoch_seconds =
        days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second)
            - offset_seconds;
    Ok((epoch_seconds, fraction))
}

fn fixed_digits(text: &str, start: usize, width: usize) -> Result<u32, TimeError> {
    let bytes = text.as_bytes();
    if start + width > bytes.len() {
        return Err(TimeError::Format);
    }
    let mut value = 0_u32;
    for byte in &bytes[start..start + width] {
        if !byte.is_ascii_digit() {
            return Err(TimeError::Format);
        }
        value = value * 10 + u32::from(*byte - b'0');
    }
    Ok(value)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Days from 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = if shifted_year >= 0 {
        shifted_year
    } else {
        shifted_year - 399
    } / 400;
    let year_of_era = shifted_year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn format_epoch(epoch_seconds: i64, fraction: Option<&str>) -> String {
    let Some(fraction) = fraction else {
        return epoch_seconds.to_string();
    };
    if epoch_seconds >= 0 || fraction.bytes().all(|byte| byte == b'0') {
        return format!("{epoch_seconds}.{fraction}");
    }
    let whole = -epoch_seconds - 1;
    let complement = complement_decimal(fraction);
    format!("-{whole}.{complement}")
}

/// `10^N - fraction` as exactly N digits, without a big integer.
fn complement_decimal(fraction: &str) -> String {
    let mut digits: Vec<u8> = fraction.bytes().map(|byte| b'9' - (byte - b'0')).collect();
    let mut carry = true;
    for digit in digits.iter_mut().rev() {
        if !carry {
            break;
        }
        if *digit == b'9' {
            *digit = b'0';
        } else {
            *digit += 1;
            carry = false;
        }
    }
    String::from_utf8(digits).expect("decimal digits are ASCII")
}
