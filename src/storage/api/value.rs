//! Backend-agnostic dynamically-typed value + typed conversion traits for storage::api.

use super::error::StorageError;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

pub trait FromValue: Sized {
    fn from_value(v: Value) -> Result<Self, StorageError>;
}

pub trait IntoValue {
    fn into_value(self) -> Value;
}

fn type_mismatch(expected: &str, got: &Value) -> StorageError {
    StorageError::Other {
        code: None,
        detail: format!("type mismatch: expected {expected}, got {got:?}"),
    }
}

fn out_of_range(target: &str, i: i64) -> StorageError {
    StorageError::Other {
        code: None,
        detail: format!("integer out of range for {target}: {i}"),
    }
}

impl FromValue for i64 {
    fn from_value(v: Value) -> Result<Self, StorageError> {
        match v {
            Value::Integer(i) => Ok(i),
            other => Err(type_mismatch("Integer", &other)),
        }
    }
}

impl FromValue for i32 {
    fn from_value(v: Value) -> Result<Self, StorageError> {
        match v {
            Value::Integer(i) => i32::try_from(i).map_err(|_| out_of_range("i32", i)),
            other => Err(type_mismatch("Integer", &other)),
        }
    }
}

impl FromValue for u32 {
    fn from_value(v: Value) -> Result<Self, StorageError> {
        match v {
            Value::Integer(i) => u32::try_from(i).map_err(|_| out_of_range("u32", i)),
            other => Err(type_mismatch("Integer", &other)),
        }
    }
}

impl FromValue for usize {
    fn from_value(v: Value) -> Result<Self, StorageError> {
        match v {
            Value::Integer(i) => usize::try_from(i).map_err(|_| out_of_range("usize", i)),
            other => Err(type_mismatch("Integer", &other)),
        }
    }
}

impl FromValue for f64 {
    fn from_value(v: Value) -> Result<Self, StorageError> {
        match v {
            Value::Real(f) => Ok(f),
            other => Err(type_mismatch("Real", &other)),
        }
    }
}

impl FromValue for String {
    fn from_value(v: Value) -> Result<Self, StorageError> {
        match v {
            Value::Text(s) => Ok(s),
            other => Err(type_mismatch("Text", &other)),
        }
    }
}

impl FromValue for Vec<u8> {
    fn from_value(v: Value) -> Result<Self, StorageError> {
        match v {
            Value::Blob(b) => Ok(b),
            other => Err(type_mismatch("Blob", &other)),
        }
    }
}

impl FromValue for bool {
    fn from_value(v: Value) -> Result<Self, StorageError> {
        match v {
            Value::Integer(0) => Ok(false),
            Value::Integer(1) => Ok(true),
            other @ Value::Integer(_) => Err(StorageError::Other {
                code: None,
                detail: format!("invalid bool encoding: {other:?}"),
            }),
            other => Err(type_mismatch("Integer(0|1)", &other)),
        }
    }
}

impl<T: FromValue> FromValue for Option<T> {
    fn from_value(v: Value) -> Result<Self, StorageError> {
        match v {
            Value::Null => Ok(None),
            other => Ok(Some(T::from_value(other)?)),
        }
    }
}

impl IntoValue for i64 {
    fn into_value(self) -> Value {
        Value::Integer(self)
    }
}

impl IntoValue for i32 {
    fn into_value(self) -> Value {
        Value::Integer(self as i64)
    }
}

impl IntoValue for u32 {
    fn into_value(self) -> Value {
        Value::Integer(self as i64)
    }
}

impl IntoValue for usize {
    fn into_value(self) -> Value {
        Value::Integer(self as i64)
    }
}

impl IntoValue for f64 {
    fn into_value(self) -> Value {
        Value::Real(self)
    }
}

impl IntoValue for String {
    fn into_value(self) -> Value {
        Value::Text(self)
    }
}

impl IntoValue for Vec<u8> {
    fn into_value(self) -> Value {
        Value::Blob(self)
    }
}

impl IntoValue for bool {
    fn into_value(self) -> Value {
        Value::Integer(if self { 1 } else { 0 })
    }
}

impl<T: IntoValue> IntoValue for Option<T> {
    fn into_value(self) -> Value {
        match self {
            Some(v) => v.into_value(),
            None => Value::Null,
        }
    }
}

impl IntoValue for &str {
    fn into_value(self) -> Value {
        Value::Text(self.to_string())
    }
}

impl IntoValue for &String {
    fn into_value(self) -> Value {
        Value::Text(self.clone())
    }
}

impl IntoValue for &[u8] {
    fn into_value(self) -> Value {
        Value::Blob(self.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::super::error::StorageError;
    use super::*;

    #[test]
    fn value_roundtrip_typed() {
        assert_eq!(i64::from_value(Value::Integer(7)).unwrap(), 7);
        assert_eq!(Option::<String>::from_value(Value::Null).unwrap(), None);
        assert!(matches!(
            i64::from_value(Value::Text("x".into())),
            Err(StorageError::Other { .. })
        ));
    }

    #[test]
    fn from_value_i32_u32_usize() {
        assert_eq!(i32::from_value(Value::Integer(-5)).unwrap(), -5);
        assert!(i32::from_value(Value::Integer(i64::MAX)).is_err());
        assert_eq!(u32::from_value(Value::Integer(5)).unwrap(), 5);
        assert!(u32::from_value(Value::Integer(-1)).is_err());
        assert_eq!(usize::from_value(Value::Integer(5)).unwrap(), 5);
        assert!(usize::from_value(Value::Integer(-1)).is_err());
    }

    #[test]
    fn from_value_f64() {
        assert_eq!(f64::from_value(Value::Real(1.5)).unwrap(), 1.5);
        assert!(f64::from_value(Value::Integer(1)).is_err());
    }

    #[test]
    fn from_value_string_and_blob() {
        assert_eq!(String::from_value(Value::Text("hi".into())).unwrap(), "hi");
        assert!(String::from_value(Value::Integer(1)).is_err());
        assert_eq!(Vec::<u8>::from_value(Value::Blob(vec![1, 2, 3])).unwrap(), vec![1, 2, 3]);
        assert!(Vec::<u8>::from_value(Value::Null).is_err());
    }

    #[test]
    fn from_value_bool() {
        assert!(!bool::from_value(Value::Integer(0)).unwrap());
        assert!(bool::from_value(Value::Integer(1)).unwrap());
        assert!(bool::from_value(Value::Integer(2)).is_err());
        assert!(bool::from_value(Value::Null).is_err());
    }

    #[test]
    fn from_value_option_some() {
        assert_eq!(Option::<i64>::from_value(Value::Integer(9)).unwrap(), Some(9));
        assert!(Option::<i64>::from_value(Value::Text("x".into())).is_err());
    }

    #[test]
    fn into_value_numeric_and_text() {
        assert_eq!(7_i64.into_value(), Value::Integer(7));
        assert_eq!((-3_i32).into_value(), Value::Integer(-3));
        assert_eq!(3_u32.into_value(), Value::Integer(3));
        assert_eq!(3_usize.into_value(), Value::Integer(3));
        assert_eq!(1.5_f64.into_value(), Value::Real(1.5));
        assert_eq!("hi".to_string().into_value(), Value::Text("hi".into()));
        assert_eq!(vec![1_u8, 2].into_value(), Value::Blob(vec![1, 2]));
        assert_eq!(true.into_value(), Value::Integer(1));
        assert_eq!(false.into_value(), Value::Integer(0));
    }

    #[test]
    fn into_value_option_and_borrowed() {
        assert_eq!(Some(5_i64).into_value(), Value::Integer(5));
        assert_eq!(Option::<i64>::None.into_value(), Value::Null);
        let s = "borrowed".to_string();
        assert_eq!((&s).into_value(), Value::Text("borrowed".into()));
        assert_eq!("literal".into_value(), Value::Text("literal".into()));
        let b: Vec<u8> = vec![9, 8, 7];
        assert_eq!(b.as_slice().into_value(), Value::Blob(vec![9, 8, 7]));
    }
}
