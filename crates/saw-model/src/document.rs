//! Any JSON document, held with its keys in their written order.

use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};
use serde_json::Number;

use crate::ordered::Ordered;

/// One JSON value. An object keeps its keys in the order they were written.
#[derive(Debug, Clone, PartialEq)]
pub enum Document {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Document>),
    Object(Ordered<Document>),
}

impl Serialize for Document {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Document::Null => serializer.serialize_unit(),
            Document::Bool(value) => serializer.serialize_bool(*value),
            Document::Number(value) => value.serialize(serializer),
            Document::String(value) => serializer.serialize_str(value),
            Document::Array(values) => serializer.collect_seq(values),
            Document::Object(entries) => entries.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AnyValue;
        impl<'de> Visitor<'de> for AnyValue {
            type Value = Document;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON value")
            }
            fn visit_unit<E>(self) -> Result<Document, E> {
                Ok(Document::Null)
            }
            fn visit_bool<E>(self, value: bool) -> Result<Document, E> {
                Ok(Document::Bool(value))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Document, E> {
                Ok(Document::Number(value.into()))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Document, E> {
                Ok(Document::Number(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Document, E> {
                Number::from_f64(value).map(Document::Number).ok_or_else(|| E::custom("a number JSON cannot hold"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Document, E> {
                Ok(Document::String(value.to_string()))
            }
            fn visit_string<E>(self, value: String) -> Result<Document, E> {
                Ok(Document::String(value))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Document, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Document::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Document, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
                }
                Ok(Document::Object(Ordered(entries)))
            }
        }
        deserializer.deserialize_any(AnyValue)
    }
}
