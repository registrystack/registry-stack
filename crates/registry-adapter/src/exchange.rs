// SPDX-License-Identifier: Apache-2.0

//! The exchange and message model, ported from Camel's `Exchange` and
//! `Message` (`products/adapter/CONCEPT.md` section 8.2).
//!
//! An exchange carries an exchange id, an `InOut` message pattern, one
//! message of headers and body, exchange properties, and an exception
//! slot. Headers are a bounded, case-insensitive map; the body is a
//! size-bounded JSON value once unmarshalled; the `http` component
//! marshals and unmarshals JSON itself instead of Camel's explicit
//! `marshal` and `unmarshal` steps, because the components speak exactly
//! one data format.
//!
//! What enters the exchange is declared: the `rest` consumer places only
//! the bound operation's validated inputs on it, under the closed names
//! of section 8.11.1, and credentials, base URLs, and secrets never
//! enter it, so no expression or header can carry them out.

use std::collections::BTreeMap;

use serde_json::Value;

/// The prefix of the exchange properties the engine owns.
pub const RESERVED_PROPERTY_PREFIX: &str = "Adapter";
/// The facade's filter inputs, as an object of the declared filters the
/// caller sent.
pub const FILTERS_PROPERTY: &str = "AdapterFilters";
/// The continuation the caller's cursor restored; absent on a first page.
pub const CONTINUATION_PROPERTY: &str = "AdapterContinuation";
/// The one reserved property a route sets: the continuation the engine
/// seals as the next cursor. Absent or null is the last page.
pub const NEXT_CONTINUATION_PROPERTY: &str = "AdapterNextContinuation";
/// The page size header the facade sets on a search.
pub const PAGE_SIZE_HEADER: &str = "pageSize";

/// Headers the redelivery loop sets while an upstream send is retried
/// (section 8.7).
pub const REDELIVERED_HEADER: &str = "camelredelivered";
pub const REDELIVERY_COUNTER_HEADER: &str = "camelredeliverycounter";
pub const REDELIVERY_MAX_COUNTER_HEADER: &str = "camelredeliverymaxcounter";

/// One message: lowercased header names and one JSON body.
#[derive(Clone, Debug, Default)]
pub struct Message {
    pub body: Value,
    headers: BTreeMap<String, Value>,
}

impl Message {
    pub fn set_header(&mut self, name: &str, value: Value) {
        self.headers.insert(name.to_ascii_lowercase(), value);
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers.remove(&name.to_ascii_lowercase());
    }

    /// A header by name, compared without case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&Value> {
        self.headers.get(&name.to_ascii_lowercase())
    }

    /// Every header as a name and its string value, the form an outbound
    /// header filter reads; a non-string value is stringified.
    #[must_use]
    pub fn string_headers(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .map(|(name, value)| {
                let text = match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
                (name.clone(), text)
            })
            .collect()
    }
}

/// One exchange: an id, the `InOut` message, and its properties.
#[derive(Clone, Debug)]
pub struct Exchange {
    id: String,
    pub message: Message,
    properties: BTreeMap<String, Value>,
}

impl Exchange {
    #[must_use]
    pub fn new(id: String) -> Self {
        Self {
            id,
            message: Message::default(),
            properties: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn set_property(&mut self, name: &str, value: Value) {
        self.properties.insert(name.to_owned(), value);
    }

    #[must_use]
    pub fn property(&self, name: &str) -> Option<&Value> {
        self.properties.get(name)
    }

    /// The `exchange` argument of a Rhai entrypoint (section 8.11.3):
    /// `#{body, headers, properties}` with lowercased header names and a
    /// null body as `()`.
    #[must_use]
    pub fn as_script_value(&self) -> Value {
        serde_json::json!({
            "body": self.message.body,
            "headers": self.message.headers,
            "properties": self.properties,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn headers_are_case_insensitive() {
        let mut exchange = Exchange::new("x".to_owned());
        exchange.message.set_header("recordId", json!("a"));
        assert_eq!(exchange.message.header("RECORDID"), Some(&json!("a")));
        exchange.message.remove_header("RecordId");
        assert!(exchange.message.header("recordid").is_none());
    }

    #[test]
    fn script_value_lowercases_headers_and_keeps_a_null_body() {
        let mut exchange = Exchange::new("x".to_owned());
        exchange.message.set_header("recordId", json!("a"));
        let value = exchange.as_script_value();
        assert_eq!(value["headers"]["recordid"], json!("a"));
        assert!(value["body"].is_null());
    }
}
