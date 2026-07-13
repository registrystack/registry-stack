// SPDX-License-Identifier: Apache-2.0
//! Zeroizing ownership for sensitive parsed JSON values.

use std::mem;

use serde_json::Value;
use zeroize::Zeroize;

pub(super) struct SensitiveJsonValue(Value);

impl SensitiveJsonValue {
    pub(super) const fn new(value: Value) -> Self {
        Self(value)
    }

    pub(super) const fn value(&self) -> &Value {
        &self.0
    }

    pub(super) const fn value_mut(&mut self) -> &mut Value {
        &mut self.0
    }

    pub(super) fn into_value(mut self) -> Value {
        mem::take(&mut self.0)
    }
}

impl Drop for SensitiveJsonValue {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

pub(super) fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(array) => array.iter_mut().for_each(zeroize_json_value),
        Value::Object(object) => {
            let retained = mem::take(object);
            for (mut name, mut member) in retained {
                name.zeroize();
                zeroize_json_value(&mut member);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
