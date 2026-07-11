// SPDX-License-Identifier: Apache-2.0
//! JSON Pointer and dotted-path lookup shared by sources and evaluation runtime.

use serde_json::Value;

pub(crate) fn get_json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.starts_with('/') {
        return value.pointer(path);
    }
    let mut current = value;
    for part in path.split('.') {
        if part.is_empty() {
            return None;
        }
        current = match current {
            Value::Array(values) => values.get(part.parse::<usize>().ok()?)?,
            _ => current.get(part)?,
        };
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_pointer_dotted_and_array_paths() {
        let value = json!({
            "message": {
                "records": [{ "id": "person-1" }]
            }
        });

        assert_eq!(
            get_json_path(&value, "/message/records/0/id"),
            Some(&json!("person-1"))
        );
        assert_eq!(
            get_json_path(&value, "message.records.0.id"),
            Some(&json!("person-1"))
        );
        assert_eq!(get_json_path(&value, "message..records"), None);
    }
}
