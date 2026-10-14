//! Serializes a read project or module back to source the reader accepts.

use serde_json::Value;

/// The source bytes of a read project or module. A module and the compiled
/// model keep some absent optional members as null when they serialize,
/// because module locks and registry revisions digest those bytes. Authored
/// source omits absent optional members. Explicit Action literal values and
/// JSON Schema const/default values retain null when written.
pub fn source_bytes(source: &impl serde::Serialize) -> Vec<u8> {
    let mut value = serde_json::to_value(source).expect("the source serializes");
    drop_null_members(&mut value);
    serde_json::to_vec(&value).expect("the source encodes")
}

fn drop_null_members(value: &mut Value) {
    match value {
        Value::Object(members) => {
            members.retain(|key, member| {
                !member.is_null() || matches!(key.as_str(), "value" | "const" | "default")
            });
            members.values_mut().for_each(drop_null_members);
        }
        Value::Array(items) => items.iter_mut().for_each(drop_null_members),
        _ => {}
    }
}
