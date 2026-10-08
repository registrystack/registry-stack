//! Serializes a read project or module back to source the reader accepts.

use serde_json::Value;

/// The source bytes of a read project or module. A module and the compiled
/// model keep some absent optional members as null when they serialize,
/// because the module lock digest and the registry revision digest those
/// bytes, while no authored file may hold a null member; the bytes leave each
/// such member out, as the author did.
pub fn source_bytes(source: &impl serde::Serialize) -> Vec<u8> {
    let mut value = serde_json::to_value(source).expect("the source serializes");
    drop_null_members(&mut value);
    serde_json::to_vec(&value).expect("the source encodes")
}

fn drop_null_members(value: &mut Value) {
    match value {
        Value::Object(members) => {
            members.retain(|_, member| !member.is_null());
            members.values_mut().for_each(drop_null_members);
        }
        Value::Array(items) => items.iter_mut().for_each(drop_null_members),
        _ => {}
    }
}
