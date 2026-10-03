// SPDX-License-Identifier: Apache-2.0

pub fn default_api_name(id: &str) -> String {
    let mut result = String::new();
    let mut upper_next = false;
    for byte in id.bytes() {
        match byte {
            b'-' | b'_' => upper_next = true,
            byte if upper_next => {
                result.push(char::from(byte).to_ascii_uppercase());
                upper_next = false;
            }
            byte => result.push(char::from(byte)),
        }
    }
    result
}

pub fn default_sql_name(id: &str) -> String {
    id.replace('-', "_")
}

/// The installed PostgreSQL spelling of an authored logical identifier.
///
/// Authored identifiers may contain 64 ASCII bytes while PostgreSQL stores at
/// most 63 bytes. Canonicalizing before compilation keeps the compiled model,
/// generated DDL, and exact catalog inventory aligned instead of relying on
/// PostgreSQL to truncate identifiers implicitly.
pub fn canonical_sql_name(id: &str) -> String {
    let mut name = default_sql_name(id);
    if name.len() > 63 {
        let mut boundary = 63;
        while !name.is_char_boundary(boundary) {
            boundary -= 1;
        }
        name.truncate(boundary);
    }
    name
}

pub(crate) fn valid_api_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

pub fn reserved_logical_name(value: &str) -> bool {
    matches!(
        value,
        "id" | "record_id"
            | "recordId"
            | "revision"
            | "created_at"
            | "createdAt"
            | "updated_at"
            | "updatedAt"
            | "deleted_at"
            | "deletedAt"
    )
}
