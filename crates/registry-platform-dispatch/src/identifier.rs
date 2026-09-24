// SPDX-License-Identifier: Apache-2.0

//! The only SQL identifier shape the core interpolates.

/// Whether `value` is a plain lowercase SQL identifier of at most `maximum`
/// bytes: a lowercase ASCII letter or underscore, then lowercase ASCII
/// letters, digits, or underscores.
///
/// Such a name needs no quoting and cannot close a statement, open a comment,
/// or change case under PostgreSQL folding, so the core interpolates only
/// names that pass this check.
#[must_use]
pub fn is_plain_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_lowercase_identifiers_pass() {
        for accepted in ["jobs", "_jobs", "message_jobs_2", "a"] {
            assert!(is_plain_identifier(accepted, 63), "{accepted}");
        }
        for refused in [
            "",
            "Jobs",
            "2jobs",
            "jobs;drop",
            "jobs table",
            "\"jobs\"",
            "jobs--",
            "schema.jobs",
            "jöbs",
        ] {
            assert!(!is_plain_identifier(refused, 63), "{refused}");
        }
        assert!(is_plain_identifier(&"a".repeat(63), 63));
        assert!(!is_plain_identifier(&"a".repeat(64), 63));
    }
}
