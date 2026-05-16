// SPDX-License-Identifier: Apache-2.0
//! Read a config file from disk, parse it, and run cross-field
//! validation.
//!
//! The loader deliberately scrubs the surfaced [`crate::error::Error`]
//! detail: response and audit detail strings never carry the source
//! path. The operational `tracing::error!` line includes the path so
//! operators can locate the offending file in their logs.

use std::fs;
use std::path::Path;

use crate::error::{ConfigError, Error};

use super::validate;
use super::Config;

/// Load and validate the YAML configuration at `path`.
///
/// # Errors
///
/// - [`ConfigError::ParseError`] on filesystem read failure or YAML
///   deserialisation failure. The path and serde error are logged via
///   `tracing` at error level; the returned `Error` is scrubbed.
/// - [`ConfigError::ValidationError`], [`ConfigError::MissingSecret`],
///   [`ConfigError::DuplicateId`] propagated from
///   [`validate::run`] on cross-field validation failures.
pub fn load(path: &Path) -> Result<Config, Error> {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(
                code = "config.parse_error",
                path = %path.display(),
                error = %err,
                "failed to read config file"
            );
            return Err(Error::from(ConfigError::ParseError));
        }
    };

    let config: Config = match serde_yml::from_str(&raw) {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(
                code = "config.parse_error",
                path = %path.display(),
                error = %err,
                "failed to parse config YAML"
            );
            return Err(Error::from(ConfigError::ParseError));
        }
    };

    validate::run(&config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn missing_file_returns_parse_error() {
        let path = Path::new("/no/such/path/registry_relay_unit_test.yaml");
        let err = load(path).expect_err("missing path must fail");
        assert_eq!(err.code(), "config.parse_error");
    }

    #[test]
    fn unparseable_yaml_returns_parse_error() {
        let mut file = NamedTempFile::new().expect("tempfile");
        // Tab indentation under a mapping is not valid YAML and will
        // also fail the document grammar check.
        writeln!(file, ":\n\t- not yaml").unwrap();
        let err = load(file.path()).expect_err("garbled yaml must fail");
        assert_eq!(err.code(), "config.parse_error");
    }
}
