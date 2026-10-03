// SPDX-License-Identifier: Apache-2.0
//! Operator lifecycle for the import authorities that bound `import` runs.
//!
//! The command opens only the configured migration connection, verifies the
//! active package binding from the runtime configuration, and delegates every
//! database change to `registry_breg::import_authority`. The operator
//! reference and reason reach the database only as keyed hashes, and no
//! refusal repeats them.

use std::path::Path;
use std::time::Duration;

use registry_breg::import_authority::{
    ImportAuthority, ImportAuthorityCloseRequest, ImportAuthorityError, ImportAuthorityOpenRequest,
    ImportAuthorityOperatorService, MAX_IMPORT_AUTHORITY_WINDOW,
};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ImportAuthorityCliError {
    RuntimeConfigPath,
    ExpiresIn,
    AuthorityId,
    Authority(ImportAuthorityError),
}

pub(crate) struct OpenArguments<'a> {
    pub runtime_config: &'a Path,
    pub entity: &'a str,
    pub profile: &'a str,
    pub max_items: i64,
    pub expires_in: &'a str,
    pub input_sha256: &'a [String],
    pub operator_reference: &'a str,
    pub reason: &'a str,
}

pub(crate) struct CloseArguments<'a> {
    pub runtime_config: &'a Path,
    pub authority_id: &'a str,
    pub operator_reference: &'a str,
    pub reason: &'a str,
}

pub(crate) fn open(
    arguments: &OpenArguments<'_>,
) -> Result<ImportAuthority, ImportAuthorityCliError> {
    runtime_config_path(arguments.runtime_config)?;
    let expires_in =
        parse_expires_in(arguments.expires_in).ok_or(ImportAuthorityCliError::ExpiresIn)?;
    let request = ImportAuthorityOpenRequest {
        entity_id: arguments.entity,
        profile_id: arguments.profile,
        max_items: arguments.max_items,
        expires_in,
        input_digests: arguments.input_sha256,
        operator_reference: arguments.operator_reference,
        reason: arguments.reason,
    };
    request
        .validate()
        .map_err(ImportAuthorityCliError::Authority)?;
    block_on(async {
        service(arguments.runtime_config)
            .await?
            .open(request)
            .await
            .map_err(ImportAuthorityCliError::Authority)
    })
}

pub(crate) fn close(
    arguments: &CloseArguments<'_>,
) -> Result<ImportAuthority, ImportAuthorityCliError> {
    runtime_config_path(arguments.runtime_config)?;
    let authority_id = Uuid::parse_str(arguments.authority_id)
        .map_err(|_| ImportAuthorityCliError::AuthorityId)?;
    let request = ImportAuthorityCloseRequest {
        authority_id,
        operator_reference: arguments.operator_reference,
        reason: arguments.reason,
    };
    request
        .validate()
        .map_err(ImportAuthorityCliError::Authority)?;
    block_on(async {
        service(arguments.runtime_config)
            .await?
            .close(request)
            .await
            .map_err(ImportAuthorityCliError::Authority)
    })
}

pub(crate) fn close_expired(
    runtime_config: &Path,
) -> Result<Vec<ImportAuthority>, ImportAuthorityCliError> {
    runtime_config_path(runtime_config)?;
    block_on(async {
        service(runtime_config)
            .await?
            .close_expired()
            .await
            .map_err(ImportAuthorityCliError::Authority)
    })
}

pub(crate) fn list(runtime_config: &Path) -> Result<Vec<ImportAuthority>, ImportAuthorityCliError> {
    runtime_config_path(runtime_config)?;
    block_on(async {
        service(runtime_config)
            .await?
            .list()
            .await
            .map_err(ImportAuthorityCliError::Authority)
    })
}

fn runtime_config_path(path: &Path) -> Result<(), ImportAuthorityCliError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(ImportAuthorityCliError::RuntimeConfigPath)
    }
}

async fn service(
    runtime_config: &Path,
) -> Result<ImportAuthorityOperatorService, ImportAuthorityCliError> {
    ImportAuthorityOperatorService::from_runtime_config(runtime_config)
        .await
        .map_err(ImportAuthorityCliError::Authority)
}

fn block_on<T>(
    future: impl std::future::Future<Output = Result<T, ImportAuthorityCliError>>,
) -> Result<T, ImportAuthorityCliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ImportAuthorityCliError::Authority(ImportAuthorityError::Unavailable))?
        .block_on(future)
}

/// Parse an authority window written as a whole number of minutes, hours,
/// or days (`90m`, `12h`, `7d`), between one minute and the 30-day maximum.
pub(crate) fn parse_expires_in(text: &str) -> Option<Duration> {
    let unit = match text.as_bytes().last()? {
        b'm' => 60,
        b'h' => 60 * 60,
        b'd' => 24 * 60 * 60,
        _ => return None,
    };
    let count = &text[..text.len() - 1];
    if count.is_empty() || count.len() > 6 || !count.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let seconds = count.parse::<u64>().ok()?.checked_mul(unit)?;
    let window = Duration::from_secs(seconds);
    (seconds > 0 && window <= MAX_IMPORT_AUTHORITY_WINDOW).then_some(window)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_accepts_minutes_hours_and_days_within_the_window() {
        assert_eq!(parse_expires_in("1m"), Some(Duration::from_secs(60)));
        assert_eq!(
            parse_expires_in("12h"),
            Some(Duration::from_secs(12 * 3600))
        );
        assert_eq!(
            parse_expires_in("7d"),
            Some(Duration::from_secs(7 * 86_400))
        );
        assert_eq!(parse_expires_in("30d"), Some(MAX_IMPORT_AUTHORITY_WINDOW));
        assert_eq!(
            parse_expires_in("43200m"),
            Some(MAX_IMPORT_AUTHORITY_WINDOW)
        );
    }

    #[test]
    fn expiry_refuses_every_other_shape() {
        for text in [
            "", "d", "0d", "0m", "31d", "721h", "43201m", "7", "7x", "7D", "+7d", "-7d", "1.5d",
            " 7d", "7d ", "9999999d",
        ] {
            assert_eq!(parse_expires_in(text), None, "{text:?}");
        }
    }
}
