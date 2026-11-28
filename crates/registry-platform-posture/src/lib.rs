//! The declared posture of a process, `development` or `production`, and the
//! rules for reading it from the `--posture` flag and `REGISTRY_STACK_POSTURE`.
//!
//! The crate depends on nothing outside `std`, so any platform crate can name
//! the type. Reading the declaration performs no file access and never echoes
//! the value it was given.

use std::ffi::OsStr;
use std::fmt;

/// The environment variable that declares the posture of a process.
pub const POSTURE_ENV: &str = "REGISTRY_STACK_POSTURE";
/// The long name of the command-line flag that declares the posture.
pub const POSTURE_FLAG: &str = "posture";
/// The HTTP field name that marks a response with its posture.
pub const POSTURE_HEADER: &str = "registry-posture";
/// The accepted spelling of [`Posture::Development`].
pub const DEVELOPMENT: &str = "development";
/// The accepted spelling of [`Posture::Production`].
pub const PRODUCTION: &str = "production";

/// A posture a process declares for itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Posture {
    Development,
    Production,
}

impl Posture {
    /// The accepted spelling of this posture.
    pub const fn as_str(self) -> &'static str {
        match self {
            Posture::Development => DEVELOPMENT,
            Posture::Production => PRODUCTION,
        }
    }

    /// Parses an exact, case-sensitive spelling. No trimming.
    pub fn parse(value: &str) -> Option<Posture> {
        match value {
            DEVELOPMENT => Some(Posture::Development),
            PRODUCTION => Some(Posture::Production),
            _ => None,
        }
    }
}

/// Where a declared posture came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostureSource {
    Flag,
    Environment,
    Default,
}

/// A posture together with the source that declared it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclaredPosture {
    pub posture: Posture,
    pub source: PostureSource,
}

/// A refusal made before any file is read. Messages never contain the value given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostureError {
    /// The variable is set to an empty, non-UTF-8 or unknown value.
    InvalidEnvironment,
    /// The flag was given an unknown value.
    InvalidFlag,
    /// Two declarations disagree.
    Conflict,
}

impl PostureError {
    /// The stable diagnostic code.
    pub const fn code(self) -> &'static str {
        match self {
            PostureError::InvalidEnvironment | PostureError::InvalidFlag => {
                "platform.posture.invalid-value"
            }
            PostureError::Conflict => "platform.posture.conflict",
        }
    }

    /// A value-free description of the refusal.
    pub const fn message(self) -> &'static str {
        match self {
            PostureError::InvalidEnvironment => {
                "REGISTRY_STACK_POSTURE is set to a value that is not a posture"
            }
            PostureError::InvalidFlag => "--posture was given a value that is not a posture",
            PostureError::Conflict => {
                "--posture and REGISTRY_STACK_POSTURE declare different postures"
            }
        }
    }

    /// What the operator can do about it.
    pub const fn suggested_action(self) -> &'static str {
        match self {
            PostureError::InvalidEnvironment => {
                "Set it to development or production, or unset it for production."
            }
            PostureError::InvalidFlag => "Pass --posture development or --posture production.",
            PostureError::Conflict => "Declare the posture once, or give both the same value.",
        }
    }
}

impl fmt::Display for PostureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for PostureError {}

/// Decides the posture from the two inputs. Pure.
///
/// A set variable is validated even when the flag is also present. When both
/// are invalid the variable is reported first. Neither input present gives
/// production with source [`PostureSource::Default`]. Both present and equal
/// gives source [`PostureSource::Flag`].
pub fn declared_from(
    flag: Option<&str>,
    environment: Option<&OsStr>,
) -> Result<DeclaredPosture, PostureError> {
    let from_environment = match environment {
        None => None,
        Some(value) => Some(
            value
                .to_str()
                .and_then(Posture::parse)
                .ok_or(PostureError::InvalidEnvironment)?,
        ),
    };
    let from_flag = match flag {
        None => None,
        Some(value) => Some(Posture::parse(value).ok_or(PostureError::InvalidFlag)?),
    };
    match (from_flag, from_environment) {
        (Some(flag), Some(environment)) if flag != environment => Err(PostureError::Conflict),
        (Some(posture), _) => Ok(DeclaredPosture {
            posture,
            source: PostureSource::Flag,
        }),
        (None, Some(posture)) => Ok(DeclaredPosture {
            posture,
            source: PostureSource::Environment,
        }),
        (None, None) => Ok(DeclaredPosture {
            posture: Posture::Production,
            source: PostureSource::Default,
        }),
    }
}

/// Reads [`POSTURE_ENV`] once and calls [`declared_from`]. Call it only from `main`
/// or a command dispatcher, so the process-global variable is read in one place.
pub fn declared(flag: Option<&str>) -> Result<DeclaredPosture, PostureError> {
    declared_from(flag, std::env::var_os(POSTURE_ENV).as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(value: &str) -> Option<&OsStr> {
        Some(OsStr::new(value))
    }

    fn ok(posture: Posture, source: PostureSource) -> Result<DeclaredPosture, PostureError> {
        Ok(DeclaredPosture { posture, source })
    }

    #[test]
    fn flag_only() {
        assert_eq!(
            declared_from(Some("development"), None),
            ok(Posture::Development, PostureSource::Flag)
        );
        assert_eq!(
            declared_from(Some("production"), None),
            ok(Posture::Production, PostureSource::Flag)
        );
    }

    #[test]
    fn variable_only() {
        assert_eq!(
            declared_from(None, env("development")),
            ok(Posture::Development, PostureSource::Environment)
        );
        assert_eq!(
            declared_from(None, env("production")),
            ok(Posture::Production, PostureSource::Environment)
        );
    }

    #[test]
    fn both_equal_report_the_flag() {
        assert_eq!(
            declared_from(Some("development"), env("development")),
            ok(Posture::Development, PostureSource::Flag)
        );
        assert_eq!(
            declared_from(Some("production"), env("production")),
            ok(Posture::Production, PostureSource::Flag)
        );
    }

    #[test]
    fn both_different_conflict() {
        assert_eq!(
            declared_from(Some("development"), env("production")),
            Err(PostureError::Conflict)
        );
        assert_eq!(
            declared_from(Some("production"), env("development")),
            Err(PostureError::Conflict)
        );
    }

    #[test]
    fn neither_is_production_by_default() {
        assert_eq!(
            declared_from(None, None),
            ok(Posture::Production, PostureSource::Default)
        );
    }

    #[test]
    fn empty_variable_is_refused() {
        assert_eq!(
            declared_from(None, env("")),
            Err(PostureError::InvalidEnvironment)
        );
    }

    #[test]
    fn variable_is_exact_and_case_sensitive() {
        for value in [
            "Development",
            "PRODUCTION",
            " production",
            "production ",
            "dev",
            "prod",
        ] {
            assert_eq!(
                declared_from(None, env(value)),
                Err(PostureError::InvalidEnvironment),
                "{value:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_variable_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let value = OsStr::from_bytes(b"production\xff");
        assert_eq!(
            declared_from(None, Some(value)),
            Err(PostureError::InvalidEnvironment)
        );
    }

    #[test]
    fn bad_flag_is_refused() {
        for value in ["", "Development", " production", "staging"] {
            assert_eq!(
                declared_from(Some(value), None),
                Err(PostureError::InvalidFlag),
                "{value:?}"
            );
        }
    }

    #[test]
    fn bad_flag_is_refused_beside_a_valid_variable() {
        assert_eq!(
            declared_from(Some("staging"), env("production")),
            Err(PostureError::InvalidFlag)
        );
    }

    #[test]
    fn bad_variable_is_refused_beside_a_valid_flag() {
        assert_eq!(
            declared_from(Some("production"), env("staging")),
            Err(PostureError::InvalidEnvironment)
        );
    }

    #[test]
    fn bad_variable_is_reported_before_a_bad_flag() {
        assert_eq!(
            declared_from(Some("staging"), env("staging")),
            Err(PostureError::InvalidEnvironment)
        );
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            PostureError::InvalidEnvironment.code(),
            "platform.posture.invalid-value"
        );
        assert_eq!(
            PostureError::InvalidFlag.code(),
            "platform.posture.invalid-value"
        );
        assert_eq!(PostureError::Conflict.code(), "platform.posture.conflict");
    }

    #[test]
    fn error_text_is_value_free_and_displayed() {
        for error in [
            PostureError::InvalidEnvironment,
            PostureError::InvalidFlag,
            PostureError::Conflict,
        ] {
            assert_eq!(error.to_string(), error.message());
            assert!(!error.suggested_action().is_empty());
        }
        assert_eq!(
            PostureError::InvalidEnvironment.message(),
            "REGISTRY_STACK_POSTURE is set to a value that is not a posture"
        );
        assert_eq!(
            PostureError::InvalidFlag.message(),
            "--posture was given a value that is not a posture"
        );
        assert_eq!(
            PostureError::Conflict.message(),
            "--posture and REGISTRY_STACK_POSTURE declare different postures"
        );
    }

    #[test]
    fn posture_spellings_round_trip() {
        for posture in [Posture::Development, Posture::Production] {
            assert_eq!(Posture::parse(posture.as_str()), Some(posture));
        }
        assert_eq!(POSTURE_ENV, "REGISTRY_STACK_POSTURE");
        assert_eq!(POSTURE_FLAG, "posture");
        assert_eq!(POSTURE_HEADER, "registry-posture");
    }
}
