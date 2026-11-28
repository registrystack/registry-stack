// SPDX-License-Identifier: Apache-2.0
//! Development-only configuration values and the one decision about them.
//!
//! A configuration type that has values only a development process may use
//! implements [`DevelopmentClass`], and the member that holds it is a
//! [`Gated`]. Decoding a `Gated` never fails because of the posture: it records
//! what it found, and [`PostureReport::decide`] is the single place where
//! production refuses and development accepts and lists. A development value
//! is readable only with the [`DevelopmentWitness`] the loader issues to a
//! process that declared development.
//!
//! # A witness cannot be made outside this crate
//!
//! ```compile_fail
//! use registry_platform_config::DevelopmentWitness;
//! let _ = DevelopmentWitness { _sealed: () };
//! ```
//!
//! The compiling twin names the type and nothing else:
//!
//! ```
//! use registry_platform_config::DevelopmentWitness;
//! fn takes(_: Option<&DevelopmentWitness>) {}
//! takes(None);
//! ```
//!
//! ```compile_fail
//! use registry_platform_config::DevelopmentWitness;
//! let _ = DevelopmentWitness::default();
//! ```
//!
//! ```
//! use registry_platform_config::DevelopmentWitness;
//! let _: Option<DevelopmentWitness> = None;
//! ```
//!
//! ```compile_fail
//! use registry_platform_config::DevelopmentWitness;
//! let _ = serde_json::from_str::<DevelopmentWitness>("null");
//! ```
//!
//! ```
//! use registry_platform_config::DevelopmentWitness;
//! let _ = serde_json::from_str::<Option<u8>>("null");
//! let _: Option<DevelopmentWitness> = None;
//! ```
//!
//! # A gated value has no way out but `get`
//!
//! ```compile_fail
//! # use registry_platform_config::{DevelopmentClass, DevelopmentSetting, Gated};
//! # enum Transport { Tls, Plaintext }
//! # static PLAINTEXT: DevelopmentSetting = DevelopmentSetting {
//! #     code: "platform.posture.example", key: "transport", summary: "s", production: "p",
//! # };
//! # impl DevelopmentClass for Transport {
//! #     const SETTINGS: &'static [&'static DevelopmentSetting] = &[&PLAINTEXT];
//! #     fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
//! #         match self { Transport::Tls => None, Transport::Plaintext => Some(&PLAINTEXT) }
//! #     }
//! # }
//! let g = Gated::everywhere(Transport::Tls).unwrap();
//! let _ = g.0;
//! ```
//!
//! ```compile_fail
//! # use registry_platform_config::{DevelopmentClass, DevelopmentSetting, Gated};
//! # enum Transport { Tls, Plaintext }
//! # static PLAINTEXT: DevelopmentSetting = DevelopmentSetting {
//! #     code: "platform.posture.example", key: "transport", summary: "s", production: "p",
//! # };
//! # impl DevelopmentClass for Transport {
//! #     const SETTINGS: &'static [&'static DevelopmentSetting] = &[&PLAINTEXT];
//! #     fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
//! #         match self { Transport::Tls => None, Transport::Plaintext => Some(&PLAINTEXT) }
//! #     }
//! # }
//! let g = Gated::everywhere(Transport::Tls).unwrap();
//! let _ = &*g;
//! ```
//!
//! The compiling twin reads the same value through `get`:
//!
//! ```
//! # use registry_platform_config::{DevelopmentClass, DevelopmentSetting, Gated};
//! # enum Transport { Tls, Plaintext }
//! # static PLAINTEXT: DevelopmentSetting = DevelopmentSetting {
//! #     code: "platform.posture.example", key: "transport", summary: "s", production: "p",
//! # };
//! # impl DevelopmentClass for Transport {
//! #     const SETTINGS: &'static [&'static DevelopmentSetting] = &[&PLAINTEXT];
//! #     fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
//! #         match self { Transport::Tls => None, Transport::Plaintext => Some(&PLAINTEXT) }
//! #     }
//! # }
//! let g = Gated::everywhere(Transport::Tls).unwrap();
//! assert!(matches!(g.get(None), Ok(Transport::Tls)));
//! let _ = Transport::Plaintext;
//! ```

use std::cell::RefCell;
use std::fmt;
use std::marker::PhantomData;
use std::path::Path;

use registry_platform_posture::{DEVELOPMENT, POSTURE_ENV, POSTURE_FLAG};
use registry_platform_yaml::{
    escape_pointer_segment, gated_site, Diagnostic, Position, Severity, Source, DEVELOPMENT_ONLY,
};
use serde::de::{Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};

pub use registry_platform_posture::{DeclaredPosture, Posture, PostureSource};

use crate::RuntimeConfigError;

/// Proof that this process declared development. Only the loader creates it.
#[derive(Clone, Copy, Debug)]
pub struct DevelopmentWitness {
    _sealed: (),
}

impl DevelopmentWitness {
    /// The loader issues the witness to a process that declared development.
    #[allow(dead_code)]
    pub(crate) const fn issue() -> Self {
        Self { _sealed: () }
    }
}

/// One development-only setting, described by the crate that owns it.
#[derive(Debug, PartialEq, Eq)]
pub struct DevelopmentSetting {
    /// `<owner>.posture.<setting>` (CFG-DIAG-3).
    pub code: &'static str,
    /// The authored key that holds the value: the last pointer segment.
    pub key: &'static str,
    /// Value-free: what the setting weakens.
    pub summary: &'static str,
    /// What to write for production.
    pub production: &'static str,
}

/// A configuration type that has development-only values.
pub trait DevelopmentClass {
    /// Every setting a value of this type can select. Docs, schemas and tests
    /// read it.
    const SETTINGS: &'static [&'static DevelopmentSetting];

    /// The setting this value selects, or `None` when it is valid in every
    /// posture. Implement it with an exhaustive `match`, so a new variant
    /// forces a decision.
    fn development_setting(&self) -> Option<&'static DevelopmentSetting>;
}

/// The refusal to read a development-only value without a witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the setting {} is accepted only when the process declares development", .setting.code)]
pub struct DevelopmentOnlyRefused {
    pub setting: &'static DevelopmentSetting,
}

/// A value that may select a development-only setting. Read it with
/// [`Gated::get`].
///
/// There is no `Deref` and no way to take the value out: a value that selects
/// a development-only setting is unreadable without a [`DevelopmentWitness`].
#[derive(Clone, PartialEq)]
pub struct Gated<T>(T);

impl<T: DevelopmentClass> Gated<T> {
    /// The value, when it is valid in every posture or the caller holds the
    /// witness.
    pub fn get(&self, witness: Option<&DevelopmentWitness>) -> Result<&T, DevelopmentOnlyRefused> {
        match (self.0.development_setting(), witness) {
            (Some(setting), None) => Err(DevelopmentOnlyRefused { setting }),
            _ => Ok(&self.0),
        }
    }

    /// The setting the value selects, or `None` when it is valid in every
    /// posture.
    pub fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        self.0.development_setting()
    }

    /// A value that is valid in every posture, for code that writes
    /// configuration.
    pub fn everywhere(value: T) -> Result<Self, DevelopmentOnlyRefused> {
        match value.development_setting() {
            Some(setting) => Err(DevelopmentOnlyRefused { setting }),
            None => Ok(Self(value)),
        }
    }

    /// A value of any kind, for tests that exercise a development path.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(value: T) -> Self {
        Self(value)
    }
}

impl<T: fmt::Debug> fmt::Debug for Gated<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl<T: Serialize> Serialize for Gated<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: DevelopmentClass + Deserialize<'de>> Deserialize<'de> for Gated<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reads<T>(PhantomData<T>);
        impl<'de, T: DevelopmentClass + Deserialize<'de>> Visitor<'de> for Reads<T> {
            type Value = Gated<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a configuration value")
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                inner: D,
            ) -> Result<Gated<T>, D::Error> {
                let site = gated_site();
                let value = T::deserialize(inner)?;
                if let Some(setting) = value.development_setting() {
                    let (pointer, position) = match site {
                        Some(site) if site.exact => (Some(site.pointer), site.position),
                        // A flattened member is one of the holding mapping's own keys.
                        Some(site) => (
                            Some(format!(
                                "{}/{}",
                                site.pointer,
                                escape_pointer_segment(setting.key)
                            )),
                            site.position,
                        ),
                        None => (None, None),
                    };
                    record(FoundSetting {
                        setting,
                        pointer,
                        position,
                        origin: SettingOrigin::RuntimeFile,
                    });
                }
                Ok(Gated(value))
            }
        }
        deserializer.deserialize_newtype_struct(DEVELOPMENT_ONLY, Reads(PhantomData))
    }
}

#[cfg(feature = "schema")]
impl<T: DevelopmentClass + schemars::JsonSchema> schemars::JsonSchema for Gated<T> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        T::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = generator.subschema_for::<T>();
        let codes: Vec<&str> = T::SETTINGS.iter().map(|setting| setting.code).collect();
        schema.insert("x-registry-development-only".to_owned(), codes.into());
        schema
    }
}

/// Where a recorded setting was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingOrigin {
    RuntimeFile,
    Package,
    Combination,
}

/// A development-only setting found in a process's configuration.
#[derive(Clone, Debug)]
pub struct FoundSetting {
    pub setting: &'static DevelopmentSetting,
    pub pointer: Option<String>,
    pub position: Option<Position>,
    pub origin: SettingOrigin,
}

/// A setting valid in every posture that an operator states deliberately and
/// that relaxes something. It never refuses and is never a diagnostic: the
/// startup log and `check` say it is in use, and `/ready`, which answers
/// without credentials, does not list it.
#[derive(Debug, PartialEq, Eq)]
pub struct ExplicitProductionSetting {
    /// `<owner>.posture.<setting>` (CFG-DIAG-3), distinct from every
    /// development code.
    pub code: &'static str,
    /// The authored key, the last pointer segment.
    pub key: &'static str,
    /// Value-free: what it relaxes and why the operator states it.
    pub summary: &'static str,
}

/// An [`ExplicitProductionSetting`] found in a process's configuration.
#[derive(Clone, Debug)]
pub struct FoundExplicitSetting {
    pub setting: &'static ExplicitProductionSetting,
    pub pointer: Option<String>,
    pub position: Option<Position>,
    pub origin: SettingOrigin,
}

/// Run `decode` and return what it returned with every development-only
/// setting a [`Gated`] recorded while it ran. Calls nest: an inner call keeps
/// its own findings and restores the outer collector, also on a panic.
pub fn collect_development_settings<R>(decode: impl FnOnce() -> R) -> (R, Vec<FoundSetting>) {
    let guard = CollectorGuard {
        previous: COLLECTOR.with(|collector| collector.borrow_mut().replace(Vec::new())),
    };
    let result = decode();
    let found = COLLECTOR
        .with(|collector| collector.borrow_mut().take())
        .unwrap_or_default();
    drop(guard);
    (result, found)
}

thread_local! {
    static COLLECTOR: RefCell<Option<Vec<FoundSetting>>> = const { RefCell::new(None) };
}

/// Restores the collector that was installed before this one, also on a panic.
struct CollectorGuard {
    previous: Option<Vec<FoundSetting>>,
}

impl Drop for CollectorGuard {
    fn drop(&mut self) {
        COLLECTOR.with(|collector| *collector.borrow_mut() = self.previous.take());
    }
}

/// Add `found` to the active collector. Outside a collector nothing is
/// recorded, and a development value stays unreadable without a witness.
fn record(found: FoundSetting) {
    COLLECTOR.with(|collector| {
        if let Some(found_so_far) = collector.borrow_mut().as_mut() {
            found_so_far.push(found);
        }
    });
}

/// The posture a process declared and every setting found under it.
#[derive(Clone, Debug)]
pub struct PostureReport {
    declared: DeclaredPosture,
    settings: Vec<FoundSetting>,
    explicit: Vec<FoundExplicitSetting>,
}

impl PostureReport {
    #[must_use]
    pub fn new(declared: DeclaredPosture) -> Self {
        Self {
            declared,
            settings: Vec::new(),
            explicit: Vec::new(),
        }
    }

    pub fn record(&mut self, found: FoundSetting) {
        self.settings.push(found);
    }

    pub fn record_explicit(&mut self, found: FoundExplicitSetting) {
        self.explicit.push(found);
    }

    #[must_use]
    pub fn posture(&self) -> Posture {
        self.declared.posture
    }

    #[must_use]
    pub fn settings(&self) -> &[FoundSetting] {
        &self.settings
    }

    #[must_use]
    pub fn explicit_settings(&self) -> &[FoundExplicitSetting] {
        &self.explicit
    }

    /// The one decision. Production refuses every recorded setting and
    /// development accepts and lists them, under the same codes.
    #[must_use]
    pub fn diagnostics(&self, file: &Path) -> Vec<Diagnostic> {
        let production = self.posture() == Posture::Production;
        self.settings
            .iter()
            .map(|found| {
                let setting = found.setting;
                let pointer = found.pointer.as_deref().unwrap_or("");
                let (message, action) = if production {
                    (
                        format!(
                            "{}; it is accepted only when the process declares development",
                            setting.summary
                        ),
                        format!(
                            "{} For a laptop or test run, start it with `rstack dev`, or declare development with {POSTURE_ENV}={DEVELOPMENT} or --{POSTURE_FLAG} {DEVELOPMENT}.",
                            setting.production
                        ),
                    )
                } else {
                    (
                        format!("{}; production refuses it", setting.summary),
                        setting.production.to_owned(),
                    )
                };
                let mut diagnostic = if production {
                    Diagnostic::error(setting.code, pointer, message, action)
                } else {
                    Diagnostic::warning(setting.code, pointer, message, action)
                };
                diagnostic.source = Some(Source {
                    file: file.display().to_string(),
                    line: found.position.map(|position| position.line),
                    column: found.position.map(|position| position.column),
                });
                diagnostic
            })
            .collect()
    }

    /// `Err` exactly when [`PostureReport::diagnostics`] holds an error.
    pub fn decide(&self, file: &Path) -> Result<(), RuntimeConfigError> {
        let diagnostics = self.diagnostics(file);
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
        {
            return Err(RuntimeConfigError::from_diagnostics(file, diagnostics));
        }
        Ok(())
    }

    /// The members a runtime adds to its `/ready` body: the posture and the
    /// development settings. Explicit production settings are left out, since
    /// `/ready` answers without credentials.
    #[must_use]
    pub fn ready_member(&self) -> Map<String, Value> {
        let listed = |code: &str, pointer: &Option<String>| {
            let mut member = Map::new();
            member.insert("code".to_owned(), Value::from(code));
            if let Some(pointer) = pointer {
                member.insert("pointer".to_owned(), Value::from(pointer.as_str()));
            }
            Value::Object(member)
        };
        let mut members = Map::new();
        members.insert("posture".to_owned(), Value::from(self.posture().as_str()));
        members.insert(
            "developmentSettings".to_owned(),
            self.settings
                .iter()
                .map(|found| listed(found.setting.code, &found.pointer))
                .collect(),
        );
        members
    }

    /// Log the declared posture and what is in use.
    pub fn log_startup(&self) {
        let source = match self.declared.source {
            PostureSource::Flag => "flag",
            PostureSource::Environment => "environment",
            PostureSource::Default => "default",
        };
        tracing::info!(
            posture = self.posture().as_str(),
            posture_source = source,
            development_settings = self.settings.len(),
            explicit_production_settings = self.explicit.len(),
            "posture declared"
        );
        if self.posture() == Posture::Development {
            for found in &self.settings {
                tracing::warn!(
                    error_code = found.setting.code,
                    pointer = found.pointer.as_deref().unwrap_or(""),
                    "development-only setting in use; production refuses it"
                );
            }
        }
        for found in &self.explicit {
            tracing::info!(
                setting_code = found.setting.code,
                pointer = found.pointer.as_deref().unwrap_or(""),
                "explicit production setting in use"
            );
        }
    }
}

/// Whether `code` is a posture code: `<owner>.posture.<setting>`.
pub(crate) fn is_posture_code(code: &str) -> bool {
    code.split('.').nth(1) == Some("posture")
}

#[cfg(test)]
#[path = "posture_tests.rs"]
mod tests;
