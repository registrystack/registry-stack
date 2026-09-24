//! Bounded, strict loading of an operator runtime configuration document.
//!
//! Every Registry Stack runtime reads its `runtime.yaml` through
//! [`RuntimeConfigLoader`], so the same file rules, the same YAML reader and the
//! same environment substitution apply everywhere:
//!
//! 1. the path is absolute and lexically normal, and no component of it is a
//!    symbolic link;
//! 2. the file is a regular file of at most the configured size, opened without
//!    following a link and checked to be the same file before and after the
//!    read;
//! 3. the bytes are UTF-8 and parse as exactly one YAML document with string
//!    keys and no tags;
//! 4. removed keys are refused with a diagnostic naming their replacement;
//! 5. `apiVersion` and `kind` must be literally the product's envelope;
//! 6. `${VAR}`, `${VAR:-default}` and `${VAR:?message}` are substituted in
//!    string values only, after parsing, and refused in every field whose name
//!    ends in `Ref` or `Refs`;
//! 7. the result is deserialized into the product's typed configuration.
//!
//! No refusal repeats a configured or substituted value.

use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use serde::de::DeserializeOwned;
use serde_json::{Map, Number, Value};

use crate::{redact_refused_values, resolve_config_env_expression, sha256_uri};

/// The default size cap for a runtime configuration document.
pub const DEFAULT_MAX_RUNTIME_CONFIG_BYTES: u64 = 1024 * 1024;

/// The longest runtime configuration path the loader accepts, in bytes.
pub const MAX_RUNTIME_CONFIG_PATH_BYTES: usize = 4096;

/// The `apiVersion` and `kind` a product's runtime configuration carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeEnvelope {
    pub api_version: &'static str,
    pub kind: &'static str,
}

/// A key a runtime configuration no longer accepts, and what replaced it.
///
/// `path` is dotted from the document root; a `*` segment matches any mapping
/// key or sequence index. `replacement` is the sentence an operator reads after
/// "`path` is no longer accepted; ".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemovedKey {
    pub path: &'static str,
    pub replacement: &'static str,
}

/// What kind of rule a runtime configuration broke.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigErrorKind {
    /// The configured path is not absolute and lexically normal.
    Path,
    /// A path component is a symbolic link, the file is not a regular file, or
    /// it changed while it was read.
    UnsafeFile,
    /// The file could not be read.
    Unavailable,
    /// The file is empty or larger than the cap.
    Bounds,
    /// The file is not UTF-8.
    Encoding,
    /// The file is not exactly one YAML document with string keys and no tags.
    Syntax,
    /// A removed key is present.
    RemovedKey,
    /// `apiVersion` or `kind` is not the product's envelope.
    Envelope,
    /// An environment expression could not be substituted.
    Substitution,
    /// An environment expression appears in a secret-reference field.
    SubstitutionInReference,
    /// A value does not satisfy the product's typed configuration.
    InvalidValue,
}

impl RuntimeConfigErrorKind {
    /// The stable diagnostic code for this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Path => "runtime_config.path",
            Self::UnsafeFile => "runtime_config.unsafe_file",
            Self::Unavailable => "runtime_config.unavailable",
            Self::Bounds => "runtime_config.bounds",
            Self::Encoding => "runtime_config.encoding",
            Self::Syntax => "runtime_config.syntax",
            Self::RemovedKey => "runtime_config.removed_key",
            Self::Envelope => "runtime_config.envelope",
            Self::Substitution => "runtime_config.substitution",
            Self::SubstitutionInReference => "runtime_config.substitution_in_reference",
            Self::InvalidValue => "runtime_config.invalid_value",
        }
    }
}

/// A refused runtime configuration: which rule broke, at which field, and a
/// message that names the field and never a configured value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{}", self.render())]
pub struct RuntimeConfigError {
    kind: RuntimeConfigErrorKind,
    file: Option<PathBuf>,
    field: String,
    message: String,
}

impl RuntimeConfigError {
    fn new(
        kind: RuntimeConfigErrorKind,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            file: None,
            field: field.into(),
            message: message.into(),
        }
    }

    fn in_file(mut self, file: &Path) -> Self {
        self.file = Some(file.to_owned());
        self
    }

    #[must_use]
    pub const fn kind(&self) -> RuntimeConfigErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// The runtime configuration file, when the refusal came from one.
    #[must_use]
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// The dotted field the refusal concerns; `/` for the whole document.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The refusal without the file prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    fn render(&self) -> String {
        match &self.file {
            Some(file) => format!("{}: {}", file.display(), self.message),
            None => self.message.clone(),
        }
    }
}

/// A loaded runtime configuration and the digest of what the runtime runs.
#[derive(Clone, Debug)]
pub struct LoadedRuntimeConfig<T> {
    pub config: T,
    /// `sha256:` label over the RFC 8785 canonical JSON of the document after
    /// substitution: two files that differ only in comments, layout or the
    /// spelling of an environment expression that resolved to the same value
    /// carry the same digest.
    pub effective_digest: String,
}

/// Loads one product's runtime configuration under the shared rules.
#[derive(Clone, Debug)]
pub struct RuntimeConfigLoader {
    envelope: RuntimeEnvelope,
    removed_keys: &'static [RemovedKey],
    max_bytes: u64,
    trusted_ownership: bool,
}

impl RuntimeConfigLoader {
    #[must_use]
    pub const fn new(envelope: RuntimeEnvelope) -> Self {
        Self {
            envelope,
            removed_keys: &[],
            max_bytes: DEFAULT_MAX_RUNTIME_CONFIG_BYTES,
            trusted_ownership: false,
        }
    }

    /// Refuse each of these keys with a diagnostic naming its replacement.
    #[must_use]
    pub const fn removed_keys(mut self, removed_keys: &'static [RemovedKey]) -> Self {
        self.removed_keys = removed_keys;
        self
    }

    /// Lower or raise the size cap.
    #[must_use]
    pub const fn max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Additionally require every directory above the file to be owned by root
    /// or the effective user and not writable by group or others (a root-owned
    /// sticky directory excepted), and the file itself to be owned by root or
    /// the effective user and not writable by group or others. Platforms
    /// without Unix ownership refuse every file under this rule.
    #[must_use]
    pub const fn require_trusted_ownership(mut self) -> Self {
        self.trusted_ownership = true;
        self
    }

    #[must_use]
    pub const fn envelope(&self) -> RuntimeEnvelope {
        self.envelope
    }

    /// Load `path`, substituting environment expressions from the process
    /// environment.
    pub fn load<T: DeserializeOwned>(
        &self,
        path: &Path,
    ) -> Result<LoadedRuntimeConfig<T>, RuntimeConfigError> {
        self.load_with(path, |name| std::env::var(name).ok())
    }

    /// Load `path`, substituting environment expressions from `lookup`.
    pub fn load_with<T: DeserializeOwned>(
        &self,
        path: &Path,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<LoadedRuntimeConfig<T>, RuntimeConfigError> {
        let bytes = self.read(path).map_err(|error| error.in_file(path))?;
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            RuntimeConfigError::new(
                RuntimeConfigErrorKind::Encoding,
                "/",
                "the runtime configuration is not UTF-8 text",
            )
            .in_file(path)
        })?;
        self.parse_str(text, lookup)
            .map_err(|error| error.in_file(path))
    }

    /// Apply every rule after the file read to `text`. Used by authoring tools
    /// that check an unsaved buffer, and by tests.
    pub fn parse_str<T: DeserializeOwned>(
        &self,
        text: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<LoadedRuntimeConfig<T>, RuntimeConfigError> {
        let mut document = parse_document(text)?;
        self.reject_removed_keys(&document)?;
        self.check_envelope(&document)?;
        substitute_environment(&mut document, &lookup)?;
        let canonical =
            registry_platform_canonical_json::canonicalize_json(&document).map_err(|_| {
                RuntimeConfigError::new(
                    RuntimeConfigErrorKind::InvalidValue,
                    "/",
                    "the runtime configuration holds a value that has no canonical JSON form",
                )
            })?;
        let effective_digest = sha256_uri(&canonical);
        let config = serde_path_to_error::deserialize(document).map_err(|error| {
            let field = error.path().to_string();
            let field = if field == "." { "/".to_owned() } else { field };
            let reason = redact_refused_values(&error.into_inner().to_string());
            RuntimeConfigError::new(
                RuntimeConfigErrorKind::InvalidValue,
                field.clone(),
                format!("{field} is invalid: {reason}"),
            )
        })?;
        Ok(LoadedRuntimeConfig {
            config,
            effective_digest,
        })
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, RuntimeConfigError> {
        validate_absolute_lexical_path(path)?;
        reject_symlink_components(path)?;
        if self.trusted_ownership {
            require_trusted_ownership(path)?;
        }
        read_bounded(path, self.max_bytes)
    }

    fn reject_removed_keys(&self, document: &Value) -> Result<(), RuntimeConfigError> {
        for removed in self.removed_keys {
            let segments = removed.path.split('.').collect::<Vec<_>>();
            if let Some(found) = find_path(document, &segments, &mut Vec::new()) {
                return Err(RuntimeConfigError::new(
                    RuntimeConfigErrorKind::RemovedKey,
                    found.clone(),
                    format!("{found} is no longer accepted; {}", removed.replacement),
                ));
            }
        }
        Ok(())
    }

    fn check_envelope(&self, document: &Value) -> Result<(), RuntimeConfigError> {
        for (field, expected) in [
            ("apiVersion", self.envelope.api_version),
            ("kind", self.envelope.kind),
        ] {
            if document.get(field).and_then(Value::as_str) != Some(expected) {
                return Err(RuntimeConfigError::new(
                    RuntimeConfigErrorKind::Envelope,
                    field,
                    format!("{field} must be exactly {expected}"),
                ));
            }
        }
        Ok(())
    }
}

/// Whether `text` holds an environment expression the runtime loader would
/// substitute: `${NAME}`, `${NAME:-...}` or `${NAME:?...}` with `NAME` a valid
/// environment variable name.
#[must_use]
pub fn contains_environment_expression(text: &str) -> bool {
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let name_end = after
            .find(|character: char| character != '_' && !character.is_ascii_alphanumeric())
            .unwrap_or(after.len());
        let name = &after[..name_end];
        let tail = &after[name_end..];
        if crate::valid_env_key(name)
            && (tail.starts_with('}') || tail.starts_with(":-") || tail.starts_with(":?"))
        {
            return true;
        }
        rest = after;
    }
    false
}

/// Refuse an authored project file that holds an environment expression in a
/// key or a string value.
///
/// Environment substitution applies to `runtime.yaml` only. An authored file
/// is reviewed and packaged as written, so an expression in it would either be
/// taken literally or make the reviewed text differ from what runs. Text that
/// does not parse as YAML is left to the product's own parser to report.
pub fn reject_environment_expressions_in_authored_yaml(
    text: &str,
) -> Result<(), RuntimeConfigError> {
    let Ok(document) = serde_norway::from_str::<serde_norway::Value>(text) else {
        return Ok(());
    };
    let mut path = Vec::new();
    match find_authored_expression(&document, &mut path) {
        Some(field) => Err(RuntimeConfigError::new(
            RuntimeConfigErrorKind::SubstitutionInReference,
            field.clone(),
            format!(
                "{field} holds an environment expression; ${{...}} substitution applies to \
                 runtime.yaml only, so write the value in the authored file directly"
            ),
        )),
        None => Ok(()),
    }
}

fn find_authored_expression(value: &serde_norway::Value, path: &mut Vec<String>) -> Option<String> {
    match value {
        serde_norway::Value::String(text) if contains_environment_expression(text) => {
            Some(dotted(path))
        }
        serde_norway::Value::Sequence(items) => {
            items.iter().enumerate().find_map(|(index, item)| {
                path.push(index.to_string());
                let found = find_authored_expression(item, path);
                path.pop();
                found
            })
        }
        serde_norway::Value::Mapping(mapping) => mapping.iter().find_map(|(key, item)| {
            let name = match key {
                serde_norway::Value::String(name) => name.clone(),
                _ => "?".to_owned(),
            };
            path.push(name.clone());
            let found = if contains_environment_expression(&name) {
                Some(dotted(path))
            } else {
                find_authored_expression(item, path)
            };
            path.pop();
            found
        }),
        serde_norway::Value::Tagged(tagged) => find_authored_expression(&tagged.value, path),
        _ => None,
    }
}

fn dotted(path: &[String]) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else {
        path.join(".")
    }
}

fn parse_document(text: &str) -> Result<Value, RuntimeConfigError> {
    let document = serde_norway::from_str::<serde_norway::Value>(text).map_err(|error| {
        RuntimeConfigError::new(
            RuntimeConfigErrorKind::Syntax,
            "/",
            format!(
                "the runtime configuration is not valid YAML: {}",
                redact_refused_values(&error.to_string())
            ),
        )
    })?;
    let document = to_json(document, &mut Vec::new())?;
    if !document.is_object() {
        return Err(RuntimeConfigError::new(
            RuntimeConfigErrorKind::Syntax,
            "/",
            "the runtime configuration must be a YAML mapping",
        ));
    }
    Ok(document)
}

fn to_json(
    value: serde_norway::Value,
    path: &mut Vec<String>,
) -> Result<Value, RuntimeConfigError> {
    Ok(match value {
        serde_norway::Value::Null => Value::Null,
        serde_norway::Value::Bool(value) => Value::Bool(value),
        serde_norway::Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                Value::Number(value.into())
            } else if let Some(value) = number.as_i64() {
                Value::Number(value.into())
            } else {
                let field = dotted(path);
                number
                    .as_f64()
                    .and_then(Number::from_f64)
                    .map(Value::Number)
                    .ok_or_else(|| {
                        RuntimeConfigError::new(
                            RuntimeConfigErrorKind::Syntax,
                            field.clone(),
                            format!("{field} is not a finite number"),
                        )
                    })?
            }
        }
        serde_norway::Value::String(value) => Value::String(value),
        serde_norway::Value::Sequence(items) => {
            let mut converted = Vec::with_capacity(items.len());
            for (index, item) in items.into_iter().enumerate() {
                path.push(index.to_string());
                converted.push(to_json(item, path)?);
                path.pop();
            }
            Value::Array(converted)
        }
        serde_norway::Value::Mapping(mapping) => {
            let mut converted = Map::new();
            for (key, item) in mapping {
                let serde_norway::Value::String(key) = key else {
                    let field = dotted(path);
                    return Err(RuntimeConfigError::new(
                        RuntimeConfigErrorKind::Syntax,
                        field.clone(),
                        format!("{field} has a key that is not a string"),
                    ));
                };
                path.push(key.clone());
                let item = to_json(item, path)?;
                path.pop();
                converted.insert(key, item);
            }
            Value::Object(converted)
        }
        serde_norway::Value::Tagged(_) => {
            let field = dotted(path);
            return Err(RuntimeConfigError::new(
                RuntimeConfigErrorKind::Syntax,
                field.clone(),
                format!("{field} carries a YAML tag, which a runtime configuration does not use"),
            ));
        }
    })
}

fn find_path(value: &Value, segments: &[&str], found: &mut Vec<String>) -> Option<String> {
    let Some((segment, rest)) = segments.split_first() else {
        return Some(found.join("."));
    };
    let children: Vec<(String, &Value)> = match value {
        Value::Object(map) if *segment == "*" => {
            map.iter().map(|(key, item)| (key.clone(), item)).collect()
        }
        Value::Object(map) => map
            .get(*segment)
            .map(|item| vec![((*segment).to_owned(), item)])
            .unwrap_or_default(),
        Value::Array(items) if *segment == "*" => items
            .iter()
            .enumerate()
            .map(|(index, item)| (index.to_string(), item))
            .collect(),
        _ => Vec::new(),
    };
    for (key, child) in children {
        found.push(key);
        if let Some(path) = find_path(child, rest, found) {
            return Some(path);
        }
        found.pop();
    }
    None
}

/// Whether a field of this name holds secret references, where substitution
/// is refused.
fn is_reference_field(name: &str) -> bool {
    name.ends_with("Ref") || name.ends_with("Refs")
}

fn substitute_environment(
    document: &mut Value,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<(), RuntimeConfigError> {
    substitute_value(document, &mut Vec::new(), false, lookup)
}

fn substitute_value(
    value: &mut Value,
    path: &mut Vec<String>,
    in_reference: bool,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<(), RuntimeConfigError> {
    match value {
        Value::String(text) if text.contains("${") => {
            let field = dotted(path);
            if in_reference {
                return Err(RuntimeConfigError::new(
                    RuntimeConfigErrorKind::SubstitutionInReference,
                    field.clone(),
                    format!(
                        "{field} is a secret reference and does not take ${{...}} substitution; \
                         write secret:env/NAME or secret:file/name instead"
                    ),
                ));
            }
            *text = substitute_string(text, &field, lookup)?;
        }
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                path.push(index.to_string());
                substitute_value(item, path, in_reference, lookup)?;
                path.pop();
            }
        }
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                path.push(key.clone());
                substitute_value(item, path, in_reference || is_reference_field(key), lookup)?;
                path.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

fn substitute_string(
    text: &str,
    field: &str,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<String, RuntimeConfigError> {
    let mut substituted = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        substituted.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            return Err(RuntimeConfigError::new(
                RuntimeConfigErrorKind::Substitution,
                field,
                format!("{field} has an unterminated ${{...}} expression"),
            ));
        };
        let (name, value) =
            resolve_config_env_expression(&after_start[..end], lookup).map_err(|error| {
                RuntimeConfigError::new(
                    RuntimeConfigErrorKind::Substitution,
                    field,
                    format!("{field} could not be substituted: {error}"),
                )
            })?;
        if value.contains('\0') {
            return Err(RuntimeConfigError::new(
                RuntimeConfigErrorKind::Substitution,
                field,
                format!("{field} could not be substituted: environment variable {name} holds a NUL byte"),
            ));
        }
        substituted.push_str(&value);
        rest = &after_start[end + 1..];
    }
    substituted.push_str(rest);
    Ok(substituted)
}

fn validate_absolute_lexical_path(path: &Path) -> Result<(), RuntimeConfigError> {
    let normal = !path.as_os_str().is_empty()
        && path.is_absolute()
        && path.as_os_str().len() <= MAX_RUNTIME_CONFIG_PATH_BYTES
        && !has_current_directory_component(path)
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        });
    if normal {
        Ok(())
    } else {
        Err(RuntimeConfigError::new(
            RuntimeConfigErrorKind::Path,
            "/",
            "the runtime configuration path must be absolute, without . or .. components",
        ))
    }
}

/// `Path::components` drops interior `.` components, so they are found in the
/// raw path instead.
fn has_current_directory_component(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .split(|byte| std::path::is_separator(char::from(*byte)))
        .any(|component| component == b".")
}

fn unsafe_file(message: &str) -> RuntimeConfigError {
    RuntimeConfigError::new(RuntimeConfigErrorKind::UnsafeFile, "/", message)
}

fn unavailable() -> RuntimeConfigError {
    RuntimeConfigError::new(
        RuntimeConfigErrorKind::Unavailable,
        "/",
        "the runtime configuration could not be read",
    )
}

fn out_of_bounds(maximum: u64) -> RuntimeConfigError {
    RuntimeConfigError::new(
        RuntimeConfigErrorKind::Bounds,
        "/",
        format!("the runtime configuration must be between 1 and {maximum} bytes"),
    )
}

/// Refuse a path any of whose components is a symbolic link.
fn reject_symlink_components(path: &Path) -> Result<(), RuntimeConfigError> {
    let mut checked = PathBuf::new();
    for component in path.components() {
        checked.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(unsafe_file(
                    "the runtime configuration path must not pass through a symbolic link",
                ))
            }
            Ok(_) => {}
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_trusted_ownership(path: &Path) -> Result<(), RuntimeConfigError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let effective_user = rustix::process::geteuid().as_raw();
    let count = path.components().count();
    let mut current = PathBuf::new();
    for (index, component) in path.components().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|_| unavailable())?;
        let last = index + 1 == count;
        let owner = metadata.uid();
        let mode = metadata.permissions().mode();
        let trusted_owner = owner == 0 || owner == effective_user;
        let not_writable_by_others = mode & 0o022 == 0;
        let root_sticky = !last && owner == 0 && mode & 0o1000 != 0;
        if !trusted_owner || !(not_writable_by_others || root_sticky) {
            return Err(unsafe_file(
                "the runtime configuration and every directory above it must be owned by root \
                 or the runtime user and not writable by group or others",
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_trusted_ownership(_path: &Path) -> Result<(), RuntimeConfigError> {
    Err(unsafe_file(
        "trusted ownership of the runtime configuration cannot be checked on this platform",
    ))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, RuntimeConfigError> {
    let not_regular = || unsafe_file("the runtime configuration must be a regular file");
    let changed = || unsafe_file("the runtime configuration changed while it was read");
    let scanned = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if scanned.file_type().is_symlink() || !scanned.is_file() {
        return Err(not_regular());
    }
    if scanned.len() == 0 || scanned.len() > maximum {
        return Err(out_of_bounds(maximum));
    }
    let file = open_no_follow(path)?;
    let opened = file.metadata().map_err(|_| unavailable())?;
    let current = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if current.file_type().is_symlink() || !opened.is_file() {
        return Err(not_regular());
    }
    if !same_file(&scanned, &opened) || !same_file(&opened, &current) {
        return Err(changed());
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| out_of_bounds(maximum))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve(capacity)
        .map_err(|_| out_of_bounds(maximum))?;
    let mut reader = file.take(maximum + 1);
    reader.read_to_end(&mut bytes).map_err(|_| unavailable())?;
    let after = reader.get_ref().metadata().map_err(|_| unavailable())?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(out_of_bounds(maximum));
    }
    if !same_file(&opened, &after) || bytes.len() as u64 != after.len() {
        return Err(changed());
    }
    Ok(bytes)
}

fn open_no_follow(path: &Path) -> Result<fs::File, RuntimeConfigError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32,
        );
    }
    options.open(path).map_err(|_| {
        fs::symlink_metadata(path).map_or_else(
            |_| unavailable(),
            |metadata| {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    unsafe_file("the runtime configuration must be a regular file")
                } else {
                    unavailable()
                }
            },
        )
    })
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.permissions().mode() == right.permissions().mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.permissions().readonly() == right.permissions().readonly()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

#[cfg(test)]
#[path = "loader_tests.rs"]
mod tests;
