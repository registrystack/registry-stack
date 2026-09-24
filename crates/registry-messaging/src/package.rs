// SPDX-License-Identifier: Apache-2.0

//! Reading an authored package from disk and computing its digest.
//!
//! A package root holds `messaging.yaml` and, when it ships templates, a
//! `templates/` tree laid out as `<id>/<version>/` directories. Each version
//! directory holds `template.yaml`, `schema.json`, an optional
//! `sample.json`, and one directory per locale holding the part sources
//! `subject.j2`, `text.j2`, and `html.j2`. Nothing else may appear under
//! `templates/`: an unknown entry, a hidden file, or a symbolic link is
//! refused rather than skipped, so what the runtime reads is exactly what
//! the author sees. Other entries beside `messaging.yaml` at the root, such
//! as a README or the runtime example, are not package content and are
//! neither read nor digested.
//!
//! The package digest is SHA-256 over the canonical JSON of the sorted file
//! list, each file named by its `/`-separated path under the root with its
//! own SHA-256 and length. The same bytes always give the same digest, and
//! changing, adding, or removing any package file changes it.

use std::io::Read as _;
use std::path::Path;

use registry_messaging_core::{
    LocaleSources, MessagingPackage, Package, PackageError, PartKind, TemplateDocument,
    TemplateSource, MAXIMUM_TEMPLATE_SOURCE_BYTES, MESSAGING_PACKAGE_API_VERSION,
    MESSAGING_PACKAGE_KIND, PACKAGE_FILE,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::config::{redact_refused_values, refused_yaml};

/// The directory under the package root holding every template version.
pub const TEMPLATES_DIRECTORY: &str = "templates";
/// A template version's descriptor.
pub const TEMPLATE_FILE: &str = "template.yaml";
/// A template version's data schema.
pub const SCHEMA_FILE: &str = "schema.json";
/// A template version's optional sample data, checked against the schema
/// and rendered in every locale when the package loads.
pub const SAMPLE_FILE: &str = "sample.json";

/// The largest `messaging.yaml` the runtime reads.
pub const MAXIMUM_MANIFEST_BYTES: u64 = 1024 * 1024;
/// The largest file under `templates/`.
pub const MAXIMUM_TEMPLATE_FILE_BYTES: u64 = MAXIMUM_TEMPLATE_SOURCE_BYTES as u64;
/// The most directory entries a package may hold under `templates/`.
pub const MAXIMUM_PACKAGE_ENTRIES: usize = 4096;
/// The most bytes all package files may hold together.
pub const MAXIMUM_PACKAGE_BYTES: u64 = 32 * 1024 * 1024;

/// One file the digest covers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageFile {
    /// The `/`-separated path under the package root.
    pub path: String,
    /// `sha256:<hex>` of the file's bytes.
    pub sha256: String,
    pub bytes: u64,
}

/// A package read from disk: the checked package and the files its digest
/// covers, sorted by path.
#[derive(Clone, Debug)]
pub struct LoadedPackage {
    pub package: Package,
    pub files: Vec<PackageFile>,
}

/// Why a package could not be loaded, and where.
#[derive(Debug, Error)]
#[error("{path} {reason}")]
pub struct PackageLoadError {
    path: String,
    reason: PackageLoadReason,
}

impl PackageLoadError {
    fn new(file: &str, reason: PackageLoadReason) -> Self {
        let path = if file.is_empty() {
            "package.root".to_owned()
        } else {
            format!("package.root/{file}")
        };
        Self { path, reason }
    }

    /// The refused entry, written `package.root/<path>`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn reason(&self) -> &PackageLoadReason {
        &self.reason
    }

    /// Whether the package could not be read at all, rather than read and
    /// refused.
    #[must_use]
    pub const fn is_read_failure(&self) -> bool {
        matches!(self.reason, PackageLoadReason::Read(_))
    }
}

#[derive(Debug, Error)]
pub enum PackageLoadReason {
    #[error("could not be read")]
    Read(#[source] std::io::Error),
    #[error("is not part of the package layout")]
    Unexpected,
    #[error("is a symbolic link, which a package may not contain")]
    Symlink,
    #[error("exceeds {0} bytes")]
    FileTooLarge(u64),
    #[error("holds more than {MAXIMUM_PACKAGE_ENTRIES} entries under templates")]
    TooManyEntries,
    #[error("holds more than {MAXIMUM_PACKAGE_BYTES} bytes of package files")]
    TooLarge,
    #[error("is not UTF-8 text")]
    NotUtf8,
    #[error("is not valid at {at}: {cause}")]
    Parse { at: String, cause: String },
    #[error("is refused: {0}")]
    Invalid(PackageError),
}

/// Read the package under `root`, compute its digest, and check it.
pub fn load_package(root: &Path) -> Result<LoadedPackage, PackageLoadError> {
    let mut reader = Reader {
        root,
        files: Vec::new(),
        bytes: 0,
        entries: 0,
    };
    let manifest_text = reader.read_file(PACKAGE_FILE, MAXIMUM_MANIFEST_BYTES)?;
    let deserializer = serde_norway::Deserializer::from_str(&manifest_text);
    let manifest: MessagingPackage =
        serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let (at, cause) = refused_yaml(error);
            PackageLoadError::new(PACKAGE_FILE, PackageLoadReason::Parse { at, cause })
        })?;
    let sources = reader.read_templates()?;
    let mut files = reader.files;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let digest = package_digest(&files);
    let package = Package::assemble(&manifest, sources, digest).map_err(|error| {
        let file = match &error {
            PackageError::Template { id, version, .. }
            | PackageError::UndeclaredTemplate { id, version }
            | PackageError::MissingTemplate { id, version } => {
                format!("{TEMPLATES_DIRECTORY}/{id}/{version}")
            }
            _ => PACKAGE_FILE.to_owned(),
        };
        PackageLoadError::new(&file, PackageLoadReason::Invalid(error))
    })?;
    Ok(LoadedPackage { package, files })
}

/// The digest of a sorted file list.
#[must_use]
pub fn package_digest(files: &[PackageFile]) -> String {
    let identity = serde_json::json!({
        "apiVersion": MESSAGING_PACKAGE_API_VERSION,
        "kind": MESSAGING_PACKAGE_KIND,
        "files": files,
    });
    // Every value is a string or an integer far below 2^53, so the
    // canonical form always exists.
    let canonical = registry_platform_canonical_json::canonicalize_json(&identity)
        .expect("a package file list is canonical JSON");
    sha256(&canonical)
}

fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut rendered = String::with_capacity(7 + digest.len() * 2);
    rendered.push_str("sha256:");
    for byte in digest {
        rendered.push(HEX[usize::from(byte >> 4)] as char);
        rendered.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    rendered
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EntryKind {
    File,
    Directory,
}

struct Reader<'a> {
    root: &'a Path,
    files: Vec<PackageFile>,
    bytes: u64,
    entries: usize,
}

impl Reader<'_> {
    fn read_templates(&mut self) -> Result<Vec<TemplateSource>, PackageLoadError> {
        let directory = self.root.join(TEMPLATES_DIRECTORY);
        let metadata = match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(PackageLoadError::new(
                    TEMPLATES_DIRECTORY,
                    PackageLoadReason::Read(error),
                ))
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(PackageLoadError::new(
                TEMPLATES_DIRECTORY,
                PackageLoadReason::Symlink,
            ));
        }
        if !metadata.is_dir() {
            return Err(PackageLoadError::new(
                TEMPLATES_DIRECTORY,
                PackageLoadReason::Unexpected,
            ));
        }
        let mut sources = Vec::new();
        for (id, kind) in self.list(TEMPLATES_DIRECTORY)? {
            let template = format!("{TEMPLATES_DIRECTORY}/{id}");
            expect_directory(&template, kind)?;
            for (version, kind) in self.list(&template)? {
                let directory = format!("{template}/{version}");
                expect_directory(&directory, kind)?;
                sources.push(self.read_version(&id, &version, &directory)?);
            }
        }
        Ok(sources)
    }

    fn read_version(
        &mut self,
        id: &str,
        version: &str,
        directory: &str,
    ) -> Result<TemplateSource, PackageLoadError> {
        let mut document = None;
        let mut schema = None;
        let mut sample = None;
        let mut locales = std::collections::BTreeMap::new();
        for (name, kind) in self.list(directory)? {
            let path = format!("{directory}/{name}");
            match (name.as_str(), kind) {
                (TEMPLATE_FILE, EntryKind::File) => {
                    let text = self.read_file(&path, MAXIMUM_TEMPLATE_FILE_BYTES)?;
                    let deserializer = serde_norway::Deserializer::from_str(&text);
                    let parsed: TemplateDocument = serde_path_to_error::deserialize(deserializer)
                        .map_err(|error| {
                        let (at, cause) = refused_yaml(error);
                        PackageLoadError::new(&path, PackageLoadReason::Parse { at, cause })
                    })?;
                    document = Some(parsed);
                }
                (SCHEMA_FILE, EntryKind::File) => {
                    schema = Some(self.read_json(&path)?);
                }
                (SAMPLE_FILE, EntryKind::File) => {
                    sample = Some(self.read_json(&path)?);
                }
                (_, EntryKind::Directory) => {
                    let sources = self.read_locale(&path)?;
                    locales.insert(name, sources);
                }
                (_, EntryKind::File) => {
                    return Err(PackageLoadError::new(&path, PackageLoadReason::Unexpected));
                }
            }
        }
        let missing = |file: &str| {
            PackageLoadError::new(
                &format!("{directory}/{file}"),
                PackageLoadReason::Read(std::io::ErrorKind::NotFound.into()),
            )
        };
        Ok(TemplateSource {
            id: id.to_owned(),
            version: version.to_owned(),
            document: document.ok_or_else(|| missing(TEMPLATE_FILE))?,
            schema: schema.ok_or_else(|| missing(SCHEMA_FILE))?,
            locales,
            sample,
        })
    }

    fn read_locale(&mut self, directory: &str) -> Result<LocaleSources, PackageLoadError> {
        let mut sources = LocaleSources::default();
        for (name, kind) in self.list(directory)? {
            let path = format!("{directory}/{name}");
            let part = [PartKind::Subject, PartKind::Text, PartKind::Html]
                .into_iter()
                .find(|part| part.file_name() == name);
            let (Some(part), EntryKind::File) = (part, kind) else {
                return Err(PackageLoadError::new(&path, PackageLoadReason::Unexpected));
            };
            let text = self.read_file(&path, MAXIMUM_TEMPLATE_FILE_BYTES)?;
            match part {
                PartKind::Subject => sources.subject = Some(text),
                PartKind::Text => sources.text = Some(text),
                PartKind::Html => sources.html = Some(text),
            }
        }
        Ok(sources)
    }

    fn read_json(&mut self, path: &str) -> Result<Value, PackageLoadError> {
        let text = self.read_file(path, MAXIMUM_TEMPLATE_FILE_BYTES)?;
        serde_json::from_str(&text).map_err(|error| {
            PackageLoadError::new(
                path,
                PackageLoadReason::Parse {
                    at: "/".to_owned(),
                    cause: redact_refused_values(&error.to_string()),
                },
            )
        })
    }

    /// List one directory under the root, sorted by name. Every entry counts
    /// against the package's entry bound before it is examined, and a
    /// hidden entry, a name that is not UTF-8, or a symbolic link is refused.
    fn list(&mut self, directory: &str) -> Result<Vec<(String, EntryKind)>, PackageLoadError> {
        let read = |error| PackageLoadError::new(directory, PackageLoadReason::Read(error));
        let mut listed = Vec::new();
        for entry in std::fs::read_dir(self.root.join(directory)).map_err(read)? {
            let entry = entry.map_err(read)?;
            self.entries += 1;
            if self.entries > MAXIMUM_PACKAGE_ENTRIES {
                return Err(PackageLoadError::new("", PackageLoadReason::TooManyEntries));
            }
            let Ok(name) = entry.file_name().into_string() else {
                return Err(PackageLoadError::new(
                    directory,
                    PackageLoadReason::Unexpected,
                ));
            };
            let path = format!("{directory}/{name}");
            if name.starts_with('.') {
                return Err(PackageLoadError::new(&path, PackageLoadReason::Unexpected));
            }
            let file_type = entry
                .file_type()
                .map_err(|error| PackageLoadError::new(&path, PackageLoadReason::Read(error)))?;
            let kind = if file_type.is_symlink() {
                return Err(PackageLoadError::new(&path, PackageLoadReason::Symlink));
            } else if file_type.is_dir() {
                EntryKind::Directory
            } else if file_type.is_file() {
                EntryKind::File
            } else {
                return Err(PackageLoadError::new(&path, PackageLoadReason::Unexpected));
            };
            listed.push((name, kind));
        }
        listed.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(listed)
    }

    /// Read one regular file of at most `limit` bytes as UTF-8 and record it
    /// for the digest.
    fn read_file(&mut self, path: &str, limit: u64) -> Result<String, PackageLoadError> {
        let full = self.root.join(path);
        let read = |error| PackageLoadError::new(path, PackageLoadReason::Read(error));
        let metadata = std::fs::symlink_metadata(&full).map_err(read)?;
        if metadata.file_type().is_symlink() {
            return Err(PackageLoadError::new(path, PackageLoadReason::Symlink));
        }
        if !metadata.is_file() {
            return Err(PackageLoadError::new(path, PackageLoadReason::Unexpected));
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&full)
            .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
            .map_err(read)?;
        let length = bytes.len() as u64;
        if length > limit {
            return Err(PackageLoadError::new(
                path,
                PackageLoadReason::FileTooLarge(limit),
            ));
        }
        self.bytes += length;
        if self.bytes > MAXIMUM_PACKAGE_BYTES {
            return Err(PackageLoadError::new("", PackageLoadReason::TooLarge));
        }
        self.files.push(PackageFile {
            path: path.to_owned(),
            sha256: sha256(&bytes),
            bytes: length,
        });
        String::from_utf8(bytes)
            .map_err(|_| PackageLoadError::new(path, PackageLoadReason::NotUtf8))
    }
}

fn expect_directory(path: &str, kind: EntryKind) -> Result<(), PackageLoadError> {
    if kind == EntryKind::Directory {
        Ok(())
    } else {
        Err(PackageLoadError::new(path, PackageLoadReason::Unexpected))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The committed starter package, which every runtime test serves.
    pub(crate) fn starter_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/messaging/examples/starter")
    }

    /// Copy the starter package's content into `to`.
    pub(crate) fn copy_starter(to: &Path) {
        copy_tree(&starter_root(), to, true);
    }

    fn copy_tree(from: &Path, to: &Path, top: bool) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            if top && name != PACKAGE_FILE && name != TEMPLATES_DIRECTORY {
                continue;
            }
            let target = to.join(&name);
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target, false);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn starter_copy() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        copy_starter(root.path());
        root
    }

    fn refusal(root: &Path) -> PackageLoadError {
        load_package(root).unwrap_err()
    }

    const REMINDER: &str = "templates/appointment-reminder/1";

    #[test]
    fn the_starter_package_loads_with_a_digest_over_its_sorted_files() {
        let root = starter_copy();
        let loaded = load_package(root.path()).unwrap();
        let paths: Vec<&str> = loaded.files.iter().map(|file| file.path.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted);
        assert_eq!(paths.first(), Some(&PACKAGE_FILE));
        assert!(paths.contains(&"templates/appointment-reminder/1/fr/html.j2"));
        assert_eq!(loaded.package.digest(), package_digest(&loaded.files));
        assert!(registry_messaging_core::valid_package_digest(
            loaded.package.digest()
        ));
        assert_eq!(loaded.package.templates().count(), 2);
        let manifest = &loaded.files[0];
        let bytes = std::fs::read(root.path().join(PACKAGE_FILE)).unwrap();
        assert_eq!(manifest.bytes, bytes.len() as u64);
        assert_eq!(manifest.sha256, sha256(&bytes));
    }

    #[test]
    fn the_digest_is_reproducible_and_covers_exactly_the_package_files() {
        let root = starter_copy();
        let digest = load_package(root.path())
            .unwrap()
            .package
            .digest()
            .to_owned();
        let again = starter_copy();
        assert_eq!(load_package(again.path()).unwrap().package.digest(), digest);

        std::fs::write(root.path().join("README.md"), "notes").unwrap();
        std::fs::write(root.path().join("runtime.yaml"), "kind: x").unwrap();
        assert_eq!(load_package(root.path()).unwrap().package.digest(), digest);

        let text = root.path().join(REMINDER).join("en/text.j2");
        let original = std::fs::read_to_string(&text).unwrap();
        std::fs::write(&text, format!("{original} ")).unwrap();
        assert_ne!(load_package(root.path()).unwrap().package.digest(), digest);
        std::fs::write(&text, original).unwrap();
        assert_eq!(load_package(root.path()).unwrap().package.digest(), digest);
    }

    #[test]
    fn a_package_without_templates_needs_no_templates_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(PACKAGE_FILE),
            concat!(
                "apiVersion: registry.registrystack.org/messaging-package/v1alpha1\n",
                "kind: MessagingPackage\n",
                "accessProfiles:\n",
                "  - {id: operations, principalClaim: sub, requesterClients: [console],\n",
                "     role: operator, requestsPerMinute: 60, burst: 10}\n",
            ),
        )
        .unwrap();
        let loaded = load_package(root.path()).unwrap();
        assert_eq!(loaded.files.len(), 1);
        assert_eq!(loaded.package.templates().count(), 0);
    }

    #[test]
    fn a_missing_manifest_is_a_read_failure() {
        let root = tempfile::tempdir().unwrap();
        let error = refusal(root.path());
        assert!(error.is_read_failure(), "{error}");
        assert_eq!(error.path(), "package.root/messaging.yaml");
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_anywhere_in_the_package_is_refused() {
        let root = starter_copy();
        let text = root.path().join(REMINDER).join("en/text.j2");
        let outside = root.path().join("outside.j2");
        std::fs::rename(&text, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &text).unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(error.reason(), PackageLoadReason::Symlink),
            "{error}"
        );
        assert_eq!(error.path(), format!("package.root/{REMINDER}/en/text.j2"));

        let root = starter_copy();
        let manifest = root.path().join(PACKAGE_FILE);
        std::fs::rename(&manifest, root.path().join("real.yaml")).unwrap();
        std::os::unix::fs::symlink(root.path().join("real.yaml"), &manifest).unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(error.reason(), PackageLoadReason::Symlink),
            "{error}"
        );
    }

    #[test]
    fn an_entry_outside_the_layout_is_refused_by_path() {
        for (entry, directory) in [
            (format!("{REMINDER}/notes.txt"), false),
            (format!("{REMINDER}/en/footer.j2"), false),
            (format!("{REMINDER}/en/.DS_Store"), false),
            ("templates/.cache".to_owned(), true),
            ("templates/stray.yaml".to_owned(), false),
            ("templates/appointment-reminder/1.txt".to_owned(), false),
            (format!("{REMINDER}/en/partials"), true),
        ] {
            let root = starter_copy();
            let path = root.path().join(&entry);
            if directory {
                std::fs::create_dir(&path).unwrap();
            } else {
                std::fs::write(&path, "x").unwrap();
            }
            let error = refusal(root.path());
            assert!(
                matches!(error.reason(), PackageLoadReason::Unexpected),
                "{entry}: {error}"
            );
            assert_eq!(error.path(), format!("package.root/{entry}"));
        }
    }

    #[test]
    fn oversized_and_non_utf8_files_are_refused() {
        let root = starter_copy();
        let text = root.path().join(REMINDER).join("en/text.j2");
        std::fs::write(
            &text,
            "a".repeat(usize::try_from(MAXIMUM_TEMPLATE_FILE_BYTES).unwrap() + 1),
        )
        .unwrap();
        assert!(matches!(
            refusal(root.path()).reason(),
            PackageLoadReason::FileTooLarge(MAXIMUM_TEMPLATE_FILE_BYTES)
        ));

        std::fs::write(&text, [0xff, 0xfe]).unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(error.reason(), PackageLoadReason::NotUtf8),
            "{error}"
        );
        assert_eq!(error.path(), format!("package.root/{REMINDER}/en/text.j2"));
    }

    #[test]
    fn the_entry_bound_is_enforced_before_the_layout_is_judged() {
        let root = starter_copy();
        let locale = root.path().join(REMINDER).join("en");
        for index in 0..MAXIMUM_PACKAGE_ENTRIES {
            std::fs::write(locale.join(format!("extra-{index}")), "").unwrap();
        }
        assert!(matches!(
            refusal(root.path()).reason(),
            PackageLoadReason::TooManyEntries
        ));
    }

    #[test]
    fn an_unknown_key_in_a_template_descriptor_is_refused_with_its_path() {
        let root = starter_copy();
        std::fs::write(
            root.path().join(REMINDER).join(TEMPLATE_FILE),
            "channel: email\nlocales: [en, fr]\nparts: [subject, text, html]\nfallback: en\n",
        )
        .unwrap();
        let error = refusal(root.path());
        assert_eq!(
            error.path(),
            format!("package.root/{REMINDER}/{TEMPLATE_FILE}")
        );
        assert!(error.to_string().contains("fallback"), "{error}");
    }

    #[test]
    fn a_template_refusal_names_its_version_directory() {
        let root = starter_copy();
        std::fs::write(
            root.path().join(REMINDER).join("en/text.j2"),
            "Hello {{ name ",
        )
        .unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(
                error.reason(),
                PackageLoadReason::Invalid(PackageError::Template { .. })
            ),
            "{error}"
        );
        assert_eq!(error.path(), format!("package.root/{REMINDER}"));

        let root = starter_copy();
        std::fs::remove_file(root.path().join(REMINDER).join(SCHEMA_FILE)).unwrap();
        let error = refusal(root.path());
        assert_eq!(
            error.path(),
            format!("package.root/{REMINDER}/{SCHEMA_FILE}")
        );

        let root = starter_copy();
        std::fs::write(root.path().join(REMINDER).join(SCHEMA_FILE), "{\"type\": ").unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(error.reason(), PackageLoadReason::Parse { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_declared_version_the_package_does_not_ship_is_refused() {
        let root = starter_copy();
        std::fs::remove_dir_all(root.path().join("templates/appointment-reminder-sms")).unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(
                error.reason(),
                PackageLoadReason::Invalid(PackageError::MissingTemplate { .. })
            ),
            "{error}"
        );
        assert_eq!(
            error.path(),
            "package.root/templates/appointment-reminder-sms/1"
        );
    }
}
