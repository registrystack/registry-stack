//! The Render Typst world: the entire filesystem a template can ever see.
//!
//! The world contains exactly three things: the bundle (project root), the
//! request's decoded assets (under the virtual `assets/` namespace), and the
//! vendored `packages/` tree. There is no host font discovery and no network
//! path anywhere. Every `source`/`file` resolution is lexically checked,
//! canonicalized, and constrained to one of those roots — path safety is a
//! property of this world, not template discipline, because untrusted data
//! can reach path-taking functions like `image()` inside a reviewed template.
//!
//! A fresh world (and a fresh `Library`) is constructed per render: inputs
//! live on the `Library`, so sharing either across requests would be both a
//! stale-memoization hazard and a cross-request leak. Freshness is also what
//! makes the captured dependency closure exact.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use chrono::Datelike;

use typst::diag::{FileError, FileResult};
use typst::foundations::{Bytes, Datetime, Dict, Duration};
use typst::syntax::{FileId, RootedPath, Source, VirtualPath, VirtualRoot};
use typst::text::{Font, FontBook};
use typst::utils::LazyHash;
use typst::World;

/// A rendered world for one request. Not `Clone`: one render, one world.
pub struct RenderWorld {
    library: LazyHash<typst::Library>,
    book: LazyHash<FontBook>,
    fonts: Vec<Font>,
    main_id: FileId,
    /// Canonicalized bundle root.
    bundle_root: PathBuf,
    /// Decoded request assets, keyed by name, served as `assets/<name>`.
    assets: BTreeMap<String, Bytes>,
    /// UTC date (and full time) the document claims issuance at.
    issued_ymd: (i32, u8, u8),
    /// Every virtual path this render actually read, relative to its root,
    /// recorded for the manifest's closure governance.
    closure: Mutex<BTreeSet<String>>,
}

impl RenderWorld {
    /// Build a world for one render. `envelope_json` is the exact canonical
    /// byte string that `sys.inputs.data` will return.
    pub fn new(
        bundle_root: &Path,
        fonts: Vec<Font>,
        main_rel_path: &str,
        assets: BTreeMap<String, Bytes>,
        issued: chrono::DateTime<chrono::Utc>,
        envelope_json: String,
    ) -> Result<Self, String> {
        let bundle_root = bundle_root
            .canonicalize()
            .map_err(|err| format!("bundle root {}: {err}", bundle_root.display()))?;
        let main_id = RootedPath::new(
            VirtualRoot::Project,
            VirtualPath::new(main_rel_path).map_err(|e| e.to_string())?,
        )
        .intern();
        use typst::LibraryExt;
        let library = LazyHash::new(
            typst::Library::builder()
                .with_inputs(Dict::from_iter([(
                    "data".into(),
                    typst::foundations::Value::Str(envelope_json.into()),
                )]))
                .build(),
        );
        let book = LazyHash::new(FontBook::from_fonts(&fonts));
        let issued_naive = issued.date_naive();
        let issued_ymd = (
            issued_naive.year(),
            issued_naive.month() as u8,
            issued_naive.day() as u8,
        );
        Ok(Self {
            library,
            book,
            fonts,
            main_id,
            bundle_root,
            assets,
            issued_ymd,
            closure: Mutex::new(BTreeSet::new()),
        })
    }

    /// The virtual paths this render consumed (its file closure), sorted.
    pub fn closure(&self) -> Vec<String> {
        self.closure
            .lock()
            .expect("closure lock")
            .clone()
            .into_iter()
            .collect()
    }

    /// Outbound-diagnostic redaction: replace any occurrence of the host
    /// bundle root with the virtual marker. The world itself only ever
    /// reports virtual paths, so this is defense in depth — a future
    /// Typst-internal leak fails closed into a redacted string instead of
    /// reaching a caller.
    pub fn redact_host_paths(&self, text: &str) -> String {
        let root = self.bundle_root.to_string_lossy();
        text.replace(root.as_ref(), "<bundle>")
    }

    fn record(&self, key: String) {
        self.closure.lock().expect("closure lock").insert(key);
    }

    /// Map a typst virtual path to a real path under `base`, enforcing the
    /// path rules: no `..`, no absolute components, and the canonicalized
    /// result must stay under the canonical `base`. Symlinks that escape are
    /// caught by the canonicalization check. Failures carry `display` — the
    /// virtual, root-relative spelling — never the joined host path.
    fn resolve_under(base: &Path, vpath: &str, display: &str) -> FileResult<PathBuf> {
        let mut clean = PathBuf::new();
        for component in Path::new(vpath).components() {
            match component {
                Component::Normal(part) => {
                    clean.push(part);
                }
                Component::CurDir => {}
                _ => {
                    return Err(FileError::AccessDenied);
                }
            }
        }
        if clean.as_os_str().is_empty() {
            return Err(FileError::AccessDenied);
        }
        let joined = base.join(&clean);
        let canon = std::fs::canonicalize(&joined).map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => FileError::NotFound(PathBuf::from(display)),
            _ => FileError::AccessDenied,
        })?;
        if !canon.starts_with(base) {
            return Err(FileError::AccessDenied);
        }
        if canon.is_dir() {
            return Err(FileError::IsDirectory);
        }
        Ok(canon)
    }

    fn root_for(&self, root: &VirtualRoot) -> FileResult<(PathBuf, String)> {
        match root {
            VirtualRoot::Project => Ok((self.bundle_root.clone(), String::new())),
            VirtualRoot::Package(spec) => {
                let dir = self
                    .bundle_root
                    .join("packages")
                    .join(spec.namespace.as_str())
                    .join(spec.name.as_str())
                    .join(spec.version.to_string());
                let prefix = format!("@{}/{}:{}", spec.namespace, spec.name, spec.version);
                Ok((dir, prefix))
            }
        }
    }
}

impl World for RenderWorld {
    fn library(&self) -> &LazyHash<typst::Library> {
        &self.library
    }

    fn book(&self) -> &LazyHash<FontBook> {
        &self.book
    }

    fn main(&self) -> FileId {
        self.main_id
    }

    fn source(&self, id: FileId) -> FileResult<Source> {
        let rooted = id.get();
        let vpath = rooted.vpath().get_without_slash().to_owned();
        let (base, prefix) = self.root_for(rooted.root())?;
        let display = closure_key(&prefix, &vpath);
        let path = Self::resolve_under(&base, &vpath, &display)?;
        if !vpath.ends_with(".typ") {
            return Err(FileError::NotSource);
        }
        let bytes = std::fs::read(&path).map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => FileError::NotFound(PathBuf::from(&display)),
            _ => FileError::AccessDenied,
        })?;
        let text = String::from_utf8(bytes).map_err(|_| FileError::InvalidUtf8)?;
        self.record(closure_key(&prefix, &vpath));
        Ok(Source::new(id, text))
    }

    fn file(&self, id: FileId) -> FileResult<Bytes> {
        let rooted = id.get();
        let vpath = rooted.vpath().get_without_slash().to_owned();
        let (base, prefix) = self.root_for(rooted.root())?;
        // The virtual assets namespace: request-scoped, never on disk.
        if matches!(rooted.root(), VirtualRoot::Project)
            && vpath.strip_prefix("assets/").is_some_and(|n| !n.is_empty())
        {
            let name = vpath.strip_prefix("assets/").expect("checked");
            if name.contains('/') || name.contains("..") {
                return Err(FileError::AccessDenied);
            }
            let bytes = self
                .assets
                .get(name)
                .cloned()
                .ok_or_else(|| FileError::NotFound(PathBuf::from(&vpath)))?;
            self.record(closure_key(&prefix, &vpath));
            return Ok(bytes);
        }
        let display = closure_key(&prefix, &vpath);
        let path = Self::resolve_under(&base, &vpath, &display)?;
        let bytes = std::fs::read(&path).map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => FileError::NotFound(PathBuf::from(&display)),
            _ => FileError::AccessDenied,
        })?;
        self.record(closure_key(&prefix, &vpath));
        Ok(Bytes::new(bytes))
    }

    fn font(&self, index: usize) -> Option<Font> {
        self.fonts.get(index).cloned()
    }

    fn today(&self, offset: Option<Duration>) -> Option<Datetime> {
        // Deterministic: the world clock is the document's issuedAt, never
        // the machine clock. `None` (local) reads as UTC of issuance.
        let (y, m, d) = self.issued_ymd;
        let date = chrono::NaiveDate::from_ymd_opt(y, m as u32, d as u32)?;
        if let Some(duration) = offset {
            let hours = duration.hours().round() as i64;
            let shifted = date
                .and_hms_opt(0, 0, 0)?
                .checked_add_signed(chrono::Duration::hours(hours))?
                .date();
            Datetime::from_ymd(shifted.year(), shifted.month() as u8, shifted.day() as u8)
        } else {
            Datetime::from_ymd(y, m, d)
        }
    }
}

/// Closure keys read `path` for bundle files and `@ns/name:ver/path` for
/// package files — a clean separator between the two halves.
fn closure_key(prefix: &str, vpath: &str) -> String {
    if prefix.is_empty() {
        vpath.to_owned()
    } else {
        format!("{prefix}/{vpath}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rejects_escape_attempts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("ok.typ"), "x").unwrap();
        // A symlink inside the root pointing outside.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "s").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path().join("secret.txt"), root.join("leak.txt"))
            .unwrap();
        assert!(RenderWorld::resolve_under(&root, "ok.typ", "ok.typ").is_ok());
        assert_eq!(
            RenderWorld::resolve_under(&root, "../ok.typ", "../ok.typ").unwrap_err(),
            FileError::AccessDenied
        );
        assert_eq!(
            RenderWorld::resolve_under(&root, "/etc/passwd", "/etc/passwd").unwrap_err(),
            FileError::AccessDenied
        );
        #[cfg(unix)]
        assert_eq!(
            RenderWorld::resolve_under(&root, "leak.txt", "leak.txt").unwrap_err(),
            FileError::AccessDenied
        );
        assert_eq!(
            RenderWorld::resolve_under(&root, "missing.typ", "missing.typ").unwrap_err(),
            FileError::NotFound(PathBuf::from("missing.typ"))
        );
    }

    #[test]
    fn not_found_reports_the_virtual_path_not_the_host_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let err = RenderWorld::resolve_under(&root, "gone.png", "gone.png").unwrap_err();
        assert_eq!(err, FileError::NotFound(PathBuf::from("gone.png")));
        let text = err.to_string();
        assert!(!text.contains(&*root.to_string_lossy()), "{text}");
    }
}
