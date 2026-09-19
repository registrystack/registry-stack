//! The Render Typst world: the entire file view a template can ever see.
//!
//! The world contains exactly three things: an immutable snapshot of the
//! governed bundle, the request's decoded assets (under the virtual `assets/`
//! namespace), and the vendored `packages/` bytes inside that snapshot. There
//! is no host font discovery, filesystem reopen, or network path anywhere.
//! Every `source`/`file` resolution is lexically checked and must name an exact
//! snapshot key. Path safety is a property of this world, not template
//! discipline, because untrusted data can reach path-taking functions like
//! `image()` inside a reviewed template.
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

use crate::bundle::BundleSnapshot;

/// A rendered world for one request. Not `Clone`: one render, one world.
pub struct RenderWorld {
    library: LazyHash<typst::Library>,
    book: LazyHash<FontBook>,
    fonts: Vec<Font>,
    main_id: FileId,
    /// Immutable governed bytes verified together before this world exists.
    snapshot: BundleSnapshot,
    /// Bundle root retained only for defense-in-depth diagnostic redaction.
    bundle_root: PathBuf,
    /// Decoded request assets, keyed by name, served as `assets/<name>`.
    assets: BTreeMap<String, Bytes>,
    /// The issuance instant: the world clock, never the machine clock.
    issued_utc: chrono::DateTime<chrono::Utc>,
    /// Every virtual path this render actually read, relative to its root,
    /// recorded for the manifest's closure governance.
    closure: Mutex<BTreeSet<String>>,
}

impl RenderWorld {
    /// Build a world for one render. `envelope_json` is the exact canonical
    /// byte string that `sys.inputs.data` will return.
    pub(crate) fn new(
        bundle_root: &Path,
        snapshot: BundleSnapshot,
        fonts: Vec<Font>,
        main_rel_path: &str,
        assets: BTreeMap<String, Bytes>,
        issued: chrono::DateTime<chrono::Utc>,
        envelope_json: String,
    ) -> Result<Self, String> {
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
        Ok(Self {
            library,
            book,
            fonts,
            main_id,
            snapshot,
            bundle_root: bundle_root.to_path_buf(),
            assets,
            issued_utc: issued,
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

    /// Normalize a Typst virtual path into the slash-separated spelling used
    /// by the sealed snapshot. No resolution ever consults the filesystem.
    fn normalize_virtual_path(vpath: &str) -> FileResult<String> {
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
        Ok(clean.to_string_lossy().replace('\\', "/"))
    }

    /// Return the governed snapshot key and caller-safe diagnostic spelling
    /// for one Typst path. Package diagnostics retain Typst's `@ns/name:ver`
    /// form while lookup uses the bundle's `packages/ns/name/ver` layout.
    fn snapshot_path(root: &VirtualRoot, vpath: &str) -> FileResult<(String, String)> {
        let clean = Self::normalize_virtual_path(vpath)?;
        match root {
            VirtualRoot::Project => Ok((clean.clone(), clean)),
            VirtualRoot::Package(spec) => {
                let prefix = format!("@{}/{}:{}", spec.namespace, spec.name, spec.version);
                let key = format!(
                    "packages/{}/{}/{}/{}",
                    spec.namespace, spec.name, spec.version, clean
                );
                Ok((key, closure_key(&prefix, &clean)))
            }
        }
    }

    fn missing(&self, key: &str, display: &str) -> FileError {
        if self.snapshot.is_dir(key) {
            FileError::IsDirectory
        } else {
            FileError::NotFound(PathBuf::from(display))
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
        let (key, display) = Self::snapshot_path(rooted.root(), &vpath)?;
        let bytes = self
            .snapshot
            .get(&key)
            .ok_or_else(|| self.missing(&key, &display))?;
        if !vpath.ends_with(".typ") {
            return Err(FileError::NotSource);
        }
        let text = bytes
            .as_str()
            .map_err(|_| FileError::InvalidUtf8)?
            .to_owned();
        self.record(display);
        Ok(Source::new(id, text))
    }

    fn file(&self, id: FileId) -> FileResult<Bytes> {
        let rooted = id.get();
        let vpath = rooted.vpath().get_without_slash().to_owned();
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
            self.record(vpath);
            return Ok(bytes);
        }
        let (key, display) = Self::snapshot_path(rooted.root(), &vpath)?;
        let bytes = self
            .snapshot
            .get(&key)
            .ok_or_else(|| self.missing(&key, &display))?;
        self.record(display);
        Ok(bytes)
    }

    fn font(&self, index: usize) -> Option<Font> {
        self.fonts.get(index).cloned()
    }

    fn today(&self, offset: Option<Duration>) -> Option<Datetime> {
        // Deterministic: the world clock is the document's issuedAt, never
        // the machine clock. `None` (local) reads as UTC of issuance; an
        // offset shifts the issuance instant itself (22:30Z + 3h lands on
        // the next day), and an offset chrono cannot represent yields None
        // rather than a panic.
        let instant = match offset {
            None => self.issued_utc,
            Some(duration) => {
                // Full-second precision: typst offsets are durations, and
                // real zones sit at half and quarter hours. The saturating
                // cast plus try_seconds keeps an absurd offset at None.
                let seconds = duration.seconds().round() as i64;
                let delta = chrono::TimeDelta::try_seconds(seconds)?;
                self.issued_utc.checked_add_signed(delta)?
            }
        };
        let date = instant.date_naive();
        Datetime::from_ymd(date.year(), date.month() as u8, date.day() as u8)
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
    fn virtual_paths_reject_escape_attempts() {
        assert_eq!(
            RenderWorld::normalize_virtual_path("ok.typ").unwrap(),
            "ok.typ"
        );
        assert_eq!(
            RenderWorld::normalize_virtual_path("../ok.typ").unwrap_err(),
            FileError::AccessDenied
        );
        assert_eq!(
            RenderWorld::normalize_virtual_path("/etc/passwd").unwrap_err(),
            FileError::AccessDenied
        );
    }

    #[test]
    fn not_found_reports_the_virtual_path_not_the_host_root() {
        let root = Path::new("/deployment/private/bundle");
        let world = RenderWorld::new(
            root,
            BundleSnapshot::default(),
            Vec::new(),
            "main.typ",
            BTreeMap::new(),
            chrono::Utc::now(),
            "null".to_owned(),
        )
        .unwrap();
        let err = world.missing("gone.png", "gone.png");
        assert_eq!(err, FileError::NotFound(PathBuf::from("gone.png")));
        let text = err.to_string();
        assert!(!text.contains(&*root.to_string_lossy()), "{text}");
    }

    fn test_world(issued: chrono::DateTime<chrono::Utc>) -> RenderWorld {
        RenderWorld::new(
            Path::new("/unused/bundle"),
            BundleSnapshot::default(),
            Vec::new(),
            "main.typ",
            BTreeMap::new(),
            issued,
            "null".to_owned(),
        )
        .unwrap()
    }

    fn ymd(datetime: Option<Datetime>) -> Option<(i32, u8, u8)> {
        let d = datetime?;
        Some((d.year()?, d.month()?, d.day()?))
    }

    #[test]
    fn today_follows_the_issued_instant_with_and_without_offset() {
        use chrono::TimeZone;
        let issued = chrono::Utc
            .with_ymd_and_hms(2026, 9, 16, 22, 30, 0)
            .unwrap();
        let world = test_world(issued);
        // No offset: UTC of issuance.
        assert_eq!(
            ymd(world.today(None)),
            Some((2026, 9, 16)),
            "today() is the issued date"
        );
        // +3h shifts the INSTANT: 22:30Z becomes 01:30 the next day.
        assert_eq!(
            ymd(world.today(Some(Duration::construct(0, 0, 3, 0, 0)))),
            Some((2026, 9, 17)),
            "today(offset) must shift the issuance instant, not its midnight"
        );
        // Negative offset crossing midnight downwards.
        assert_eq!(
            ymd(world.today(Some(Duration::construct(0, 0, -5, 0, 0)))),
            Some((2026, 9, 16)),
            "22:30Z - 5h is still the 16th"
        );
    }

    #[test]
    fn today_offset_honors_fractional_hours() {
        use chrono::TimeZone;
        // 18:15Z + 5h30m is 23:45 the same day; rounding the offset to a
        // whole 6h would cross midnight and answer the wrong day.
        let issued = chrono::Utc
            .with_ymd_and_hms(2026, 9, 16, 18, 15, 0)
            .unwrap();
        let world = test_world(issued);
        let offset = Duration::construct(0, 30, 5, 0, 0); // 5h30m
        assert_eq!(
            ymd(world.today(Some(offset))),
            Some((2026, 9, 16)),
            "a half-hour offset must not be rounded across midnight"
        );
        // 19:00Z + 5h15m crosses to the next day.
        let issued = chrono::Utc.with_ymd_and_hms(2026, 9, 16, 19, 0, 0).unwrap();
        let world = test_world(issued);
        let offset = Duration::construct(0, 15, 5, 0, 0); // 5h15m
        assert_eq!(
            ymd(world.today(Some(offset))),
            Some((2026, 9, 17)),
            "fractional offsets still cross midnight when they really do"
        );
    }

    #[test]
    fn today_with_an_absurd_offset_returns_none_without_panicking() {
        let world = test_world(chrono::Utc::now());
        assert!(world
            .today(Some(Duration::construct(i64::MAX / 2, 0, 0, 0, 0)))
            .is_none());
        assert!(world
            .today(Some(Duration::construct(i64::MIN / 2, 0, 0, 0, 0)))
            .is_none());
    }
}
