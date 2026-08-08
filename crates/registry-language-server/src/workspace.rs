// SPDX-License-Identifier: Apache-2.0
//! The project roots one session indexes: how a document finds its root, and the document store
//! and index each root keeps.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;

use crate::{
    evidence,
    refs::{document_diagnostic, IndexedDiagnostic, IndexedReference, IndexedSymbol, ProjectIndex},
    relay,
    yaml::ParsedDocument,
};

/// How many roots one session indexes. A client that reaches across many unrelated projects stops
/// adding roots here instead of holding an unbounded part of the filesystem open.
pub(crate) const MAX_INDEXED_ROOTS: usize = 32;

/// How many resolved paths one session remembers.
///
/// The map spares a filesystem call for every document a session works with, which stays a small
/// set even in a large project. It is a cache and not a record, so it stops growing here: a client
/// that delivers a whole branch of changed files at once must not be able to make the server hold
/// that branch's path set for the rest of the session.
const MAX_INTERNED_PATHS: usize = 4096;

const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;

/// What one family's loader found under a root: the documents it read, and the reasons it could
/// not read the rest.
#[derive(Debug)]
pub(crate) struct LoadedProjectDocuments {
    pub(crate) documents: BTreeMap<PathBuf, String>,
    pub(crate) diagnostics: Vec<IndexedDiagnostic>,
}

/// How large a document may be for the family that owns it to index it, and the sentence an author
/// reads when it is larger.
///
/// The two travel together because they are answered together on every path that admits a
/// document: the first scan of a root, a buffer the client opened, and a change that arrived from
/// disk. A ceiling only the first scan applies is a ceiling the editor does not have, and a
/// ceiling applied without its sentence takes a file out of the index with nothing on screen to
/// say so.
#[derive(Debug)]
pub(crate) struct DocumentCeiling {
    pub(crate) max_bytes: u64,
    pub(crate) message: String,
}

impl DocumentCeiling {
    /// The one ceiling a family applies to every document it holds, whatever part that document
    /// plays in the project.
    pub(crate) fn project_document() -> Self {
        Self {
            max_bytes: MAX_DOCUMENT_BYTES,
            message: "Project document exceeds the 1 MiB indexing limit".to_owned(),
        }
    }

    /// Whether a document of this many bytes in hand is one the editor reads. A caller holding a
    /// file's metadata rather than its bytes weighs it against [`Self::max_bytes`] directly, which
    /// is how the first scan of a root refuses a file without reading it.
    pub(crate) fn admits(&self, bytes: usize) -> bool {
        u64::try_from(bytes).is_ok_and(|bytes| bytes <= self.max_bytes)
    }
}

/// A family of project documents. Each one answers for its own roots, its own documents, and its
/// own diagnostics, and never for another family's.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ProjectFamily {
    Relay,
    Evidence,
}

impl ProjectFamily {
    /// Every family discovery tests, in the order it tests them. The order decides a directory that
    /// somehow answers for two families, so it is fixed here rather than left to whichever test
    /// runs first.
    const ALL: &'static [Self] = &[Self::Relay, Self::Evidence];

    /// Whether this family claims a directory as one of its roots.
    fn declares_root(self, directory: &Path) -> bool {
        match self {
            Self::Relay => relay::declares_root(directory),
            Self::Evidence => evidence::declares_root(directory),
        }
    }

    fn load_documents(self, root: &Path) -> Result<LoadedProjectDocuments> {
        match self {
            Self::Relay => relay::load_project_documents(root),
            Self::Evidence => evidence::load_project_documents(root),
        }
    }

    fn owns_document(self, root: &Path, path: &Path) -> bool {
        match self {
            Self::Relay => relay::is_project_document(root, path),
            Self::Evidence => evidence::is_project_document(root, path),
        }
    }

    fn is_safe_authored_file(self, root: &Path, path: &Path) -> bool {
        match self {
            Self::Relay => relay::is_safe_authored_file(root, path),
            Self::Evidence => evidence::is_safe_authored_file(root, path),
        }
    }

    /// How large a document at this path may be for this family to index it.
    ///
    /// Relay holds every project document to one limit. Evidence holds each document to the
    /// ceiling the authoring form gives the part it plays, so a document an author's compiler
    /// refuses for its size is a document the editor refuses for the same size.
    fn document_ceiling(self, root: &Path, path: &Path) -> DocumentCeiling {
        match self {
            Self::Relay => DocumentCeiling::project_document(),
            Self::Evidence => evidence::document_ceiling(root, path),
        }
    }

    /// The directory holding this path, when this family bounds how many documents it indexes from
    /// it, and `None` for every other path.
    ///
    /// Relay bounds none of its directories. Evidence bounds the ones the authoring form bounds and
    /// no others, so a definition the compiler resolves cannot become an unresolved reference on
    /// screen.
    fn bounded_directory_of(self, root: &Path, path: &Path) -> Option<PathBuf> {
        match self {
            Self::Relay => None,
            Self::Evidence => evidence::bounded_directory_of(root, path),
        }
    }

    /// Reads a bounded directory of this family whole, for a caller settling it after a change
    /// arrived from disk. A family that bounds nothing has nothing to settle.
    fn scan_bounded_directory(
        self,
        root: &Path,
        path: &Path,
    ) -> Result<Option<evidence::ScannedDirectory>> {
        match self {
            Self::Relay => Ok(None),
            Self::Evidence => evidence::scan_bounded_directory(root, path),
        }
    }

    /// Builds one family's symbols, references, and diagnostics.
    ///
    /// Both the source text and the parsed tree are passed because the two answer different
    /// questions. The tree gives a name its position, and it gives it whether or not the rest of the
    /// document is finished. The text is what a deserializer reads, and Evidence checks a question's
    /// shape by handing that text to the authoring library rather than by restating its rules here.
    ///
    /// `dropped` names the project's own documents this root holds no text for, each one already
    /// reported for its own reason. A family whose documents are named by where they sit can still
    /// answer for those names, so one unreadable file stays one sentence instead of one sentence per
    /// document that spells it. Relay is not such a family: a Relay name is written inside the
    /// document, so a path there declares nothing on its own.
    pub(crate) fn build_index(
        self,
        root: &Path,
        documents: &BTreeMap<PathBuf, String>,
        parsed: &BTreeMap<PathBuf, ParsedDocument>,
        dropped: &BTreeSet<PathBuf>,
    ) -> (
        Vec<IndexedSymbol>,
        Vec<IndexedReference>,
        Vec<IndexedDiagnostic>,
    ) {
        match self {
            Self::Relay => relay::build_index(root, parsed),
            Self::Evidence => evidence::build_index(root, documents, parsed, dropped),
        }
    }

    /// The name this family's diagnostics are published under.
    ///
    /// An editor groups and filters by this string, and a reader has to be able to tell which tool
    /// is talking. A project that holds both families would otherwise show one undifferentiated
    /// list, so each family says who it is.
    pub(crate) fn diagnostic_source(self) -> &'static str {
        match self {
            Self::Relay => "registry-stack",
            Self::Evidence => "evidence",
        }
    }

    /// The code a diagnostic of this family carries for `rule`, for the rules that belong to no one
    /// symbol kind. See [`crate::refs::SymbolKind::diagnostic_code`] for why Relay publishes none.
    pub(crate) fn diagnostic_code(self, rule: &str) -> Option<String> {
        match self {
            Self::Relay => None,
            Self::Evidence => Some(format!("{}/{rule}", self.diagnostic_source())),
        }
    }
}

/// One indexed project root: the documents it holds, the versions of the ones a client has open,
/// and the index built from both.
#[derive(Debug)]
pub(crate) struct RootState {
    root: PathBuf,
    family: ProjectFamily,
    documents: BTreeMap<PathBuf, String>,
    open_versions: BTreeMap<PathBuf, i32>,
    disk_diagnostics: Vec<IndexedDiagnostic>,
    index: ProjectIndex,
}

impl RootState {
    fn load(root: &Path, family: ProjectFamily) -> Result<Self> {
        let root = root.canonicalize()?;
        let loaded = family.load_documents(&root)?;
        let index = ProjectIndex::from_documents_with_diagnostics(
            family,
            &root,
            &loaded.documents,
            loaded.diagnostics.clone(),
        );
        Ok(Self {
            root,
            family,
            documents: loaded.documents,
            open_versions: BTreeMap::new(),
            disk_diagnostics: loaded.diagnostics,
            index,
        })
    }

    pub(crate) fn index(&self) -> &ProjectIndex {
        &self.index
    }

    /// The name the diagnostics of this root are published under.
    pub(crate) fn diagnostic_source(&self) -> &'static str {
        self.family.diagnostic_source()
    }

    pub(crate) fn open_versions(&self) -> &BTreeMap<PathBuf, i32> {
        &self.open_versions
    }

    /// Takes the text of a buffer the client has open.
    ///
    /// The directory ceiling is deliberately not applied here. It bounds what the editor reads from
    /// a project on its own; a document the client is holding open is one the author is looking at,
    /// and leaving it out would give them a file on screen with no symbols and no reason for it.
    fn update(&mut self, path: PathBuf, text: String, version: i32) {
        if !self.family.owns_document(&self.root, &path) {
            return;
        }
        self.open_versions.insert(path.clone(), version);
        self.disk_diagnostics
            .retain(|diagnostic| diagnostic.path != path);
        let ceiling = self.family.document_ceiling(&self.root, &path);
        if ceiling.admits(text.len()) {
            self.documents.insert(path, text);
        } else {
            // A buffer that has grown past the ceiling stops being indexed and says so. Leaving the
            // last text that fitted would answer every later request from a revision the author can
            // no longer see, and silently: nothing else in the session would report the change.
            self.documents.remove(&path);
            self.disk_diagnostics
                .push(document_diagnostic(&path, &ceiling.message));
        }
        self.rebuild();
    }

    fn close(&mut self, path: &Path) {
        if !self.family.owns_document(&self.root, path) {
            return;
        }
        self.open_versions.remove(path);
        self.reload_from_disk(path);
    }

    /// Applies one batch of watched changes together, as the client delivered it.
    ///
    /// A rename inside a directory the family bounds is the reason this is a batch and not a loop. A
    /// client may deliver the arrival and the departure in one notification, in either order, or
    /// spread over two, and a bounded directory cannot answer any of those a path at a time: an
    /// arrival weighed against what the root holds at that instant is refused for room the departure
    /// beside it is about to free, and the refusal is decided once and never revisited. So a bounded
    /// directory is not changed a path at a time at all. Every one the batch touched is settled from
    /// a fresh read of the directory, which holds the property an author can see for themselves:
    /// after a batch is applied, a bounded directory holds what a first scan of the same tree would
    /// hold.
    fn reload_watched_batch(&mut self, paths: &[PathBuf]) -> Result<()> {
        let mut bounded: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
        for path in paths {
            match self.family.bounded_directory_of(&self.root, path) {
                Some(directory) => {
                    bounded.entry(directory).or_insert_with(|| path.clone());
                }
                None => self.apply_from_disk(path),
            }
        }
        let mut failure = None;
        for path in bounded.into_values() {
            if let Err(error) = self.settle_bounded_directory(&path) {
                failure.get_or_insert(error);
            }
        }
        self.rebuild();
        failure.map_or(Ok(()), Err)
    }

    /// Replaces what this root holds from one bounded directory with what a fresh read of it finds.
    ///
    /// A document the client has open is left alone, text and diagnostics both. The author is
    /// looking at that buffer, and its text is the unsaved revision rather than whatever is on disk.
    /// The read happens before anything is dropped, so a directory the server cannot enumerate
    /// leaves the root exactly as it was and says why.
    fn settle_bounded_directory(&mut self, path: &Path) -> Result<()> {
        let Some(scan) = self.family.scan_bounded_directory(&self.root, path)? else {
            return Ok(());
        };
        let Some(directory) = path.parent() else {
            return Ok(());
        };
        let open_versions = &self.open_versions;
        let settled =
            |path: &Path| path.parent() == Some(directory) && !open_versions.contains_key(path);
        self.documents.retain(|path, _| !settled(path));
        self.disk_diagnostics
            .retain(|diagnostic| !settled(&diagnostic.path));
        for path in scan.admitted {
            self.apply_from_disk(&path);
        }
        self.disk_diagnostics.extend(scan.diagnostics);
        Ok(())
    }

    fn reload_from_disk(&mut self, path: &Path) {
        self.apply_from_disk(path);
        self.rebuild();
    }

    /// Takes one document from disk, without rebuilding the index around it.
    fn apply_from_disk(&mut self, path: &Path) {
        if !self.family.owns_document(&self.root, path) || self.open_versions.contains_key(path) {
            return;
        }
        self.disk_diagnostics
            .retain(|diagnostic| diagnostic.path != path);
        if !self.family.is_safe_authored_file(&self.root, path) {
            self.documents.remove(path);
            return;
        }
        let ceiling = self.family.document_ceiling(&self.root, path);
        match fs::read(path) {
            Ok(bytes) if !ceiling.admits(bytes.len()) => {
                self.documents.remove(path);
                self.disk_diagnostics
                    .push(document_diagnostic(path, &ceiling.message));
            }
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => {
                    self.documents.insert(path.to_path_buf(), text);
                }
                Err(_) => {
                    self.documents.remove(path);
                    self.disk_diagnostics.push(document_diagnostic(
                        path,
                        "Project document is not valid UTF-8 and cannot be indexed",
                    ));
                }
            },
            Err(_) => {
                self.documents.remove(path);
                self.disk_diagnostics.push(document_diagnostic(
                    path,
                    "Project document could not be read; check its permissions",
                ));
            }
        }
    }

    fn rebuild(&mut self) {
        self.index = ProjectIndex::from_documents_with_diagnostics(
            self.family,
            &self.root,
            &self.documents,
            self.disk_diagnostics.clone(),
        );
    }
}

/// Every root this session serves, and the canonical form of each path it has stored.
///
/// A document with no discoverable root is served without an index and without diagnostics rather
/// than as an error: an editor opens YAML that belongs to no project all the time.
#[derive(Debug, Default)]
pub(crate) struct Workspace {
    folders_declared: bool,
    folders: Vec<PathBuf>,
    roots: BTreeMap<PathBuf, RootState>,
    canonical_paths: BTreeMap<PathBuf, PathBuf>,
}

impl Workspace {
    /// Records the folders the client opened. Discovery keeps every root inside one of them, so a
    /// path that leaves the folders through a symbolic link cannot anchor a root.
    pub(crate) fn set_folders(&mut self, folders: Vec<PathBuf>) {
        self.folders_declared = !folders.is_empty();
        self.folders = folders
            .into_iter()
            .filter_map(|folder| folder.canonicalize().ok())
            .collect();
        self.folders.sort();
        self.folders.dedup();
    }

    /// Indexes the workspace folders that are themselves project roots. Nothing is scanned below a
    /// folder; a root deeper in the tree is found when a document inside it opens.
    pub(crate) fn adopt_folder_roots(&mut self) -> Vec<anyhow::Error> {
        let mut errors = Vec::new();
        for folder in self.folders.clone() {
            if let Some((root, family)) = self.root_at(&folder) {
                if let Err(error) = self.insert_root(root, family) {
                    errors.push(error);
                }
            }
        }
        errors
    }

    /// Indexes the root that owns `path`, if one exists and is not indexed already.
    pub(crate) fn ensure_root_for(&mut self, path: &Path) -> Result<()> {
        if self.root_for(path).is_some() {
            return Ok(());
        }
        let Some((root, family)) = self.root_above(path) else {
            return Ok(());
        };
        self.insert_root(root, family)
    }

    fn insert_root(&mut self, root: PathBuf, family: ProjectFamily) -> Result<()> {
        if self.roots.contains_key(&root) || self.roots.len() >= MAX_INDEXED_ROOTS {
            return Ok(());
        }
        let state = RootState::load(&root, family)?;
        self.roots.insert(root, state);
        Ok(())
    }

    /// The canonical form of a path the server is about to store, remembered so later requests for
    /// the same document resolve by lookup instead of by another filesystem call.
    ///
    /// Past [`MAX_INTERNED_PATHS`] the answer is still correct and only costs what it costs: a path
    /// the map does not hold is resolved from the filesystem, which is what [`Self::resolve`] does
    /// for every path a session has never stored.
    pub(crate) fn intern(&mut self, path: &Path) -> PathBuf {
        if let Some(canonical) = self.canonical_paths.get(path) {
            return canonical.clone();
        }
        let canonical = canonical_path(path);
        if self.canonical_paths.len() < MAX_INTERNED_PATHS {
            self.canonical_paths
                .insert(path.to_path_buf(), canonical.clone());
        }
        canonical
    }

    /// The canonical form of a path a request names. Paths the server has stored resolve from the
    /// map; anything else falls back to the filesystem.
    pub(crate) fn resolve(&self, path: &Path) -> PathBuf {
        self.canonical_paths
            .get(path)
            .cloned()
            .unwrap_or_else(|| canonical_path(path))
    }

    pub(crate) fn roots(&self) -> impl Iterator<Item = &RootState> {
        self.roots.values()
    }

    /// The indexed root that owns a canonical path: the deepest root the path sits under.
    pub(crate) fn root_for(&self, path: &Path) -> Option<&RootState> {
        self.roots
            .values()
            .rfind(|state| path.starts_with(&state.root))
    }

    fn root_for_mut(&mut self, path: &Path) -> Option<&mut RootState> {
        self.roots
            .values_mut()
            .rfind(|state| path.starts_with(&state.root))
    }

    pub(crate) fn update(&mut self, path: PathBuf, text: String, version: i32) {
        if let Some(state) = self.root_for_mut(&path) {
            state.update(path, text, version);
        }
    }

    pub(crate) fn close(&mut self, path: &Path) {
        if let Some(state) = self.root_for_mut(path) {
            state.close(path);
        }
    }

    /// Applies one batch of watched changes, root by root.
    ///
    /// The batch is split by the root that owns each path and handed on whole, because a root that
    /// sees half a batch answers a question the client did not ask. A root that cannot read one of
    /// its own directories is reported once, and the roots after it are still applied: a session
    /// that stopped at the first unreadable directory would leave every later root holding text its
    /// files no longer have.
    pub(crate) fn reload_watched(&mut self, paths: &[PathBuf]) -> Result<()> {
        let mut batches: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
        for path in paths {
            if let Some(root) = self.root_for(path).map(|state| state.root.clone()) {
                batches.entry(root).or_default().push(path.clone());
            }
        }
        let mut failure = None;
        for (root, batch) in batches {
            if let Some(state) = self.roots.get_mut(&root) {
                if let Err(error) = state.reload_watched_batch(&batch) {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// Tests one directory against every family. This never walks anywhere: a workspace folder is
    /// a root or it is not.
    fn root_at(&self, directory: &Path) -> Option<(PathBuf, ProjectFamily)> {
        for family in ProjectFamily::ALL {
            if !family.declares_root(directory) {
                continue;
            }
            let Ok(root) = directory.canonicalize() else {
                continue;
            };
            if !self.contains(&root) {
                continue;
            }
            return Some((root, *family));
        }
        None
    }

    /// Walks up from a document to the nearest directory that marks a project root.
    fn root_above(&self, start: &Path) -> Option<(PathBuf, ProjectFamily)> {
        let start = if start.is_file() {
            start.parent()?
        } else {
            start
        };
        start
            .ancestors()
            .find_map(|candidate| self.root_at(candidate))
    }

    /// Whether a candidate root lies inside the folders the client opened.
    ///
    /// A session with no folders at all has nothing to contain the root to and accepts whatever the
    /// walk reaches. A session whose declared folders all failed to resolve accepts nothing: the
    /// workspace the client named is not on this filesystem, so no root can be inside it.
    fn contains(&self, root: &Path) -> bool {
        if !self.folders_declared {
            return true;
        }
        self.folders.iter().any(|folder| root.starts_with(folder))
    }
}

fn canonical_path(path: &Path) -> PathBuf {
    if let Ok(path) = path.canonicalize() {
        return path;
    }
    path.parent()
        .and_then(|parent| parent.canonicalize().ok())
        .and_then(|parent| path.file_name().map(|name| parent.join(name)))
        .unwrap_or_else(|| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use registry_evidence_authoring::{
        layout::{
            ACCESS_DIRECTORY, ACCESS_POLICIES_DIRECTORY, MAX_QUESTIONS, MAX_QUESTION_BYTES,
            OPENAPI_FILE, QUESTIONS_DIRECTORY,
        },
        marker::{default_project_marker_document, PROJECT_MARKER_FILE},
    };
    use tempfile::TempDir;
    use tower_lsp_server::ls_types::Position;

    use super::*;
    use crate::refs::DOCUMENT_START;

    const MANIFEST: &str = "version: 1\nregistry: { id: demo }\nservices: {}\n";
    /// Enough of a question for the tests here, which are about which root owns which file. What a
    /// whole question has to say for itself is `crates/registry-language-server/tests/`.
    const QUESTION: &str = "version: 1\nid: adult-status\n";

    fn project_in(directory: &Path) {
        fs::create_dir_all(directory).unwrap();
        fs::write(directory.join("registry-stack.yaml"), MANIFEST).unwrap();
    }

    /// An authoring project as `evidencectl` leaves it: a marker over the description and the
    /// questions.
    fn evidence_project_in(directory: &Path) {
        evidence_project_without_marker_in(directory);
        fs::write(
            directory.join(PROJECT_MARKER_FILE),
            default_project_marker_document(),
        )
        .unwrap();
    }

    /// The same project as written before the marker existed.
    fn evidence_project_without_marker_in(directory: &Path) {
        fs::create_dir_all(directory.join(QUESTIONS_DIRECTORY)).unwrap();
        fs::write(directory.join(OPENAPI_FILE), "openapi: 3.1.0\n").unwrap();
        fs::write(
            directory
                .join(QUESTIONS_DIRECTORY)
                .join("adult-status.yaml"),
            QUESTION,
        )
        .unwrap();
    }

    fn workspace_over(folders: &[&Path]) -> Workspace {
        let mut workspace = Workspace::default();
        workspace.set_folders(folders.iter().map(|path| path.to_path_buf()).collect());
        workspace.adopt_folder_roots();
        workspace
    }

    #[test]
    fn finds_project_from_nested_directory() {
        let temp = TempDir::new().unwrap();
        project_in(temp.path());
        let nested = temp.path().join("integrations/people");
        fs::create_dir_all(&nested).unwrap();

        let workspace = Workspace::default();
        assert_eq!(
            workspace.root_above(&nested),
            Some((temp.path().canonicalize().unwrap(), ProjectFamily::Relay))
        );
    }

    #[test]
    fn a_workspace_folder_that_is_a_project_is_indexed_at_initialize() {
        let temp = TempDir::new().unwrap();
        project_in(temp.path());

        let workspace = workspace_over(&[temp.path()]);

        assert_eq!(workspace.roots().count(), 1);
        assert!(workspace.roots().any(|state| state
            .index()
            .workspace_symbols("demo")
            .iter()
            .any(|symbol| symbol.name == "demo")));
    }

    #[test]
    fn a_root_below_a_workspace_folder_is_indexed_when_a_document_opens() {
        let temp = TempDir::new().unwrap();
        let nested = temp.path().join("projects/registry");
        project_in(&nested);

        let mut workspace = workspace_over(&[temp.path()]);
        assert_eq!(workspace.roots().count(), 0);

        workspace
            .ensure_root_for(&nested.join("registry-stack.yaml").canonicalize().unwrap())
            .unwrap();

        assert_eq!(workspace.roots().count(), 1);
        assert!(workspace
            .root_for(&nested.canonicalize().unwrap().join("registry-stack.yaml"))
            .is_some());
    }

    #[cfg(unix)]
    #[test]
    fn a_root_reached_through_a_symlinked_ancestor_is_rejected() {
        let temp = TempDir::new().unwrap();
        let folder = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&folder).unwrap();
        project_in(&outside);
        std::os::unix::fs::symlink(&outside, folder.join("link")).unwrap();

        let mut workspace = workspace_over(&[&folder]);
        let through_link = folder.join("link/registry-stack.yaml");
        assert!(
            fs::symlink_metadata(&through_link)
                .is_ok_and(|metadata| metadata.file_type().is_file()),
            "the fixture must place a real project file behind the link"
        );

        assert_eq!(workspace.root_above(&through_link), None);
        workspace.ensure_root_for(&through_link).unwrap();
        assert_eq!(workspace.roots().count(), 0);

        // The same project is reachable once the client opens the folder that really holds it.
        let unconstrained = Workspace::default();
        assert_eq!(
            unconstrained.root_above(&through_link),
            Some((outside.canonicalize().unwrap(), ProjectFamily::Relay))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_project_file_does_not_declare_a_root() {
        let temp = TempDir::new().unwrap();
        let real = temp.path().join("real");
        let decoy = temp.path().join("decoy");
        project_in(&real);
        fs::create_dir_all(&decoy).unwrap();
        std::os::unix::fs::symlink(
            real.join("registry-stack.yaml"),
            decoy.join("registry-stack.yaml"),
        )
        .unwrap();

        let workspace = workspace_over(&[&decoy]);

        assert_eq!(workspace.roots().count(), 0);
    }

    #[test]
    fn an_evidence_marker_declares_an_evidence_root() {
        let temp = TempDir::new().unwrap();
        evidence_project_in(temp.path());

        let workspace = Workspace::default();

        assert_eq!(
            workspace.root_at(temp.path()),
            Some((temp.path().canonicalize().unwrap(), ProjectFamily::Evidence))
        );
    }

    #[test]
    fn an_evidence_project_without_a_marker_is_declared_by_its_description_and_questions() {
        let temp = TempDir::new().unwrap();
        evidence_project_without_marker_in(temp.path());
        assert!(
            !temp.path().join(PROJECT_MARKER_FILE).exists(),
            "the fixture must leave the project unmarked"
        );

        let workspace = Workspace::default();

        assert_eq!(
            workspace.root_at(temp.path()),
            Some((temp.path().canonicalize().unwrap(), ProjectFamily::Evidence))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_evidence_marker_does_not_declare_a_root() {
        let temp = TempDir::new().unwrap();
        let real = temp.path().join("real");
        let decoy = temp.path().join("decoy");
        evidence_project_in(&real);
        fs::create_dir_all(&decoy).unwrap();
        std::os::unix::fs::symlink(
            real.join(PROJECT_MARKER_FILE),
            decoy.join(PROJECT_MARKER_FILE),
        )
        .unwrap();

        let workspace = Workspace::default();

        assert_eq!(workspace.root_at(&decoy), None);
    }

    #[cfg(unix)]
    #[test]
    fn an_unmarked_evidence_project_reached_through_a_symbolic_link_does_not_declare_a_root() {
        let temp = TempDir::new().unwrap();
        let real = temp.path().join("real");
        evidence_project_without_marker_in(&real);

        let linked_questions = temp.path().join("linked-questions");
        fs::create_dir_all(&linked_questions).unwrap();
        fs::write(linked_questions.join(OPENAPI_FILE), "openapi: 3.1.0\n").unwrap();
        std::os::unix::fs::symlink(
            real.join(QUESTIONS_DIRECTORY),
            linked_questions.join(QUESTIONS_DIRECTORY),
        )
        .unwrap();

        let linked_description = temp.path().join("linked-description");
        fs::create_dir_all(linked_description.join(QUESTIONS_DIRECTORY)).unwrap();
        std::os::unix::fs::symlink(
            real.join(OPENAPI_FILE),
            linked_description.join(OPENAPI_FILE),
        )
        .unwrap();

        let workspace = Workspace::default();

        assert_eq!(workspace.root_at(&linked_questions), None);
        assert_eq!(workspace.root_at(&linked_description), None);
    }

    #[test]
    fn an_evidence_root_loads_its_documents_and_declares_what_they_name() {
        let temp = TempDir::new().unwrap();
        evidence_project_in(temp.path());

        let workspace = workspace_over(&[temp.path()]);

        let root = workspace.roots().next().expect("the project is a root");
        let question = temp
            .path()
            .canonicalize()
            .unwrap()
            .join(QUESTIONS_DIRECTORY)
            .join("adult-status.yaml");
        assert!(root.index().document_paths().any(|path| path == question));
        assert_eq!(
            root.index()
                .workspace_symbols("adult-status")
                .into_iter()
                .map(|symbol| symbol.location.path.clone())
                .collect::<Vec<_>>(),
            vec![question],
            "the question document declares the question its file is named for"
        );
        // The stub above is not a whole question, and the authoring form says so once.
        assert_eq!(
            root.index()
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.code.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("evidence/question-shape")]
        );
    }

    #[test]
    fn sibling_roots_of_two_families_each_answer_for_their_own_documents() {
        let temp = TempDir::new().unwrap();
        let relay = temp.path().join("relay");
        let evidence = temp.path().join("evidence");
        project_in(&relay);
        evidence_project_in(&evidence);

        let workspace = workspace_over(&[&relay, &evidence]);
        assert_eq!(workspace.roots().count(), 2);

        let manifest = relay.join("registry-stack.yaml").canonicalize().unwrap();
        let question = evidence
            .join(QUESTIONS_DIRECTORY)
            .join("adult-status.yaml")
            .canonicalize()
            .unwrap();
        let relay_root = workspace.root_for(&manifest).unwrap();
        let evidence_root = workspace.root_for(&question).unwrap();

        assert_eq!(relay_root.family, ProjectFamily::Relay);
        assert_eq!(evidence_root.family, ProjectFamily::Evidence);
        assert_eq!(relay_root.diagnostic_source(), "registry-stack");
        assert_eq!(evidence_root.diagnostic_source(), "evidence");
        assert!(relay_root
            .index()
            .document_paths()
            .any(|path| path == manifest));
        assert!(!relay_root
            .index()
            .document_paths()
            .any(|path| path == question));
        assert!(evidence_root
            .index()
            .document_paths()
            .any(|path| path == question));
        assert!(!evidence_root
            .index()
            .document_paths()
            .any(|path| path == manifest));
    }

    #[test]
    fn declared_folders_that_do_not_resolve_contain_nothing() {
        let temp = TempDir::new().unwrap();
        project_in(temp.path());

        let mut workspace = workspace_over(&[&temp.path().join("does-not-exist")]);
        workspace
            .ensure_root_for(&temp.path().join("registry-stack.yaml"))
            .unwrap();

        assert_eq!(workspace.roots().count(), 0);
    }

    #[test]
    fn a_document_outside_every_root_is_served_without_an_index() {
        let temp = TempDir::new().unwrap();
        let loose = temp.path().join("notes.yaml");
        fs::write(&loose, "id: loose\n").unwrap();

        let mut workspace = workspace_over(&[temp.path()]);
        workspace
            .ensure_root_for(&loose.canonicalize().unwrap())
            .unwrap();
        workspace.update(loose.canonicalize().unwrap(), "id: loose\n".to_owned(), 1);

        assert_eq!(workspace.roots().count(), 0);
        assert!(workspace.root_for(&loose).is_none());
        assert_eq!(
            workspace
                .roots()
                .flat_map(|state| state.index().diagnostics())
                .count(),
            0
        );
    }

    #[test]
    fn indexed_roots_stop_at_the_cap() {
        let temp = TempDir::new().unwrap();
        let mut workspace = Workspace::default();
        for index in 0..MAX_INDEXED_ROOTS + 4 {
            let root = temp.path().join(format!("project-{index}"));
            project_in(&root);
            workspace
                .ensure_root_for(&root.join("registry-stack.yaml").canonicalize().unwrap())
                .unwrap();
        }

        assert_eq!(workspace.roots().count(), MAX_INDEXED_ROOTS);
    }

    #[test]
    fn each_root_answers_for_its_own_documents() {
        let temp = TempDir::new().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(
            first.join("registry-stack.yaml"),
            "version: 1\nregistry: { id: first-registry }\nservices: {}\n",
        )
        .unwrap();
        fs::write(
            second.join("registry-stack.yaml"),
            "version: 1\nregistry: { id: second-registry }\nservices: {}\n",
        )
        .unwrap();

        let mut workspace = workspace_over(&[&first, &second]);
        assert_eq!(workspace.roots().count(), 2);

        let first_manifest = first.join("registry-stack.yaml").canonicalize().unwrap();
        let second_manifest = second.join("registry-stack.yaml").canonicalize().unwrap();
        assert!(workspace
            .root_for(&first_manifest)
            .unwrap()
            .index()
            .workspace_symbols("second-registry")
            .is_empty());
        assert!(workspace
            .root_for(&second_manifest)
            .unwrap()
            .index()
            .workspace_symbols("second-registry")
            .iter()
            .any(|symbol| symbol.name == "second-registry"));

        workspace.update(
            second_manifest.clone(),
            "version: 1\nregistry: { id: renamed }\nservices: {}\n".to_owned(),
            2,
        );
        assert!(workspace
            .root_for(&first_manifest)
            .unwrap()
            .index()
            .workspace_symbols("first-registry")
            .iter()
            .any(|symbol| symbol.name == "first-registry"));
        assert!(workspace
            .root_for(&second_manifest)
            .unwrap()
            .index()
            .workspace_symbols("renamed")
            .iter()
            .any(|symbol| symbol.name == "renamed"));
    }

    #[test]
    fn a_stored_path_resolves_without_returning_to_the_filesystem() {
        let temp = TempDir::new().unwrap();
        project_in(temp.path());
        let mut workspace = workspace_over(&[temp.path()]);

        let as_the_client_sends_it = temp.path().join("registry-stack.yaml");
        let canonical = workspace.intern(&as_the_client_sends_it);
        assert_eq!(canonical, as_the_client_sends_it.canonicalize().unwrap());

        fs::remove_file(&as_the_client_sends_it).unwrap();
        assert_eq!(workspace.resolve(&as_the_client_sends_it), canonical);
    }

    /// The interned map stops growing, and a session that has filled it keeps answering.
    ///
    /// A client that watches a large repository can deliver an unbounded number of distinct paths
    /// over one session, and every one of them is interned. The map is a cache and not a record, so
    /// past the bound a path is resolved and not stored, and the size is the whole of the behaviour:
    /// nothing an author sees changes, which is why it is read here directly.
    #[test]
    fn the_interned_paths_stop_at_the_cap_and_the_session_keeps_answering() {
        let temp = TempDir::new().unwrap();
        project_in(temp.path());
        let entities = temp.path().join("entities");
        fs::create_dir(&entities).unwrap();
        let mut workspace = workspace_over(&[temp.path()]);

        for index in 0..MAX_INTERNED_PATHS + 8 {
            workspace.intern(&entities.join(format!("person-{index:05}.yaml")));
        }

        assert_eq!(workspace.canonical_paths.len(), MAX_INTERNED_PATHS);
        let past_the_cap = entities.join(format!("person-{:05}.yaml", MAX_INTERNED_PATHS + 7));
        assert_eq!(
            workspace.resolve(&past_the_cap),
            entities
                .canonicalize()
                .unwrap()
                .join(past_the_cap.file_name().unwrap()),
            "a path the map has no room for is still resolved, from the filesystem"
        );
    }

    #[test]
    fn invalid_edits_index_what_still_parses_and_report_one_syntax_error() {
        let temp = TempDir::new().unwrap();
        project_in(temp.path());
        let mut state = RootState::load(temp.path(), ProjectFamily::Relay).unwrap();
        let manifest = temp
            .path()
            .join("registry-stack.yaml")
            .canonicalize()
            .unwrap();
        state.update(
            manifest.clone(),
            "version: 1\nregistry: { id: current }\nservices: {}\n".to_owned(),
            2,
        );
        assert!(state
            .index
            .workspace_symbols("current")
            .iter()
            .any(|symbol| symbol.name == "current"));

        state.update(
            manifest.clone(),
            "version: 1\nregistry: { id: current }\nservices: {}\nbroken: [\n".to_owned(),
            3,
        );
        assert_eq!(state.open_versions.get(&manifest), Some(&3));
        assert!(state
            .index
            .workspace_symbols("current")
            .iter()
            .any(|symbol| symbol.name == "current"));
        assert_eq!(
            state
                .index
                .definitions_at(&manifest, Position::new(1, 20))
                .len(),
            1
        );
        let diagnostics = state.index.diagnostics();
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert!(diagnostics[0].message.starts_with("Invalid YAML syntax"));
        assert_eq!(diagnostics[0].range.start, Position::new(3, 8));

        state.update(manifest.clone(), "registry: [\n".to_owned(), 4);
        assert!(state.index.workspace_symbols("current").is_empty());
        assert_eq!(state.index.diagnostics().len(), 1);
    }

    #[test]
    fn reloads_external_changes_from_disk() {
        let temp = TempDir::new().unwrap();
        project_in(temp.path());
        let manifest = temp
            .path()
            .join("registry-stack.yaml")
            .canonicalize()
            .unwrap();
        let mut state = RootState::load(temp.path(), ProjectFamily::Relay).unwrap();

        fs::write(
            &manifest,
            "version: 1\nregistry: { id: external }\nservices: {}\n",
        )
        .unwrap();
        state.reload_from_disk(&manifest);

        assert!(state
            .index
            .workspace_symbols("external")
            .iter()
            .any(|symbol| symbol.name == "external"));
    }

    #[test]
    fn adds_and_removes_external_project_documents() {
        let temp = TempDir::new().unwrap();
        project_in(temp.path());
        let mut state = RootState::load(temp.path(), ProjectFamily::Relay).unwrap();
        let entities = temp.path().join("entities");
        fs::create_dir(&entities).unwrap();
        let entity = entities.join("person.yaml");
        fs::write(&entity, "version: 1\nid: person\n").unwrap();
        let entity = entity.canonicalize().unwrap();

        state
            .reload_watched_batch(std::slice::from_ref(&entity))
            .unwrap();
        assert!(state
            .index
            .workspace_symbols("person")
            .iter()
            .any(|symbol| symbol.name == "person"));

        fs::remove_file(&entity).unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&entity))
            .unwrap();
        assert!(state.index.workspace_symbols("person").is_empty());
    }

    /// The role ceilings are the authoring form's, so the fixtures below build a question past
    /// `MAX_QUESTION_BYTES` rather than past the workspace-wide limit: a document under 1 MiB and
    /// over 64 KiB is exactly the document the two limits disagree about.
    fn oversized_question() -> String {
        let mut text = String::from("version: 1\nid: adult-status\n#");
        text.push_str(&" ".repeat(MAX_QUESTION_BYTES as usize));
        text
    }

    fn evidence_root_with_a_question(directory: &Path) -> (RootState, PathBuf) {
        evidence_project_in(directory);
        let state = RootState::load(directory, ProjectFamily::Evidence).unwrap();
        let question = directory
            .join(QUESTIONS_DIRECTORY)
            .join("adult-status.yaml")
            .canonicalize()
            .unwrap();
        (state, question)
    }

    fn ceiling_messages(state: &RootState) -> Vec<&str> {
        state
            .index
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("limit the editor indexes"))
            .map(|diagnostic| diagnostic.message.as_str())
            .collect()
    }

    #[test]
    fn an_open_buffer_past_its_role_s_ceiling_is_dropped_and_reported() {
        let temp = TempDir::new().unwrap();
        let (mut state, question) = evidence_root_with_a_question(temp.path());
        let written = state.index.workspace_symbols("adult-status");
        assert_eq!(written.len(), 1);
        assert_ne!(
            written[0].location.range, DOCUMENT_START,
            "a question the root reads is anchored at the identifier it writes"
        );

        state.update(question.clone(), oversized_question(), 2);

        assert!(!state.documents.contains_key(&question));
        let declared = state.index.workspace_symbols("adult-status");
        assert_eq!(
            declared
                .iter()
                .map(|symbol| symbol.location.range)
                .collect::<Vec<_>>(),
            vec![DOCUMENT_START],
            "the file still declares the question, and nothing is answered from the text the buffer no longer holds"
        );
        assert_eq!(
            ceiling_messages(&state),
            vec!["This question exceeds the 65536-byte limit the editor indexes"]
        );
    }

    #[test]
    fn a_change_on_disk_past_its_role_s_ceiling_is_refused_and_reported() {
        let temp = TempDir::new().unwrap();
        let (mut state, question) = evidence_root_with_a_question(temp.path());

        fs::write(&question, oversized_question()).unwrap();
        state.reload_from_disk(&question);

        assert!(!state.documents.contains_key(&question));
        assert_eq!(
            ceiling_messages(&state),
            vec!["This question exceeds the 65536-byte limit the editor indexes"]
        );
    }

    #[test]
    fn the_ceiling_the_first_scan_reported_survives_opening_and_closing_the_file() {
        let temp = TempDir::new().unwrap();
        evidence_project_in(temp.path());
        let question = temp.path().join(QUESTIONS_DIRECTORY).join("large.yaml");
        fs::write(&question, oversized_question()).unwrap();
        let question = question.canonicalize().unwrap();
        let mut state = RootState::load(temp.path(), ProjectFamily::Evidence).unwrap();
        assert_eq!(ceiling_messages(&state).len(), 1);

        state.update(question.clone(), oversized_question(), 1);
        assert_eq!(ceiling_messages(&state).len(), 1, "opening it keeps it");

        state.close(&question);
        assert_eq!(ceiling_messages(&state).len(), 1, "closing it keeps it");
    }

    /// An authoring project whose questions directory holds exactly the [`MAX_QUESTIONS`] documents
    /// the authoring form allows, and one access policy admitting `admitted`.
    ///
    /// `admitted` need not exist yet: the tests below move it in and out of the directory, and the
    /// policy is there so that a question the root fails to hold shows up twice, once as the
    /// refusal and once as the unresolved name.
    fn full_questions_project(directory: &Path, admitted: &str) -> (RootState, PathBuf) {
        evidence_project_in(directory);
        let questions = directory.join(QUESTIONS_DIRECTORY);
        for index in 0..MAX_QUESTIONS - 1 {
            write_question(&questions, &format!("filler-{index:03}"));
        }
        let policies = directory
            .join(ACCESS_DIRECTORY)
            .join(ACCESS_POLICIES_DIRECTORY);
        fs::create_dir_all(&policies).unwrap();
        fs::write(
            policies.join("admissions.yaml"),
            format!("version: 1\nid: admissions\nquestions: [{admitted}]\n"),
        )
        .unwrap();
        let state = RootState::load(directory, ProjectFamily::Evidence).unwrap();
        let questions = questions.canonicalize().unwrap();
        assert_eq!(questions_held(&state, &questions), MAX_QUESTIONS);
        (state, questions)
    }

    fn write_question(questions: &Path, name: &str) {
        fs::write(
            questions.join(format!("{name}.yaml")),
            format!("version: 1\nid: {name}\n"),
        )
        .unwrap();
    }

    fn questions_held(state: &RootState, questions: &Path) -> usize {
        state
            .documents
            .keys()
            .filter(|path| path.parent() == Some(questions))
            .count()
    }

    fn documents_not_indexed(state: &RootState) -> Vec<&str> {
        state
            .index
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("not indexed"))
            .map(|diagnostic| diagnostic.message.as_str())
            .collect()
    }

    fn unresolved_questions(state: &RootState) -> Vec<&str> {
        state
            .index
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_deref() == Some("evidence/unknown-question"))
            .map(|diagnostic| diagnostic.message.as_str())
            .collect()
    }

    /// A rename inside a full bounded directory, delivered the way a client delivers one: a single
    /// batch holding the arrival and the departure, in whatever order the client chose.
    ///
    /// The project holds exactly the documents the authoring form allows both before and after the
    /// rename, so `evidencectl` builds it either way and the editor has nothing to report. Applying
    /// the batch a path at a time cannot hold that: the arrival is refused for a directory the
    /// departure is about to leave room in.
    #[test]
    fn a_rename_inside_a_full_bounded_directory_reports_nothing() {
        let temp = TempDir::new().unwrap();
        let (mut state, questions) = full_questions_project(temp.path(), "aaa-renamed");
        let arrived = questions.join("aaa-renamed.yaml");
        let departed = questions.join("filler-126.yaml");
        assert!(
            arrived < departed,
            "the arrival has to sort first for the order inside the batch to matter"
        );

        fs::remove_file(&departed).unwrap();
        write_question(&questions, "aaa-renamed");
        state
            .reload_watched_batch(&[arrived.clone(), departed.clone()])
            .unwrap();

        assert!(state.documents.contains_key(&arrived));
        assert!(!state.documents.contains_key(&departed));
        assert_eq!(questions_held(&state, &questions), MAX_QUESTIONS);
        assert_eq!(documents_not_indexed(&state), Vec::<&str>::new());
        assert_eq!(unresolved_questions(&state), Vec::<&str>::new());
    }

    /// The same rename spread over two batches, which a client is equally free to deliver: the
    /// author writes a question the directory has no room for, and deletes another one afterwards.
    /// The first batch is a project the authoring form refuses and the editor says so, and the
    /// second one is a project it accepts, so the refusal has to lift on its own.
    #[test]
    fn a_document_a_full_directory_refused_is_taken_once_a_later_batch_frees_room() {
        let temp = TempDir::new().unwrap();
        let (mut state, questions) = full_questions_project(temp.path(), "zzz-arrived");
        let arrived = questions.join("zzz-arrived.yaml");
        write_question(&questions, "zzz-arrived");
        state
            .reload_watched_batch(std::slice::from_ref(&arrived))
            .unwrap();
        assert!(
            !state.documents.contains_key(&arrived),
            "129 questions is a project the authoring form refuses"
        );
        assert_eq!(documents_not_indexed(&state).len(), 1);

        let departed = questions.join("filler-000.yaml");
        fs::remove_file(&departed).unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&departed))
            .unwrap();

        assert!(state.documents.contains_key(&arrived));
        assert_eq!(questions_held(&state, &questions), MAX_QUESTIONS);
        assert_eq!(documents_not_indexed(&state), Vec::<&str>::new());
        assert_eq!(unresolved_questions(&state), Vec::<&str>::new());
    }

    /// A directory that really does overflow keeps reporting it, and reports it about the first
    /// document it stopped reading rather than about whichever one happened to arrive last.
    #[test]
    fn a_bounded_directory_that_overflows_reports_the_first_document_it_stopped_reading() {
        let temp = TempDir::new().unwrap();
        let (mut state, questions) = full_questions_project(temp.path(), "adult-status");
        let extra = questions.join("zzz-extra.yaml");
        write_question(&questions, "zzz-extra");
        state
            .reload_watched_batch(std::slice::from_ref(&extra))
            .unwrap();

        assert!(!state.documents.contains_key(&extra));
        assert_eq!(questions_held(&state, &questions), MAX_QUESTIONS);
        assert!(
            state.index.diagnostics().iter().any(|diagnostic| {
                diagnostic.path == extra
                    && diagnostic.message
                        == "This project directory holds more than the 128 documents the editor indexes; this file and the ones after it are not indexed"
            }),
            "{:?}",
            documents_not_indexed(&state)
        );
    }

    #[test]
    fn a_directory_the_authoring_form_does_not_bound_keeps_taking_documents_from_disk() {
        let temp = TempDir::new().unwrap();
        evidence_project_in(temp.path());
        let selectors = temp.path().join("selectors");
        fs::create_dir_all(&selectors).unwrap();
        for index in 0..MAX_QUESTIONS {
            fs::write(
                selectors.join(format!("profile-{index:03}.yaml")),
                "kind: exact\n",
            )
            .unwrap();
        }
        let mut state = RootState::load(temp.path(), ProjectFamily::Evidence).unwrap();

        let extra = selectors.join("profile-999.yaml");
        fs::write(&extra, "kind: exact\n").unwrap();
        let extra = extra.canonicalize().unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&extra))
            .unwrap();

        assert!(
            state.documents.contains_key(&extra),
            "the compiler reads every selector, so the editor does too"
        );
        assert!(state
            .index
            .workspace_symbols("profile-999")
            .iter()
            .any(|symbol| symbol.name == "profile-999"));
    }

    #[test]
    fn external_changes_do_not_replace_an_open_document() {
        let temp = TempDir::new().unwrap();
        project_in(temp.path());
        let manifest = temp
            .path()
            .join("registry-stack.yaml")
            .canonicalize()
            .unwrap();
        let mut state = RootState::load(temp.path(), ProjectFamily::Relay).unwrap();
        state.update(
            manifest.clone(),
            "version: 1\nregistry: { id: unsaved }\nservices: {}\n".to_owned(),
            7,
        );

        fs::write(
            &manifest,
            "version: 1\nregistry: { id: on-disk }\nservices: {}\n",
        )
        .unwrap();
        state.reload_from_disk(&manifest);

        assert!(state
            .index
            .workspace_symbols("unsaved")
            .iter()
            .any(|symbol| symbol.name == "unsaved"));
        assert!(state.index.workspace_symbols("on-disk").is_empty());

        state.close(&manifest);
        assert!(state
            .index
            .workspace_symbols("on-disk")
            .iter()
            .any(|symbol| symbol.name == "on-disk"));
    }
}
