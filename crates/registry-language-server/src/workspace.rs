// SPDX-License-Identifier: Apache-2.0
//! The project roots one session indexes: how a document finds its root, and the document store
//! and index each root keeps.

use std::{
    collections::BTreeMap,
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

const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// What one family's loader found under a root: the documents it read, and the reasons it could
/// not read the rest.
#[derive(Debug)]
pub(crate) struct LoadedProjectDocuments {
    pub(crate) documents: BTreeMap<PathBuf, String>,
    pub(crate) diagnostics: Vec<IndexedDiagnostic>,
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

    /// Builds one family's symbols, references, and diagnostics.
    ///
    /// Both the source text and the parsed tree are passed because the two answer different
    /// questions. The tree gives a name its position, and it gives it whether or not the rest of the
    /// document is finished. The text is what a deserializer reads, and Evidence checks a question's
    /// shape by handing that text to the authoring library rather than by restating its rules here.
    pub(crate) fn build_index(
        self,
        root: &Path,
        documents: &BTreeMap<PathBuf, String>,
        parsed: &BTreeMap<PathBuf, ParsedDocument>,
    ) -> (
        Vec<IndexedSymbol>,
        Vec<IndexedReference>,
        Vec<IndexedDiagnostic>,
    ) {
        match self {
            Self::Relay => relay::build_index(root, parsed),
            Self::Evidence => evidence::build_index(root, documents, parsed),
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

    fn update(&mut self, path: PathBuf, text: String, version: i32) {
        if !self.family.owns_document(&self.root, &path) {
            return;
        }
        self.open_versions.insert(path.clone(), version);
        if text.len() <= MAX_DOCUMENT_BYTES {
            self.disk_diagnostics
                .retain(|diagnostic| diagnostic.path != path);
            self.documents.insert(path, text);
            self.rebuild();
        }
    }

    fn close(&mut self, path: &Path) {
        if !self.family.owns_document(&self.root, path) {
            return;
        }
        self.open_versions.remove(path);
        self.reload_from_disk(path);
    }

    fn reload_from_disk(&mut self, path: &Path) {
        if !self.family.owns_document(&self.root, path) || self.open_versions.contains_key(path) {
            return;
        }
        self.disk_diagnostics
            .retain(|diagnostic| diagnostic.path != path);
        if !self.family.is_safe_authored_file(&self.root, path) {
            self.documents.remove(path);
            self.rebuild();
            return;
        }
        match fs::read(path) {
            Ok(bytes) if bytes.len() > MAX_DOCUMENT_BYTES => {
                self.documents.remove(path);
                self.disk_diagnostics.push(document_diagnostic(
                    path,
                    "Project document exceeds the 1 MiB indexing limit",
                ));
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
        self.rebuild();
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
    pub(crate) fn intern(&mut self, path: &Path) -> PathBuf {
        if let Some(canonical) = self.canonical_paths.get(path) {
            return canonical.clone();
        }
        let canonical = canonical_path(path);
        self.canonical_paths
            .insert(path.to_path_buf(), canonical.clone());
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

    pub(crate) fn reload_from_disk(&mut self, path: &Path) {
        if let Some(state) = self.root_for_mut(path) {
            state.reload_from_disk(path);
        }
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
        layout::{OPENAPI_FILE, QUESTIONS_DIRECTORY},
        marker::{default_project_marker_document, PROJECT_MARKER_FILE},
    };
    use tempfile::TempDir;
    use tower_lsp_server::ls_types::Position;

    use super::*;

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

        state.reload_from_disk(&entity);
        assert!(state
            .index
            .workspace_symbols("person")
            .iter()
            .any(|symbol| symbol.name == "person"));

        fs::remove_file(&entity).unwrap();
        state.reload_from_disk(&entity);
        assert!(state.index.workspace_symbols("person").is_empty());
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
