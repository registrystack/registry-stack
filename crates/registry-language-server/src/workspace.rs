// SPDX-License-Identifier: Apache-2.0
//! The project roots one session indexes: how a document finds its root, and the document store
//! and index each root keeps.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::Result;

use crate::{
    evidence,
    refs::{
        document_diagnostic, document_rule_diagnostic, IndexedDiagnostic, IndexedProject,
        ProjectIndex, DOCUMENT_CEILING_RULE, PROJECT_CEILING_RULE,
    },
    relay_v2,
    safety::{secure_regular_file, SecureFileRead},
    yaml::ParsedDocument,
};

/// How many roots one session indexes.
///
/// This bounds the number of roots in addition to the shared aggregate document-and-byte ceiling
/// and each family's per-document budgets. A client that reaches across many unrelated projects
/// stops adding roots here, which keeps those per-root costs multiplied by 32 rather than by
/// whatever a session is pointed at.
pub(crate) const MAX_INDEXED_ROOTS: usize = 32;

/// The operational budget for YAML documents one root parses into its live index.
pub(crate) const MAX_INDEXED_PROJECT_DOCUMENTS: usize = 1024;
pub(crate) const MAX_INDEXED_PROJECT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) const PROJECT_CEILING_MESSAGE: &str =
    "This project exceeds the editor's aggregate limit of 1024 documents or 16 MiB; no project documents are indexed until it is reduced";

/// The first path, in project order, that crosses the editor's aggregate document or byte budget.
pub(crate) fn project_ceiling_path(documents: &BTreeMap<PathBuf, String>) -> Option<PathBuf> {
    let mut bytes = 0usize;
    for (index, (path, source)) in documents.iter().enumerate() {
        bytes = bytes.saturating_add(source.len());
        if index >= MAX_INDEXED_PROJECT_DOCUMENTS || bytes > MAX_INDEXED_PROJECT_BYTES {
            return Some(path.clone());
        }
    }
    None
}

const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;

/// What one family's loader found under a root: the documents it read, and the reasons it could
/// not read the rest.
#[derive(Debug)]
pub(crate) struct LoadedProjectDocuments {
    pub(crate) documents: BTreeMap<PathBuf, String>,
    pub(crate) diagnostics: Vec<IndexedDiagnostic>,
    pub(crate) indexing_ceiling_path: Option<PathBuf>,
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
    RelayV2,
    Evidence,
}

impl ProjectFamily {
    /// Every family discovery tests, in the order it tests them. The order decides a directory that
    /// somehow answers for two families, so it is fixed here rather than left to whichever test
    /// runs first.
    const ALL: &'static [Self] = &[Self::RelayV2, Self::Evidence];

    /// Whether this family claims a directory as one of its roots.
    fn declares_root(self, directory: &Path) -> bool {
        match self {
            Self::RelayV2 => relay_v2::declares_root(directory),
            Self::Evidence => evidence::declares_root(directory),
        }
    }

    pub(crate) fn load_documents(self, root: &Path) -> Result<LoadedProjectDocuments> {
        match self {
            Self::RelayV2 => relay_v2::load_project_documents(root),
            Self::Evidence => evidence::load_project_documents(root),
        }
    }

    fn owns_document(self, root: &Path, path: &Path) -> bool {
        match self {
            Self::RelayV2 => relay_v2::is_project_document(root, path),
            Self::Evidence => evidence::is_project_document(root, path),
        }
    }

    /// Whether building this family's index opens the file at `path` for itself.
    ///
    /// The two questions beside each other are the whole of what a save can change. A document the
    /// family owns is answered from the text the client just sent, and one it does not own is
    /// answered from disk at the next build or from nowhere at all. Evidence has one file in the
    /// second class, and a family with none is unaffected: Relay's index is built from the
    /// documents it holds and nothing else.
    fn is_read_by_a_build(self, root: &Path, path: &Path) -> bool {
        match self {
            // A saved governed reference can change the closure the compiler
            // reads, so Relay V2 settles the complete project after any save.
            Self::RelayV2 => true,
            Self::Evidence => evidence::is_read_by_a_build(root, path),
        }
    }

    fn is_safe_authored_file(self, root: &Path, path: &Path) -> bool {
        match self {
            Self::RelayV2 => relay_v2::is_safe_authored_file(root, path),
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
            Self::RelayV2 => DocumentCeiling::project_document(),
            Self::Evidence => evidence::document_ceiling(root, path),
        }
    }

    /// The first document that puts this family past its aggregate editor budget.
    fn project_ceiling_path(self, documents: &BTreeMap<PathBuf, String>) -> Option<PathBuf> {
        project_ceiling_path(documents)
    }

    /// The directory holding this path, when this family bounds how many documents it indexes from
    /// it, and `None` for every other path.
    ///
    /// Evidence bounds the directories its authoring form bounds, so a definition the compiler
    /// resolves cannot become an unresolved reference on screen.
    fn bounded_directory_of(self, root: &Path, path: &Path) -> Option<PathBuf> {
        match self {
            Self::RelayV2 => None,
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
            Self::RelayV2 => Ok(None),
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
    /// document that spells it.
    pub(crate) fn build_index(
        self,
        root: &Path,
        documents: &BTreeMap<PathBuf, String>,
        parsed: &BTreeMap<PathBuf, ParsedDocument>,
        dropped: &BTreeSet<PathBuf>,
    ) -> IndexedProject {
        match self {
            Self::RelayV2 => relay_v2::build_index(root, documents, parsed),
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
            Self::RelayV2 => "relay-v2",
            Self::Evidence => "evidence",
        }
    }

    /// The code a diagnostic of this family carries for `rule`, for the rules that belong to no one
    /// symbol kind.
    pub(crate) fn diagnostic_code(self, rule: &str) -> Option<String> {
        match self {
            Self::RelayV2 => Some(format!("{}/{rule}", self.diagnostic_source())),
            Self::Evidence => Some(format!("{}/{rule}", self.diagnostic_source())),
        }
    }

    /// Whether a document contributes a YAML syntax tree. Relay V2 also holds
    /// governed Markdown rationale bytes for compiler closure validation; they
    /// are project inputs but not YAML documents.
    pub(crate) fn parses_as_yaml(self, path: &Path) -> bool {
        match self {
            Self::Evidence => true,
            Self::RelayV2 => path.extension().is_some_and(|extension| {
                matches!(extension.to_str(), Some("yaml" | "yml" | "json"))
            }),
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
    /// The text of the buffers this root holds aside: the ones the client has open over paths the
    /// project does not hold. They take no part in the index, and they are kept rather than dropped
    /// because the client still owns those documents. When the file under one comes back, this
    /// revision is what the root answers from, and not what the returning file says.
    absent_buffers: BTreeMap<PathBuf, String>,
    /// Per-document ceiling reports for open buffers whose text is deliberately not retained.
    /// Keeping these separate from disk diagnostics lets a project-level ceiling suppress them
    /// temporarily without losing the explanation when the project later recovers.
    open_ceiling_diagnostics: BTreeMap<PathBuf, IndexedDiagnostic>,
    disk_diagnostics: Vec<IndexedDiagnostic>,
    indexing_ceiling_path: Option<PathBuf>,
    index: ProjectIndex,
}

impl RootState {
    fn load(root: &Path, family: ProjectFamily) -> Result<Self> {
        let root = root.canonicalize()?;
        let loaded = family.load_documents(&root)?;
        let index = if loaded.indexing_ceiling_path.is_some() {
            ProjectIndex::diagnostics_only(&root, loaded.diagnostics.clone())
        } else {
            ProjectIndex::from_documents_with_diagnostics(
                family,
                &root,
                &loaded.documents,
                loaded.diagnostics.clone(),
            )
        };
        Ok(Self {
            root,
            family,
            documents: loaded.documents,
            open_versions: BTreeMap::new(),
            absent_buffers: BTreeMap::new(),
            open_ceiling_diagnostics: BTreeMap::new(),
            disk_diagnostics: loaded.diagnostics,
            indexing_ceiling_path: loaded.indexing_ceiling_path,
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
    ///
    /// Whether the project still holds the file under the buffer is not asked here either. The
    /// revision that just arrived is this root's text for the path either way, and
    /// [`Self::settle_open_buffers`] decides on every rebuild which side of the project it sits on,
    /// so one keystroke over a path the project has lost is answered in the one place that answers
    /// it for every other path as well.
    fn update(&mut self, path: PathBuf, text: String, version: i32) {
        if !self.family.owns_document(&self.root, &path) {
            return;
        }
        let was_blocked = self.indexing_ceiling_path.is_some();
        self.open_versions.insert(path.clone(), version);
        // The revision that arrived is the whole of what the client holds, so it replaces whatever
        // this root was keeping for the path on either side of the project.
        self.absent_buffers.remove(&path);
        self.disk_diagnostics
            .retain(|diagnostic| diagnostic.path != path);
        let ceiling = self.family.document_ceiling(&self.root, &path);
        let admitted = ceiling.admits(text.len());
        if admitted {
            self.open_ceiling_diagnostics.remove(&path);
            self.documents.insert(path.clone(), text);
        } else {
            // A buffer that has grown past the ceiling stops being indexed and says so. Leaving the
            // last text that fitted would answer every later request from a revision the author can
            // no longer see, and silently: nothing else in the session would report the change.
            self.documents.remove(&path);
            self.open_ceiling_diagnostics.insert(
                path.clone(),
                document_rule_diagnostic(
                    &path,
                    self.family.diagnostic_code(DOCUMENT_CEILING_RULE),
                    &ceiling.message,
                ),
            );
        }
        if self.family == ProjectFamily::RelayV2
            && self.reload_relay_v2_with_open_documents().is_ok()
        {
            return;
        }
        if was_blocked && self.reload_project_from_disk().is_ok() {
            return;
        }
        self.rebuild();
    }

    /// Takes a revision the client saved to disk.
    ///
    /// A document this root holds is taken exactly as any other revision is: the text the client
    /// sent is the text of the document, saved or not. What a save adds is the other case. The
    /// bytes of a file this root does not hold have just changed, and if a build reads that file
    /// then everything resolved against it is answered from a revision that is gone. The author is
    /// looking at a document the save did not touch, so nothing they type there would reach it.
    fn save(&mut self, path: PathBuf, text: String, version: i32) {
        if self.family.owns_document(&self.root, &path) {
            self.update(path, text, version);
            return;
        }
        if self.family.is_read_by_a_build(&self.root, &path) {
            if self.family == ProjectFamily::RelayV2 {
                let _ = self.reload_relay_v2_with_open_documents();
            } else {
                self.rebuild();
            }
        }
    }

    fn close(&mut self, path: &Path) {
        if !self.family.owns_document(&self.root, path) {
            return;
        }
        self.open_versions.remove(path);
        self.absent_buffers.remove(path);
        self.open_ceiling_diagnostics.remove(path);
        self.reload_from_disk(path);
    }

    /// Whether the project still holds `path` as a document this root reads.
    ///
    /// This is the question the loader answers before it opens any file, asked again because the
    /// answer changes under a running session: the author switches a branch, renames a file in the
    /// explorer, or deletes one while a buffer is open over it. It is the same gate every read in
    /// this crate goes through, so a path that has left the project answers no here for exactly the
    /// reasons a first scan of the same tree would pass it by.
    fn project_holds(&self, path: &Path) -> bool {
        if self.family == ProjectFamily::RelayV2 {
            self.family.owns_document(&self.root, path)
        } else {
            self.family.is_safe_authored_file(&self.root, path)
        }
    }

    /// Whether this root answers for `path` from a buffer the client has open rather than from the
    /// file on disk.
    ///
    /// Only the protocol answers this. Between `didOpen` and `didClose` the client owns the
    /// document's content, whatever becomes of the file underneath it, so a buffer wins here until
    /// the client closes it. What such a buffer stops doing when the file leaves the project is
    /// contributing to the project, which is [`Self::project_holds`] and is asked on its own.
    fn answers_from_a_buffer(&self, path: &Path) -> bool {
        self.open_versions.contains_key(path)
    }

    /// Puts every buffer the client has open on the side of the project it belongs to now.
    ///
    /// A buffer open over a path the project no longer holds is held aside, and contributes no
    /// symbols, no references, and no diagnostics. The compiler reads the project's directories, so
    /// a file that has left them is not in the tree it builds, and every sentence drawn from that
    /// buffer is drawn over a project it accepts. A client keeps such a buffer open for as long as
    /// the author keeps the tab open, which is well past the deletion that emptied it. Nothing is
    /// reported in its place: there is no edit to the buffer that would answer it, and the client
    /// already shows the author that the document is gone.
    ///
    /// A buffer whose file has come back is taken up again, from the revision the client holds and
    /// not from the file, because the client owns that document until it closes it. The unsaved
    /// work an author can still see on screen is the revision every request about that document is
    /// answered from, and a branch switched back over an edited tab is the ordinary way a file
    /// leaves and returns underneath one.
    ///
    /// Both moves run on every rebuild rather than at the notification that caused one, because a
    /// session learns about the filesystem only from what the client tells it, and a client may
    /// tell it half of a change: a deletion whose matching return never arrives would otherwise
    /// leave a name reported unknown over a project the compiler builds, until the author happened
    /// to type into that very buffer.
    ///
    /// Two bounds are left. This reaches the paths the client has open and no others, so a file
    /// deleted with no tab over it and returned unannounced is not one this root remembers to ask
    /// about. And a root is asked nothing between one notification and the next, so what the client
    /// last published stands until the session does something. Closing either would take a watcher
    /// of the filesystem, which this server does not have.
    fn settle_open_buffers(&mut self) {
        for path in self.open_versions.keys().cloned().collect::<Vec<_>>() {
            if self.project_holds(&path) {
                if let Some(text) = self.absent_buffers.remove(&path) {
                    self.documents.insert(path, text);
                }
                continue;
            }
            if let Some(text) = self.documents.remove(&path) {
                self.absent_buffers.insert(path.clone(), text);
            }
            self.disk_diagnostics
                .retain(|diagnostic| diagnostic.path != path);
        }
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
        if self.indexing_ceiling_path.is_some() {
            self.reload_project_from_disk()?;
            return Ok(());
        }
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
        if self.family == ProjectFamily::RelayV2 {
            self.reload_relay_v2_with_open_documents()?;
        } else if self.indexing_ceiling_path.is_some() {
            self.reload_project_from_disk()?;
        } else {
            self.rebuild();
        }
        failure.map_or(Ok(()), Err)
    }

    /// Replaces what this root holds from one bounded directory with what a fresh read of it finds.
    ///
    /// A document the client has open is left alone, text and diagnostics both. The author is
    /// looking at that buffer, and its text is the unsaved revision rather than whatever is on disk.
    /// Whether the directory still holds the file under such a buffer is not decided here: a batch
    /// is how a deletion reaches this root, but it is also how half of one does, so that question is
    /// asked of every open buffer at the rebuild closing the batch. The read happens before anything
    /// is dropped, so a directory the server cannot enumerate leaves the root exactly as it was and
    /// says why.
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
        if self.indexing_ceiling_path.is_some() {
            let _ = self.reload_project_from_disk();
            return;
        }
        self.apply_from_disk(path);
        if self.family == ProjectFamily::RelayV2 {
            let _ = self.reload_relay_v2_with_open_documents();
        } else {
            self.rebuild();
        }
    }

    /// Retries a project that crossed its aggregate indexing budget.
    ///
    /// Disk state is loaded through the same bounded first-scan path. Text still owned by the
    /// client is then overlaid where it remains available, and the aggregate ceiling is weighed
    /// again before anything is parsed.
    fn reload_project_from_disk(&mut self) -> Result<()> {
        if self.family == ProjectFamily::RelayV2 {
            return self.reload_relay_v2_with_open_documents();
        }
        let open_text = self
            .open_versions
            .keys()
            .filter_map(|path| {
                self.documents
                    .get(path)
                    .or_else(|| self.absent_buffers.get(path))
                    .map(|text| (path.clone(), text.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let loaded = self.family.load_documents(&self.root)?;
        self.documents = loaded.documents;
        self.disk_diagnostics = loaded.diagnostics;
        self.indexing_ceiling_path = loaded.indexing_ceiling_path;
        for path in self.open_versions.keys() {
            self.documents.remove(path);
            self.disk_diagnostics
                .retain(|diagnostic| diagnostic.path != *path);
        }
        for (path, text) in open_text {
            if self.project_holds(&path) {
                self.absent_buffers.remove(&path);
                self.documents.insert(path, text);
            } else {
                self.absent_buffers.insert(path, text);
            }
        }
        self.rebuild();
        Ok(())
    }

    /// Recompute Relay V2's exact governed-file closure around the revisions
    /// held by the client, reading only newly referenced bounded files from
    /// disk. This is what makes an unsaved `registry.yaml` or classification
    /// review compile as one complete in-memory project.
    fn reload_relay_v2_with_open_documents(&mut self) -> Result<()> {
        debug_assert_eq!(self.family, ProjectFamily::RelayV2);
        let overrides = self
            .open_versions
            .keys()
            .filter_map(|path| {
                self.documents
                    .get(path)
                    .or_else(|| self.absent_buffers.get(path))
                    .map(|text| (path.clone(), text.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let loaded = relay_v2::load_project_documents_with_overrides(&self.root, &overrides)?;
        self.documents = loaded.documents;
        self.disk_diagnostics = loaded.diagnostics;
        self.indexing_ceiling_path = loaded.indexing_ceiling_path;
        for path in self.open_versions.keys() {
            if !overrides.contains_key(path) {
                self.documents.remove(path);
                self.disk_diagnostics
                    .retain(|diagnostic| diagnostic.path != *path);
            }
        }
        for (path, text) in overrides {
            if self.documents.contains_key(&path) {
                self.absent_buffers.remove(&path);
            } else {
                self.absent_buffers.insert(path, text);
            }
        }
        self.rebuild();
        Ok(())
    }

    /// Takes one document from disk, without rebuilding the index around it.
    ///
    /// A path the client has open is left to the client, whatever the file under it now says or
    /// whether it is there at all: the content of an open document is the client's until it closes
    /// it, so this root does not read one back from disk.
    fn apply_from_disk(&mut self, path: &Path) {
        if self.indexing_ceiling_path.is_some()
            || !self.family.owns_document(&self.root, path)
            || self.answers_from_a_buffer(path)
        {
            return;
        }
        self.disk_diagnostics
            .retain(|diagnostic| diagnostic.path != path);
        let Ok(Some(file)) = secure_regular_file(&self.root, path) else {
            self.documents.remove(path);
            return;
        };
        let ceiling = self.family.document_ceiling(&self.root, path);
        match file.read_bounded(ceiling.max_bytes) {
            Ok(SecureFileRead::TooLarge) => {
                self.documents.remove(path);
                self.disk_diagnostics.push(document_rule_diagnostic(
                    path,
                    self.family.diagnostic_code(DOCUMENT_CEILING_RULE),
                    &ceiling.message,
                ));
            }
            Ok(SecureFileRead::Bytes(bytes)) => match String::from_utf8(bytes) {
                Ok(text) => {
                    self.documents.insert(path.to_path_buf(), text);
                    self.enforce_project_ceiling();
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

    /// Rebuilds the index this root answers from.
    ///
    /// Every path into this root ends here, which is why the buffers the client has open are
    /// settled against the project first: an index built without asking would be built from a tree
    /// the project had before whatever prompted the rebuild.
    fn rebuild(&mut self) {
        self.settle_open_buffers();
        self.enforce_project_ceiling();
        let diagnostics = if let Some(path) = &self.indexing_ceiling_path {
            vec![document_rule_diagnostic(
                path,
                self.family.diagnostic_code(PROJECT_CEILING_RULE),
                PROJECT_CEILING_MESSAGE,
            )]
        } else {
            let mut diagnostics = self.disk_diagnostics.clone();
            diagnostics.extend(
                self.open_ceiling_diagnostics
                    .iter()
                    .filter(|(path, _)| self.project_holds(path))
                    .map(|(_, diagnostic)| diagnostic.clone()),
            );
            diagnostics
        };
        self.index = if self.indexing_ceiling_path.is_some() {
            ProjectIndex::diagnostics_only(&self.root, diagnostics)
        } else {
            ProjectIndex::from_documents_with_diagnostics(
                self.family,
                &self.root,
                &self.documents,
                diagnostics,
            )
        };
    }

    /// Stops holding disk documents as soon as the root crosses the aggregate editor budget.
    /// Open buffers remain client-owned, but none are parsed while the project is blocked.
    fn enforce_project_ceiling(&mut self) {
        if self.indexing_ceiling_path.is_some() {
            return;
        }
        let Some(path) = self.family.project_ceiling_path(&self.documents) else {
            return;
        };
        self.indexing_ceiling_path = Some(path);
        self.documents
            .retain(|path, _| self.open_versions.contains_key(path));
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

    /// The canonical form of a path the server is about to store.
    pub(crate) fn intern(&self, path: &Path) -> PathBuf {
        canonical_path(path)
    }

    /// The canonical form of a path a request names.
    pub(crate) fn resolve(&self, path: &Path) -> PathBuf {
        canonical_path(path)
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

    pub(crate) fn save(&mut self, path: PathBuf, text: String, version: i32) {
        if let Some(state) = self.root_for_mut(&path) {
            state.save(path, text, version);
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

    use super::*;
    use crate::refs::DOCUMENT_START;
    use registry_evidence_authoring::{
        layout::{
            ACCESS_DIRECTORY, ACCESS_POLICIES_DIRECTORY, MAX_QUESTIONS, MAX_QUESTION_BYTES,
            MAX_SOURCE_ARTIFACT_BYTES, OPENAPI_FILE, QUESTIONS_DIRECTORY,
        },
        marker::{default_project_marker_document, PROJECT_MARKER_FILE},
    };
    use tempfile::TempDir;

    /// Enough of a question for the tests here, which are about which root owns which file. What a
    /// whole question has to say for itself is `crates/registry-language-server/tests/`.
    const QUESTION: &str = "version: 1\nid: adult-status\n";

    fn relay_v2_project_in(directory: &Path) {
        fs::create_dir_all(directory).unwrap();
        fs::write(
            directory.join(relay_v2::PROJECT_FILE),
            "apiVersion: relay.registrystack.org/v2alpha1\nkind: RegistryContract\n",
        )
        .unwrap();
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

    /// A project marked inside an already indexed root stays undiscovered, and says nothing about
    /// itself.
    ///
    /// This pins a decision that is deferred rather than a behavior that is wanted.
    /// [`Workspace::ensure_root_for`] stops as soon as [`Workspace::root_for`] answers, and that
    /// answer is drawn from the roots this session has indexed rather than from the directories
    /// above the document, so a nearer marked root under an indexed one is never walked to. The
    /// consequence is silence: the containing root's family does not own the inner project's
    /// documents, so the document is indexed by nobody, reported on by nobody, and contributes
    /// nothing to the root it sits under. Silence is what this server is allowed to answer with,
    /// because its one invariant is one-sided: the editor may stay quiet where the compiler
    /// speaks, and may never speak where the compiler is quiet.
    ///
    /// Walking to the nearer root at every notification would mean replacing the [`RootState`] of
    /// the root that answers now, and that state is where the session knows which documents the
    /// client holds unsaved and which of those sit over paths the project has lost. Dropping a
    /// root without losing that bookkeeping is root eviction, which nothing else in this design
    /// asks for.
    ///
    /// The control below is the other half of the property. The same project on disk, opened as
    /// the root it is, is indexed and reports the sentence its question earns, so what is pinned
    /// above is a project left undiscovered and not a project nothing can read.

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
    fn a_relay_v2_marker_declares_a_relay_v2_root() {
        let temp = TempDir::new().unwrap();
        relay_v2_project_in(temp.path());

        let workspace = Workspace::default();

        assert_eq!(
            workspace.root_at(temp.path()),
            Some((temp.path().canonicalize().unwrap(), ProjectFamily::RelayV2))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_relay_v2_marker_does_not_declare_a_root() {
        let temp = TempDir::new().unwrap();
        let real = temp.path().join("real");
        let decoy = temp.path().join("decoy");
        relay_v2_project_in(&real);
        fs::create_dir_all(&decoy).unwrap();
        std::os::unix::fs::symlink(
            real.join(relay_v2::PROJECT_FILE),
            decoy.join(relay_v2::PROJECT_FILE),
        )
        .unwrap();

        assert_eq!(Workspace::default().root_at(&decoy), None);
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

    /// Every ceiling this root reports, as the rule it names and the sentence an author reads.
    fn ceiling_rules(state: &RootState) -> Vec<(Option<&str>, &str)> {
        state
            .index
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("the editor indexes"))
            .map(|diagnostic| (diagnostic.code.as_deref(), diagnostic.message.as_str()))
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
    fn an_aggregate_overflow_reports_once_without_dependent_diagnostics_and_recovers() {
        let temp = TempDir::new().unwrap();
        let (mut state, question) = evidence_root_with_a_question(temp.path());
        fs::write(
            temp.path().join(OPENAPI_FILE),
            r#"openapi: 3.1.0
info: {title: Test, version: 1.0.0}
paths:
  /check:
    get:
      operationId: published-operation
      responses:
        '200': {description: ok}
"#,
        )
        .unwrap();
        for index in 0..MAX_INDEXED_PROJECT_DOCUMENTS {
            state.documents.insert(
                state
                    .root
                    .join("selectors")
                    .join(format!("profile-{index:04}.yaml")),
                "kind: exact\n".to_owned(),
            );
        }

        state.rebuild();

        assert!(state.documents.is_empty());
        assert_eq!(state.index.diagnostics().len(), 1);
        assert_eq!(
            state.index.diagnostics()[0].code.as_deref(),
            Some("evidence/project-ceiling")
        );
        assert!(state.index.workspace_symbols("adult-status").is_empty());
        assert!(state.index.workspace_symbols("profile-").is_empty());
        assert!(state
            .index
            .workspace_symbols("published-operation")
            .is_empty());

        state
            .reload_watched_batch(std::slice::from_ref(&question))
            .unwrap();

        assert!(state.indexing_ceiling_path.is_none());
        assert_eq!(state.index.workspace_symbols("adult-status").len(), 1);
        assert!(state
            .index
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code.as_deref() != Some("evidence/project-ceiling")));
    }

    #[test]
    fn reducing_the_open_buffer_that_crossed_the_aggregate_budget_recovers_immediately() {
        let temp = TempDir::new().unwrap();
        let (mut state, question) = evidence_root_with_a_question(temp.path());
        let mut remaining = MAX_INDEXED_PROJECT_BYTES - MAX_QUESTION_BYTES as usize / 2;
        let mut index = 0usize;
        while remaining > 0 {
            let bytes = remaining.min(MAX_SOURCE_ARTIFACT_BYTES as usize);
            state.documents.insert(
                state
                    .root
                    .join("selectors")
                    .join(format!("profile-{index:02}.yaml")),
                "x".repeat(bytes),
            );
            remaining -= bytes;
            index += 1;
        }

        state.update(question.clone(), "x".repeat(MAX_QUESTION_BYTES as usize), 2);
        assert!(state.indexing_ceiling_path.is_some());

        state.update(question, QUESTION.to_owned(), 3);

        assert!(state.indexing_ceiling_path.is_none());
        assert_eq!(state.index.workspace_symbols("adult-status").len(), 1);
    }

    #[test]
    fn project_recovery_preserves_another_open_buffer_s_ceiling_report() {
        let temp = TempDir::new().unwrap();
        evidence_project_in(temp.path());
        let selectors = temp.path().join("selectors");
        fs::create_dir_all(&selectors).unwrap();
        for index in 0..MAX_INDEXED_PROJECT_DOCUMENTS {
            fs::write(
                selectors.join(format!("profile-{index:04}.yaml")),
                "kind: exact\n",
            )
            .unwrap();
        }
        let question = temp
            .path()
            .join(QUESTIONS_DIRECTORY)
            .join("adult-status.yaml")
            .canonicalize()
            .unwrap();
        let second_buffer = selectors.join("profile-1023.yaml").canonicalize().unwrap();
        let mut state = RootState::load(temp.path(), ProjectFamily::Evidence).unwrap();
        assert!(state.indexing_ceiling_path.is_some());

        state.update(question.clone(), oversized_question(), 1);
        state.update(second_buffer.clone(), "kind: exact\n".to_owned(), 1);
        assert!(state.indexing_ceiling_path.is_some());

        fs::remove_file(selectors.join("profile-0000.yaml")).unwrap();
        fs::remove_file(selectors.join("profile-0001.yaml")).unwrap();
        state.update(second_buffer, "kind: exact\n".to_owned(), 2);

        assert!(state.indexing_ceiling_path.is_none());
        assert!(!state.documents.contains_key(&question));
        assert_eq!(
            reported_at(&state, &question),
            vec!["This question exceeds the 65536-byte limit the editor indexes"]
        );
        assert!(state
            .index
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code.as_deref() != Some("evidence/project-ceiling")));
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

    /// Every sentence this root reports against one path.
    fn reported_at<'a>(state: &'a RootState, path: &Path) -> Vec<&'a str> {
        state
            .index
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.path == path)
            .map(|diagnostic| diagnostic.message.as_str())
            .collect()
    }

    /// A question pointing at a derivation and a fixture no directory of the project holds.
    ///
    /// Both pointers are unresolved, so a root reading this text says two things about it, and a
    /// root that no longer holds the file says nothing at all. The question is written in full
    /// because that is what makes it say them: the names inside a question the authoring form
    /// refuses are resolved for navigation and reported to nobody, so a stub here would prove the
    /// silence this fixture exists to tell apart from the real one.
    fn question_naming_absent_files(name: &str) -> String {
        format!(
            r#"id: {name}
question: Is the person at least 18 years old?
purpose: fixture-eligibility
subject:
  role: subject
  selector: person_id
source:
  ref: people
answers:
  - concept: is_adult
    id: urn:example:concepts:is-adult
    type: boolean
derivation: derivations/{name}.rhai
disclosure:
  allow: [is_adult]
governance:
  requirement: urn:example:requirements:{name}:v1
  kind: criterion
  referenceFrameworks: [urn:example:frameworks:{name}:v1]
  evidenceType: urn:example:evidence-types:{name}:v1
  validitySeconds: 86400
  observationTimezone: Etc/UTC
  fixtures: fixtures/{name}.yaml
  disclosureFamilies: [urn:example:disclosure-families:{name}]
"#
        )
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
    fn an_add_before_delete_rename_at_the_project_ceiling_recovers_in_the_same_batch() {
        let temp = TempDir::new().unwrap();
        evidence_project_in(temp.path());
        let selectors = temp.path().join("selectors");
        fs::create_dir_all(&selectors).unwrap();
        for index in 0..MAX_INDEXED_PROJECT_DOCUMENTS - 2 {
            fs::write(
                selectors.join(format!("profile-{index:04}.yaml")),
                "kind: exact\n",
            )
            .unwrap();
        }
        let selectors = selectors.canonicalize().unwrap();
        let mut state = RootState::load(temp.path(), ProjectFamily::Evidence).unwrap();
        assert_eq!(state.documents.len(), MAX_INDEXED_PROJECT_DOCUMENTS);

        let departed = selectors.join("profile-0000.yaml");
        let arrived = selectors.join("profile-9999.yaml");
        fs::rename(&departed, &arrived).unwrap();
        state
            .reload_watched_batch(&[arrived.clone(), departed.clone()])
            .unwrap();

        assert!(state.indexing_ceiling_path.is_none());
        assert_eq!(state.documents.len(), MAX_INDEXED_PROJECT_DOCUMENTS);
        assert!(state.documents.contains_key(&arrived));
        assert!(!state.documents.contains_key(&departed));
        assert!(state
            .index
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code.as_deref() != Some("evidence/project-ceiling")));
    }

    /// Both ceilings the editor applies name the rule they report under.
    ///
    /// The code is how an author silences one rule instead of everything the server says, and these
    /// two are the rules a finished project meets: a question that grew, a directory that filled.
    /// A sentence published without a code leaves that author nothing to name. The sentences
    /// themselves are pinned here beside the codes, because they are what an author reads.
    #[test]
    fn the_ceilings_the_editor_applies_name_the_rules_they_report_under() {
        let temp = TempDir::new().unwrap();
        let (mut state, questions) = full_questions_project(temp.path(), "adult-status");
        state.update(questions.join("filler-000.yaml"), oversized_question(), 2);

        let extra = questions.join("zzz-extra.yaml");
        write_question(&questions, "zzz-extra");
        state
            .reload_watched_batch(std::slice::from_ref(&extra))
            .unwrap();

        assert_eq!(
            ceiling_rules(&state),
            vec![
                (
                    Some("evidence/document-ceiling"),
                    "This question exceeds the 65536-byte limit the editor indexes"
                ),
                (
                    Some("evidence/directory-ceiling"),
                    "This project directory holds more than the 128 documents the editor indexes; this file and the ones after it are not indexed"
                ),
            ]
        );
    }

    /// A buffer left open over a file the project no longer holds says nothing about the project.
    ///
    /// A client keeps a tab open on a document that has been deleted, and the author goes on seeing
    /// it after a branch switch or a rename in the explorer. What the editor may not do is go on
    /// building the project around it: `evidence check` reads the directory and never sees the
    /// file, so every sentence the buffer contributes is drawn over a project the compiler accepts.
    /// A plain deletion is the shortest way to that disagreement, with no rename and no ceiling in
    /// it.
    #[test]
    fn a_buffer_over_a_deleted_file_reports_nothing_against_the_project() {
        let temp = TempDir::new().unwrap();
        let (mut state, questions) = full_questions_project(temp.path(), "adult-status");
        let departed = questions.join("filler-000.yaml");
        state.update(
            departed.clone(),
            question_naming_absent_files("filler-000"),
            2,
        );
        assert!(
            reported_at(&state, &departed)
                .contains(&"Unknown derivation file reference 'derivations/filler-000.rhai'"),
            "the project holds this question, so the editor reads its pointers: {:?}",
            reported_at(&state, &departed)
        );

        fs::remove_file(&departed).unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&departed))
            .unwrap();

        assert_eq!(
            reported_at(&state, &departed),
            Vec::<&str>::new(),
            "the compiler reads 127 questions here and refuses none of them"
        );
        assert_eq!(questions_held(&state, &questions), MAX_QUESTIONS - 1);
    }

    /// The same buffer, under a rename delivered as one batch.
    ///
    /// This is the case a client really delivers: the arrival and the departure together, with the
    /// old path still open because the client closes the tab afterwards. The directory holds the
    /// documents the authoring form allows before and after, so `evidencectl` builds the project
    /// either way, and the editor has to reach the silence a session opened on the settled tree
    /// reaches.
    #[test]
    fn a_rename_delivered_under_an_open_buffer_reports_nothing_on_the_departed_path() {
        let temp = TempDir::new().unwrap();
        let (mut state, questions) = full_questions_project(temp.path(), "aaa-renamed");
        let arrived = questions.join("aaa-renamed.yaml");
        let departed = questions.join("filler-126.yaml");
        state.update(
            departed.clone(),
            question_naming_absent_files("filler-126"),
            2,
        );

        fs::remove_file(&departed).unwrap();
        write_question(&questions, "aaa-renamed");
        state
            .reload_watched_batch(&[arrived.clone(), departed.clone()])
            .unwrap();

        assert_eq!(reported_at(&state, &departed), Vec::<&str>::new());
        assert!(state.documents.contains_key(&arrived));
        assert_eq!(questions_held(&state, &questions), MAX_QUESTIONS);
        assert_eq!(documents_not_indexed(&state), Vec::<&str>::new());
        assert_eq!(unresolved_questions(&state), Vec::<&str>::new());
    }

    /// A file that comes back under an open buffer is read again.
    ///
    /// Dropping a departed path is only right while it is gone. A branch switched back, or an
    /// undone delete, puts the document in the project again, and from that moment the compiler
    /// reads it; a root that stayed quiet would be answering from a tree neither the author nor the
    /// compiler has.
    #[test]
    fn a_buffer_over_a_path_that_comes_back_is_read_again() {
        let temp = TempDir::new().unwrap();
        let (mut state, questions) = full_questions_project(temp.path(), "adult-status");
        let question = questions.join("filler-000.yaml");
        state.update(
            question.clone(),
            question_naming_absent_files("filler-000"),
            2,
        );
        fs::remove_file(&question).unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&question))
            .unwrap();
        assert_eq!(reported_at(&state, &question), Vec::<&str>::new());

        fs::write(&question, question_naming_absent_files("filler-000")).unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&question))
            .unwrap();

        assert!(state.documents.contains_key(&question));
        assert!(state
            .index
            .workspace_symbols("filler-000")
            .iter()
            .any(|symbol| symbol.name == "filler-000"));
        assert!(
            reported_at(&state, &question)
                .contains(&"Unknown fixture file reference 'fixtures/filler-000.yaml'"),
            "the project holds the question again, and its pointers with it: {:?}",
            reported_at(&state, &question)
        );
    }

    /// A tab closed over a departed path leaves nothing of it behind.
    ///
    /// This one was written after the change it covers rather than before it. The two defects that
    /// prompted the change are pinned over the protocol in `tests/evidence_open_buffers.rs`; this
    /// holds the store to the retention rule they imply. A buffer held aside is the author's text,
    /// kept for one reason: to give it back when the file returns. A client that closes the document
    /// ends that reason, and the text stops being this root's to keep.
    #[test]
    fn a_buffer_closed_over_a_departed_path_is_not_kept() {
        let temp = TempDir::new().unwrap();
        let (mut state, questions) = full_questions_project(temp.path(), "adult-status");
        let departed = questions.join("filler-000.yaml");
        state.update(
            departed.clone(),
            question_naming_absent_files("filler-000"),
            2,
        );
        fs::remove_file(&departed).unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&departed))
            .unwrap();
        assert_eq!(
            state.absent_buffers.keys().collect::<Vec<_>>(),
            vec![&departed],
            "the client still holds the tab, so the root holds the revision it would give back"
        );

        state.close(&departed);

        assert!(state.absent_buffers.is_empty());
        assert!(!state.open_versions.contains_key(&departed));
        assert!(!state.documents.contains_key(&departed));
    }

    /// A settle keeps the unsaved text of a buffer whose file is still there.
    ///
    /// A buffer over a departed path stops being one this root answers from. A buffer over a
    /// document the project still holds does not: its unsaved revision is what the author is
    /// looking at and what every request about that document is answered from, and a batch settling
    /// the directory around it changes nothing about that.
    #[test]
    fn a_settle_keeps_the_unsaved_text_of_a_buffer_whose_file_is_still_there() {
        let temp = TempDir::new().unwrap();
        let (mut state, questions) = full_questions_project(temp.path(), "adult-status");
        let open = questions.join("filler-000.yaml");
        state.update(
            open.clone(),
            "version: 1\nid: filler-000\nanswers: [{ concept: unsaved-concept }]\n".to_owned(),
            2,
        );

        let departed = questions.join("filler-001.yaml");
        fs::remove_file(&departed).unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&departed))
            .unwrap();

        assert!(
            state
                .index
                .workspace_symbols("unsaved-concept")
                .iter()
                .any(|symbol| symbol.name == "unsaved-concept"),
            "the file is still on disk, so the buffer is still what the root answers from"
        );
    }
}
