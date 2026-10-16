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

pub(crate) const PROJECT_CEILING_MESSAGE: &str = "This project exceeds the editor's aggregate limit of 1024 documents or 16 MiB; no project documents are indexed until it is reduced";

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
    Evidence,
    Product(crate::products::ProductKind),
}

impl ProjectFamily {
    /// Every family discovery tests, in the order it tests them. The order decides a directory that
    /// somehow answers for two families, so it is fixed here rather than left to whichever test
    /// runs first.
    const ALL: &'static [Self] = &[
        Self::Evidence,
        Self::Product(crate::products::ProductKind::Breg),
        Self::Product(crate::products::ProductKind::Casework),
        Self::Product(crate::products::ProductKind::Coordinator),
        Self::Product(crate::products::ProductKind::Scheduling),
        Self::Product(crate::products::ProductKind::Messaging),
        Self::Product(crate::products::ProductKind::Discovery),
        Self::Product(crate::products::ProductKind::Manifest),
        Self::Product(crate::products::ProductKind::Render),
        Self::Product(crate::products::ProductKind::EvidenceOid4vci),
    ];

    /// Whether this family claims a directory as one of its roots.
    fn declares_root(self, directory: &Path) -> bool {
        match self {
            Self::Evidence => evidence::declares_root(directory),
            Self::Product(product) => crate::products::declares_root(directory, product),
        }
    }

    fn load_documents(self, root: &Path) -> Result<LoadedProjectDocuments> {
        match self {
            Self::Evidence => evidence::load_project_documents(root),
            Self::Product(product) => {
                crate::products::load_documents(root, product, &BTreeMap::new())
            }
        }
    }

    /// Whether building this family's index opens the file at `path` for itself.
    ///
    /// The two questions beside each other are the whole of what a save can change. A document the
    /// family owns is answered from the text the client just sent, and one it does not own is
    /// answered from disk at the next build or from nowhere at all. Evidence has one file in the
    /// second class, and a family with none is unaffected.
    fn is_read_by_a_build(self, root: &Path, path: &Path) -> bool {
        match self {
            Self::Product(_) => false,
            Self::Evidence => evidence::is_read_by_a_build(root, path),
        }
    }

    /// How large a document at this path may be for this family to index it.
    ///
    /// Generic products use one project-document limit. Evidence holds each document to the
    /// ceiling the authoring form gives the part it plays, so a document an author's compiler
    /// refuses for its size is a document the editor refuses for the same size.
    fn document_ceiling(self, root: &Path, path: &Path) -> DocumentCeiling {
        match self {
            Self::Product(_) => DocumentCeiling::project_document(),
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
            Self::Product(_) => None,
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
            Self::Product(_) => Ok(None),
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
            Self::Evidence => evidence::build_index(root, documents, parsed, dropped),
            Self::Product(product) => crate::products::build_index(root, product, parsed),
        }
    }

    /// The name this family's diagnostics are published under.
    ///
    /// An editor groups and filters by this string, and a reader has to be able to tell which tool
    /// is talking. A project that holds both families would otherwise show one undifferentiated
    /// list, so each family says who it is.
    pub(crate) fn diagnostic_source(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Product(product) => product.name(),
        }
    }

    /// The code a diagnostic of this family carries for `rule`, for the rules that belong to no one
    /// symbol kind.
    pub(crate) fn diagnostic_code(self, rule: &str) -> Option<String> {
        match self {
            Self::Evidence => Some(registry_evidence_authoring::formats::finding_code(
                "project", rule,
            )),
            Self::Product(_) => Some(format!("{}/{rule}", self.diagnostic_source())),
        }
    }

    /// Whether a document contributes a YAML syntax tree for its product.
    pub(crate) fn parses_as_yaml(self, path: &Path) -> bool {
        match self {
            Self::Evidence => path
                .extension()
                .is_some_and(|extension| extension == "yaml" || extension == "yml"),
            Self::Product(_) => path
                .extension()
                .is_some_and(|value| value == "yaml" || value == "yml" || value == "json"),
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
    /// The project must hold the path before the revision is retained. Each product answers from
    /// its current exact governed closure, rather than from root containment; Evidence then uses
    /// [`Self::settle_open_buffers`] to decide on every rebuild which side of its fixed authoring
    /// layout an already-held path sits on.
    fn update(&mut self, path: PathBuf, text: String, version: i32) {
        if !self.project_holds(&path) {
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
        if matches!(self.family, ProjectFamily::Product(_)) {
            self.reload_product_with_open_documents();
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
        if self.project_holds(&path) {
            self.update(path, text, version);
            return;
        }
        if self.family.is_read_by_a_build(&self.root, &path) {
            self.rebuild();
        }
    }

    fn close(&mut self, path: &Path) {
        if !self.answers_from_a_buffer(path) {
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
        match self.family {
            ProjectFamily::Evidence => evidence::is_safe_authored_file(&self.root, path),
            ProjectFamily::Product(product) => {
                crate::products::is_project_document(&self.root, path, product, &self.documents)
            }
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
        if matches!(self.family, ProjectFamily::Product(_)) {
            self.reload_product_with_open_documents();
            return Ok(());
        }
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
        if self.indexing_ceiling_path.is_some() {
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
        if matches!(self.family, ProjectFamily::Product(_)) {
            self.reload_product_with_open_documents();
            return;
        }
        if self.indexing_ceiling_path.is_some() {
            let _ = self.reload_project_from_disk();
            return;
        }
        self.apply_from_disk(path);
        self.rebuild();
    }

    /// Reloads a product project from disk with the text of every open buffer laid over it.
    ///
    /// The product loader is the one path that reads a product project, so every change reloads it
    /// whole. A read that fails is not returned: it becomes a `document-read` diagnostic on the
    /// entry document that names the failure, the project holds no documents until the author
    /// retries, and every open buffer is held aside so the retry can take it up again.
    fn reload_product_with_open_documents(&mut self) {
        let ProjectFamily::Product(product) = self.family else {
            unreachable!()
        };
        let overrides = self
            .open_versions
            .keys()
            .filter_map(|path| {
                self.documents
                    .get(path)
                    .or_else(|| self.absent_buffers.get(path))
                    .map(|text| (path.clone(), text.clone()))
            })
            .collect();
        let loaded = match crate::products::load_documents(&self.root, product, &overrides) {
            Ok(loaded) => loaded,
            Err(error) => {
                self.absent_buffers.extend(overrides);
                self.documents.clear();
                self.indexing_ceiling_path = None;
                let entry = crate::products::entry_path(&self.root, product)
                    .unwrap_or_else(|| self.root.clone());
                self.disk_diagnostics = vec![document_rule_diagnostic(
                    &entry,
                    Some(format!("{}/document-read", product.name())),
                    &format!(
                        "Cannot read the complete authoring project ({error:#}); restore file \
                         permissions and save or refresh to retry"
                    ),
                )];
                self.rebuild();
                return;
            }
        };
        for (path, text) in &overrides {
            if !loaded.documents.contains_key(path) {
                self.absent_buffers.insert(path.clone(), text.clone());
            } else {
                self.absent_buffers.remove(path);
            }
        }
        self.documents = loaded.documents;
        self.disk_diagnostics = loaded.diagnostics;
        self.indexing_ceiling_path = loaded.indexing_ceiling_path;
        for path in self
            .open_versions
            .keys()
            .filter(|path| !overrides.contains_key(*path))
        {
            self.documents.remove(path);
        }
        self.rebuild();
    }

    /// Retries a project that crossed its aggregate indexing budget.
    ///
    /// Disk state is loaded through the same bounded first-scan path. Text still owned by the
    /// client is then overlaid where it remains available, and the aggregate ceiling is weighed
    /// again before anything is parsed.
    fn reload_project_from_disk(&mut self) -> Result<()> {
        if matches!(self.family, ProjectFamily::Product(_)) {
            self.reload_product_with_open_documents();
            return Ok(());
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

    /// Takes one document from disk, without rebuilding the index around it.
    ///
    /// A path the client has open is left to the client, whatever the file under it now says or
    /// whether it is there at all: the content of an open document is the client's until it closes
    /// it, so this root does not read one back from disk.
    fn apply_from_disk(&mut self, path: &Path) {
        if self.indexing_ceiling_path.is_some()
            || !evidence::is_project_document(&self.root, path)
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
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    const PROJECT: &str = "apiVersion: id.registrystack.org/formats/evidence/project/v1alpha1\nkind: EvidenceProject\nid: synthetic\nselectorProfiles: {}\nfunctions: []\nsources: {}\nassertionDefinitions: {}\n";
    fn project(root: &Path) {
        fs::write(root.join("evidence.yaml"), PROJECT).unwrap();
    }
    fn state() -> (tempfile::TempDir, RootState, PathBuf) {
        let temp = tempdir().unwrap();
        project(temp.path());
        let root = temp.path().canonicalize().unwrap();
        let path = root.join("evidence.yaml");
        let state = RootState::load(&root, ProjectFamily::Evidence).unwrap();
        (temp, state, path)
    }
    fn ceiling(state: &RootState) -> bool {
        state
            .index
            .diagnostics()
            .iter()
            .any(|d| d.code.as_deref() == Some("evidence.project.document-ceiling"))
    }
    #[test]
    fn a_retired_relay_marker_does_not_declare_a_supported_root() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("registry.yaml"),
            "apiVersion: relay.registrystack.org/v2alpha1\nkind: RegistryContract\n",
        )
        .unwrap();
        assert!(ProjectFamily::ALL
            .iter()
            .all(|family| !family.declares_root(temp.path())));
    }
    #[test]
    fn evidence_root_requires_the_normalized_project_file() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("questions")).unwrap();
        fs::write(temp.path().join("source.openapi.yaml"), "openapi: 3.1.0\n").unwrap();
        fs::write(
            temp.path().join("evidence-project.yaml"),
            "kind: EvidenceAuthoringProject\n",
        )
        .unwrap();
        assert!(Workspace::default().root_at(temp.path()).is_none());
        project(temp.path());
        assert_eq!(
            Workspace::default().root_at(temp.path()).unwrap().1,
            ProjectFamily::Evidence
        );
    }
    #[cfg(unix)]
    #[test]
    fn a_symlink_cannot_declare_an_evidence_root() {
        let temp = tempdir().unwrap();
        let other = tempdir().unwrap();
        project(other.path());
        std::os::unix::fs::symlink(
            other.path().join("evidence.yaml"),
            temp.path().join("evidence.yaml"),
        )
        .unwrap();
        assert!(Workspace::default().root_at(temp.path()).is_none());
    }
    #[test]
    fn a_normalized_component_is_discovered_below_a_workspace_folder() {
        let parent = tempdir().unwrap();
        let child = parent.path().join("component");
        fs::create_dir(&child).unwrap();
        project(&child);
        let mut workspace = Workspace::default();
        workspace.set_folders(vec![parent.path().canonicalize().unwrap()]);
        workspace.adopt_folder_roots();
        assert!(workspace.roots.is_empty());
        workspace
            .ensure_root_for(&child.join("evidence.yaml"))
            .unwrap();
        assert_eq!(workspace.roots.len(), 1);
    }
    #[test]
    fn an_open_project_buffer_uses_the_shared_reader_without_saving() {
        let (_temp, mut state, path) = state();
        state.update(path.clone(),"apiVersion: id.registrystack.org/formats/evidence/question/v1alpha1\nkind: EvidenceQuestion\n".to_owned(),2);
        assert!(state.index.diagnostics().iter().any(|d| d.path == path));
        assert!(state.index.symbols().is_empty());
    }
    #[test]
    fn oversized_open_buffer_is_dropped_and_recovers() {
        let (_temp, mut state, path) = state();
        state.update(path.clone(), " ".repeat(1_048_577), 2);
        assert!(!state.documents.contains_key(&path));
        assert!(ceiling(&state));
        state.update(path.clone(), PROJECT.to_owned(), 3);
        assert!(!ceiling(&state));
        assert!(state.documents.contains_key(&path));
    }
    #[test]
    fn oversized_disk_document_reports_on_load_and_reload() {
        let (_temp, mut state, path) = state();
        fs::write(&path, " ".repeat(1_048_577)).unwrap();
        state.reload_from_disk(&path);
        assert!(ceiling(&state));
        let loaded = RootState::load(&state.root, ProjectFamily::Evidence).unwrap();
        assert!(ceiling(&loaded));
        state.close(&path);
        assert!(ceiling(&state));
    }
    #[test]
    fn aggregate_overflow_reports_once_and_a_watched_reload_recovers() {
        let (_temp, mut state, path) = state();
        for index in 0..MAX_INDEXED_PROJECT_DOCUMENTS {
            state.documents.insert(
                state.root.join(format!("functions/{index}.rhai")),
                "// bounded\n".to_owned(),
            );
        }
        state.rebuild();
        assert!(state.documents.is_empty());
        assert_eq!(state.index.diagnostics().len(), 1);
        assert_eq!(
            state.index.diagnostics()[0].code.as_deref(),
            Some("evidence.project.ceiling")
        );
        state.reload_watched_batch(&[path]).unwrap();
        assert!(state.indexing_ceiling_path.is_none());
    }
    #[test]
    fn reducing_an_open_buffer_recovers_the_aggregate_byte_budget() {
        let (_temp, mut state, path) = state();
        let mut remaining = MAX_INDEXED_PROJECT_BYTES - 524_288;
        let mut index = 0;
        while remaining > 0 {
            let bytes = remaining.min(1_048_576);
            state.documents.insert(
                state.root.join(format!("functions/{index}.rhai")),
                " ".repeat(bytes),
            );
            remaining -= bytes;
            index += 1;
        }
        state.update(path.clone(), " ".repeat(1_048_576), 2);
        assert!(state.indexing_ceiling_path.is_some());
        state.update(path, PROJECT.to_owned(), 3);
        assert!(state.indexing_ceiling_path.is_none());
    }
    #[test]
    fn deleting_and_returning_a_function_preserves_the_unsaved_buffer() {
        let (temp, mut state, _) = state();
        let path = state.root.join("functions/derive.rhai");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "fn derive(a,b,c) {}\n").unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&path))
            .unwrap();
        state.update(path.clone(), "// unsaved\n".to_owned(), 2);
        fs::remove_file(&path).unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&path))
            .unwrap();
        assert!(!state.documents.contains_key(&path));
        assert_eq!(state.absent_buffers.get(&path).unwrap(), "// unsaved\n");
        fs::write(&path, "// disk\n").unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&path))
            .unwrap();
        assert_eq!(state.documents.get(&path).unwrap(), "// unsaved\n");
        drop(temp);
    }
    #[test]
    fn closing_a_deleted_buffer_releases_retained_text() {
        let (_temp, mut state, path) = state();
        state.update(path.clone(), PROJECT.to_owned(), 2);
        fs::remove_file(&path).unwrap();
        state
            .reload_watched_batch(std::slice::from_ref(&path))
            .unwrap();
        assert!(state.absent_buffers.contains_key(&path));
        state.close(&path);
        assert!(!state.absent_buffers.contains_key(&path));
        assert!(!state.open_versions.contains_key(&path));
    }
    #[test]
    fn watched_batches_preserve_a_surviving_unsaved_project() {
        let (_temp, mut state, path) = state();
        let edited = PROJECT.replace("id: synthetic", "id: unsaved");
        state.update(path.clone(), edited.clone(), 2);
        state
            .reload_watched_batch(&[state.root.join("functions/changed.rhai")])
            .unwrap();
        assert_eq!(state.documents.get(&path), Some(&edited));
    }
}
