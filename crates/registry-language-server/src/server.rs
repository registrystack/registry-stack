// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use tokio::sync::{Mutex, RwLock};
use tower_lsp_server::{
    jsonrpc::Result,
    ls_types::{
        Diagnostic, DidChangeTextDocumentParams, DidChangeWatchedFilesParams,
        DidChangeWatchedFilesRegistrationOptions, DidCloseTextDocumentParams,
        DidOpenTextDocumentParams, DidSaveTextDocumentParams, DocumentSymbol, DocumentSymbolParams,
        DocumentSymbolResponse, FileSystemWatcher, GlobPattern, GotoDefinitionParams,
        GotoDefinitionResponse, InitializeParams, InitializeResult, InitializedParams, Location,
        MessageType, OneOf, PositionEncodingKind, ReferenceParams, Registration, SaveOptions,
        ServerCapabilities, ServerInfo, SymbolInformation, TextDocumentSyncCapability,
        TextDocumentSyncKind, TextDocumentSyncOptions, Uri, WorkspaceSymbolParams,
        WorkspaceSymbolResponse,
    },
    Client, LanguageServer,
};

use crate::index::{
    document_diagnostic, is_project_document, is_safe_authored_file, is_valid_yaml,
    load_project_documents, IndexedDiagnostic, IndexedLocation, IndexedSymbol, ProjectIndex,
};

const SERVER_NAME: &str = "Registry Stack Language Server";
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub struct Backend {
    client: Client,
    state: RwLock<Option<WorkspaceState>>,
    load_error: RwLock<Option<String>>,
    published_paths: Mutex<BTreeSet<PathBuf>>,
    supports_dynamic_file_watching: AtomicBool,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            state: RwLock::new(None),
            load_error: RwLock::new(None),
            published_paths: Mutex::new(BTreeSet::new()),
            supports_dynamic_file_watching: AtomicBool::new(false),
        }
    }

    async fn publish_diagnostics(&self) {
        let (mut by_path, versions) = {
            let state = self.state.read().await;
            let Some(state) = state.as_ref() else {
                return;
            };
            let mut by_path = state
                .index
                .document_paths()
                .map(|path| (path.to_path_buf(), Vec::new()))
                .collect::<BTreeMap<_, Vec<Diagnostic>>>();
            for diagnostic in state.index.diagnostics() {
                by_path
                    .entry(diagnostic.path.clone())
                    .or_default()
                    .push(Diagnostic::new(
                        diagnostic.range,
                        Some(diagnostic.severity),
                        None,
                        Some("registry-stack".to_owned()),
                        diagnostic.message.clone(),
                        None,
                        None,
                    ));
            }
            (by_path, state.open_versions.clone())
        };

        let mut published = self.published_paths.lock().await;
        let current_paths = by_path.keys().cloned().collect::<BTreeSet<_>>();
        for stale_path in published.iter() {
            by_path.entry(stale_path.clone()).or_default();
        }

        for (path, diagnostics) in by_path {
            if let Some(uri) = Uri::from_file_path(&path) {
                self.client
                    .publish_diagnostics(uri, diagnostics, versions.get(&path).copied())
                    .await;
            }
        }
        *published = current_paths;
    }

    async fn update_document(&self, path: PathBuf, text: String, version: i32) {
        let path = normalize_document_path(&path);
        let mut state = self.state.write().await;
        let mut load_error = None;
        if state.is_none() {
            if let Some(root) = find_project_root(&path) {
                match WorkspaceState::load(&root) {
                    Ok(loaded) => {
                        *state = Some(loaded);
                        *self.load_error.write().await = None;
                    }
                    Err(error) => load_error = Some(bounded_load_error(&error)),
                }
            }
        }
        if let Some(state) = state.as_mut() {
            state.update(path, text, version);
        }
        drop(state);
        if let Some(error) = load_error {
            *self.load_error.write().await = Some(error.clone());
            self.client.log_message(MessageType::ERROR, error).await;
        }
        self.publish_diagnostics().await;
    }

    async fn reload_closed_document(&self, path: PathBuf) {
        let path = normalize_document_path(&path);
        let mut state = self.state.write().await;
        if let Some(state) = state.as_mut() {
            state.close(&path);
        }
        drop(state);
        self.publish_diagnostics().await;
    }

    async fn reload_watched_documents(&self, paths: Vec<PathBuf>) {
        let mut paths = paths
            .into_iter()
            .map(|path| normalize_document_path(&path))
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        let mut state = self.state.write().await;
        let mut load_error = None;
        if state.is_none() {
            if let Some(root) = paths.iter().find_map(|path| find_project_root(path)) {
                match WorkspaceState::load(&root) {
                    Ok(loaded) => {
                        *state = Some(loaded);
                        *self.load_error.write().await = None;
                    }
                    Err(error) => load_error = Some(bounded_load_error(&error)),
                }
            }
        }
        if let Some(state) = state.as_mut() {
            for path in paths {
                state.reload_from_disk(&path);
            }
        }
        drop(state);
        if let Some(error) = load_error {
            *self.load_error.write().await = Some(error.clone());
            self.client.log_message(MessageType::ERROR, error).await;
        }
        self.publish_diagnostics().await;
    }
}

impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        let supports_dynamic_file_watching = params
            .capabilities
            .workspace
            .as_ref()
            .and_then(|workspace| workspace.did_change_watched_files.as_ref())
            .and_then(|capability| capability.dynamic_registration)
            .unwrap_or(false);
        self.supports_dynamic_file_watching
            .store(supports_dynamic_file_watching, Ordering::Relaxed);
        if let Some(root) = project_root_from_initialize(&params) {
            match WorkspaceState::load(&root) {
                Ok(state) => {
                    *self.state.write().await = Some(state);
                    *self.load_error.write().await = None;
                }
                Err(error) => *self.load_error.write().await = Some(bounded_load_error(&error)),
            }
        }

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                position_encoding: Some(PositionEncodingKind::UTF16),
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::FULL),
                        save: Some(
                            SaveOptions {
                                include_text: Some(true),
                            }
                            .into(),
                        ),
                        ..TextDocumentSyncOptions::default()
                    },
                )),
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                workspace_symbol_provider: Some(OneOf::Left(true)),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: SERVER_NAME.to_owned(),
                version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            }),
            offset_encoding: None,
        })
    }

    async fn initialized(&self, _params: InitializedParams) {
        if self.supports_dynamic_file_watching.load(Ordering::Relaxed) {
            let register_options = serde_json::to_value(DidChangeWatchedFilesRegistrationOptions {
                watchers: vec![FileSystemWatcher {
                    glob_pattern: GlobPattern::String("**/*.yaml".to_owned()),
                    kind: None,
                }],
            })
            .expect("watched-file registration options serialize");
            if let Err(error) = self
                .client
                .register_capability(vec![Registration {
                    id: "registry-stack-yaml-files".to_owned(),
                    method: "workspace/didChangeWatchedFiles".to_owned(),
                    register_options: Some(register_options),
                }])
                .await
            {
                self.client
                    .log_message(
                        MessageType::WARNING,
                        format!("Could not watch Registry Stack YAML files: {error}"),
                    )
                    .await;
            }
        }

        let (message_type, message) = {
            let state = self.state.read().await;
            if let Some(state) = state.as_ref() {
                (
                    MessageType::INFO,
                    format!(
                        "Registry Stack project indexed at {}",
                        state.index.root().display()
                    ),
                )
            } else if let Some(error) = self.load_error.read().await.clone() {
                (MessageType::ERROR, error)
            } else {
                (
                    MessageType::INFO,
                    "No registry-stack.yaml project found in the workspace".to_owned(),
                )
            }
        };
        self.client.log_message(message_type, message).await;
        self.publish_diagnostics().await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let document = params.text_document;
        if let Some(path) = document.uri.to_file_path() {
            self.update_document(path.into_owned(), document.text, document.version)
                .await;
        }
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let Some(change) = params.content_changes.into_iter().last() else {
            return;
        };
        if change.range.is_some() {
            self.client
                .log_message(
                    MessageType::WARNING,
                    "Registry Stack language server received an incremental edit despite advertising full synchronization",
                )
                .await;
            return;
        }
        if let Some(path) = params.text_document.uri.to_file_path() {
            self.update_document(path.into_owned(), change.text, params.text_document.version)
                .await;
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let Some(text) = params.text else {
            return;
        };
        let Some(path) = params.text_document.uri.to_file_path() else {
            return;
        };
        let path = path.into_owned();
        let version = {
            let state = self.state.read().await;
            state
                .as_ref()
                .and_then(|state| state.open_versions.get(&normalize_document_path(&path)))
                .copied()
                .unwrap_or(0)
        };
        self.update_document(path, text, version).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        if let Some(path) = params.text_document.uri.to_file_path() {
            self.reload_closed_document(path.into_owned()).await;
        }
    }

    async fn did_change_watched_files(&self, params: DidChangeWatchedFilesParams) {
        let paths = params
            .changes
            .into_iter()
            .filter_map(|change| change.uri.to_file_path().map(|path| path.into_owned()))
            .collect::<Vec<_>>();
        if !paths.is_empty() {
            self.reload_watched_documents(paths).await;
        }
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let document = params.text_document_position_params;
        let Some(path) = document.text_document.uri.to_file_path() else {
            return Ok(None);
        };
        let locations = {
            let state = self.state.read().await;
            state
                .as_ref()
                .map(|state| state.index.definitions_at(&path, document.position))
                .unwrap_or_default()
        };
        let locations = locations
            .into_iter()
            .filter_map(to_lsp_location)
            .collect::<Vec<_>>();
        Ok((!locations.is_empty()).then_some(GotoDefinitionResponse::Array(locations)))
    }

    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let document = params.text_document_position;
        let Some(path) = document.text_document.uri.to_file_path() else {
            return Ok(None);
        };
        let locations = {
            let state = self.state.read().await;
            state
                .as_ref()
                .map(|state| {
                    state.index.references_at(
                        &path,
                        document.position,
                        params.context.include_declaration,
                    )
                })
                .unwrap_or_default()
        };
        let locations = locations
            .into_iter()
            .filter_map(to_lsp_location)
            .collect::<Vec<_>>();
        Ok(Some(locations))
    }

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let Some(path) = params.text_document.uri.to_file_path() else {
            return Ok(None);
        };
        let symbols = {
            let state = self.state.read().await;
            state
                .as_ref()
                .map(|state| {
                    state
                        .index
                        .document_symbols(&path)
                        .into_iter()
                        .map(to_document_symbol)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        Ok(Some(DocumentSymbolResponse::Nested(symbols)))
    }

    async fn symbol(
        &self,
        params: WorkspaceSymbolParams,
    ) -> Result<Option<WorkspaceSymbolResponse>> {
        let symbols = {
            let state = self.state.read().await;
            state
                .as_ref()
                .map(|state| {
                    state
                        .index
                        .workspace_symbols(&params.query)
                        .into_iter()
                        .filter_map(to_symbol_information)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        Ok(Some(WorkspaceSymbolResponse::Flat(symbols)))
    }
}

#[derive(Debug)]
struct WorkspaceState {
    root: PathBuf,
    documents: BTreeMap<PathBuf, String>,
    open_versions: BTreeMap<PathBuf, i32>,
    disk_diagnostics: Vec<IndexedDiagnostic>,
    index: ProjectIndex,
}

impl WorkspaceState {
    fn load(root: &Path) -> anyhow::Result<Self> {
        let root = root.canonicalize()?;
        let loaded = load_project_documents(&root)?;
        let index = ProjectIndex::from_documents_with_diagnostics(
            &root,
            &loaded.documents,
            loaded.diagnostics.clone(),
        );
        Ok(Self {
            root,
            documents: loaded.documents,
            open_versions: BTreeMap::new(),
            disk_diagnostics: loaded.diagnostics,
            index,
        })
    }

    fn update(&mut self, path: PathBuf, text: String, version: i32) {
        if !is_project_document(&self.root, &path) {
            return;
        }
        self.open_versions.insert(path.clone(), version);
        if text.len() <= MAX_DOCUMENT_BYTES && is_valid_yaml(&text) {
            self.disk_diagnostics
                .retain(|diagnostic| diagnostic.path != path);
            self.documents.insert(path, text);
            self.rebuild();
        }
    }

    fn close(&mut self, path: &Path) {
        if !is_project_document(&self.root, path) {
            return;
        }
        self.open_versions.remove(path);
        self.reload_from_disk(path);
    }

    fn reload_from_disk(&mut self, path: &Path) {
        if !is_project_document(&self.root, path) || self.open_versions.contains_key(path) {
            return;
        }
        self.disk_diagnostics
            .retain(|diagnostic| diagnostic.path != path);
        if !is_safe_authored_file(&self.root, path) {
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
                Ok(text) if is_valid_yaml(&text) => {
                    self.documents.insert(path.to_path_buf(), text);
                }
                Ok(_) => {
                    self.documents.remove(path);
                    self.disk_diagnostics.push(document_diagnostic(
                        path,
                        "Invalid YAML syntax; fix this project document before it can be indexed",
                    ));
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
            &self.root,
            &self.documents,
            self.disk_diagnostics.clone(),
        );
    }
}

fn bounded_load_error(error: &anyhow::Error) -> String {
    const MAX_CHARS: usize = 500;
    let detail = format!("{error:#}")
        .chars()
        .take(MAX_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    format!("Could not index Registry Stack project: {detail}")
}

fn project_root_from_initialize(params: &InitializeParams) -> Option<PathBuf> {
    if let Some(folders) = params.workspace_folders.as_ref() {
        for folder in folders {
            if let Some(path) = folder.uri.to_file_path() {
                if let Some(root) = find_project_root(&path) {
                    return Some(root);
                }
            }
        }
    }

    #[allow(deprecated)]
    if let Some(uri) = params.root_uri.as_ref() {
        if let Some(path) = uri.to_file_path() {
            if let Some(root) = find_project_root(&path) {
                return Some(root);
            }
        }
    }

    #[allow(deprecated)]
    params
        .root_path
        .as_deref()
        .and_then(|path| find_project_root(Path::new(path)))
}

fn find_project_root(start: &Path) -> Option<PathBuf> {
    let start = if start.is_file() {
        start.parent()?
    } else {
        start
    };
    for candidate in start.ancestors() {
        let manifest = candidate.join("registry-stack.yaml");
        if fs::symlink_metadata(&manifest).is_ok_and(|metadata| metadata.file_type().is_file()) {
            return candidate.canonicalize().ok();
        }
    }
    None
}

fn normalize_document_path(path: &Path) -> PathBuf {
    if let Ok(path) = path.canonicalize() {
        return path;
    }
    path.parent()
        .and_then(|parent| parent.canonicalize().ok())
        .and_then(|parent| path.file_name().map(|name| parent.join(name)))
        .unwrap_or_else(|| path.to_path_buf())
}

fn to_lsp_location(location: IndexedLocation) -> Option<Location> {
    Some(Location::new(
        Uri::from_file_path(location.path)?,
        location.range,
    ))
}

#[allow(deprecated)]
fn to_document_symbol(symbol: &IndexedSymbol) -> DocumentSymbol {
    DocumentSymbol {
        name: symbol.name.clone(),
        detail: Some(symbol.kind.label().to_owned()),
        kind: symbol.kind.lsp_kind(),
        tags: None,
        deprecated: None,
        range: symbol.location.range,
        selection_range: symbol.location.range,
        children: None,
    }
}

#[allow(deprecated)]
fn to_symbol_information(symbol: &IndexedSymbol) -> Option<SymbolInformation> {
    Some(SymbolInformation {
        name: symbol.name.clone(),
        kind: symbol.kind.lsp_kind(),
        tags: None,
        deprecated: None,
        location: Location::new(
            Uri::from_file_path(&symbol.location.path)?,
            symbol.location.range,
        ),
        container_name: symbol.container_name.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;
    use tower_lsp_server::ls_types::Position;

    use super::*;

    fn project() -> TempDir {
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("registry-stack.yaml"),
            "version: 1\nregistry: { id: demo }\nservices: {}\n",
        )
        .unwrap();
        temp
    }

    #[test]
    fn finds_project_from_nested_directory() {
        let temp = project();
        let nested = temp.path().join("integrations/people");
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            find_project_root(&nested),
            Some(temp.path().canonicalize().unwrap())
        );
    }

    #[test]
    fn retains_last_valid_index_during_invalid_edits() {
        let temp = project();
        let mut state = WorkspaceState::load(temp.path()).unwrap();
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

        state.update(manifest.clone(), "registry: [\n".to_owned(), 3);
        assert!(state
            .index
            .workspace_symbols("current")
            .iter()
            .any(|symbol| symbol.name == "current"));
        assert_eq!(state.open_versions.get(&manifest), Some(&3));
        assert_eq!(
            state
                .index
                .definitions_at(&manifest, Position::new(1, 20))
                .len(),
            1
        );
    }

    #[test]
    fn reloads_external_changes_from_disk() {
        let temp = project();
        let manifest = temp
            .path()
            .join("registry-stack.yaml")
            .canonicalize()
            .unwrap();
        let mut state = WorkspaceState::load(temp.path()).unwrap();

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
        let temp = project();
        let mut state = WorkspaceState::load(temp.path()).unwrap();
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
        let temp = project();
        let manifest = temp
            .path()
            .join("registry-stack.yaml")
            .canonicalize()
            .unwrap();
        let mut state = WorkspaceState::load(temp.path()).unwrap();
        state.update(
            manifest.clone(),
            "version: 1\nregistry: { id: unsaved }\nservices: {}\n".to_owned(),
            2,
        );

        fs::write(
            &manifest,
            "version: 1\nregistry: { id: external }\nservices: {}\n",
        )
        .unwrap();
        state.reload_from_disk(&manifest);
        assert!(state
            .index
            .workspace_symbols("unsaved")
            .iter()
            .any(|symbol| symbol.name == "unsaved"));
        assert!(state.index.workspace_symbols("external").is_empty());

        state.close(&manifest);
        assert!(state
            .index
            .workspace_symbols("external")
            .iter()
            .any(|symbol| symbol.name == "external"));
    }
}
