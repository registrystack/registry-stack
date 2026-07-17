// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use tokio::sync::{Mutex, RwLock};
use tower_lsp_server::{
    jsonrpc::Result,
    ls_types::{
        Diagnostic, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
        DidOpenTextDocumentParams, DidSaveTextDocumentParams, DocumentSymbol, DocumentSymbolParams,
        DocumentSymbolResponse, GotoDefinitionParams, GotoDefinitionResponse, InitializeParams,
        InitializeResult, InitializedParams, Location, MessageType, OneOf, PositionEncodingKind,
        ReferenceParams, SaveOptions, ServerCapabilities, ServerInfo, SymbolInformation,
        TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions, Uri,
        WorkspaceSymbolParams, WorkspaceSymbolResponse,
    },
    Client, LanguageServer,
};

use crate::index::{
    is_project_document, is_valid_yaml, load_project_documents, IndexedLocation, IndexedSymbol,
    ProjectIndex,
};

const SERVER_NAME: &str = "Registry Stack Language Server";
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub struct Backend {
    client: Client,
    state: RwLock<Option<WorkspaceState>>,
    published_paths: Mutex<BTreeSet<PathBuf>>,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            state: RwLock::new(None),
            published_paths: Mutex::new(BTreeSet::new()),
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
        for stale_path in published.iter() {
            by_path.entry(stale_path.clone()).or_default();
        }
        let current_paths = by_path.keys().cloned().collect::<BTreeSet<_>>();

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
        if state.is_none() {
            *state = find_project_root(&path).and_then(|root| WorkspaceState::load(&root).ok());
        }
        if let Some(state) = state.as_mut() {
            state.update(path, text, version);
        }
        drop(state);
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
}

impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        if let Some(root) = project_root_from_initialize(&params) {
            *self.state.write().await = WorkspaceState::load(&root).ok();
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
        let message = {
            let state = self.state.read().await;
            state
                .as_ref()
                .map(|state| {
                    format!(
                        "Registry Stack project indexed at {}",
                        state.index.root().display()
                    )
                })
                .unwrap_or_else(|| {
                    "No registry-stack.yaml project found in the workspace".to_owned()
                })
        };
        self.client.log_message(MessageType::INFO, message).await;
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
        let Some(path) = params.text_document.uri.to_file_path() else {
            return;
        };
        let path = path.into_owned();
        let text = params.text.or_else(|| fs::read_to_string(&path).ok());
        if let Some(text) = text {
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
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        if let Some(path) = params.text_document.uri.to_file_path() {
            self.reload_closed_document(path.into_owned()).await;
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
    index: ProjectIndex,
}

impl WorkspaceState {
    fn load(root: &Path) -> anyhow::Result<Self> {
        let root = root.canonicalize()?;
        let documents = load_project_documents(&root)?;
        let index = ProjectIndex::from_documents(&root, &documents);
        Ok(Self {
            root,
            documents,
            open_versions: BTreeMap::new(),
            index,
        })
    }

    fn update(&mut self, path: PathBuf, text: String, version: i32) {
        if !is_project_document(&self.root, &path) {
            return;
        }
        self.open_versions.insert(path.clone(), version);
        if text.len() <= MAX_DOCUMENT_BYTES && is_valid_yaml(&text) {
            self.documents.insert(path, text);
            self.rebuild();
        }
    }

    fn close(&mut self, path: &Path) {
        if !is_project_document(&self.root, path) {
            return;
        }
        self.open_versions.remove(path);
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && metadata.len() <= MAX_DOCUMENT_BYTES as u64 =>
            {
                if let Ok(text) = fs::read_to_string(path) {
                    if is_valid_yaml(&text) {
                        self.documents.insert(path.to_path_buf(), text);
                    }
                }
            }
            Ok(_) => {
                self.documents.remove(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.documents.remove(path);
            }
            Err(_) => {}
        }
        self.rebuild();
    }

    fn rebuild(&mut self) {
        self.index = ProjectIndex::from_documents(&self.root, &self.documents);
    }
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
}
