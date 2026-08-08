// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

use tokio::sync::{Mutex, RwLock};
use tower_lsp_server::{
    jsonrpc::Result,
    ls_types::{
        CompletionItem, CompletionList, CompletionOptions, CompletionParams, CompletionResponse,
        CompletionTextEdit, Diagnostic, DidChangeTextDocumentParams, DidChangeWatchedFilesParams,
        DidChangeWatchedFilesRegistrationOptions, DidCloseTextDocumentParams,
        DidOpenTextDocumentParams, DidSaveTextDocumentParams, DocumentSymbol, DocumentSymbolParams,
        DocumentSymbolResponse, FileSystemWatcher, GlobPattern, GotoDefinitionParams,
        GotoDefinitionResponse, Hover, HoverContents, HoverParams, HoverProviderCapability,
        InitializeParams, InitializeResult, InitializedParams, Location, MarkupContent, MarkupKind,
        MessageType, NumberOrString, OneOf, PositionEncodingKind, ReferenceParams, Registration,
        SaveOptions, ServerCapabilities, ServerInfo, SymbolInformation, TextDocumentSyncCapability,
        TextDocumentSyncKind, TextDocumentSyncOptions, TextEdit, Uri, WorkspaceSymbolParams,
        WorkspaceSymbolResponse,
    },
    Client, LanguageServer,
};

use crate::{
    evidence::layout::watched_globs,
    refs::{CompletionCandidate, IndexedLocation, IndexedSymbol},
    workspace::Workspace,
};

const SERVER_NAME: &str = "Registry Stack Language Server";

/// What brought one revision of a document to the server.
///
/// The two carry the same text and differ in what else the notification says about the project. An
/// edit changes a buffer, and a buffer over a file no root holds changes nothing a root answers
/// from. A save changes the file, which is what the parts of a project read from disk are read
/// from, so it reaches further than the document it names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Revision {
    Edited,
    Saved,
}

#[derive(Debug)]
pub struct Backend {
    client: Client,
    workspace: RwLock<Workspace>,
    load_error: RwLock<Option<String>>,
    published_paths: Mutex<BTreeSet<PathBuf>>,
    supports_dynamic_file_watching: AtomicBool,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            workspace: RwLock::new(Workspace::default()),
            load_error: RwLock::new(None),
            published_paths: Mutex::new(BTreeSet::new()),
            supports_dynamic_file_watching: AtomicBool::new(false),
        }
    }

    async fn publish_diagnostics(&self) {
        let (mut by_path, versions) = {
            let workspace = self.workspace.read().await;
            let mut by_path = BTreeMap::<PathBuf, Vec<Diagnostic>>::new();
            let mut versions = BTreeMap::new();
            for root in workspace.roots() {
                for path in root.index().document_paths() {
                    by_path.entry(path.to_path_buf()).or_default();
                }
                for diagnostic in root.index().diagnostics() {
                    by_path
                        .entry(diagnostic.path.clone())
                        .or_default()
                        .push(Diagnostic::new(
                            diagnostic.range,
                            Some(diagnostic.severity),
                            // The code names the rule, so a client can filter or suppress one rule
                            // instead of the whole source.
                            diagnostic.code.clone().map(NumberOrString::String),
                            // The root says which tool is talking, so a reader of a mixed workspace
                            // can tell one family's diagnostics from another's.
                            Some(root.diagnostic_source().to_owned()),
                            diagnostic.message.clone(),
                            None,
                            None,
                        ));
                }
                versions.extend(
                    root.open_versions()
                        .iter()
                        .map(|(path, version)| (path.clone(), *version)),
                );
            }
            (by_path, versions)
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

    /// Records the load failure a lazily discovered root reported, once, where the client can see it.
    async fn report_load_error(&self, error: Option<String>) {
        if let Some(error) = error {
            *self.load_error.write().await = Some(error.clone());
            self.client.log_message(MessageType::ERROR, error).await;
        }
    }

    async fn update_document(&self, path: PathBuf, text: String, version: i32, revision: Revision) {
        let load_error = {
            let mut workspace = self.workspace.write().await;
            let path = workspace.intern(&path);
            let load_error = match workspace.ensure_root_for(&path) {
                Ok(()) => {
                    *self.load_error.write().await = None;
                    None
                }
                Err(error) => Some(bounded_load_error(&error)),
            };
            match revision {
                Revision::Edited => workspace.update(path, text, version),
                Revision::Saved => workspace.save(path, text, version),
            }
            load_error
        };
        self.report_load_error(load_error).await;
        self.publish_diagnostics().await;
    }

    async fn reload_closed_document(&self, path: PathBuf) {
        {
            let mut workspace = self.workspace.write().await;
            let path = workspace.intern(&path);
            workspace.close(&path);
        }
        self.publish_diagnostics().await;
    }

    async fn reload_watched_documents(&self, paths: Vec<PathBuf>) {
        let load_error = {
            let mut workspace = self.workspace.write().await;
            let mut paths = paths
                .iter()
                .map(|path| workspace.intern(path))
                .collect::<Vec<_>>();
            paths.sort();
            paths.dedup();
            let mut load_error = None;
            for path in &paths {
                if let Err(error) = workspace.ensure_root_for(path) {
                    load_error.get_or_insert_with(|| bounded_load_error(&error));
                }
            }
            if let Err(error) = workspace.reload_watched(&paths) {
                load_error.get_or_insert_with(|| bounded_load_error(&error));
            }
            if load_error.is_none() {
                *self.load_error.write().await = None;
            }
            load_error
        };
        self.report_load_error(load_error).await;
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

        let mut workspace = self.workspace.write().await;
        workspace.set_folders(workspace_folders(&params));
        let errors = workspace.adopt_folder_roots();
        *self.load_error.write().await = errors.first().map(bounded_load_error);
        drop(workspace);

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
                completion_provider: Some(CompletionOptions {
                    // The three characters after which an author is one keystroke into a value:
                    // the `:` that opens a field, the `.` inside a file name, and the `/` that
                    // opens a path or a JSON pointer. A client that sends none of them and
                    // invokes completion by hand gets the same list, because the list is read
                    // from the document rather than from the trigger.
                    trigger_characters: Some(vec![":".to_owned(), ".".to_owned(), "/".to_owned()]),
                    // Every candidate is whole when it is offered, so there is nothing for a
                    // client to spend a second round trip resolving.
                    resolve_provider: Some(false),
                    ..CompletionOptions::default()
                }),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
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
            // The globs cover every file an Evidence index resolves against, so a Relay project
            // document (always `.yaml`), an Evidence derivation (`.rhai`), and a source's own
            // artifact all fire a watched-file event. Relay reads only `.yaml` project documents,
            // which the extension half covers, so this list still covers Relay's own watcher.
            let watchers = watched_globs()
                .into_iter()
                .map(|glob| FileSystemWatcher {
                    glob_pattern: GlobPattern::String(glob),
                    kind: None,
                })
                .collect();
            let register_options =
                serde_json::to_value(DidChangeWatchedFilesRegistrationOptions { watchers })
                    .expect("watched-file registration options serialize");
            if let Err(error) = self
                .client
                .register_capability(vec![Registration {
                    id: "registry-stack-authored-files".to_owned(),
                    method: "workspace/didChangeWatchedFiles".to_owned(),
                    register_options: Some(register_options),
                }])
                .await
            {
                self.client
                    .log_message(
                        MessageType::WARNING,
                        format!("Could not watch Registry Stack authored files: {error}"),
                    )
                    .await;
            }
        }

        let (message_type, message) = {
            let workspace = self.workspace.read().await;
            let roots = workspace
                .roots()
                .map(|root| root.index().root().display().to_string())
                .collect::<Vec<_>>();
            if !roots.is_empty() {
                (
                    MessageType::INFO,
                    format!("Registry Stack project indexed at {}", roots.join(", ")),
                )
            } else if let Some(error) = self.load_error.read().await.clone() {
                (MessageType::ERROR, error)
            } else {
                (
                    MessageType::INFO,
                    "No Relay or Evidence project found in the workspace".to_owned(),
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
        if let Some(path) = document_path(&document.uri) {
            self.update_document(path, document.text, document.version, Revision::Edited)
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
        if let Some(path) = document_path(&params.text_document.uri) {
            self.update_document(
                path,
                change.text,
                params.text_document.version,
                Revision::Edited,
            )
            .await;
        }
    }

    /// A save the client reported, with the text it wrote.
    ///
    /// The text is required and the URI is never opened. A notification without it names a path the
    /// client chose and says nothing about what is at it, and a server that answered one by reading
    /// that path would read whatever the client pointed it at. What a save still tells the server
    /// with no text of its own read is that the file behind it changed, which is why the revision
    /// carries the reason it arrived: the parts of a project a build reads from disk are read again
    /// from the root's own paths, never from this one.
    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let Some(text) = params.text else {
            return;
        };
        let Some(path) = document_path(&params.text_document.uri) else {
            return;
        };
        let version = {
            let workspace = self.workspace.read().await;
            let canonical = workspace.resolve(&path);
            workspace
                .root_for(&canonical)
                .and_then(|root| root.open_versions().get(&canonical))
                .copied()
                .unwrap_or(0)
        };
        self.update_document(path, text, version, Revision::Saved)
            .await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        if let Some(path) = document_path(&params.text_document.uri) {
            self.reload_closed_document(path).await;
        }
    }

    async fn did_change_watched_files(&self, params: DidChangeWatchedFilesParams) {
        let paths = params
            .changes
            .into_iter()
            .filter_map(|change| document_path(&change.uri))
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
        let Some(path) = document_path(&document.text_document.uri) else {
            return Ok(None);
        };
        let locations = {
            let workspace = self.workspace.read().await;
            let path = workspace.resolve(&path);
            workspace
                .root_for(&path)
                .map(|root| root.index().definitions_at(&path, document.position))
                .unwrap_or_default()
        };
        let locations = locations
            .into_iter()
            .filter_map(to_lsp_location)
            .collect::<Vec<_>>();
        Ok((!locations.is_empty()).then_some(GotoDefinitionResponse::Array(locations)))
    }

    /// The names that could stand where the author is writing one.
    ///
    /// The request's context is deliberately not read. A client sends `Invoked` for a list the
    /// author asked for and `TriggerCharacter` for one the typing opened, and which of the two
    /// arrives is decided by client settings this server has no say in: an editor configured not to
    /// suggest inside strings sends only the invoked kind, over the very fields this server
    /// completes. The document says everything needed, so both are answered identically.
    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let document = params.text_document_position;
        let Some(path) = document_path(&document.text_document.uri) else {
            return Ok(None);
        };
        let candidates = {
            let workspace = self.workspace.read().await;
            let path = workspace.resolve(&path);
            workspace
                .root_for(&path)
                .map(|root| root.index().completions_at(&path, document.position))
                .unwrap_or_default()
        };
        Ok(Some(CompletionResponse::List(CompletionList {
            // The list is always reoffered on the next keystroke. A value slot holding nothing yet
            // holds no scalar for the index to find a reference in, which is the state a `:`
            // trigger fires in, so a client that cached this answer as complete would show nothing
            // for the rest of the word. Saying it is incomplete costs one rebuildless lookup per
            // character and makes the list appear as soon as there is one character to place it on.
            is_incomplete: true,
            items: candidates.into_iter().map(completion_item).collect(),
        })))
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let document = params.text_document_position_params;
        let Some(path) = document_path(&document.text_document.uri) else {
            return Ok(None);
        };
        let hover = {
            let workspace = self.workspace.read().await;
            let path = workspace.resolve(&path);
            workspace
                .root_for(&path)
                .and_then(|root| root.index().hover_at(&path, document.position))
        };
        Ok(hover.map(|hover| Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: hover.markdown,
            }),
            range: Some(hover.range),
        }))
    }

    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let document = params.text_document_position;
        let Some(path) = document_path(&document.text_document.uri) else {
            return Ok(None);
        };
        let locations = {
            let workspace = self.workspace.read().await;
            let path = workspace.resolve(&path);
            workspace
                .root_for(&path)
                .map(|root| {
                    root.index().references_at(
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
        let Some(path) = document_path(&params.text_document.uri) else {
            return Ok(None);
        };
        let symbols = {
            let workspace = self.workspace.read().await;
            let path = workspace.resolve(&path);
            workspace
                .root_for(&path)
                .map(|root| {
                    root.index()
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
            let workspace = self.workspace.read().await;
            workspace
                .roots()
                .flat_map(|root| root.index().workspace_symbols(&params.query))
                .filter_map(to_symbol_information)
                .collect::<Vec<_>>()
        };
        Ok(Some(WorkspaceSymbolResponse::Flat(symbols)))
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

/// The filesystem path a document URI names, for `file:` URIs only.
///
/// `Uri::to_file_path` reads the path component of any scheme, so an `untitled:` buffer or a
/// virtual `zipfile:` document would otherwise arrive as an ordinary path and take part in root
/// discovery and indexing. Only a `file:` URI names something on this filesystem.
fn document_path(uri: &Uri) -> Option<PathBuf> {
    uri.scheme()
        .as_str()
        .eq_ignore_ascii_case("file")
        .then(|| uri.to_file_path().map(|path| path.into_owned()))
        .flatten()
}

/// The folders a client opened, in the order the protocol prefers them.
fn workspace_folders(params: &InitializeParams) -> Vec<PathBuf> {
    if let Some(folders) = params.workspace_folders.as_ref() {
        let folders = folders
            .iter()
            .filter_map(|folder| document_path(&folder.uri))
            .collect::<Vec<_>>();
        if !folders.is_empty() {
            return folders;
        }
    }

    #[allow(deprecated)]
    if let Some(path) = params.root_uri.as_ref().and_then(document_path) {
        return vec![path];
    }

    #[allow(deprecated)]
    params
        .root_path
        .as_deref()
        .map(|path| vec![PathBuf::from(path)])
        .unwrap_or_default()
}

fn to_lsp_location(location: IndexedLocation) -> Option<Location> {
    Some(Location::new(
        Uri::from_file_path(location.path)?,
        location.range,
    ))
}

/// One candidate as a client draws and applies it.
///
/// The edit is explicit rather than left to the client's own idea of the word under the cursor: a
/// fact path and a file name both hold characters an editor treats as word boundaries, so a client
/// guessing the replaced range would leave half of the old value beside the new one.
fn completion_item(candidate: CompletionCandidate) -> CompletionItem {
    CompletionItem {
        label: candidate.label.clone(),
        kind: Some(candidate.kind),
        detail: Some(candidate.detail),
        text_edit: Some(CompletionTextEdit::Edit(TextEdit {
            range: candidate.range,
            new_text: candidate.label,
        })),
        ..CompletionItem::default()
    }
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
    use std::path::Path;

    use tower_lsp_server::ls_types::{
        ClientCapabilities, DidChangeWatchedFilesClientCapabilities, WorkspaceClientCapabilities,
    };

    use super::*;

    fn initialize_params(folders: Option<Vec<&Path>>, root: Option<&Path>) -> InitializeParams {
        #[allow(deprecated)]
        InitializeParams {
            workspace_folders: folders.map(|folders| {
                folders
                    .into_iter()
                    .map(|path| tower_lsp_server::ls_types::WorkspaceFolder {
                        uri: Uri::from_file_path(path).unwrap(),
                        name: path.display().to_string(),
                    })
                    .collect()
            }),
            root_uri: root.map(|path| Uri::from_file_path(path).unwrap()),
            capabilities: ClientCapabilities {
                workspace: Some(WorkspaceClientCapabilities {
                    did_change_watched_files: Some(DidChangeWatchedFilesClientCapabilities {
                        dynamic_registration: Some(true),
                        ..DidChangeWatchedFilesClientCapabilities::default()
                    }),
                    ..WorkspaceClientCapabilities::default()
                }),
                ..ClientCapabilities::default()
            },
            ..InitializeParams::default()
        }
    }

    #[test]
    fn reads_folders_from_workspace_folders_then_the_deprecated_root() {
        let first = Path::new("/projects/first");
        let second = Path::new("/projects/second");
        assert_eq!(
            workspace_folders(&initialize_params(Some(vec![first, second]), None)),
            vec![first.to_path_buf(), second.to_path_buf()]
        );
        assert_eq!(
            workspace_folders(&initialize_params(None, Some(first))),
            vec![first.to_path_buf()]
        );
        assert!(workspace_folders(&initialize_params(None, None)).is_empty());
    }

    #[test]
    fn only_file_uris_name_a_document_on_this_filesystem() {
        let path = Path::new("/projects/demo/registry-stack.yaml");
        assert_eq!(
            document_path(&Uri::from_file_path(path).unwrap()),
            Some(path.to_path_buf())
        );
        for foreign in [
            "untitled:Untitled-1",
            "zipfile:///archive.zip::/registry-stack.yaml",
            "https://example.test/registry-stack.yaml",
        ] {
            let uri = serde_json::from_str::<Uri>(&format!("{foreign:?}")).unwrap();
            assert_eq!(document_path(&uri), None, "{foreign}");
        }
    }

    #[test]
    fn a_load_failure_is_reported_without_the_underlying_detail_running_away() {
        let error = anyhow::anyhow!("{}", "detail ".repeat(500));
        let message = bounded_load_error(&error);
        assert!(message.starts_with("Could not index Registry Stack project:"));
        assert!(message.chars().count() <= 560);
    }
}
