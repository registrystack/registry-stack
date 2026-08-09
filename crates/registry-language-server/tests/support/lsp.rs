// SPDX-License-Identifier: Apache-2.0
//! Driving the real server in process, over real files.
//!
//! The session below holds the same `Backend` the binary serves and speaks the same JSON-RPC to it,
//! without a process or a pipe in between. Everything it points the server at is a real temporary
//! directory: a mocked filesystem would answer every question the loader asks about symbolic links
//! with whatever the mock was written to say, and those answers are the defence being tested.

use std::path::Path;

use futures::{FutureExt, StreamExt};
use registry_language_server::Backend;
use serde_json::{json, Value};
use tower::{Service, ServiceExt};
use tower_lsp_server::{
    jsonrpc::{Id, Request, Response},
    ls_types::Uri,
    ClientSocket, LspService,
};

/// One client talking to one server.
pub struct LspSession {
    service: LspService<Backend>,
    socket: ClientSocket,
    received: Vec<Request>,
    next_id: i64,
}

impl LspSession {
    pub fn start() -> Self {
        let (service, socket) = LspService::new(Backend::new);
        Self {
            service,
            socket,
            received: Vec::new(),
            next_id: 0,
        }
    }

    /// Initializes the session against one workspace folder and completes the handshake.
    ///
    /// The advertised capabilities do not include dynamic registration of file watching, so the
    /// server has no reason to ask the client a question this session would have to answer.
    pub async fn initialize(&mut self, root: &Path) -> Value {
        let result = self
            .request(
                "initialize",
                json!({
                    "processId": null,
                    "capabilities": {},
                    "workspaceFolders": [{"uri": uri(root), "name": "project"}],
                }),
            )
            .await;
        self.notify("initialized", json!({})).await;
        result
    }

    pub async fn open(&mut self, path: &Path, text: &str, version: i32) {
        self.notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri(path),
                    "languageId": "yaml",
                    "version": version,
                    "text": text,
                },
            }),
        )
        .await;
    }

    /// Sends a request and returns its result, failing the test on a JSON-RPC error.
    pub async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = Id::Number(self.next_id);
        let response = self
            .call(
                Request::build(method.to_owned())
                    .id(id)
                    .params(params)
                    .finish(),
            )
            .await
            .unwrap_or_else(|| panic!("{method} answers"));
        let (_, result) = response.into_parts();
        result.unwrap_or_else(|error| panic!("{method} failed: {error:?}"))
    }

    pub async fn notify(&mut self, method: &str, params: Value) {
        let response = self
            .call(Request::build(method.to_owned()).params(params).finish())
            .await;
        assert!(
            response.is_none(),
            "{method} is a notification and answers nothing"
        );
    }

    /// The diagnostics the server last published for one document, or `None` if it never
    /// published for that document at all. An editor keeps the latest publication and forgets the
    /// ones before it, so `Some` reads the same list an author sees; `None` is kept distinct from
    /// `Some(vec![])` because a server that published nothing and a server that published a clean
    /// result are different states, and only one of them proves the document was checked.
    pub fn published_diagnostics(&self, path: &Path) -> Option<Vec<Value>> {
        let uri = uri(path);
        self.received
            .iter()
            .filter(|request| request.method() == "textDocument/publishDiagnostics")
            .filter_map(Request::params)
            .rfind(|params| params.get("uri") == Some(&uri))
            .map(|params| {
                params
                    .get("diagnostics")
                    .and_then(Value::as_array)
                    .cloned()
                    .expect("a publishDiagnostics notification carries a diagnostics array")
            })
    }

    /// Every method the server sent the client, in order.
    pub fn received_methods(&self) -> Vec<&str> {
        self.received.iter().map(Request::method).collect()
    }

    /// Calls the server, draining what it sends the client meanwhile and once more immediately
    /// after the call answers.
    ///
    /// The server-to-client channel holds one message. A handler publishing diagnostics while
    /// nothing reads them would wait forever on the very call that is waiting for the handler, so
    /// the two run together while the call is outstanding. That is not enough on its own: a
    /// handler's publish and its own answer can both be ready on the same poll, and `select!`
    /// picks whichever branch it happens to check first, not whichever happened first. A handler
    /// cannot answer before every message it sent has been accepted onto the channel, so
    /// anything still queued once the answer arrives belongs to this call; draining once more,
    /// without waiting for anything new, picks it up regardless of which way `select!` broke.
    async fn call(&mut self, request: Request) -> Option<Response> {
        let Self {
            service,
            socket,
            received,
            ..
        } = self;
        let call = service
            .ready()
            .await
            .expect("the server is still serving")
            .call(request);
        tokio::pin!(call);
        let answered = loop {
            tokio::select! {
                answered = &mut call => break answered.expect("the server is still serving"),
                Some(sent) = socket.next() => received.push(sent),
            }
        };
        while let Some(Some(sent)) = socket.next().now_or_never() {
            received.push(sent);
        }
        answered
    }
}

/// The URI an editor names a path by. Every path a test hands the server is canonical, so the URI
/// the server publishes back is comparable to this one.
pub fn uri(path: &Path) -> Value {
    Value::String(
        Uri::from_file_path(path)
            .expect("a temporary path is absolute")
            .to_string(),
    )
}
