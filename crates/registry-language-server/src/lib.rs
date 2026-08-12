// SPDX-License-Identifier: Apache-2.0
//! Cross-file navigation for Registry Stack project YAML.

mod evidence;
mod refs;
mod relay_v2;
mod safety;
mod server;
mod workspace;
mod yaml;

pub use refs::{
    CompletionCandidate, EvidenceKind, HoverText, IndexedDiagnostic, IndexedLocation,
    IndexedSymbol, ProjectIndex, RelayV2Kind, SymbolKind,
};
pub use server::Backend;

/// Serve the Registry Stack language protocol over standard input and output.
pub async fn run_stdio() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = tower_lsp_server::LspService::new(Backend::new);
    tower_lsp_server::Server::new(stdin, stdout, socket)
        .serve(service)
        .await;
}
