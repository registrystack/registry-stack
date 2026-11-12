// SPDX-License-Identifier: Apache-2.0

#[tokio::main]
async fn main() {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next()) {
        (None, None) => registry_language_server::run_stdio().await,
        (Some(arg), None) if arg == "--workspace-analysis" => {
            if let Err(error) = registry_language_server::run_workspace_analysis_stdio() {
                println!("{}", error.response());
                std::process::exit(1);
            }
        }
        (Some(arg), None) if arg == "--workspace-lsp" => {
            registry_language_server::run_workspace_lsp_stdio().await;
        }
        (Some(arg), None) if arg == "--version" => {
            println!("registry-language-server {}", env!("CARGO_PKG_VERSION"));
        }
        (Some(arg), None) if arg == "--help" => {
            println!("Usage: registry-language-server [--workspace-analysis|--workspace-lsp|--version|--help]");
            println!(
                "Without options, serve the language protocol over standard input and output."
            );
            println!("--workspace-analysis reads one versioned JSON request from standard input.");
            println!("--workspace-lsp serves stateless authorized workspace queries over LSP.");
        }
        _ => {
            eprintln!("error: unrecognized language-server arguments; run with --help");
            std::process::exit(2);
        }
    }
}
