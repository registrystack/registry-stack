# Registry Stack for Zed

This extension attaches `registry-language-server` to Zed's built-in YAML language. It adds
cross-file definitions, references, workspace/document symbols, and Registry Stack reference
diagnostics. Zed's YAML language server remains responsible for YAML syntax, schema validation,
completion, formatting, and ordinary hover information.

## Development setup

1. Build the server from the repository root and put it on `PATH`:

   ```console
   cargo build -p registry-language-server
   export PATH="$PWD/target/debug:$PATH"
   ```

2. In Zed, run `zed: install dev extension` and select this directory.

Zed extensions cannot bundle an external language server. This launcher first looks for
`registry-language-server`, then falls back to `registryctl authoring language-server`. A future
marketplace package can also download a matching signed Registry Stack release asset.
