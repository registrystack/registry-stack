# Registry Stack for VS Code

This extension starts `registry-language-server` for a workspace whose root contains
`registry-stack.yaml`. It adds cross-file definitions, references, workspace/document symbols,
and Registry Stack reference diagnostics. Red Hat YAML remains responsible for YAML syntax,
schema validation, completion, formatting, and ordinary hover information.

## Development setup

1. Build the server from the repository root:

   ```console
   cargo build -p registry-language-server
   ```

2. In this directory, install dependencies and compile the extension:

   ```console
   npm ci
   npm run compile
   ```

3. Set `registryStack.languageServer.path` to the built executable, put
   `registry-language-server` on `PATH`, or use a `registryctl` build that provides
   `registryctl authoring language-server`.

For a packaged extension, place the platform executable at
`bin/registry-language-server` (`bin/registry-language-server.exe` on Windows) before running
the VS Code extension packaging tool.
