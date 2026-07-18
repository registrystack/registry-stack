# Registry Stack language server

`registry-language-server` adds Registry Stack project semantics to YAML editors through the
Language Server Protocol. It discovers the bounded authoring surface rooted at
`registry-stack.yaml` and indexes:

- registry, integration, entity, service, consultation, claim, credential-profile, fixture, and
  environment definitions;
- integration and entity aliases across the project manifest, their definition files, and
  environment files;
- consultation integration references, records-service entity references, credential-profile
  claim references, direct claim-output consultation references, and fixture expected-claim
  references.

It provides go to definition, find references, workspace symbols, document symbols, and errors for
missing, duplicate, or ambiguous references. It deliberately leaves syntax, schemas, completion,
hover, and formatting to the editor's YAML language server.

## Run

```console
cargo run -p registry-language-server
```

The same server is available from a release installation as:

```console
registryctl authoring language-server
```

The server communicates over standard input and output and expects the opened workspace (or a
nested directory) to be inside a Registry Stack project.

Only regular files in the documented Registry Stack project layout are indexed. Symbolic links,
files outside the project root, unrelated YAML files, and project documents larger than 1 MiB are
ignored. This keeps editor analysis inside the same bounded authoring surface as `registryctl`.
