# registry-notary-source-adapter-rhai

A sandboxed [Rhai](https://rhai.rs) scripting engine for governed source
adapters.

It runs small, untrusted scripts that resolve a lookup against an upstream
source. Every resource axis is bounded (operations, call depth, string/array/map
sizes, wall-clock time, HTTP-call count, output bytes, concurrency), the only
effect a script may perform is a single host capability, and the script's output
is shape-validated before it leaves the engine.

## Script-visible API

A script defines `fn lookup(ctx) { ... }` and may call:

- `source.get(target, path, query)` — the host capability (the only effect).
- `xw.text.*`, `xw.date.*`, `xw.ids.*`, `xw.json.*`, `xw.email.*`,
  `xw.redaction.*` — pure, deterministic helpers.

A script must return an array of plain JSON objects.

## Testing

```sh
cargo test -p registry-notary-source-adapter-rhai
```

All tests run fully offline against a deterministic mock host.
