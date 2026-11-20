# Registry Render

Render turns registry data into **governed, byte-stable PDF documents** —
receipts, notices, certificates, letters, ID/member cards (photo, QR,
duplex), tags and labels — using [Typst](https://typst.app) embedded as a
library.

> Give Render a verified template package and validated record data. Render
> returns the identical PDF every time, with the hashes and audit events an
> institution needs to stand behind the printed artifact.

Render is a **pure function**: data in, PDF out, with no database. The optional
HTTP adapter validates resource-bound access tokens through the shared OIDC
verifier or uses an explicit legacy API key. Only the adapter fetches issuer
metadata and keys; CLI and library rendering remain offline. It runs three ways
with the same rendering guarantees:

- **CLI** — `registry-render compile --bundle … --data … --issued-at … --output …`,
  offline, zero config: branch printing, template authoring, CI.
- **Service** — `registry-render serve`: one POST endpoint (`/v1/render/{type}`),
  resource-token or legacy API-key auth, supervised workers, and value-free audit entries
  written before every render and before every response.
- **Seal** (optional): with a `signing` block in the runtime file, `serve`
  adds `POST /v1/seal/{type}`, which returns the rendered document with a PAdES
  signature (see
  [Seal documents](https://docs.registrystack.org/operate/registry-render/#seal-documents)).
- **Library** — `registry_render::render(bundle, document, request)` for
  embedding.

## The 10-minute path

```bash
cargo run -p registry-render -- init ./my-bundle
# write data.json with {reference, body, footer-note}
cargo run -p registry-render -- compile --bundle ./my-bundle --type letter \
  --data data.json --issued-at 2026-01-01T00:00:00Z --output letter.pdf
cargo run -p registry-render -- package --bundle ./my-bundle \
  --output ./my-package --revision "$(git rev-parse HEAD)"
```

The scaffold compiles offline out of the box: the binary embeds a baseline
Latin font set. Scripts beyond Latin (Arabic, Hebrew, …) need a bundle font
(see `registry-render init`'s note) and `registry-render check` names the gap.

## Where to read next

- [Deploy Registry Render](https://docs.registrystack.org/operate/registry-render/): install,
  runtime file, authentication, the seal route, and the audit file.
- [What a Render template receives](https://docs.registrystack.org/reference/render-payload/): the
  envelope every template author needs.
- [Registry Render configuration reference](https://docs.registrystack.org/reference/render-configuration/):
  every manifest, label and runtime key, and the
  [exit codes](https://docs.registrystack.org/reference/render-configuration/#exit-codes).
- [Registry Render overview](https://docs.registrystack.org/start/registry-render/): the
  byte-stability, path-safety, resource-bound and audit guarantees.
- [Registry Render security](https://docs.registrystack.org/security/render/): the trust
  boundaries, operator obligations and accepted residuals.
- `bundles/`: three immutable packaged examples: a bilingual RTL receipt, a PDF/A-4 certificate, and
  an ID-1 duplex card with a photo. Formal PDF/A conformance validation (for example veraPDF) is not
  run on these bundles. Use them with `check`, `compile`,
  or `serve`; start editable source with `registry-render init`.
- `integrations/`: the OpenFn job wiring.
- `schemas/`: JSON Schemas for `manifest.yaml`, `labels/<locale>.yaml`, and the `serve` runtime file,
  generated from the types Render reads. Regenerate them with
  `cargo run -p registry-render --features schema --example render-schema -- --output products/render/schemas`;
  `examples/runtime.yaml` is a minimal runtime file they accept.
