# Script (Rhai) Source Adapter Guide

Registry Notary can read source data through a small, sandboxed **Rhai
orchestration script** when a source API needs a little imperative shaping that
is awkward for the declarative `http_json` / `http_flow` engines but too small to
justify a bespoke adapter. The script is **orchestration-only**: it decides which
configured request to make next and shapes the returned JSON into records. It
never holds network authority, credentials, or policy — the sidecar host keeps
all of those.

Notary configs use the normal `connector: source_adapter_sidecar`; the
`script_rhai` engine is selected inside the sidecar's own signed manifest, so no
Notary-side or OpenAPI change is needed. The adapter returns the same projected
row shape every engine returns:

```json
{ "data": [{ "national_id": "person-123", "birth_date": "1990-01-01" }] }
```

## When to use it

Reach for `script_rhai` only when the declarative engines do not fit:

- `http_json` — one governed request and a JSON/CEL projection.
- `http_flow` — a fixed declarative sequence of dependent reads.
- `fhir` — a bounded FHIR R4 GET graph.
- `script_rhai` — 1–3 governed source calls where the script must **branch** on
  a response (e.g. POST a search body, then GET a returned id; try one path,
  fall back on a 404), or normalize source-specific JSON that the declarative
  mappers cannot express.

If a single request with a CEL projection works, prefer `http_json`.

## Security model

Scripts are trusted, signed, in-house content, but the engine is still hardened
so a buggy script or a hostile *upstream response* cannot escalate:

- **No ambient capability.** A script has no generic HTTP, filesystem,
  environment, process, or module access. Its only I/O is the host-registered
  `source.get(target, path, query)` and
  `source.post_json(target, path, query, body)`. Module loading and `eval` are
  disabled.
- **Secrets never reach the script.** The script sees only the whitelisted
  **public** credential projection (`credential_public`). Target credentials are
  resolved by the host and applied to the outbound request; they are never
  exposed to script code, response shaping, error text, logs, or cache keys.
- **The host owns every effect.** `source.get` and `source.post_json` reuse the
  same outbound path as `http_json`: `allowed_base_urls` allow-listing,
  percent-decode-then-validate path canonicalization, same-origin enforcement,
  a DNS-pinned client with redirects disabled, SSRF/private-IP/cloud-metadata
  blocking, target-owned auth, the per-source rate-limit and `Retry-After`
  backoff gate, and byte-bounded JSON request/response handling.
- **Sandbox limits.** Operation count, call depth, string/array/map sizes, the
  per-run source-call budget, output bytes, wall-clock timeout, and engine
  concurrency are all bounded. The script is **compiled and smoke-tested at
  startup**; a compile, policy, or smoke failure blocks readiness.
- **Governed provenance.** The script is embedded inline in the signed runtime
  target, so it is covered by the target's `config_hash` — the same TUF-verified
  content anchor used for inline CEL today.

## The script contract

A source names an entrypoint (default `lookup`) that receives one `ctx` and
returns an array of record maps (or one map):

```rhai
fn lookup(ctx) {
  // ctx.lookup.value is the minimized primary lookup value.
  let r = source.get("primary", "/people", #{ id: ctx.lookup.value });
  if r.status == 404 {
    // Observe the 404 (see visible_statuses) and fall back.
    source.get("fallback", "/legacy", #{ id: ctx.lookup.value }).body
  } else {
    r.body
  }
}
```

`ctx` carries only minimized request inputs:

| Field | Meaning |
| --- | --- |
| `ctx.source_id` | the source id |
| `ctx.dataset`, `ctx.entity` | dataset / entity being read |
| `ctx.lookup.field`, `ctx.lookup.value` | the primary lookup field and value |
| `ctx.fields` | requested projection fields |
| `ctx.limit` | record cap |
| `ctx.purpose` | the forwarded `Data-Purpose` |
| `ctx.credential_public` | whitelisted public credential fields only |

`source.get(target, path, query)` returns `#{ status, body }`:

- `target` must be a key in the source's `targets` map (unknown targets are
  denied).
- `path` is canonicalized and joined onto the target `base_url`; traversal and
  encoded separators are rejected.
- `query` is a map of name → string/number/bool; names are validated.
- `status` is the upstream HTTP status; `body` is the parsed JSON, or `()`
  (null) for an observable non-2xx with an empty, non-JSON, or oversized body.

`source.post_json(target, path, query, body)` has the same response shape and
visibility rules, but sends `body` as a JSON request body. The body is bounded
by the Rhai JSON conversion caps and by the sidecar `limits.max_request_bytes`.
It is intended for APIs that require a small search or envelope POST before a
read:

```rhai
fn lookup(ctx) {
  let search = source.post_json(
    "primary",
    "/search",
    #{},
    #{ value: ctx.lookup.value, fields: ctx.fields }
  );
  source.get("primary", "/people/" + search.body[0].national_id, #{}).body
}
```

### Pure `xw` helpers

The script may call pure helpers from the Crosswalk function library for
normalization, registered under `xw.*`: `xw.text.*`, `xw.date.*`, `xw.ids.*`,
`xw.json.*`, `xw.email.*`, and `xw.redaction.*` (for example
`xw.text.upper_ascii`, `xw.date.parse_date`, `xw.ids.clean_id`). Context- or
registry-dependent helpers (regex, code systems, phone, clock-dependent dates)
are intentionally **not** registered, so referencing one is a startup compile
error rather than a runtime surprise.

## Source manifest

```yaml
sources:
  civil_person_rhai:
    engine: script_rhai
    dataset: civil_registry
    entity: civil_person
    credential_env: CIVIL_REGISTRY_CREDENTIAL_JSON
    credential_public_fields:
      - clientId
    allowed_base_urls:
      - https://registry.example.gov
    rhai:
      entrypoint: lookup
      # Optional sandbox limits; each defaults to the engine policy.
      limits:
        timeout_ms: 4000
        max_http_calls: 3
        max_output_bytes: 65536
      script: |
        fn lookup(ctx) {
          let r = source.get("primary", "/v1/people", #{ id: ctx.lookup.value });
          if r.status == 404 { [] } else { r.body }
        }
      targets:
        primary:
          base_url: https://registry.example.gov
          # Static, non-secret request headers (optional).
          headers:
            Accept: application/json
            X-Api-Version: "2024-01"
          # Statuses the script may observe instead of terminating (optional).
          visible_statuses:
            - 404
          auth:
            type: api_key_header
            header: X-API-Key
            token:
              secret: apiKey
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
```

`credential_env` names an environment variable holding a JSON object of secret
fields. `credential_public_fields` lists the subset the script may see; every
other field stays host-only. `credential_env` is required only when at least one
target configures `auth`.

### Target authentication

Target auth reuses the shared sidecar credential machinery (so `http_json` and
`http_flow` get the same kinds). Each kind names its secret as a top-level field
of the credential object; the host resolves and applies it, and it never reaches
the script.

| `type` | Required fields | Effect |
| --- | --- | --- |
| `bearer` | `token.secret` | `Authorization: Bearer <secret>` |
| `basic` | `username.secret`, `password.secret` | HTTP Basic |
| `api_key_header` | `header`, `token.secret` | sets `<header>: <secret>` |
| `api_key_query` | `query_param`, `token.secret` | appends `?<query_param>=<secret>` |
| `oauth2_client_credentials` | `token_url`, `client_id.secret`, `client_secret.secret` | fetches and caches a host-owned bearer token |

`api_key_query` is for messy upstreams that expect the key in the URL; the value
is a secret, so the host keeps it out of logs and cache keys (the cache key is
built from request fields, not the resolved URL).

OAuth2 client-credentials token URLs must also appear in `allowed_base_urls`.
The token request defaults to `request_format: form`; set `request_format: json`
for upstreams that require a JSON token request. Optional fields are `scope`,
`audience`, and `refresh_skew_seconds` (default `60`).

```yaml
          auth:
            type: oauth2_client_credentials
            token_url: https://identity.example.gov/oauth/token
            request_format: form
            scope: people.read
            client_id:
              secret: clientId
            client_secret:
              secret: clientSecret
```

### Static request headers

`targets.<name>.headers` injects fixed, non-secret headers (for example `Accept`
or a vendor API-version header) on every call to that target. Header values are
governed config and flow through the `config_hash`. Authentication, cookie,
host/length framing, hop-by-hop, and forwarding headers (and any `Proxy-*`
header) are **rejected at startup** — put credentials in `auth`, not `headers`.

### Observable statuses

By default any non-2xx terminates the run and maps to a problem code
(`401`/`403` → `source.target_auth`, `429` → `source.target_rate_limit`,
timeout → `source.timeout`, everything else → `source.unavailable`). List a
status in a target's `visible_statuses` to let the script **observe** it as
`#{ status, body }` and branch instead — for example a `404` that means
"not found here, try the fallback". The engine is compiled with the union of all
targets' visible statuses as a ceiling, and the per-target list is enforced by
the host.

## Batch reads

`script_rhai` supports the standard `records:batchMatch` contract in the
per-item lookup modes:

```yaml
    batch:
      mode: parallel_lookup   # or sequential_lookup (the default)
      max_parallel: 4
```

Each batch item runs one governed single-item script lookup; results preserve
request order by item. A per-item not-found or upstream failure is isolated to
that item's entry, while a shared credential error (`target_auth` /
`target_rate_limit`) short-circuits the whole batch so a bad credential cannot be
probed item by item. `workflow_batch` and `native_batch` are not valid for
`script_rhai` (it has no single bulk upstream endpoint) and are rejected at
config validation.

## Assurance and governance

Pin the sidecar runtime with `expected_sidecar` exactly as for the other
engines. Because the script is inline in the signed runtime target, it is
covered by the target `config_hash` that Notary verifies before source reads.
The `/ready` and `/v1/assurance` booleans (`expression_hashes_verified`,
`runtime_verified`, `smoke_verified`) attest that whole-target hash together
with the startup compile and smoke check — a startup failure on any of them
blocks readiness, so a sidecar that serves these values has satisfied all three.

## Local verification

```bash
# Library engine: sandbox limits, conversion, path-traversal, isolation.
cargo test -p registry-notary-source-adapter-rhai

# Sidecar wiring: data flow, visibility gate, auth on the wire, rate limit,
# xw helpers, batch, SSRF/path-traversal, credential isolation, validation.
cargo test -p registry-notary-source-adapter-sidecar

# End-to-end Notary RDA + governed assurance pinning through a script_rhai
# sidecar against a mock upstream.
cargo test -p registry-notary-server --lib governed_script_rhai
```

Gate checks: `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
and `cargo deny check`.

## Current Limits

- Supported source calls are `source.get` and `source.post_json`; there is no
  built-in pagination helper yet.
- JSON request/response bodies only; XML/CSV upstreams stay out of scope.
- Auth kinds are `bearer`, `basic`, `api_key_header`, `api_key_query`, and
  `oauth2_client_credentials`. Session/cookie login, HMAC request signing, and
  mTLS are not yet available.
- The per-run source-call budget is small (default `3`, hard cap `5`); design
  scripts for a handful of calls, not arbitrary fan-out.
