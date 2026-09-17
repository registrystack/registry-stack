# Security-invariant matrix

Each security row of the Definition of Done, named as a threat, with its
enforcement point and the executable negative test that proves it. Source:
implementation review 2026-09-17 (two adversarial reviews; all findings
fixed or explicitly documented as residuals below), extended by the PR
#1113 review round the same day (rows 17-20).

| # | Threat | Enforcement point | Negative test |
|---|---|---|---|
| 1 | Untrusted data reaches a path-taking template function and reads files outside the bundle | `RenderWorld::resolve_under` (world.rs): lexical rejection of `..`/absolute components, canonicalize-then-contain on every `source`/`file` resolution; typst additionally virtualizes absolute paths as root-relative before the world sees them | `golden::data_paths_cannot_escape_the_bundle`; `world::tests::resolve_rejects_escape_attempts` (traversal, absolute, symlink-escape fixtures) |
| 2 | A template imports an unvendored package; render fetches from the network | There is no network code path in library mode; package resolution serves only `packages/` through the world | `golden::unvendored_package_import_fails_without_network` |
| 3 | Bundle content drifts after sealing (tamper or accidental edit) | Per-file sha256 in the manifest, verified at `check`, at serve startup, **and per render**: serve workers load sealed and the response's bundle hash must equal the startup hash (drift → `BundleTampered`) | `golden::tampered_sealed_bundle_is_refused`; `serve::tampered_bundle_refuses_to_serve` (exit code = tampered); `serve::bundle_drift_after_serve_starts_is_refused_per_render` (tamper after startup → 400 per render) |
| 4 | An unsealed bundle is served | `Bundle::load_sealed` at startup and in every worker | `golden::unsealed_bundle_is_refused_for_serving`; `serve::bundle_drift_after_serve_starts_is_refused_per_render` (seal stripped after startup → 400 per render) |
| 5 | Caller without the API key reads documents or renders | Bearer authentication as a layer on `/v1/*` **before body buffering**; constant-time compare; ≥32-byte ASCII key; identical 401 bodies for missing/wrong/short keys; the key file gets exactly one trailing line ending trimmed and any other whitespace refuses startup (no silently mis-armed key with `/health` green) | `serve::unauthorized_requests_are_refused_and_audited` (two indistinguishable 401s); `serve::api_key_file_with_one_trailing_newline_is_trimmed`; `serve::api_key_with_stray_whitespace_is_refused_at_startup`; `/v1/documents` behind the same layer |
| 6 | The immutable audit ledger is used as an unauthenticated write oracle (huge or hostile route params) | Route parameters are bounded (64 chars) and kebab-validated (`sanitize_document_type`) before any audit append, including pre-auth 401 events | code-reviewed; audit shape asserted in `serve::unauthorized_requests_are_refused_and_audited` |
| 7 | Request data values or the API key leak into the ledger or logs | Audit events carry a closed, value-free field set; lifecycle logs use fixed dimensions (method class, route template, status, latency, trace id) | `serve::audit_events_are_value_free` (canary + key scans over the ledger) |
| 8 | The ledger lies: records removed, rewritten, or reordered | Keyed HMAC hash chain, sealed non-deleting segments; `render audit-verify` proves the chain end to end | `scaffold::tampered_ledger_fails_audit_verify` (a flipped byte fails verification; the happy path counts real records, not zero) |
| 9 | A render succeeds but is wrong on paper (missing glyphs) | Check-time label-script coverage over the actual label characters; render-time warnings; `--strict` fails on warnings | `scaffold::check_seal_refuses_to_seal_a_broken_bundle` (CJK label, no font → refusal, and no seal written) |
| 10 | Pathological template data exhausts CPU or memory | Serves render in a supervised worker process: killed at the configured timeout, `RLIMIT_AS` on Linux, recycled on panic; bounded concurrency; request body and output caps with hard ceilings | `serve::slow_renders_are_killed_and_the_service_recovers` (504, audited twice, service healthy after) |
| 11 | Assets smuggle executables or balloons | base64-decoded, JPEG/PNG magic sniffed, per-asset 2 MiB / per-request 8 MiB caps, exact bytes covered by `dataSha256` | `golden::wrong_media_type_and_oversize_assets_are_refused` |
| 12 | Deeply nested JSON parse DoS | `serde_json` default 128-depth recursion limit on top of the tower body-limit layer | platform-owned; body limit exercised by config ceiling (`runtime.rs` 64 MiB hard cap) |
| 13 | Response header injection via echoed `Idempotency-Key` | `HeaderValue::from_str` rejects CR/LF/NUL; 128-char bound at read | code-reviewed; echo asserted in `serve::render_returns_pdf_with_hash_headers_matching_golden` |
| 14 | Byte drift between renders, machines, or dependency upgrades | Fresh world+library per render, canonical (RFC 8785) envelope = injected = hashed bytes, deterministic font order, `ident: Auto` (content-derived), comemo eviction; lockfile pins Typst **and the deflate stack** | `golden::golden_hashes_match` + `rendering_is_deterministic…` on two OSes in CI (`.github/workflows/render-golden.yml`); merge-gate record in EVIDENCE.md |
| 15 | Sealed-bundle hash coverage misses nested files or symlinks | Hashes cover every file except the root manifest itself (nested `manifest.yaml` is governed content); any symlink in the bundle refuses sealing | `scaffold::bundle_with_symlink_cannot_be_sealed` |
| 16 | 401 audit-append failures vanish silently | Failures are logged (`audit-append-failed` warn) even though the refusal itself stands | code-reviewed with the lifecycle-log middleware |
| 17 | Compile diagnostics or bundle-load failures leak the host deployment (paths) or raw engine output | World file errors carry virtual, root-relative paths only; a redaction pass replaces any residual host bundle root with `<bundle>` in problem details and warnings, and per-request bundle-load failures in the worker are redacted the same way before they cross the pipe | `golden::compile_diagnostics_report_virtual_paths_only`; `world::tests::not_found_reports_the_virtual_path_not_the_host_root`; `serve::bundle_drift_after_serve_starts_is_refused_per_render` (a refused symlink names `<bundle>/escape`, never the host path) |
| 18 | Oversized or unframed bodies DoS the service or dodge the audit trail | Body ceiling enforced **after authentication** (unauthenticated oversized bodies are 401s, never buffered); an authenticated over-ceiling body gets the audited `body-too-large` problem (413), and chunked transfer is refused up front with an audited problem — once a chunked stream trips the stream limit mid-body the connection is broken and no response can be delivered at all, so refusal must precede the first body byte; the tower stream limit stays as the last-ditch backstop (a mid-stream abort there closes the connection: the residual recorded below) | `serve::oversized_bodies_are_refused_after_auth_as_problems`; `serve::chunked_bodies_are_refused_upfront_as_problems` |
| 19 | A panicking worker's stderr (paths, data fragments) reaches the operator log | Worker stderr is piped and drained, never inherited; problem documents are the diagnosis surface | code-reviewed with the supervise loop (`worker::supervise`); `serve::slow_renders_are_killed_and_the_service_recovers` exercises abnormal worker exits without asserting on the drained bytes, so no test covers the drain itself |
| 20 | Serve listens on a public or all-interfaces address | `runtime::validate_bind` refuses non-loopback/private/unspecified binds at startup; the whole `server:` section defaults to `127.0.0.1:8080` | `runtime::tests::loopback_private_and_link_local_binds_are_allowed`, `runtime::tests::public_and_unspecified_binds_are_refused`, `runtime::tests::bind_defaults_to_loopback` |
| 21 | A caller-controlled value makes a refusal unbounded (response and log amplification) | Problem details are capped at 2048 characters with an explicit truncation marker before they reach the wire; the values that can grow (an undeclared locale, an asset name) are caller-supplied | `serve::problem_details_are_bounded`; `server::tests::a_long_detail_is_cut_on_a_character_boundary`; `server::tests::a_detail_at_the_cap_is_kept_verbatim` |
| 22 | A shutdown grace that disarms the drain or overflows the bounded wait | `runtime::load` refuses anything outside 1 to 3600 seconds at startup, so zero cannot drop renders in flight and a huge value cannot panic the wait that adds the grace twice | `runtime::tests::shutdown_grace_outside_the_supported_range_is_refused`; `runtime::tests::shutdown_grace_at_the_range_ends_is_accepted` |

## Documented residuals (accepted, with conditions)

- **Canonicalize-then-read TOCTOU** in `resolve_under`: an attacker who can
  write inside the bundle directory between the containment check and the
  read could swap a last-component symlink. Any such writer can also
  rewrite the manifest, so the seal was never a boundary against an active
  writer; deployments must treat bundle directories as read-only content
  (the same assumption the audit ledger makes of its directory). `O_NOFOLLOW`
  reads are the future hardening if that assumption ever weakens.
- **macOS workers have no address-space cap** (`RLIMIT_AS` is not exposed
  by rustix there): the timeout kill is the sole wall. Serve deployments
  for pilots should run on Linux, where the rlimit applies.
- **The output-size check runs after PDF export** in memory; Linux workers
  bound the spike by `RLIMIT_AS`, macOS only by the kill.
- **A chunked body that trips the tower stream limit mid-body** breaks the
  request stream, so the connection closes with no response and no audit
  event. Refusing chunked transfer before the first body byte is what keeps
  that path unreachable for ordinary callers; the backstop remains for a
  client that frames a Content-Length and then sends more.
- **Asset caps are code-level constants** (per-asset 2 MiB, request total
  8 MiB, JPEG/PNG only), not per-document manifest declarations; the DoD's
  assets row was amended to match. Per-document asset policy is a v2
  option if a journey needs it.
