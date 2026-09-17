# Acceptance coverage map

Binds each Definition-of-Done area to its executable evidence. Run
everything with `cargo test --locked -p registry-render` (CI runs the same
on two OSes via `.github/workflows/render-golden.yml`).

| DoD area | Executable evidence |
|---|---|
| Merge gate (library ≡ CLI) | `EVIDENCE.md` procedure + hashes (2026-09-17, all three bundles, byte-identical); `golden_hashes_match` keeps the library side pinned |
| Determinism (fresh world/library, canonical injection, ident, evict, font order) | `golden.rs`: `golden_hashes_match`, `rendering_is_deterministic_across_fresh_worlds_and_processes`, `injected_bytes_are_the_hashed_canonical_bytes`, `issued_at_changes_bytes_and_is_the_only_knob` |
| Bundle format, sealing, tamper/unsealed refusals | `golden.rs`: `tampered_sealed_bundle_is_refused`, `unsealed_bundle_is_refused_for_serving`; unit: `manifest::tests`, `problem::tests` |
| Path safety (world-enforced) | `golden.rs`: `data_paths_cannot_escape_the_bundle`, `unvendored_package_import_fails_without_network`; unit: `world::tests::resolve_rejects_escape_attempts` (traversal, absolute, symlink escape) |
| Assets (media type, size caps, virtual namespace) | `golden.rs`: `wrong_media_type_and_oversize_assets_are_refused`; merge gate on the card bundle proves the virtual `assets/` namespace renders byte-identically to a real file |
| Data validation with JSON pointers | `golden.rs`: `schema_violations_carry_json_pointers`, `bad_locale_is_refused_with_a_pointer` |
| Labels + script coverage at check time | `render check` on all three bundles (CI smoke via the golden suite's sealed loads); coverage logic in `check.rs::check_script_coverage`, exercised by the sealed Arabic bundles |
| Resource enforcement (kill at timeout, recycle, recover) | `serve.rs`: `slow_renders_are_killed_and_the_service_recovers` (504 problem, service healthy afterwards, both kills audited) |
| Auth (constant-time, indistinguishable 401s, audited) | `serve.rs`: `unauthorized_requests_are_refused_and_audited` |
| HTTP contract (headers, JSON variant, correlation, problems) | `serve.rs`: `render_returns_pdf_with_hash_headers_matching_golden`, `json_variant_serves_openfn_clients`, `missing_issued_at_and_bad_data_are_named_problems`, `serve_health_and_ready` |
| Audit (append-before-respond, failures audited, value-free, verify) | `serve.rs`: `audit_chain_verifies_from_the_cli`, `audit_events_are_value_free` (canary + API-key scans), `unauthorized_requests_are_refused_and_audited`, `slow_renders_are_killed_and_the_service_recovers` |
| Sealed-bundle-only serving | `serve.rs`: `tampered_bundle_refuses_to_serve` (exit code = BundleTampered) |
| Cross-machine byte stability | `.github/workflows/render-golden.yml` runs the golden suite on ubuntu-24.04 and macos-14 against the same `golden.json` |
| DX (scaffold compiles offline, validate dry-run, errors) | Manual smoke 2026-09-17 recorded in EVIDENCE-style: `render init` + first compile offline, warning-clean after the font fix; `render validate` refuses bad data with exit 9 and pointers |
| Domain neutrality | Bundle fixtures and label files carry all domain wording; production crate types are domain-free (reviewer-verified; a scan gate can follow the Relay pattern post-v1) |
| OpenFn journey (walked 2026-09-17) | `integrations/openfn/JOURNEY.md`: real OpenFn CLI 1.40.1 + language-common 3.3.4 job (notify.js idiom) read back through a real breg v0.32.0 dev registry's `record-reader` profile (readableFields = the template data contract, `get`-only, row boundary), rendered via `Accept: application/json` to the golden `pdfSha256`, delivered, then a delivery-outage dead-letter and a recovery replay with the same `eventEffectId` delivered byte-identical PDFs (`cmp` clean); unknown record → 404 read-back refusal with nothing rendered; `render audit-verify` after shutdown: 3 records, all correlated by the effect id |

## Known deferred evidence

- Full PDF/A conformance validation (veraPDF) — the certificate golden test
  asserts the `pdfaid` identification and byte stability; formal conformance
  runs with the release tooling.
- The App Kit print journey is specified in `integrations/app-kit/` with its
  contract (brief rows, `APP_DOCUMENTS_FILE`, host route, sha256 attach) but
  must be *walked* in the App Kit repository once the kit-side documents
  capability is built there — every render-side behavior that journey
  exercises (loopback serve, sealed bundle, PDF bytes and hash headers,
  deterministic redelivery) is covered above by the serve suite and the
  walked OpenFn journey. A 2026-09-17 read-only sizing of the kit worktree
  puts that capability at a multi-component change (config parser, render
  route with session-token data assembly, sha256 attach fields, a new public
  QR-verify surface with its own credential, a staff print page, deployment
  supervision, and the kit's brief/skill/walkthrough anatomy) — kit-product
  scope, not render-side work.
- The docs-site CLI reference record (`docs/site/src/data/cli-reference.yaml`)
  covers released binaries; `render` joins it at roster entry per the
  release checklist.
