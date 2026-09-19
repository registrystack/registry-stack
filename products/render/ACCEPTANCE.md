# Acceptance coverage map

Binds each Definition-of-Done area to its executable evidence. Run
everything with `cargo test --locked -p registry-render` (CI runs the same
suites on two OSes via `.github/workflows/render-golden.yml`). Updated for
the PR #1113 review round (2026-09-17) and immutable bundle snapshot
hardening (2026-09-19); see EVIDENCE.md for the change list.

| DoD area | Executable evidence |
|---|---|
| Merge gate (library ≡ CLI) | `EVIDENCE.md` procedure + hashes (2026-09-17, all three bundles, byte-identical); `golden_hashes_match` keeps the library side pinned |
| Determinism (fresh world/library, canonical injection, ident, evict, font order) | `golden.rs`: `golden_hashes_match`, `rendering_is_deterministic_across_fresh_worlds_and_processes`, `injected_bytes_are_the_hashed_canonical_bytes`, `issued_at_changes_bytes_and_is_the_only_knob` |
| Bundle format, sealing, immutable verified-byte consumption, tamper/unsealed refusals | `golden.rs`: `tampered_sealed_bundle_is_refused`, `sealed_template_and_package_bytes_are_bound_to_the_loaded_snapshot`, `unsealed_bundle_is_refused_for_serving`; unit: `bundle::tests::assembly_uses_captured_bytes`, `bundle::tests::accepted_manifest_path_spellings_render_from_snapshot`, `bundle::tests::bundle_root_and_ancestor_symlinks_are_refused_for_every_spelling`, `manifest::tests`, `problem::tests` |
| Path safety (world-enforced; virtual-path diagnostics) | `golden.rs`: `data_paths_cannot_escape_the_bundle`, `unvendored_package_import_fails_without_network`, `compile_diagnostics_report_virtual_paths_only`; unit: `world::tests::virtual_paths_reject_escape_attempts`, manifest schema-path validation tests; scaffold symlink-seal refusal |
| Assets (media type, size caps, virtual namespace) | `golden.rs`: `wrong_media_type_and_oversize_assets_are_refused`; merge gate on the card bundle proves the virtual `assets/` namespace renders byte-identically to a real file |
| Data validation with JSON pointers | `golden.rs`: `schema_violations_carry_json_pointers`, `bad_locale_is_refused_with_a_pointer` |
| Labels + script coverage at check time | `registry-render check` on all three bundles (CI smoke via the golden suite's sealed loads); coverage logic in `check.rs::check_script_coverage`, exercised by the sealed Arabic bundles; per-locale label key sets must agree: `scaffold::check_names_a_locale_missing_a_label_key` |
| Resource enforcement (kill at timeout, recycle, recover) | `serve.rs`: `slow_renders_are_killed_and_the_service_recovers` (504 problem, service healthy afterwards, both kills audited); the CLI shares the wall: `scaffold::compile_is_bounded_by_a_timeout` |
| Auth (constant-time, indistinguishable 401s, audited, key-file normalization) | `serve.rs`: `unauthorized_requests_are_refused_and_audited`, `api_key_file_with_one_trailing_newline_is_trimmed`, `api_key_with_stray_whitespace_is_refused_at_startup` |
| HTTP contract (headers, JSON variant, correlation, problems, 413, versions in /health) | `serve.rs`: `render_returns_pdf_with_hash_headers_matching_golden`, `json_variant_serves_openfn_clients`, `missing_issued_at_and_bad_data_are_named_problems`, `oversized_bodies_are_refused_after_auth_as_problems`, `serve_health_and_ready` |
| Audit (append-before-respond, failures audited, value-free, verify) | `serve.rs`: `audit_chain_verifies_from_the_cli`, `audit_events_are_value_free` (canary + API-key scans), `unauthorized_requests_are_refused_and_audited`, `slow_renders_are_killed_and_the_service_recovers` |
| Sealed-bundle-only serving (startup and per render) | `serve.rs`: `tampered_bundle_refuses_to_serve` (exit code = BundleTampered), `bundle_drift_after_serve_starts_is_refused_per_render` (tamper and unseal after startup) |
| Cross-machine byte stability; closure drift | `.github/workflows/render-golden.yml` runs the golden, serve, and scaffold suites on ubuntu-24.04 and macos-14 against the same `golden.json`; `golden_hashes_match` also pins each bundle's file closure and requires every non-virtual dep to be manifest-governed |
| DX (scaffold compiles offline, validate dry-run, errors) | Manual smoke 2026-09-17 recorded in EVIDENCE-style: `registry-render init` + first compile offline, warning-clean after the font fix; `registry-render validate` refuses bad data with exit 9 and pointers |
| Domain neutrality | Bundle fixtures and label files carry all domain wording; production crate types are domain-free (reviewer-verified; a scan gate can follow the Relay pattern post-v1) |
| OpenFn journey (walked 2026-09-17) | `integrations/openfn/JOURNEY.md`: real OpenFn CLI 1.40.1 + language-common 3.3.4 job (notify.js idiom) read back through a real breg v0.32.0 dev registry's `record-reader` profile (readableFields = the template data contract, `get`-only, row boundary), rendered via `Accept: application/json` to the golden `pdfSha256`, delivered, then a delivery-outage dead-letter and a recovery replay with the same `eventEffectId` delivered byte-identical PDFs (`cmp` clean); unknown record → 404 read-back refusal with nothing rendered; `registry-render audit-verify` after shutdown: 3 records, all correlated by the effect id |

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
  covers released binaries; `registry-render` is registered in the generated
  catalog, so its command reference builds with the rest of the stack's.
