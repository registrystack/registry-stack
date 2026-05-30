# Registry Manifest: Pre-Beta Security Audit

- **Date:** 2026-05-30
- **Target:** first BETA release (`registry-manifest` 0.1.2; never been stable). A **parser / validator / renderer** library + CLI (`registry-manifest-core` + `registry-manifest-cli`, ~10k LOC) that ingests an untrusted YAML **metadata manifest** and renders it into trusted downstream artifacts: catalog JSON; base DCAT / BRegDCAT-AP / CPSV-AP JSON-LD; SHACL shapes; JSON Schema Draft 2020-12 (entity + form); OGC API Records; ODRL policy documents; evidence-offering metadata; and a public federation/discovery block (`catalog.json` + `.well-known/`) that Registry Notary operators consult for discovery when configuring delegated evaluation (it is **not** ingested by Notary at runtime — see M2).
- **Scope:** both crates (`core` ≈ 5.9k LOC `lib.rs`, `cli` ≈ 0.9k LOC `main.rs`), all 13 renderers and their node/shape/schema builders, the CURIE/vocabulary expander, the `validate`/`render`/`publish`/`validate-profiles` CLI commands, `deny.toml`, `Cargo.lock`, the shipped `examples/`, `fixtures/`, `profiles/`, `docs/`, and supply-chain posture. Cross-referenced against `apps/registry-notary` to test the federation trust boundary.
- **Method:** 7 parallel domain finder lanes (output-rendering/injection [weighted highest]; federation-metadata trust boundary; input-parsing/validation; CURIE/vocabulary expansion; CLI path & filesystem; resource-exhaustion/DoS & panic; supply-chain/hygiene). Every finding independently re-verified against the code; **High findings got a 2-lens adversarial panel** (lens A proves a *schema-valid* manifest reaches the sink; lens B assumes validation already blocks it and hunts the guard) followed by a synthesis verdict. Two completeness critics then swept for missed surface and wrongly-dismissed issues, **running the actual parser** to settle disputed DoS claims. Deterministic scans: `cargo audit`, `gitleaks` (filesystem + history). 34 agents, ~1.38M tokens, 577 tool calls. **Load-bearing findings re-confirmed by hand by the lead**, including a live `/usr/bin/time` measurement of the YAML-amplification DoS against the release binary.
- **Threat-model reframing (this is a parser/renderer, not a server):** there is no network, auth, signing, or server surface, so the notary/platform lanes for **authn, authz, replay/nonce, and signing-key handling are N/A by design** (confirmed absent in every lane, not assumed). The real trust boundary is **untrusted-input → trusted-output**: a manifest author is semi-trusted, but the rendered artifacts are consumed by downstream systems (Notary discovery, public catalogs, RDF/JSON-LD/SHACL consumers) as authoritative. Each finding is classed **MALICIOUS-MANIFEST** (a crafted-but-schema-valid manifest poisons an output, traverses the filesystem, or DoSes the tool), **OPERATOR-FOOTGUN** (a CLI default lets an operator publish something unsafe), or **MISUSE-ONLY**. The audit weights MALICIOUS-MANIFEST.

---

## Verdict: CONDITIONAL GO for beta

**No RCE, no shell-out, no SSRF, no network or filesystem fetch on untrusted input, no `unsafe` in first-party code, no committed secrets, and no `cargo audit` vulnerabilities.** The architecture has two strong, deliberate defenses that hold up under adversarial reading: **(1)** every renderer emits a `serde_json::Value` tree serialized by serde, so classic string-breakout JSON/JSON-LD/Turtle injection is structurally impossible (manifest strings in *value* position are escaped); and **(2)** `compile_manifest` runs `validate_manifest` *before* any render (`lib.rs:1502-1503`), and the strict `validate_id` grammar (`lib.rs:5374`) is correctly applied to almost every identifier that becomes a filesystem path segment or an RDF identifier.

The blockers are a small set of places where that second defense is **incomplete**, plus two parser-level resource bugs that precede validation entirely:

- **H1** — the **one** path-segment id that `validate_manifest` never checks (`profiles[].id`) flows into a `publish` file write, giving **arbitrary-path file write** outside the output tree from a schema-valid manifest.
- **H2** — the manifest-controlled `vocabularies` map is **never validated and overrides well-known prefixes**, silently repointing structural IRIs (`@type`, `@id`, `sh:path`, `sh:targetClass`) in the published JSON-LD/SHACL/DCAT to an attacker namespace while the static `@context` still claims the legitimate one.
- **H3** — a **linear YAML alias amplification** (one large anchored scalar aliased N times) is *not* caught by the library's billion-laughs guard and OOMs the process at parse time, before any validation runs. **Lead-confirmed: 220 KB of input → 412 MB resident against the release binary.**

All three are cheap to fix (one validation loop, one map-validation pass, and alias-rejection + a size cap) and should be fixed before tagging beta. The remaining structural-IRI-injection finding (H4, dataset-embedded `public_services[].id` emitted verbatim as a `cpsv:PublicService @id`) is the same class as H2 and shares its fix pattern. The Mediums are an additional parse-time CPU DoS (M1), a federation-metadata origin-binding gap that is **contained** because Notary loads peers from its own config and does *not* ingest this catalog (M2, verified in both repos), a malformed-IRI-via-CURIE-suffix vector (M3), and an unvalidated codelist-concept `@id` path (M4). For a renderer whose whole job is to emit authoritative metadata, the bar is "no crafted manifest can poison a structural position in a trusted artifact, traverse the filesystem, or crash the tool"; H1/H2/H3 cross that bar today.

### Confirmed findings: 17, plus 1 positive confirmation (I4) and 1 corrected false-positive framing (H3) — 18 rows below

| # | Sev | Lane | Title | Exposure |
|---|-----|------|-------|----------|
| **H1** | **High** | cli/fs | `profiles[].id` is the only path-segment id `validate_manifest` never checks → arbitrary-path file write during `publish` (`out/profiles/{id}.json`) | **MALICIOUS / default** |
| **H2** | **High** | render/curie | `vocabularies` map is unvalidated and overrides well-known prefixes; expanded attacker IRIs land in `@type`/`@id`/`sh:path`/`sh:targetClass` while the static `@context` still claims the legit namespace | **MALICIOUS / default** |
| **H3** | **High** | dos/parse | Linear YAML alias amplification (big anchored scalar aliased N×) evades the repetition guard → multi-GB allocation / OOM before validation (lead-measured 220 KB → 412 MB) | **MALICIOUS / default** |
| **H4** | **High** | render | Dataset-embedded `public_services[].id` is emitted verbatim as a `cpsv:PublicService @id` with only a non-empty check (catalog-level uses `validate_id`); forges RDF node identity in CPSV-AP / BReg-DCAT output | **MALICIOUS / default** |
| M1 | Med | dos/parse | Quadratic nested-flow YAML parse cost (no input-size cap) burns tens of seconds–minutes of CPU before validation; distinct from H3 | MALICIOUS / default |
| M2 | Med | federation | Published federation block does not bind `jwks_uri`/`federation_api` to the issuer origin → rogue key-source URL in authoritative `catalog.json` (contained: Notary does not auto-trust this metadata) | MALICIOUS / default |
| M3 | Med | curie | CURIE suffix concatenated into IRIs with no content check → spaces/control-chars/`> <…>` produce malformed-but-trusted `@id`/`@type` IRIs (RDF-serialization-layer injection) | MALICIOUS / default |
| M4 | Med | render | `codelists[].concepts[].iri`/`.code` are wholly unvalidated and emitted as `skos:Concept @id` / interpolated into an `@id` in SHACL output (critic-surfaced, lead-confirmed) | MALICIOUS / default |
| L1 | Low | render | `concept_uri`/`concepts`/`publisher.iri`/`data_type` accept any `did:`/`urn:`/compact IRI into `@id`/`@type`/`sh:*` (intended IRI fields; harm is consumer-dependent) | MALICIOUS / default |
| L2 | Low | render | Form field `name` (JSON Schema property key) only non-empty-checked → whitespace/unicode/`__proto__` keys + silent key collision in the published schema | MALICIOUS / default |
| L3 | Low | federation | `evaluation_profiles[].ruleset` is an arbitrary non-empty string (homoglyph/whitespace) embedded in `catalog.json` that operators transcribe into Notary config | FOOTGUN / default |
| L4 | Low | cli/fs | `--out`/`--site-root` taken verbatim; `.well-known`/artifact writes use bare `fs::write` (no `O_EXCL`, follows symlinks) | FOOTGUN / default |
| L5 | Low | cli/fs | `validate-profiles` reads arbitrary files via unsanitized fixture `path` in operator `profile.yaml` (`../../etc/passwd`); error text leaks existence/snippets | FOOTGUN / config |
| L6 | Low | render | ODRL literal `right_operand.value` accepted with no content check, emitted as `@value` with an attacker-asserted (validated) `@type` it need not match (critic-surfaced) | MALICIOUS / default |
| I1 | Info | cli/fs | `fs::copy` republishes the raw untrusted manifest to `out/metadata.yaml` (world-readable by default); operator-awareness, fixed filename (no traversal) | FOOTGUN / default |
| I2 | Info | render | Form field `language` is unvalidated free text (no BCP-47 check) emitted into the published form schema (critic-surfaced) | MALICIOUS / default |
| I3 | Info | render | `LocalizedText` non-`en` language-tag keys and per-language values bypass all validation; **currently contained** (no renderer emits the raw map; `.text()` collapses to one validated string) — latent the moment localized output is added (critic-surfaced) | latent |
| I4 | Info | curie | **Positive confirmation:** CURIE expansion and `@context` construction perform **no** remote or filesystem resolution and **no** recursion/expansion loop on untrusted input (no SSRF/file-read/amplification primitive) | n/a |

**False positive corrected by the lead (1):** the DoS lane's original framing of H3 as *exponential* "alias amplification OOM" and the input lane's blanket "billion-laughs is BLOCKED" **both overstate their case**. The lead ran both shapes against the release binary: the classic **nested** billion-laughs is rejected in ~0 ms (the `unsafe-libyaml` repetition guard works), but the **linear** big-scalar-aliased-N-times vector is *not* caught and amplifies ~1900× (see H3). Both agents were right about the shape they tested; the report records the precise, measured distinction rather than either blanket claim.

---

## High findings (detail)

### H1 — Arbitrary-path file write via unvalidated `profiles[].id` on `publish`
**`crates/registry-manifest-cli/src/main.rs:247-253,876-879`, `crates/registry-manifest-core/src/lib.rs:27,89-92,1138-1139,1331-1500,1632`** · CWE-22

`ProfileClaim { id, version }` (`lib.rs:89-92`) is the **only** id-bearing list that `validate_manifest` never iterates. The validation body (`lib.rs:1331-1500`) checks `catalog.id`, `dataset.id` (`:1430`), `entity.name` (`:2905`), `field.name`, `offering.id` (`:3019`), `form.id` (`:2608` via `validate_service_catalog`), `codelist.id` (`:1391`), and `application_profiles[].id` (`:1363`) with the strict `validate_id` (which rejects `/`, `.`, uppercase, unicode) — but there is **no loop over `manifest.profiles`**. `ProfileClaim.id` is a free `String` guarded only by `#[serde(deny_unknown_fields)]`, which constrains *keys*, not values. `compiled.profiles()` returns the verbatim clone (`lib.rs:1632,1138-1139`), and `publish_command` does:

```rust
let filename = format!("{}.json", profile.id);                       // main.rs:249
write_json(out.join("profiles").join(&filename), &json!(profile))?;  // main.rs:250-251
```

`Path::join` preserves `..` components literally, and `write_json` (`main.rs:876-879`) is a bare `fs::write` with no canonicalization, no containment check, and no `O_EXCL`.

**Attack:** a schema-valid manifest (a superset of the shipped `fixtures/cpsv-ap/health-linked-child-support.metadata.yaml`) adds:
```yaml
profiles:
  - id: ../../../../tmp/poc
    version: "1"
```
`registry-manifest publish manifest.yaml --out public/metadata` resolves the write to `public/metadata/profiles/../../../../tmp/poc.json` and writes attacker-influenced JSON (`{"id":"../../../../tmp/poc","version":"1"}`) outside `--out`. The attacker controls both the on-disk location and the JSON body, and the write follows symlinks and truncates, so it can clobber a co-located web-root or `*.json` auto-discovery file. **Both exploit forms work**, with the sole constraint that the target's parent directory already exist (`fs::write` does not create traversed parents):

- a relative `../../../../tmp/poc` id climbs out of `--out`;
- an **absolute** id writes directly to that path — `Path::join` *discards* the base when its argument is absolute, so `id: /tmp/poc` resolves to `/tmp/poc.json`. **Lead-confirmed against the release binary:** `publish` with an absolute `profiles[].id` pointing into an existing directory wrote `pwned.json` there, fully outside `--out`. (This corrects the original finder note that claimed absolute ids do not work.)

The asymmetry with every validated sibling field confirms this is an oversight, not a design choice.

**Fix:** add a `validate_id` + uniqueness loop over `manifest.profiles` in `validate_manifest`, mirroring the `catalog.application_profiles` loop (`lib.rs:1362-1379`). Defense in depth: in `write_json`/`publish_command`, reject any path component containing `/`, `\`, or `..`, and canonicalize-and-assert the final path stays within `out` before `fs::write`.

### H2 — Manifest `vocabularies` override well-known prefixes → silent structural-IRI repointing
**`crates/registry-manifest-core/src/lib.rs:25,5516-5542,4091-4095,5036,5054,3763-3767,4749-4750,5739-5856,1331-1503`** · CWE-345 *(merges finder lanes OUT-1 and VOC-1)*

`vocabularies` is a manifest-controlled `BTreeMap<String,String>` (`lib.rs:25`) and is **never validated** — `validate_manifest` contains no iteration over its keys or values, no protected-prefix list, and no requirement that values be absolute https IRIs. In `expand_uri` (`lib.rs:5524-5528`) the manifest map is consulted **before** the well-known defaults:

```rust
vocabularies.get(prefix).map(String::as_str).or(match prefix {
    "dcat" => Some("http://www.w3.org/ns/dcat#"), "cccev" => Some("http://data.europa.eu/m8g/"), ...
})?
```

so a manifest entry `dcat: "https://evil.example/ns#"` **shadows** the real namespace. Every CURIE field is gated only by `validate_uri`/`validate_optional_uri`/`validate_policy_iri`, which accept a value iff `expand_uri` returns `Some` (`lib.rs:5508`) — and an override *guarantees* `Some`, so it passes. The overridden expansion is baked into the compiled structs (`CompiledField.concepts` `:4094`, `CompiledEntity.concept_uri` `:4141`, `requirement.rdf_type` `:3766`) and emitted verbatim as the node `@type` (`:4749-4750`), `sh:path` (`field_shape:5054` via `field_property_uri:5590`), and `sh:targetClass`/`sh:class` (`entity_shape:5036` via `entity_class_uri:5606`).

**The poisoning is silent:** the emitted `@context` is built entirely from hardcoded `json!` literals (`jsonld_context*`, `lib.rs:5739-5856`) and **never reflects the manifest map**, so it still maps `cccev → http://data.europa.eu/m8g/` while the document body asserts `@type: https://evil.example/ns#Requirement`. Because the body value is already a fully-expanded *absolute* IRI, a JSON-LD/RDF/SHACL consumer trusts the attacker IRI directly regardless of the context; the legitimate-looking context misleads a human auditor.

**Attack:**
```yaml
vocabularies: { cccev: "https://attacker.example/ns#" }
requirements:
  - id: req-1
    iri: https://victim.gov/requirements/req-1
    title: {en: Eligibility}
    rdf_type: cccev:Requirement
```
The published `bregdcat-ap.jsonld` / evidence-offering / `shacl.jsonld` asserts a requirement node typed `https://attacker.example/ns#Requirement` (a class the attacker defines arbitrary semantics for) under the victim's IRI. The vector generalizes to every well-known prefix (`dcat`/`dcterms`/`odrl`/`eli`/`skos`/…) and every CURIE-valued field. Produced by `render --format shacl|bregdcat-ap|cpsv-ap` and `publish` at default exposure, no opt-in flag.

**Fix (mandatory):** validate the `vocabularies` map — reject any key colliding with a built-in well-known prefix unless the value is byte-identical to the built-in, and require every value to be an absolute http(s) IRI; **or** flip `expand_uri` precedence to consult the well-known defaults first, so a manifest can only *add* prefixes, never override them. **Defense in depth (not sufficient alone):** rebuilding the emitted `@context` from the same resolved namespace table removes the silent context/body mismatch, but on its own it still lets a manifest redefine `cccev`/`dcat`/`odrl` to an attacker namespace (now *consistently* across body and context) — so it improves auditability, not safety. The protected-prefix / precedence control is the load-bearing fix; context synchronization is optional hardening on top of it.

### H3 — Linear YAML alias amplification → OOM before validation (lead-measured)
**`crates/registry-manifest-cli/src/main.rs:695-698`, `Cargo.lock` (serde_yaml_ng 0.10.0 → unsafe-libyaml 0.2.11)** · CWE-400

`load_manifest` (`main.rs:693-698`) does `fs::read_to_string` + `serde_yaml_ng::from_str` with **no input-size cap and no deserializer limits**. The blow-up happens during `from_str`, *before* `validate_manifest` runs, so schema validity is irrelevant. `unsafe-libyaml`'s repetition guard catches the **nested/exponential** billion-laughs (a 9-level fan-out-9 bomb is rejected in ~0 ms), but it counts node-expansion *events*, not *bytes* — so a single large anchored scalar aliased many times in a **flat** sequence (count well under the limit) is materialized into N owned `String` copies when serde deserializes the target `Vec<String>` field (e.g. `catalog.conforms_to`, `lib.rs:62).

**Attack + lead measurement (release binary, `/usr/bin/time -l`):**
```yaml
catalog:
  conforms_to:
    - &big "AAAA… (200 KB scalar)"
    - *big   # ×1999
```
- **220 KB on disk → 432,111,616 bytes (412 MB) peak RSS**, 0.61 s wall — a ~1900× amplification, and the validation error enumerated all 2000 materialized entries (proving each alias became a distinct heap string).
- The same input shape with the nested billion-laughs is rejected in ~0 ms at 2.2 MB baseline (guard confirmed working).

The amplification ratio scales with the attacker-chosen scalar size and alias count, so a few-MB manifest drives multi-GB allocation and OOM-kills the process. Every CLI command (`validate`/`render`/`publish`) calls `load_manifest` first, so this is default-reachable.

**Fix:** a byte cap *alone* is insufficient — the demonstrated attack is only 220 KB (amplification ~1900×, and the ratio is attacker-tunable via scalar size), so any cap large enough for legitimate manifests would still admit it. The primary control is to **reject YAML aliases/anchors at parse time**: the manifest format has no legitimate use for them (lead-confirmed — zero shipped `examples/`/`fixtures/`/`profiles/` manifests contain `&`/`*`), so rejecting them costs nothing and removes the amplification primitive entirely. Pair this with a **low** pre-parse byte cap via `fs::metadata().len()` in `load_manifest` (and the profile/fixture loaders, `main.rs:492-498,576,594`) — real manifests are ~12 KB, so a ~64 KB cap leaves generous headroom and also bounds M1's quadratic nested-flow CPU cost — and bound post-deserialization element counts in `validate_manifest` (max datasets/entities/fields/codelist-concepts/`conforms_to` entries) so a large-but-valid manifest cannot drive multi-GB renders downstream.

### H4 — Dataset `public_services[].id` emitted verbatim as `cpsv:PublicService @id`
**`crates/registry-manifest-core/src/lib.rs:1463-1468,3710-3714,4411-4414,1779`** · CWE-345

Catalog-level public services validate their id with `validate_id` (`lib.rs:2470`), but the **dataset-embedded** `public_services[].id` path applies neither `validate_id` nor `validate_uri` — only `if service.id.as_deref().is_some_and(str::is_empty)` (`lib.rs:1463`), which rejects emptiness alone. `compile_dataset` stores it verbatim (`:3711-3714`), and `public_service_node` emits `"@id": service.id` and `"dcterms:identifier": service.id` for a `cpsv:PublicService` node (`:4412-4414`); `render_cpsv_ap` also references it under `dcterms:hasPart` via `iri_object(&service.id)` (`:1779`).

**Attack:** a dataset declares `public_services: [{ id: "https://trusted-authority.gov/services/official-service", title: {en: Forged} }]`. The published `cpsv-ap.jsonld` / `bregdcat-ap.jsonld` asserts a public-service node whose IRI is wholly attacker-chosen, and the node carries `cv:hasCompetentAuthority` pointing at the catalog's *real* publisher (`:4417`) — so a consumer that dereferences or trusts `@id` sees the publishing authority vouching for a service IRI it does not own (impersonation, or a pointer at an attacker-controlled dereferenceable URL). Same structural-`@id`-injection class as H2.

**Fix:** validate dataset `public_services[].id` with `validate_id` (or `validate_uri` if a full IRI is intended) when present, matching the catalog-level treatment. (Note: an IRI-format check still cannot stop foreign-authority IRI impersonation — a syntactically valid IRI the author does not own — so consider constraining the authority to the catalog `base_url` origin or an allowlist.)

---

## Selected Medium findings (detail)

### M1 — Quadratic nested-flow YAML parse cost (CPU DoS, distinct from H3)
**`crates/registry-manifest-cli/src/main.rs:693-698,112-113`, `crates/registry-manifest-core/src/lib.rs:1331-1335`** · CWE-400/CWE-1333

Separate from H3's memory blow-up: `serde_yaml_ng`'s recursion limit (~128) prevents a *stack overflow* on deeply nested flow collections (`x: [[[…]]]`), but the cost of *reaching* that rejection is **quadratic in input length** — the parser composes the partial node graph on every nesting frame before returning the error, and this happens before `validate_manifest` or `deny_unknown_fields` can reject. The wrongly-dismissed critic measured against the exact dependency: ~300 KB nested-flow ≈ 30 s, ~640 KB ≈ 141 s of single-threaded CPU; the nesting can ride inside a legitimate `Vec<String>` field, so it does not even need an unknown field. Shares H3's root cause (no input-size cap in `load_manifest`); rated Medium because it stalls the tool rather than crashing it. The low byte cap recommended for H3 (~64 KB) bounds this quadratic cost to well under a second; alias rejection is not needed for M1, but the shared input-size cap covers it.

### M2 — Federation `jwks_uri`/`federation_api` not bound to issuer origin (contained)
**`crates/registry-manifest-core/src/lib.rs:1248-1297,1680-1681,5410-5417`**

`validate_federation` (`lib.rs:1248-1297`) checks `issuer`/`jwks_uri`/`federation_api` each as a standalone https+host string (`validate_https_url`, `:5410-5417` checks only the `https://` prefix and a non-empty host) and binds the `did:web` `node_id` host **only** to `issuer` (`:1281-1296`). Nothing requires `jwks_uri` or `federation_api` to share the issuer origin. `render_catalog` embeds the block verbatim via `json!(federation)` (`:1680-1681`), so a schema-valid manifest with `node_id: did:web:registry.legit.gov`, `issuer: https://registry.legit.gov`, `jwks_uri: https://attacker.example/jwks.json` publishes an authoritative `catalog.json` advertising an attacker-controlled key source under a legitimate issuer identity.

**Containment (verified in both repos, why this is Medium not High):** Registry Notary does **not** ingest this `catalog.json`. Its federation peers, `jwks_uri`, issuer, and evaluation profiles are loaded from the operator's own config file (`registry-notary-bin/src/main.rs:363-364`), validated independently (`registry-notary-core/src/config.rs:746-786`), and resolved at request time by matching the JWT `iss` against `peers_by_issuer` built solely from that config (`federation/runtime.rs:49-90`, `federation/mod.rs:142-147`). A grep of `apps/registry-notary` for ingestion of a `catalog.json`/registry-manifest federation block returns nothing, and `registry-manifest README.md:112-115` documents the metadata as **discovery-only — it does not grant runtime access.** So a poisoned manifest cannot inject a live rogue peer into a running Notary; the harm is bounded to poisoning the public artifact and misleading any out-of-band consumer that trusts the advertised `jwks_uri`.

**Fix:** after the existing `did:web`↔issuer binding, require `jwks_uri` and `federation_api` to share the issuer origin (same host[:port] via `url_host`), or make a cross-origin key source an explicit opt-in field. (Cross-link: Notary's own peer-config validation has the **symmetric** gap — `registry-notary-core/src/config.rs:746-762` validates `peer.jwks_uri` only as an https URL with no issuer-origin binding — but it operates on operator config, so it is a Notary-lane config-validation note, not a manifest-reachable path.)

### M3 — CURIE suffix concatenation → malformed-but-trusted IRIs
**`crates/registry-manifest-core/src/lib.rs:5524-5542,5499-5514,3400-3412,4748-4750`**

`expand_uri` splits on the first `:` and returns `Some(format!("{base}{suffix}"))` (`:5542`) with **no check on suffix content**; the sole validation gate is `expand_uri(...).is_none()` (`:5508`), which always returns `Some` for a known-prefix CURIE regardless of what follows the colon. So a `rdf_type: "cccev:Requirement> <https://attacker.example/evil"` expands to `http://data.europa.eu/m8g/Requirement> <https://attacker.example/evil` and is emitted verbatim into `@type` (`:4750`). serde keeps the JSON string syntactically valid, but the IRI inside is malformed; a downstream consumer that re-serializes JSON-LD to Turtle/N-Triples (where IRIs are `<…>`-delimited and whitespace is significant) can be tripped into emitting a token boundary or a second IRI — a semantic injection at the RDF-serialization layer. Rated Medium (high confidence on the mechanic, medium on downstream exploitability, since it requires a cooperating downstream bug). **Fix:** after expansion, reject IRIs containing ASCII whitespace, control chars `U+0000-U+001F`, or `` <>"{}|^` `` (illegal in IRIs per RFC 3987).

### M4 — Unvalidated codelist concepts emitted as SKOS `@id` (critic-surfaced, lead-confirmed)
**`crates/registry-manifest-core/src/lib.rs:1389-1410,624-641,5123-5147,2164-2176`** · CWE-345

The codelist validation loop (`lib.rs:1389-1410`) validates only `codelist.id`/`scheme_iri`/`external_ref` and **never iterates `codelist.concepts`**. `CodelistConcept.code` (required) and `.iri` (optional) are therefore wholly unvalidated. In `codelist_shape` (`:5123-5147`), `concept.iri` is emitted **verbatim** as the `@id` of a `skos:Concept` (`:5132-5135`); when `iri` is absent the `@id` is `format!("{}/{}", scheme_iri, concept.code)` (so `concept.code` is interpolated into an IRI), and `concept.code` is emitted as `skos:notation` (`:5137`). `codelist_shape` is chained into `render_shacl` (`:2170`), a real `render`/`publish` surface. A manifest with `concepts: [{ code: y, iri: "https://evil.example/forged-concept" }]` yields a SKOS concept with an attacker-chosen node identity in the authoritative SHACL graph. Same class as H4 but on a field path with *no* validation at all. **Fix:** validate `concept.iri` with `validate_uri` and constrain `concept.code` to a safe charset (it is also string-interpolated into an `@id`).

---

## Notary cross-check (does a poisoned manifest weaken any Notary trust assumption?)

| Manifest-side surface | Reaches a Notary trust decision? | Notes |
|----------------------|----------------------------------|-------|
| Published `catalog.json` federation block (`issuer`/`jwks_uri`/`federation_api`) | **No** | Notary loads peers from its own operator config and resolves by JWT `iss` against that config only (`registry-notary-bin/src/main.rs:363-364`, `federation/runtime.rs:49-90`); no ingestion of the published metadata. README disclaims runtime trust. The manifest gap (M2) poisons the public artifact, not a running Notary. |
| `evaluation_profiles[].ruleset` (L3) | **No (human-in-the-loop)** | Documented as a value an operator *manually transcribes* into Notary `federation.peers[].allowed_profiles`; Notary re-validates its own config. Confusable/whitespace strings are an operator-footgun, not a direct push. |
| `node_id`↔`issuer` `did:web` binding | n/a (holds on both sides) | registry-manifest binds it (`lib.rs:1281-1296`); Notary independently calls `validate_did_web_https_issuer_binding` for its node and each peer (`registry-notary-core/src/config.rs:646,763`). |
| **N/A by design (no such surface in registry-manifest):** authn, authz/issuance-control, replay/nonce, signing-key lifecycle, OIDC/OID4VCI, the OpenFn sidecar | — | Confirmed absent in every lane: no network, no auth, no signing, no server. The notary audit's 9 lanes for these have no counterpart here. |

The headline: **a poisoned manifest cannot inject a rogue peer, key, or trust entry into a running Notary**, because Notary's federation trust is config-driven and re-validated locally, and the published metadata is discovery-only. The residual risk is integrity of the *public artifact* (M2) and operator-transcription confusability (L3), both bounded.

---

## What holds up (independently confirmed solid)

- **Structural JSON/JSON-LD injection is impossible by construction:** every renderer builds a `serde_json::Value` via `json!` and serializes with `to_vec_pretty`/`to_string_pretty`; manifest strings in *value* position are escaped. The only viable injection is *semantic* (structural-position IRIs), which is exactly what H2/H4/M3/M4/L1 cover.
- **No HTML/markdown/SVG/script sink anywhere** — output is JSON only; XSS is N/A.
- **`@context` is not manifest-populated** — built from hardcoded prefix tables (`lib.rs:5739-5876`); direct `@context` term-injection is absent (the override risk is at compile-time expansion, H2).
- **Filesystem path traversal is blocked for every path-segment id except `profiles[].id`** — `dataset.id`, `entity.name`, `field.name`, `offering.id`, `form.id`, `application_profiles[].id`, `codelist.id` all pass strict `validate_id`. `profiles[].id` (H1) is the lone gap.
- **No remote or local resolution on untrusted input (I4):** `expand_uri`/`expand_policy_uri`/`expand_form_data_type` are pure string functions; no `reqwest`/`hyper`/`std::fs`/`include_*`/`Command::new` in core `lib.rs`. No SSRF/file-read/expansion-loop primitive.
- **`deny_unknown_fields` coverage is complete** — all 41 manifest-input structs carry it; no input struct silently accepts attacker keys.
- **Duplicate YAML keys are rejected** at both the typed-struct and untyped-`Value` level (no parser differential vs the `metadata.yaml` that `publish` copies verbatim).
- **Nested/exponential billion-laughs and deep-nesting stack overflow are blocked** by `unsafe-libyaml`'s repetition + 128-recursion limits (lead-confirmed). The residual parse DoS is the *linear* alias (H3) and *quadratic* nested-flow (M1) vectors the guards don't cover.
- **Renderer fan-out is strictly linear** (datasets × entities × fields nest as sums, not cross-products); no small-manifest → huge-output amplification beyond input size.
- **No attacker-reachable panic:** zero `unwrap`/`expect`/`panic!` in core `lib.rs`; the one `.expect` in the CLI (`main.rs:563`) runs on operator profile paths and cannot panic (`.parent()` of a `…/profile.yaml` is always `Some`); host/identifier helpers use char-boundary-safe `split`/`strip_prefix`/`rsplit_once`; no `s[a..b]`/`bytes[i]` indexing on manifest strings; `min/max_occurs` are only compared, never used for allocation.
- **No `unsafe` in first-party code** (`unsafe_code = "forbid"` workspace-wide); **no `build.rs`**; **no env-var-driven behavior** (only `env::args()`); **no shell-out** (only `std::process::exit`).

---

## Known coverage gaps (recommend a follow-up pass)

1. **No fuzzing / property testing.** All findings are from static reading plus targeted measurements (H3 OOM, M1 CPU, duplicate-key/billion-laughs rejection). The serde-escaping invariant that underpins "no structural JSON injection" was reasoned and spot-checked, not fuzzed against the full renderer matrix.
2. **`serde_yaml_ng` / `unsafe-libyaml` internals** (the exact repetition-limit accounting, behavior on pathological anchor graphs other than the two shapes measured) were trusted beyond the two tested shapes.
3. **Downstream consumer behavior is assumed, not exercised.** H2/H4/M3/M4 harm depends on how a given JSON-LD/SHACL/RDF/SKOS consumer treats an attacker-chosen `@id`/`@type` or a malformed IRI; no real consumer (Notary federation parser, a SHACL engine, a triple store) was driven with poisoned output.
4. **`I3` (LocalizedText) is latent, not live** — it becomes an injection surface the moment any renderer emits true `@language` maps. Worth a validation pass on language-tag keys/values *before* localized output ships.
5. **OGC API Records and the `record_feature_json`/`records_collection_json` path** were enumerated and covered by the rendering lane's general analysis but not given a dedicated consumer-conformance read.

---

## Tooling notes

- **cargo audit** (cargo-audit 0.22.1, 1099 advisories, 100 deps): **0 vulnerabilities**; exactly 2 unmaintained-crate warnings, both already in `deny.toml` with scoped rationale — RUSTSEC-2024-0388 (`derivative`) and RUSTSEC-2024-0370 (`proc-macro-error`). Both are **dev-only**: `cargo tree --edges normal` confirms the shipped CLI runtime tree is `registry-manifest-core` (serde/serde_json/thiserror) + `serde_yaml_ng` (indexmap/hashbrown/itoa/ryu/unsafe-libyaml) only; `sophia_*`/`json-ld`/`derivative`/`proc-macro-error` appear solely under core's `[dev-dependencies]`. The `deny.toml` rationale is **accurate**. Two further advisories on runtime deps do not apply: `unsafe-libyaml` 0.2.11 satisfies RUSTSEC-2023-0075's patched range (and the target is 64-bit), and `hashbrown` 0.17.1 is past RUSTSEC-2024-0402 (which affects only `=0.15.0`).
- **gitleaks** (8.30.1): `gitleaks dir .` (337 MB incl. `target/`) and `gitleaks detect` over 24 commits of history both report **no leaks**. No tracked secrets in `profiles/`, `fixtures/`, `examples/`, `docs/`, `README.md`, or `SECURITY.md`.
- **`deny.toml`:** `[sources]` denies unknown registries/git; all 100 packages resolve to crates.io (zero git sources); the `allow-git` entry for `github.com/jeremi/registry-manifest` is dormant (no dep resolves to it). `Cargo.lock` is committed.

---

## Recommended must-fix before beta (all cheap)

1. **H1** — add a `validate_id` + uniqueness loop over `manifest.profiles` in `validate_manifest` (mirror the `application_profiles` loop), and add a canonicalize/`starts_with(out)` containment check in `write_json`.
2. **H3 + M1** — **reject YAML aliases/anchors at parse time** (no legitimate use in the manifest format; this removes H3's amplification primitive — a byte cap *alone* does not, since the demonstrated attack is only 220 KB) **and** add a low pre-parse byte cap (~64 KB; real manifests are ~12 KB) in `load_manifest` and the profile/fixture loaders, which also bounds M1's quadratic-CPU parse. Add post-deserialization element-count bounds in `validate_manifest` as defense in depth.
3. **H2** — validate the `vocabularies` map (reject keys shadowing well-known prefixes unless byte-identical; require absolute http(s) IRI values) **or** flip `expand_uri` precedence so manifests can only add prefixes. Rebuilding `@context` from the resolved table is auditability-only defense in depth — it does not stop attacker prefix redefinition and is not a substitute for the protected-prefix control.
4. **H4 + M4** — apply `validate_uri` (or `validate_id`) to dataset `public_services[].id` and to `codelists[].concepts[].iri`/`.code`, matching the treatment of every other `@id`/path-bearing field.

**Fast-follow (same release if time permits):** M3 (post-expansion IRI well-formedness check), M2 (bind `jwks_uri`/`federation_api` to the issuer origin), L2 (conservative property-name charset + `name` uniqueness for form fields — *not* `validate_id`, which would reject the project's own camelCase wire keys), L3 (apply `validate_id` to `evaluation_profiles[].ruleset`), L5 (reject `..`/absolute fixture paths in `validate-profiles`), L4/I1 (document/guard `--out`/`--site-root` and the raw-manifest republish), I3 (validate `LocalizedText` keys/values before localized output ships).
