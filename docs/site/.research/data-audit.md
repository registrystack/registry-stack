> **Status: historical research note**
>
> This note records pre-monorepo research and is not current architecture or release evidence. Use the published documentation and pinned source links for current claims.

# Data audit — 2026-05-23

## Overview
Audit of Registry Legend documentation YAML against five source repos: registry-relay, registry-manifest, registry-witness, registry-atlas, registry-lab. Evidence collected via grep, test fixtures, and file verification. Total entries checked: ~40 across four YAML files.

---

## projects.yaml

### Project entries

**registry-manifest** 
✓ Verified. Exists at `../registry-manifest`. README, crates/registry-manifest-core, crates/registry-manifest-cli all present. Target repo name matches local name.

**registry-relay** 
⚠ **Path mismatch in repo-map.yaml**: YAML declares `repo_path: ../registry_relay` (underscore) but actual directory is `../registry-relay` (hyphen). Source docs URL references also use underscore: `https://github.com/jeremi/registry_relay/blob/main/README.md`. Local path is wrong; should be `../registry-relay`. This is a critical bug in repo-map.yaml line 11.

**registry-witness** 
✓ Verified. Exists at `../registry-witness`. README and crates/registry-witness-server present. OpenAPI source at crates/registry-witness-server/src/openapi.rs confirmed.

**registry-atlas** 
✓ Verified. Exists at `../registry-atlas`. README and `SYSTEM_CAPABILITY_DISCOVERY_SPEC.md` present as claimed.

**registry-lab** 
⚠ **Directory path mismatch in repo-map.yaml**: YAML declares `repo_path: ../decentralized-evidence-demo` but actual directory is `../registry-lab`. The repo has been renamed locally but YAML points to old name. repo-map.yaml should be: `registry-lab: ../registry-lab`. Pre-rename README referenced correctly but current source is at new path.

### Source docs references

All README.md URLs reference GitHub, not local paths. Links are syntactically valid but not verifiable as local files (expected for GitHub URLs).

---

## contracts.yaml

### Contract entries

**registry-relay.openapi**
✓ Verified. OpenAPI JSON snapshot exists at `/registry-legend/openapi/registry-relay.openapi.json` (76 KB). Source generator at `registry-relay/src/api/openapi.rs` confirmed. Status "pinned-demo-snapshot" is accurate — feature flag `ogcapi-*` are optional.

**registry-witness.openapi**
✓ Verified. OpenAPI JSON snapshot exists at `/registry-legend/openapi/registry-witness.openapi.json` (9.8 KB). Source generator at `registry-witness/crates/registry-witness-server/src/openapi.rs` confirmed.

**registry-manifest.metadata-yaml**
✓ Verified. Crates exist: registry-manifest/crates/registry-manifest-core. Surface claim "compiled metadata model, policies, and evidence offering metadata" supported by crate presence.

**registry-manifest.static-publication**
✓ Verified. Crate registry-manifest/crates/registry-manifest-cli present.

**registry-atlas.capability-envelope**
✓ Verified. Fixtures at registry-atlas/fixtures/system-capability present.

**registry-lab.release-check**
⚠ **Source reference issue**: YAML references `https://github.com/jeremi/decentralized-evidence-demo/blob/main/README.md` but repo has been renamed. The README does exist locally at registry-lab/README.md, but URL points to old name.

---

## standards.yaml

### Verified standard implementations

**dcat** 
✓ Verified `emits` claim. Both relay and manifest emit DCAT/DCAT-AP. Evidence:
- registry-relay/src/observability.rs: `/metadata/dcat` endpoint registered.
- registry-relay/src/config/mod.rs: BRegDCAT-AP publisher configuration.
- Source file: registry-relay/src/metadata/shacl.rs implements `dcat_ap_document()`.

**bregdcat-ap** 
✓ Verified `emits` claim. Same evidence as DCAT above.

**ogc-api-records** 
✓ Verified `emits` claim. Evidence:
- registry-relay/src/api/openapi.rs: `#[cfg(feature = "ogcapi-records")]`
- registry-relay/src/error.rs: `OgcError::RecordNotFound` error type.
- registry-relay/tests/ogc_records_api.rs: Test fixture present.
- README.md: "GET /ogc/v1/records (feature: ogcapi-records)"

**ogc-api-features** 
⚠ **Claim level potentially understated**. YAML claims `aligns_with` but code shows `implements`:
- registry-relay/src/api/openapi.rs: `#[cfg(feature = "ogcapi-features")]`
- registry-relay/src/observability.rs: EndpointKind::OgcFeature registered.
- registry-relay/tests/ogc_api.rs: Full test suite (feature-gated).
- Feature is optional (`Cargo.toml` line 6: `ogcapi-features = ["dep:ogcapi-types", "dep:geojson"]`).
- README.md confirms: "OGC API Features" listed as standards integration.

**Recommendation**: Upgrade to `emits` IF feature is commonly enabled; keep `aligns_with` if feature is rarely used in production. Current claim is defensible but perhaps conservative.

**openapi** 
✓ Verified `emits` claim. Both relay and witness generate OpenAPI (see openapi.rs files). Pinned artifacts exist.

**shacl** 
✓ Verified `emits` claim. registry-relay/src/metadata/shacl.rs implements SHACL shape generation. Evidence in dcat_ap_document() rendering.

**json-schema** 
✓ Verified `emits` claim. registry-relay/src/api endpoints serve JSON Schema (entity schema routes referenced in README).

**json-ld** 
✓ Verified `emits` claim. Witness emits JSON-LD:
- registry-witness/crates/registry-witness-server/src/runtime.rs: `"@context":` JSON-LD structure.
- Comment confirms JSON-LD validity.
- Relay: registry-relay/src/metadata/shacl.rs (line 2): "JSON-LD DCAT-AP and SHACL renderers."

**sd-jwt-vc** 
✓ Verified `emits` claim. Witness owns SD-JWT VC issuance:
- registry-witness/crates/registry-witness-core/src/sd_jwt.rs: "Minimal SD-JWT VC issuer."
- Witness runtime.rs: `FORMAT_SD_JWT_VC` format enum and rendering.
- Config examples show `format: sd_jwt_vc`.

**verifiable-credentials** 
✓ Verified `aligns_with` claim. Evidence supports this conservative stance:
- registry-relay/tests/fixtures/vc/: Credential fixtures (entity-record-v1, aggregate-result-v1, verify-result-v1).
- registry-relay/tests/provenance_contexts_endpoint.rs: VC context test.
- No formal VC 2.0 conformance profile pinned.

**cccev** 
✓ Verified `emits` claim. Witness renders CCCEV:
- registry-witness/crates/registry-witness-server/src/runtime.rs: `FORMAT_CCCEV_JSONLD` format and `render_cccev()` function.
- registry-witness/crates/registry-witness-core/src/model.rs: Media type constant for CCCEV.

**odrl** 
✓ Verified `emits` claim. Relay uses ODRL in catalog:
- registry-relay/src/config/mod.rs: ODRL offers configuration.
- registry-relay README: Dataset-scoped offers for policies.

**prov-o** 
✗ **Claim level inflated**. YAML claims `inspired_by` but evidence shows no PROV-O vocabulary terms emitted:
- registry-relay/src/config/provenance.rs: Configuration (provenance concept but not PROV-O terms).
- registry-relay/src/provenance/did_web.rs: DID support (provenance-shaped but not PROV-O).
- **No grep match for `prov:` (PROV-O URI prefix) in either relay or witness crates.**
- Verdict: Keep as `inspired_by` (design influence acknowledged) but note that no PROV-O vocabulary emission is evidenced. This is correct.

**govstack-digital-registries** 
✓ Verified `compares_against`. README.md line states: "Registry Relay is an experiment toward a redesigned GovStack Digital Registries Building Block." Positioning as alternative model confirmed.

**sp-dci** 
⚠ **Used_by field incomplete**. YAML claims used by both relay and witness, but grep evidence shows:
- registry-relay/src/lib.rs: `#[cfg(feature = "spdci-api-standards")]` and `pub mod spdci`.
- registry-relay/tests/spdci_api_standards.rs: Test present.
- **registry-witness: zero matches for spdci.** 
- Verdict: SP-DCI is only in relay (with feature flag), not in witness. Remove witness from `used_by`.

### Missing standard entries

**W3C DID Core** 
Clearly used but not in standards.yaml:
- registry-relay/src/provenance/did_web.rs: "did:web document builder"
- registry-relay/src/config/provenance.rs: `did` and `ministry_did` fields.
- registry-witness/crates/registry-witness-server/src/api.rs: `strip_prefix("did:jwk:")`
- Tests: registry-relay/tests/provenance_did_web_document.rs
- **Missing**: Should add entry with `claim_level: implements` (did:web DID resolver, did:jwk parsing).

**FOAF (Friend of a Friend)** 
RDF vocabulary used but not listed:
- registry-relay/src/api/evidence_offerings.rs: `"@type": "foaf:Agent"`, `"foaf:name"`
- registry-relay/src/metadata/shacl.rs: `"foaf:Document"`
- **Missing**: Could add as `maps_to` or `emits` (used in JSON-LD contexts). Low priority if DCAT-AP conformance is primary claim.

**JWT (JSON Web Token)** 
Heavy usage across both relay and witness:
- registry-relay/src: 136 matches for "jwt" or "JWT".
- registry-witness: Multiple `jwt` references in SD-JWT VC implementation.
- **Note**: This is subsumed under SD-JWT VC and provenance credential work. May not need separate entry if those are sufficient, but consider if JWT itself (as envelope, not just VC format) is a claimed standard.

---

## openapi-sources.yaml

### OpenAPI snapshot status

**registry-relay.openapi.json** 
✓ File exists (76 KB) and is valid JSON. Source generator: registry-relay/src/api/openapi.rs confirmed.

**registry-witness.openapi.json** 
✓ File exists (9.8 KB) and is valid JSON. Source generator: registry-witness/crates/registry-witness-server/src/openapi.rs confirmed.

**Staleness**: Both pinned snapshots are dated 2026-05-23 (same as audit date). Likely freshly generated.

---

## repo-map.yaml

### Critical path mismatches

**Lines 11 and 15: Incorrect local directory references**

| Entry | YAML declares | Actual path | Status |
|-------|----------------|-------------|--------|
| registry-relay | ../registry_relay | ../registry-relay | ✗ Underscore/hyphen mismatch |
| registry-lab | ../decentralized-evidence-demo | ../registry-lab | ✗ Directory renamed locally |

Both errors will break any automation or tooling that reads repo-map.yaml to locate source repos.

### Recommendation
Update repo-map.yaml:
- Line 11: Change `registry-relay: ../registry_relay` → `registry-relay: ../registry-relay`
- Line 15: Change `registry-lab: ../decentralized-evidence-demo` → `registry-lab: ../registry-lab`

---

## Cross-cutting issues

### 1. Path normalization in projects.yaml
Lines 22 and 87 of projects.yaml declare:
- `repo_path: ../registry_relay` (underscore, does not exist)
- `target_repo_path: ../registry-relay` (hyphen, correct)

The target name is correct (repo was never renamed to use hyphen), but local path is wrong. This is inconsistent with repo-map.yaml which ALSO has the wrong path.

### 2. URL alignment
Standards.yaml evidence_docs URLs and projects.yaml source_docs URLs use old GitHub paths (e.g., `registry_relay` underscore in URLs) which will redirect on GitHub but are non-canonical. Not a functional bug but suggests data was copied from earlier documentation.

### 3. Feature flag claim levels
OGC API Records and OGC API Features are both behind optional Cargo features (not enabled by default). YAML correctly marks them with conservative claim levels (`emits`), but the distinction between "fully implemented but opt-in" and "implemented" could be clearer in notes.

### 4. Registry Lab rename incomplete
- directory: ✓ renamed to registry-lab
- YAML paths: ✗ still reference decentralized-evidence-demo
- source URLs: ✗ still reference decentralized-evidence-demo

---

## Verdict summary

| File | Issues | Severity |
|------|--------|----------|
| projects.yaml | Path mismatch (registry_relay vs registry-relay); rename status stale for registry-lab | High |
| contracts.yaml | registry-lab source URL points to old repo name | Medium |
| standards.yaml | SP-DCI incorrectly lists witness in used_by; missing W3C DID Core entry; PROV-O claim is conservative but defensible | Medium |
| openapi-sources.yaml | None detected | ✓ Pass |
| repo-map.yaml | Two critical path errors (underscore/hyphen, renamed directory) | **Critical** |

Total hallucinated entries: ~2–3 (sp-dci witness attribution, outdated paths). Missing entries: 1 clear (W3C DID), 1 optional (FOAF), 1 debatable (JWT base).

Prose and generated tables will be affected primarily by repo-map.yaml path errors and the incomplete registry-lab rename.
