# Candidate exercise records

The files in this directory separate reusable preparation from evidence
captured against an exact release candidate. Upgrade evidence and product-input
lifecycle evidence use separate, closed record contracts. Neither kind of
template is evidence.

## Product-input lifecycle

`product-input-lifecycle/product-input-lifecycle-v1.template.json` defines the
versioned, machine-validated record for the separate Relay and Notary
product-input lifecycle. It reuses the release candidate and upgrade exercise
coordinate fields: release ID, version, prepare source ref, exact source
commit, release-manifest digest, image-lock digest, release-capsule digest,
candidate-receipt digest, and image digests. The coordinate occurs once and is
bound by its canonical SHA-256.

`product-input-lifecycle/product-input-lifecycle-v1.schema.json` is the closed
Draft 2020-12 structural contract. The validator applies it before semantic and
cryptographic checks. Runtime/schema drift tests bind the schema version,
fields, evidence groups, check IDs, review classes, template constraints, and
candidate constraints to the validator.

The template is preparation only. Its `record_kind` is `template`, candidate
attestations are false, trust and activation generations are zero, every result
is `not_run`, and every evidence field is null. Validation never upgrades it to
candidate evidence:

```sh
python3 release/scripts/validate-product-input-lifecycle.py --template \
  release/exercises/product-input-lifecycle/product-input-lifecycle-v1.template.json
python3 release/scripts/validate-product-input-lifecycle.py \
  --discover release/exercises
```

For an exact frozen candidate:

1. Copy the template within `release/exercises/product-input-lifecycle/`.
2. Set `record_kind` to `candidate_evidence` and replace every placeholder.
3. Bind the one candidate coordinate to the exact committed release manifest
   and retained release-candidate receipt. Place the authenticated release
   image lock, capsule, signatures, certificates, provenance, checksums, and
   receipt in one version-named directory under an operator-supplied candidate
   asset root. Do not add those paths, country values, credentials, key
   material, or raw evidence to the record.
4. Record separate Relay and Notary unsigned-input, signed-bundle, operator
   trust, trust-generation, and anti-rollback-lineage identities.
5. Record a closed `passed` or `failed` result, subject digest, evidence label,
   and evidence digest for every authoring, build, verification, staged
   activation, traffic-admission, upgrade, recovery, and rollback check.
   Authoring subjects bind the candidate and complete product-input set to the
   artifact manifest. Bundle-verification subjects also bind the exact trust
   generation, trust set, and anti-rollback lineage. Advanced-operation
   subjects bind the exact candidate, product-input set, and activation.
6. Preserve an exact zero source-call count for a passing consultation-contract
   mismatch check. A nonzero observation must be retained as a failed check and
   cannot pass discovery.
7. Add distinct independent correctness, security, maintainability, and
   operator reviews after lifecycle evidence has been captured.
8. Keep every limitation false and the evidence grade
   `candidate_non_production`. This record cannot prove live country
   interoperability, country-owner acceptance, legal approval, or production
   authorization.

Candidate validation reuses the release-owned image-lock, capsule, Cosign,
SLSA, Git-lineage, and annotated-tag receipt binding checks. A digest or boolean
alone cannot make a candidate record pass. The validator intentionally does
not ingest the retained lifecycle logs, reports, or review bodies. Their opaque
digests and labels remain bound by the access-controlled evidence system and
the four independent reviews. The required
`retained_evidence_content_authenticated_by_validator: false` limitation makes
that trust boundary explicit.

Validate an honest in-progress or failed record structurally with:

```sh
LIFECYCLE_RECORD=release/exercises/product-input-lifecycle/candidate-record.json
python3 release/scripts/validate-product-input-lifecycle.py \
  --candidate-asset-root "${CANDIDATE_ASSET_ROOT}" \
  "$LIFECYCLE_RECORD"
```

Require all checks and reviews to pass with:

```sh
LIFECYCLE_RECORD=release/exercises/product-input-lifecycle/candidate-record.json
python3 release/scripts/validate-product-input-lifecycle.py --require-pass \
  --candidate-asset-root "${CANDIDATE_ASSET_ROOT}" \
  "$LIFECYCLE_RECORD"
```

Discovery accepts the template only as non-evidence. Any discovered real
record must be complete, passing, and authenticated from candidate assets:

```sh
python3 release/scripts/validate-product-input-lifecycle.py \
  --discover release/exercises \
  --candidate-asset-root "${CANDIDATE_ASSET_ROOT}"
```

If the candidate coordinate, manifest, product inputs, trust generation,
activation generation, or retained evidence changes, discard the result and
repeat the lifecycle against the new exact digests.

## Historical Notary-era upgrade lifecycle

The `registry-stack.upgrade-exercise/v1` contract is retained to validate
committed Notary-era upgrade records whose target version is earlier than
v0.17.0. The validator rejects v0.17.0 and later targets before reading any
Notary-era schema, image, or release-input path. Post-Notary upgrades require
a successor contract; do not repurpose v1 by removing its Notary fields.

## Candidate-neutral preparation

`upgrade-exercise-v1.template.json` defines the machine-validated evidence
record for a historical Registry Stack stable upgrade. The template is
preparation only.
Its `record_kind` is `template`, every result is `not_run`, and both candidate
attestations are `false`. Every result's observation and evidence fields are
null. A validated template contains zero candidate evidence and does not
satisfy a release gate.

Validate the template with:

```sh
python3 release/scripts/validate-upgrade-exercise.py --template \
  release/exercises/upgrade-exercise-v1.template.json
```

The template consumes the committed Relay and Notary configuration schemas in
`schemas/`. It does not define another configuration model.

## Frozen-candidate evidence

After the candidate source, release manifest, images, and standalone Solmara
release are frozen and independently verified:

1. Copy the template to a candidate-specific JSON file.
2. Change `record_kind` to `candidate_evidence`.
3. Replace every placeholder with an exact version, commit, digest, timestamp,
   bounded authority identifier, or evidence label. `target_release.source_ref`
   is the reviewed prepare commit P and `source_commit` is the finalized target
   T. The manifest path and hash must identify the manifest stored at T.
4. Hash each committed configuration schema and every complete recovery-set
   artifact. For audited SnapshotExact, capture immutable source inputs, the
   Relay ingest cache, and the complete Relay database at one coordinated,
   quiesced recovery point. The database artifact includes the active
   publication pointer and history.
5. Fill `materialization_recovery` with the exact source-input, ingest-cache,
   and Relay-database artifact digests. Bind the private active-publication
   tuple as one value-free commitment over its binding, generation, restricted
   content digest, source revision, and source-observed fields. Also bind the
   coordinated recovery point, exact target release, committed Relay
   schema, role-bootstrap identity, recovery metadata, and audit watermark.
   Compute `binding_sha256` over the other fields in that closed object as
   canonical compact JSON (`sort_keys=True`, separators `,` and `:`).
   Do not expose the tuple values, source paths, rows, credentials, or key
   material in the public record.
6. Fill the canonical artifact set with the two P and T binary inventories,
   image-input inventories, retained image-layout-pair identities, target
   images, manifest, image lock, and P/T release-input identities. Its
   `sha256` is the SHA-256 of canonical compact JSON for the `artifacts` object
   (`sort_keys=True`, separators `,` and `:`).
   Under a private candidate-asset root, keep one directory named for each
   source and target version. Each version directory contains the downloaded
   `registryctl-<version>-image-lock.json` beside its `SHA256SUMS`,
   signed release capsule, Cosign signatures and certificates, and shared SLSA
   provenance. The validator authenticates both releases and requires their
   signed tag targets and image pins to match the corresponding record. The
   target image-lock byte digest must also match the canonical artifact set.
7. Exercise every required check against the pinned standalone Solmara
   topology. Record `passed` only when the retained evidence proves the check.
   Honest `failed` and `not_run` records remain structurally valid; a `not_run`
   result uses null evidence fields. Materialization checks cover an exact
   restart with zero source calls, missing and mismatched cache failures,
   pointer-mutation rejection, and rejection of stale or live fallback.
8. Set both candidate attestations to `true` only after independent review.
9. Compute `record_binding_sha256` over the complete record except that field,
   using the same canonical compact JSON encoding. This binds every result and
   recovery commitment to the exact authenticated upgrade record, not to a
   free-standing evidence digest.
10. Validate the record structure, then require every promotion check to pass:

   ```sh
   UPGRADE_RECORD=release/exercises/candidate-upgrade-record.json
   CANDIDATE_ASSET_ROOT=operator-evidence/candidate-release-assets
   python3 release/scripts/prepare-upgrade-exercise-assets.py \
     --discover release/exercises \
     --asset-root "$CANDIDATE_ASSET_ROOT"
   python3 release/scripts/validate-upgrade-exercise.py \
     --candidate-asset-root "$CANDIDATE_ASSET_ROOT" \
     "$UPGRADE_RECORD"
   python3 release/scripts/validate-upgrade-exercise.py --require-pass \
     --candidate-asset-root "$CANDIDATE_ASSET_ROOT" \
     "$UPGRADE_RECORD"
   ```

The validator authenticates release coordinates and enforces equality among
the redaction-safe P/T inventory and layout digests. The underlying private
inventory, layout, Solmara execution, and result evidence remains subject to
the candidate-freeze and independent-review attestations; it is not ingested
from the public record.

The validator also requires the three materialization artifacts to equal their
complete recovery-set entries, the Relay release and schema commitments to
equal the authenticated target coordinates, the closed materialization binding
to match all recovery commitments, and the record binding to match the complete
upgrade record.

The validator accepts only a bounded schema. It records hashes and labels, not
raw commands, logs, database URLs, credentials, tokens, subject identifiers,
source rows, audit contents, or key material. Keep the underlying evidence in
the access-controlled release-evidence system and use its SHA-256 digest in the
public record.

The candidate run must prove all of the following before the record validates:

- Independently verified candidate artifacts and a ready source deployment
- Complete version-specific backup and restore sets
- Forward Notary schema upgrade and rejection by the older Notary binary
- Readiness before traffic admission and retained correctness state after restart
- Exactly one Notary authority paired with each Relay authority
- Registry-backed direct and OpenID for Verifiable Credential Issuance issuance
- General rollback before target traffic
- Fix-forward behavior after target writes or credential issuance
- Complete restore, restored readiness, and config anti-rollback rejection
- Exact SnapshotExact restart without source access
- Missing or mismatched cache rejection without pointer mutation or stale/live fallback

If any frozen candidate artifact changes, discard the result and repeat the
exercise against the new exact digests.
