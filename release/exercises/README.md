# Upgrade exercise records

The files in this directory separate reusable release preparation from evidence
captured against an exact release candidate.

## Candidate-neutral preparation

`upgrade-exercise-v1.template.json` defines the machine-validated evidence
record for a Registry Stack stable upgrade. The template is preparation only.
Its `record_kind` is `template`, every result is `not_run`, and both candidate
attestations are `false`. A validated template does not satisfy a release gate.

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
   bounded authority identifier, or evidence label.
4. Hash each committed configuration schema and every complete recovery-set
   artifact. Do not copy secret values into the record.
5. Exercise every required check against the pinned standalone Solmara
   topology. Record `passed` only when the retained evidence proves the check.
6. Set `candidate_frozen` and `candidate_independently_verified` to `true`.
7. Validate the candidate record without `--template`:

   ```sh
   python3 release/scripts/validate-upgrade-exercise.py \
     release/exercises/<candidate-upgrade-record.json>
   ```

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

If any frozen candidate artifact changes, discard the result and repeat the
exercise against the new exact digests.
