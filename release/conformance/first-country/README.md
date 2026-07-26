# First-country acceptance evidence

This directory defines the closed, value-free public record for one bounded
first-country acceptance run. It records hashes, safe classifications, and
owner roles. It does not record country values, source or operator identities,
credentials, secret names, paths, URLs, raw logs, private origins, or source
responses.

The record covers the complete first-country acceptance matrix:

- a clean offline authoring journey;
- missing and wrong caller and purpose denials;
- service-policy denial;
- allowed Relay consultation, no-match, ambiguity, and subject mismatch;
- unavailable, rejected, malformed, and late source behavior;
- Notary value, predicate, and redacted claims;
- consultation contract mismatch;
- promotion, rollback or recovery, and teardown.

Every case repeats the canonical acceptance binding digest. The validator
recomputes that digest from the exact candidate, project semantic digest,
environment digest, and source-profile digests, then checks the case result,
source-call classification, evidence hashes, and owner roles against the closed
case contract.

## Evidence boundary

[`acceptance-record.template.json`](acceptance-record.template.json) is a
machine-checked planning aid. It is explicitly marked `is_evidence: false`,
uses reserved zero-digest sentinels, and cannot pass evidence validation.
Copy it only into approved restricted working storage. Do not fill it in
inside this public repository.

An approved operator may validate a sanitized record without contacting a
source:

```sh
python3 release/scripts/validate-first-country-acceptance.py validate \
  sanitized-first-country-acceptance.json
```

Validate the checked-in schema and template:

```sh
python3 release/scripts/validate-first-country-acceptance.py check-packet
```

The validator checks the public record only. It cannot inspect the restricted
evidence committed by its hashes, verify country-owner authority, or infer
legal or production approval. The publication reviewer must compare the
public hashes and classifications with the restricted evidence.
Evidence digests must commit to reviewed evidence collections or value-free
indexes. Never publish a direct hash of a country value, identifier, secret,
private origin, path, source response, or other low-entropy restricted value.
Public, restricted, source-call, and owner-attestation fields name separate
evidence envelopes and must have distinct digests within a case. One public
summary or one restricted index may cover multiple cases, but a digest cannot
cross the public and restricted evidence domains.

A passing record is bounded to one exact candidate, project, environment,
source profile, and approved non-production journey. It is not production
authorization, broad interoperability, upstream product certification, or
general country-system conformance. Offline fixtures are not live evidence,
and signing is not country governance approval.

Failed runs are retained as honest, non-closing records when their public
artifact passes the same redaction, retention, publication-review, and
teardown accounting rules. A structurally valid failed record does not close
Country ready or First-country success.
