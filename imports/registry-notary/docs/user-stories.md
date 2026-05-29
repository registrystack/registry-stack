# Registry Notary User Stories

## Purpose

These user stories describe the core Registry Notary product journeys. They
merge the supporting security, privacy, policy, audit, and operational concerns
into acceptance criteria instead of treating each concern as a separate user
story.

## 1. Authorized Service Evaluates A Configured Claim

As an authorized service, I want to ask Registry Notary whether a subject
satisfies a configured claim, so that I can make an eligibility or workflow
decision without directly reading registry source data.

Acceptance criteria:

- The request is authenticated through a configured API key, bearer token, or
  OIDC policy before any source lookup occurs.
- The caller can request only configured claims, purposes, formats, and
  disclosures.
- Registry Notary returns only the configured claim result or disclosure, not
  raw source rows.
- Ambiguous source matches fail safely instead of attesting against a possibly
  incorrect subject.
- Allow and deny decisions emit redacted audit events.

## 2. Citizen Requests Self-Attestation About Themself

As a citizen, I want to request an attestation about myself after authenticating
through a trusted identity provider, so that I can receive verified evidence
without exposing raw registry records.

Acceptance criteria:

- Self-attestation is disabled by default and requires OIDC authentication when
  enabled.
- Registry Notary verifies the token, scopes, client or audience policy, and
  exact subject binding before reading any source.
- The citizen can request only one subject at a time, and that subject must be
  bound to the authenticated token.
- Batch evaluation, arbitrary subject lookup, raw registry access, and delegated
  access are denied.
- Denied subject-binding attempts are generic to the caller, rate limited, and
  auditable without recording raw citizen identifiers.

## 3. Wallet Holder Receives A Holder-Bound Credential

As a wallet holder, I want Registry Notary to issue a short-lived SD-JWT VC
bound to my holder key, so that I can present verified evidence to a relying
party.

Acceptance criteria:

- Credential issuance is based on a valid, recent claim evaluation.
- The requested credential profile, disclosure, and format are allowed by
  configuration.
- When the profile requires holder binding, Registry Notary validates proof of
  possession for the holder key before issuance.
- Issued credentials are short-lived for citizen-facing use cases unless a
  later credential-status design changes that policy.
- Replay attempts, invalid holder proofs, and stale evaluations are denied and
  audited without exposing holder private material.

## 4. Notary Evaluates A Claim Through An OpenFn Sidecar Source

As an implementer, I want Registry Notary to evaluate claims using a
Registry Data API-shaped sidecar backed by pinned OpenFn adaptor jobs, so that
existing registry integrations can provide evidence without becoming part of
Registry Notary itself.

Acceptance criteria:

- Registry Notary calls the sidecar through the existing registry data source
  connector contract.
- The sidecar maps target-service outcomes to the expected `{ "data": [...] }`
  response shape for exact match, not found, and ambiguous match.
- Registry Notary remains the attestation authority for caller auth, claim
  rules, disclosure, provenance, audit, and credential issuance.
- Sidecar readiness fails when pinned jobs, adaptors, credentials, workers, or
  smoke lookups are missing or mismatched.
- Sidecar timeouts, worker saturation, invalid output, target failures, and
  credential non-disclosure are handled explicitly.

