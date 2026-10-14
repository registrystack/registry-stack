# Citizen self-registration (historical integration fixture)

This BReg fixture records an earlier proposed citizen signup integration. Its
Casework subproject, source-synchronization hook, and automatic review executor
use the retired Casework model. The retained `tests/run-live.py` runner exits
with status 2 and a replacement guide before starting resources; it is not a
current acceptance gate for the review-only Casework API.
Do not use this fixture as an integration setup. For a maintained native
Proposal context export, exact provider pairing, retained ReviewResult, and
separately authorized BReg apply, use the
[canonical Casework review](../../../casework/examples/canonical-review/README.md)
and [current-source development guide](../../../casework/DEV-SOURCES.md).
The historical names, phone numbers, and program details below are synthetic.

The native development and source-authoring tools derive the reader's principal
claim from the governed registry model. Every BReg access profile here uses
`sub`; an operated deployment must explicitly configure
`authentication.authorityClaims.principal: sub` as well.

The application exists before a Person. Its `owner` is the verified account's
`sub`, within the single trusted issuer configured for this registry. Applicants
can save, resume, edit, submit, revise, or withdraw only their own applications.
This example supports self-application only.

The former setup had Casework review the submitted proposal and BReg's
`registration-applier` apply it automatically. Current Casework returns a
review result only; an independently authorized BReg principal must check and
apply the exact proposal. The reviewed
Rhai planner creates a Person, an active account link, and an enrollment in
`synthetic-citizen-program` in one BReg transaction. The planner fixes
`active: true`; the applicant cannot supply link state or an existing Person
target. A unique account-link principal prevents a second approved application
from creating another Person for the same account. A conflict rolls back all
three effects. The former automatic executor retried a generic precondition
refusal with backoff, so the duplicate remains queued between attempts. This
proof observes repeated attempts without extra records; it does not wait for
retry exhaustion or approval expiry.

An approved citizen reads the enrollment through BReg's current account link.
No ThunderID claim change is needed after approval. An operator can deactivate
the link, after which the same previously issued token loses enrollment access.

## Historical runner boundary

The retained `tests/run-live.py` and BReg authoring fixture describe the former
combined journey. Direct runner invocation refuses before resource setup
because its Casework subproject and source-sync webhook are retired. The
[native identity setup](identity/README.md) remains useful for the
synthetic ThunderID flows, but integration with current Casework must follow
the canonical review and current-source guides linked above.

## Former acceptance claims

The retained runner describes these historical assertions. They are not
verified against the current Casework contract:

- Incorrect OTP refusal before account provisioning, and refusal of a citizen's
  attempt to acquire a staff scope.
- Two previously unknown accounts; saved drafts survive native login with the
  same account subject.
- Owner spoofing, arbitrary Person targets, cross-account reads and edits,
  direct Person/link/enrollment creation, and applicant application authority
  are refused.
- No Person, link, or enrollment before approval. Changes requested can be
  revised and resubmitted, with exact current source context shown to reviewers.
- Native Casework approval automatically creates exactly one Person, link, and
  enrollment. Rejection and withdrawal create none.
- Replayed create, submit, and decision requests preserve their committed
  result. Duplicate approval rolls back every target effect; retained BReg
  restart preserves the applied result and the duplicate's retry state and
  attempt count.
- Enrollment get and list are account-bound, and link revocation removes access
  from a token issued before revocation.

The authored `tests/journeys.yaml` is a small source-reader schema rehearsal.
It does not stand in for citizen or staff authentication. The former live
driver used interactive tokens in `tests/live_journey.py`.

## Scope and remaining work

This was drafted as a backend acceptance example for
[#1972](https://github.com/registrystack/registry-stack/issues/1972), intended for
the release after 0.40. It does not change release versions or implement App Kit
applicant mode. App Kit can subsequently use the same owner-bound application
and status APIs before an account has a Person link.

The citizen read surface here is an enrollment containing its Person reference.
The current membership predicate joins a stored reference field to the account
link; this example does not grant direct Person reads. It creates one enrollment,
so it reports pagination continuation after revocation as unexercised. It also
does not prove representative authority, multi-issuer account namespaces,
identity deduplication across different accounts, production delivery, or browser
UX. Institutions must define those separately before adopting a wider flow.
