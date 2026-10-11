# Citizen self-registration

This example registers a previously unknown citizen with native ThunderID SMS
OTP, saves an account-owned application in BReg, reviews it in Casework, and
automatically enrolls the approved citizen. It uses the existing product
runtimes and public APIs. All names, phone numbers, and program details are
synthetic.

The native development and source-authoring tools derive the reader's principal
claim from the governed registry model. Every BReg access profile here uses
`sub`; an operated deployment must explicitly configure
`authentication.authorityClaims.principal: sub` as well.

The application exists before a Person. Its `owner` is the verified account's
`sub`, within the single trusted issuer configured for this registry. Applicants
can save, resume, edit, submit, revise, or withdraw only their own applications.
This example supports self-application only.

Casework reviews the submitted proposal. Its approval lets BReg's dedicated
`registration-applier` apply that exact proposal automatically. The reviewed
Rhai planner creates a Person, an active account link, and an enrollment in
`synthetic-citizen-program` in one BReg transaction. The planner fixes
`active: true`; the applicant cannot supply link state or an existing Person
target. A unique account-link principal prevents a second approved application
from creating another Person for the same account. A conflict rolls back all
three effects. The current automatic executor retries a generic precondition
refusal with backoff, so the duplicate remains queued between attempts. This
proof observes repeated attempts without extra records; it does not wait for
retry exhaustion or approval expiry.

An approved citizen reads the enrollment through BReg's current account link.
No ThunderID claim change is needed after approval. An operator can deactivate
the link, after which the same previously issued token loses enrollment access.

## Run the live proof

Requirements: Docker, Rust, `uv`, and a checkout whose BReg and Casework binaries
come from the same source revision. The native development tools own two
disposable TLS PostgreSQL databases and the pinned ThunderID container. The
runner does not use an existing deployment or database.

From the repository root:

```sh
cargo build --locked \
  -p registry-breg --features runtime -p registry-bregctl \
  -p registry-casework -p registry-caseworkctl --bins

PYTHONDONTWRITEBYTECODE=1 uv run --no-project --with PyYAML==6.0.2 python \
  products/breg/acceptance/citizen-self-registration/tests/run-live.py \
  --breg target/debug/breg \
  --bregctl target/debug/bregctl \
  --casework target/debug/casework \
  --caseworkctl target/debug/caseworkctl
```

For a macOS source build that needs the FIPS dynamic library, supply
`--library-directory` with the directory containing the build's
`libaws_lc_fips_*_crypto.dylib`. Managed worktrees should also use the build
settings in the repository's `AGENTS.md`.

The runner creates an owner-only temporary directory, chooses unused ports,
generates fresh secrets, materializes both projects, and uses the native
development lifecycle to compile, rehearse, package, migrate, and activate
them. It installs the declarative citizen SMS flows while the isolated issuer
is stopped, then restarts it. Staff review uses a native password login through
`registration-console`; citizens use authorization code with PKCE and SMS OTP
through `citizen-portal`.

The SMS delivery endpoint is a local test transport. The real issuer generates
and verifies OTPs, creates accounts, assigns the fixed applicant role, and issues
tokens. The test transport receives rendered messages in memory. It does not
prove delivery to a real phone or a production SMS provider. See
[native identity setup](identity/README.md) for the declarative flows and scope
boundaries, and [Casework setup](casework/README.md) for source generation,
webhook authentication, and review configuration.

On success, the runner exits zero and writes `result.json` with binary versions,
the source commit, the pinned issuer, the activated package digest, and individual
checkpoints. Logs and private service state stay outside the repository. By
default, the runner stops and removes its disposable services and databases.
`--keep-state` stops them while retaining private state for diagnosis;
`--output /absolute/absent/path` chooses its private directory.

## Assertions

The live driver exercises the following through public APIs:

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
It does not stand in for citizen or staff authentication; those assertions run
against real interactive tokens in `tests/live_journey.py`.

## Scope and remaining work

This is the backend acceptance example for
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
