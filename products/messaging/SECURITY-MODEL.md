# Registry Messaging security model

This document states what Messaging's security boundaries hold, what an
operator must do for them to hold, and which residual risks are accepted. The
row-per-invariant baseline is
[`contracts/security-invariant-matrix.yaml`](contracts/security-invariant-matrix.yaml)
(`MESSAGING-SEC-01` to `-11`); each row names its enforcement and tests. This
file does not repeat the rows.

## 1. Scope and trust boundaries

Messaging accepts a message from an authenticated caller, renders it from a
reviewed template or permitted direct content, and sends it through a provider
the operator configured. It stores the message, its dispatch state, and
provider delivery reports in PostgreSQL.

**Callers.** There is no unauthenticated mode. Every `/v1` route except the
provider callback routes resolves its caller first. A credential is an RFC 9068
access token from the configured issuer and audience, from a client in
`authentication.oidc.allowedClients`, signed by a published or static key. An
exchanged token is refused unless `assertionIssuers` declares its authority.
`allowedClients: unrestricted` is refused in every mode, because an access
profile resolves from the matched client. A refused or malformed credential,
or one whose verified claims do not resolve to a client, is
`401 authentication.refused` with a `WWW-Authenticate: Bearer` challenge. A
credential that verifies but resolves to no usable access profile (including an
exchanged token when `assertionIssuers` declares no authority) is
`403 profile.not-authorized`. A verifier that cannot reach a verdict, because
the issuer's discovery document or key set cannot be fetched, read or used, is
`503 service.unavailable` with `Retry-After: 5`; the credential is not what is
wrong, so a caller should retry rather than rotate it. Causes inside each
status are told apart only by value-free metric reasons and rate-limited log
stage labels. A client listed in two access
profiles is refused when the package loads, and a profile must state its
scopes or write `unrestricted`. (MESSAGING-SEC-01, -04)

**Authorization.** It is decided against the one access profile the verified
client resolves to, never against raw claims. A sender submits only through the
sender profiles and templates its profile lists, and direct content only where
`allowDirectContent` is set. Operators never submit. A message is visible to
the principal that submitted it (same issuer and subject) and to operator
profiles; a missing message answers exactly like an invisible one, so an
identifier cannot be probed. A replay is authorized and rendered again against
the active package before the stored receipt is returned, so a key cannot
outlive the caller's authority.

**Provider callbacks.** They carry no bearer token. Each is authenticated by
the verifier its provider's runtime configuration names (`hmac-sha1-url-form`,
`hmac-sha256-body`, or `path-token`; there is no `none`). Every cause of
refusal answers `403 callback.unverified`, so the route does not reveal which
providers receive callbacks. It is 403 rather than 401 because a provider
cannot answer a challenge. A callback changes a message only forward, and
only for the message whose provider reference the accepting attempt stored,
scoped to that provider. (MESSAGING-SEC-07)

**Providers.** HTTP and SMTP providers are trusted to receive what the operator
sends them and nothing else. HTTP sends only through the platform
fixed-destination substrate: no userinfo, query, fragment or dot segment in the
base URL, no redirects, and loopback, private, shared, link-local and metadata
addresses refused unless an exact `allowedPrivateCidrs` entry admits them.
Scripts choose a relative target, declared header values, and a body; they
never see a credential, the base URL, or a runtime-owned header, and run with
an operation budget, the send deadline, and no `import`, `eval`, `print` or
`debug`. SMTP requires `STARTTLS` or implicit TLS, verifies the certificate
against the configured host name, sends no credential to a relay that does not
offer `STARTTLS`, and cannot have a header line opened from template data.
Plain `http` and `development-loopback` SMTP are limited to loopback; a
production listener posture refuses plaintext SMTP at `messagingctl check` and
at startup. (MESSAGING-SEC-03)

**Templates.** They come only from the package digested at startup and render
in an empty `minijinja` environment (no loader, macros, filters, globals, file,
network or clock access), bounded by fuel, recursion and per-part output size.
HTML escapes every value and ignores a template's own `autoescape` block. A
locale the version does not declare is refused, never answered in another
language. (MESSAGING-SEC-09)

**The package and database.** A package carries a checksum envelope and is
pinned by digest; symbolic links, unknown files and oversized files are
refused. `messaging serve` refuses unless the active ledger row matches the
configured deployment and installed package, and `/ready` stops passing if the
database identity, digest, schema, role grants or audit writer health change.
In split-role mode the runtime credential cannot write either ledger or own
Messaging objects; the migration credential holder is trusted to change them.
PostgreSQL 17 or newer is required, and the server version is checked before
any migration or activation write. A shipped runtime refuses
`database.testOnlyPlaintext: true`, so database traffic is TLS.

**Audit and logs.** Records carry the operation, caller pseudonym, sender
profile, template reference, correlation, outcome class and a keyed recipient
reference. They never carry a contact, rendered part, template data,
credential or provider reference. Metric labels are closed sets fixed in code,
and `MESSAGING_LOG` accepts only `error`, `warn` or `info`. Authentication and
access-profile refusals, duplicate or no-op callbacks and reads (the status
route, `messagingctl messages list` and `show`) are not journaled: a refusal is
counted on the private metrics listener, and a message view releases no
contact, part or data. (MESSAGING-SEC-08)

**Dispatch.** The worker holds a lease and every outcome write names the lease
and generation, so a stale worker changes nothing. A send that may have reached
the provider stops the message as `unknown` rather than retrying, unless the
sender profile sets `onUncertain: retry`, which the package accepts only over a
provider that declares `idempotentSubmit` or a profile that sets
`acceptDuplicates`. A cancel and a claim serialize on the job row; a message
whose current attempt may have reached the provider is refused
`409 message.dispatch-started`. (MESSAGING-SEC-05, -06)

**Operator tooling.** `messagingctl messages retry`, `settle` and `cancel`
preview and change nothing without `--apply`, recheck status in the changing
transaction, and write an `operator-tool` audit record. `list` and `show` mask
the recipient and never print a part, template data or the submitter's subject.
`messagingctl check` reads no database, network or secret.

**Listeners.** The public listener refuses a public unicast bind in every
setting. `/metrics` is served only on `metricsListener`, a concrete loopback or
private address that cannot share the public socket.

**Configuration and secrets.** Every mapping is closed and an unknown, removed
or retired key is refused with its path, so an old file cannot fall back to a
default. Credentials are `secret:env/NAME` or `secret:file/name` references in
`...Ref` members, resolved once at startup before a listener binds. `${VAR}`
expansion cannot reach a `Ref` member or alter document structure. No
diagnostic repeats a value read from the file or environment.

## 2. Operator obligations

The invariants above hold only if the deployment does the following.

1. **Require provider idempotency, or accept duplicates deliberately.** Set
   `onUncertain: retry` only over a provider that declares `idempotentSubmit`,
   or on a profile that sets `acceptDuplicates`. Messaging cannot make a
   provider deduplicate. The capability is stored with each accepted message,
   so removing it from a later package does not withdraw the key from a retry
   already accepted.
2. **Drain senders before narrowing a package or profile.** An exact retry
   refused `403` or `422` after such a change proves nothing about the first
   attempt, which may have been accepted and may still be sending.
3. **Apply a new package digest explicitly, then restart.** A new digest is
   served only after restart. Copy installed packages into place; symlink
   mounts (for example ConfigMap volumes) are refused.
4. **Run split database roles in production** and migrate with the migration
   credential only.
5. **Put an edge proxy in front of the public listener** that bounds request
   rates and authenticated floods (see MESSAGING-RES-02).
6. **Ship audit to storage you control.** Messaging fsyncs file acceptance but
   does not chain, sign, aggregate or archive audit segments. Tamper evidence
   and retention beyond local `retentionDays` are yours, and off-host shipping
   must precede local expiry. Keep the runtime stream and the `messagingctl`
   stream; there is no total order across process streams and no audit outbox
   replay.
7. **Tell callers to choose random idempotency keys.** The API reference says
   so; the confidentiality of a spent key depends on it (MESSAGING-RES-01).
8. **Set `principalClaim: sub`** on any caller profile that must be bound to
   its issuer and subject when it observes an original receipt. Other profiles
   keep the configured principal ownership rule.
9. **Name `scopeClaim` explicitly** if your issuer puts different scopes in
   `scope` and another claim. Messaging reads exactly one claim, `scope` by
   default, and a scope refusal logs the configured claim, the first missing
   scope and the access profile, never token contents.
10. **Set `allowedPrivateCidrs` only for relays and providers you run,** and
    treat `allowInsecureHttp: true` as a loopback or test setting; startup
    warns when it is set. With it, an attacker on the network path to the
    issuer can substitute keys. Declare only issuer and JWKS addresses you
    intend Messaging to reach, because a declared private address is trusted on
    your word (MESSAGING-RES-09).
11. **For AWS SMS, provide the IAM authority, origination registration and
    secret rotation yourself.** Temporary credentials are loaded at activation
    and need replacing and a restart before they expire. The adapter declares
    no provider idempotency and no delivery receipts, so an ambiguous failure
    holds the message as `unknown`; settle or retry it with `messagingctl`.
12. **Rotating `audit.hashKeyRef` changes pseudonyms only.** It frees no spent
    idempotency key, so an exact retry across a rotation replays its receipt or
    is refused as expired, and never sends again.
13. **Drain or cancel queued and retrying messages before a provider id
    points at a different account or receiver.** The worker looks up the
    transport by the provider id stored on the message each time it sends, and
    callbacks match on provider id plus reference. A message accepted for the
    old receiver is therefore sent, and retried, through whatever the id names
    when the worker picks it up, and a report from the new account can match an
    older message under the same id. Messaging stores no receiver digest and
    has no rebind command. Give an incompatible receiver a new provider id and
    keep the old one configured until its queued, `unknown` and retained
    callback work has settled; or drain or cancel those messages first. Same
    receiver credential rotation needs none of this.

## 3. Accepted residuals

Each residual states the condition, the consequence, the operator mitigation
and the related matrix rows.

### MESSAGING-RES-01: spent idempotency keys are confirmable from an unkeyed digest

- **Condition.** A spent key is found under `key_reference`, an unkeyed SHA-256
  over a fixed domain and the length-prefixed issuer, subject, operation and
  key. The digest is unkeyed on purpose: a keyed digest would let an audit-key
  rotation free every spent key and so allow duplicate sends.
- **Consequence.** Anyone who can read the table and can guess a caller's
  issuer, subject and key can confirm that the caller spent that key. The row
  also holds the raw issuer, subject and key while its receipt stands, and
  under some access profiles the subject may identify a person (for example a
  staff email address). Retention erases all three when the receipt is erased
  after `receiptRetentionDays` (a schema constraint holds them together); the
  digest then stays until `recordRetentionDays`, so the key stays spent for that
  caller alone.
- **Mitigation.** Callers use random keys. Restrict read access to the
  database. Keep `receiptRetentionDays` short.
- **Related.** MESSAGING-SEC-02, -08, -11.

### MESSAGING-RES-02: floods of refused or authenticated requests grow the journal

- **Condition.** A caller sending past its rate, or repeating original-receipt
  observation, still makes the runtime authenticate each request and write one
  journal record. The body limit bounds each request; nothing bounds journal
  growth from the flood. The per-caller token bucket is in process: each
  replica enforces its own, and a restart refills it. `maximumMessagesPerDay`
  is stored-count based and holds across restarts and replicas.
- **Consequence.** Disk growth and verification work, not data exposure.
  Receipt observation is deliberately outside the submission budget so that
  exhausting that budget never prevents recovering an already accepted command.
- **Mitigation.** Bound request rates at the edge proxy.
- **Related.** MESSAGING-SEC-01, -02, -08.

### MESSAGING-RES-03: a callback can arrive before it can match, and some never match

- **Condition.** A callback that arrives before the accepting attempt commits
  finds no reference. A message held as `unknown` after a maybe-sent attempt
  stores no reference, so no receipt can settle it. A reference shared by two
  messages is applied to neither. A reference over 128 bytes is not stored and
  never matches.
- **Consequence.** The report stays where it was, or the callback is counted
  `unmatched` or `ambiguous` and answers 204 so the provider does not retry.
  A genuine report may be lost unless the provider repeats it.
- **Mitigation.** Use providers that repeat callbacks; settle `unknown`
  messages with `messagingctl messages settle`.
- **Related.** MESSAGING-SEC-07.

### MESSAGING-RES-04: callback verification has no replay window and spends a per-process budget

- **Condition.** None of the three verifier kinds signs a timestamp, so no
  replay window can be enforced. A replayed genuine callback repeats a report
  the message already holds or has passed, so it changes nothing and is not
  stored or audited again. The callback rate (6000 a minute, burst 600) is
  charged before verification, per provider and per process, and is not
  configurable. `hmac-sha1-url-form` uses HMAC-SHA1 as a MAC (SHA-1's collision
  weakness does not apply) because a widely deployed provider signs with it,
  and verifies over the configured external `url`, so a wrong `url` refuses
  every callback.
- **Consequence.** Anyone who knows a provider's id can spend that provider's
  budget and delay its genuine callbacks, which the provider retries; separate
  buckets keep the flood from delaying another provider. A provider reporting
  faster than 100 a second is refused in bursts.
- **Mitigation.** Rate-limit the callback path at the edge; configure the
  external `url` exactly as the provider signs it.
- **Related.** MESSAGING-SEC-07.

### MESSAGING-RES-05: template rendering can briefly allocate up to a multiple of the data size

- **Condition.** The fuel budget counts instructions, not bytes, so an
  expression such as string repetition can allocate up to the data's size
  multiplied by one factor before the per-part output ceiling refuses it.
  `{% autoescape false %}` is accepted by the parser and has no effect. The
  loader reads each file after listing the directory, so a file swapped
  between the two reads is caught only by the digest the ledger compares.
- **Consequence.** Bounded memory pressure per render; no escape change; a
  swapped package file is refused at activation by digest mismatch.
- **Mitigation.** The request body limit bounds the data; keep the package
  directory writable only by the deployer.
- **Related.** MESSAGING-SEC-09.

### MESSAGING-RES-06: HTTP provider address checks and script placement

- **Condition.** The test suite cannot inject a resolver; it proves refusal
  with a name that resolves to loopback and with literal private and metadata
  addresses, and the substrate's own tests cover an answer that changes between
  resolutions. Provider scripts run on the async runtime thread within the send
  deadline. The OAuth token decoder is closed (`access_token`, `token_type`
  `Bearer`, `expires_in` unless `assumedLifetimeSeconds` is set, optional
  `scope`) and refuses any other member, so the send is transient. Plain `http`
  to a loopback host is accepted by every build. A 2xx the interpret script
  cannot classify is `maybe-sent`, never accepted.
- **Consequence.** A script can occupy its thread until the send deadline; an
  unexpected token response fails the send as transient.
- **Mitigation.** Review provider scripts before promotion; pass package
  activation and example evaluation. Keep production base URLs on `https`.
- **Related.** MESSAGING-SEC-03.

### MESSAGING-RES-07: SMTP credentials are not zeroized

- **Condition.** lettre's `Credentials` holds the username and password as
  plain `String` values that are not zeroized on drop, unlike the runtime's own
  protected secrets. They live for the life of the process. The EHLO name is
  lettre's address literal `[127.0.0.1]` and is not configurable.
- **Consequence.** A process memory dump can reveal the relay credential. A
  relay that checks the EHLO name may refuse the session.
- **Mitigation.** Restrict who can dump runtime memory (no debugger or core
  dump access); use a relay credential scoped to Messaging alone.
- **Related.** MESSAGING-SEC-03, -08.

### MESSAGING-RES-08: retention depends on batch completion and audit expiry is separate

- **Condition.** An applied retention run erases in batches of at most 1,000
  of each kind under a five-second lock timeout and a sixty-second statement
  timeout. A batch that exceeds either is rolled back whole. Audit segment
  retention is independent of payload and record erasure.
- **Consequence.** A backlog stalls only when one batch of 1,000 cannot
  complete in sixty seconds; payloads then outlive `payloadRetentionDays` until
  it can. Audit segments can outlive or predate the data they describe.
- **Mitigation.** Watch `messaging_retention_runs_total{outcome="failed"}`;
  ship audit off host before local expiry.
- **Related.** MESSAGING-SEC-10, -11.

### MESSAGING-RES-09: declared issuer and key endpoints are trusted

- **Condition.** The runtime file names an issuer or JWKS URI, or sets
  `authentication.oidc.allowInsecureHttp: true`.
- **Consequence.** A declared issuer or JWKS URI may name any private address
  that is not cloud metadata or link-local; the operator who writes the file is
  trusted to name it. A discovered key endpoint on another origin stays under
  the strict public-network policy and must use HTTPS, and redirects are
  disabled. Under `allowInsecureHttp: true`, an attacker on the network path to
  the issuer can substitute keys and so mint tokens Messaging accepts. Startup
  logs a fixed warning when the setting is on.
- **Mitigation.** Use an HTTPS issuer; leave `allowInsecureHttp` unset; or pin
  keys with a static `jwksSource`.
- **Related.** MESSAGING-SEC-01.

## 4. Development tooling

`messagingctl dev` is for a developer's machine. It publishes PostgreSQL and
Mailpit on 127.0.0.1 only, runs the runtime on a `development-loopback`
listener (refused on any non-loopback bind), and writes every generated secret
owner-only (files 0600 under 0700 directories, never through a symbolic link)
in `.messaging/dev`, which `.messaging/.gitignore` keeps out of version
control. No secret is placed on a command line. The database serves TLS and
SCRAM and the runtime connects with the least-privilege role, as in
production. A session token is signed with the session's own ES256 key and
expires in an hour. With `--issuer-project OWNER --resource URI` the session
borrows a ready BReg development issuer through the public
`bregctl dev export-client` command; Messaging never starts, stops or resets
that issuer. `messagingctl api` takes its destination only from the loopback
origin in the session record, follows no redirects, ignores ambient proxy
settings and owns the `Host` and `Authorization` headers (see the
[`registry-cli-api` security boundary](../../crates/registry-cli-api/README.md#security-boundary));
the runtime still authorizes every protected route.

Residuals: the audit journal and log of the last session stay in
`.messaging/dev` until the next start (neither carries a payload value). A
session killed with SIGKILL leaves its containers running until the next start
in the same project removes them. A borrowed session keeps each exported
client assertion key in an owner-only file until the next start replaces the
session directory, and a `dev token` killed before it returns can leave a
second owner-only copy under `.messaging/dev/.client-check-*`. These are
development keys for a loopback issuer only.

## 5. Reporting

Report a suspected vulnerability as described in [`SECURITY.md`](../../SECURITY.md).
