# Registry Document Store changelog

## Unreleased

- BREAKING: Rust client configurations take a peer policy in `DocumentsClientConfig::new`. Migration: pass `PeerPolicy::AcceptDevelopmentPeer` in application code and the runtime's policy in runtimes.

- Document Store accepts development S3 and content-verifier responses when the runtime declares development.

- Under `database.transport: loopback-plaintext` or `private-network-plaintext`, the database connection goes to the numeric addresses its host check accepted at startup. A host name such as `localhost` is no longer looked up again for each connection, so a later, different answer cannot send the connection to an address that was not checked.
- Under `database.transport: loopback-plaintext` or `private-network-plaintext`, a keyword connection string host written as an IP address in brackets, such as `host=[::1]` or `host=[127.0.0.1]`, is skipped when the transport otherwise permits it and the driver would dial it, as the driver itself fails that entry and tries the next. When no other host is left, the connection is refused when it is configured, with `platform.database.bracketed-host` naming the address. Write `host=::1`. When a keyword host has an authored `hostaddr`, the connection still uses that `hostaddr`. A bracketed IPv6 address in a URL, such as `postgresql://app@[::1]/registry`, still works.

- Start a local development run from the starter with `rstack dev start`.

- A reservation may omit `custodian` when the caller is a person: the document is
  held in that person's own custody, as if the body had named their own subject.
  A service must still name the custodian and is refused `request.unprocessable`
  without one. The OpenAPI `ReserveDocumentRequest` no longer requires
  `custodian`.
- Development Document Store hook captures include `"posture":"development"` in the signed canonical body. Production capture and replay of unmarked deliveries keep their original wire form. A production worker dead-letters a retained development-marked envelope with `payload-refused` before sending.
- BREAKING: The runtime accepts access tokens from several issuers. The issuer
  members move under `authentication.oidc.issuers.ISSUER_ID`, one entry per
  issuer: `issuer`, `audience`, `jwksSource`, `allowInsecureHttp`,
  `allowedClients`, `assertionIssuers` and `scopeClaim`. The old flat members
  under `authentication.oidc` are refused with the entry they move under. A
  client belongs to one entry, and two entries that name one issuer are
  refused. The same subject at two issuers is two callers. Custody a service
  places, and a grant's recipient, are scoped to the caller's issuer entry: a
  person who signs in through another entry does not see them.
  Migration: Wrap the members of `authentication.oidc` in `issuers.main`, then run `documentsctl check`.

- BREAKING: An access token typed `JWT` is refused unless the issuer entry sets `accessTokenType: JWT`. Under either type an ID token is refused, and a resolved package client equal to the audience is refused under `JWT`.
  Migration: Set `accessTokenType: JWT` on the entry of an issuer that types its access tokens `JWT`.

- BREAKING: A token that grants only OpenID Connect scopes, or none, is refused at authentication unless the issuer entry or the client declares an actor kind. A kind the token claims does not exempt it. Every access profile requires a scope, so such a token used to be refused with 403 `profile.not-authorized` and is now refused with 401 `authentication.refused`.
  Migration: Declare `actorKind` or `clientActorKinds` on the issuer entry, or issue tokens that carry the scopes the access profile requires.

- An issuer entry can declare the actor kind of its tokens with `actorKind`, or of each client's tokens with `clientActorKinds`. A token that names another kind than the declared one is refused. A caller with no kind is refused by every access profile with 403, because every profile pins a kind.

- A refusal in development carries `failedCheck` in the problem body, naming the check that failed. Production answers are unchanged.

- `documentsctl generate identity-facts PROJECT --runtime-config FILE --output FILE` writes the identity facts one issuer entry states. With more than one entry, `--issuer ISSUER_ID` names it, and a missing or unknown id is refused with `identity.facts.issuer-required` or `identity.facts.unknown-issuer`.

- `documentsctl check` reports `explicitProductionSettings`, right after `posture`: each explicit setting of the runtime file that is valid in every posture and worth a reviewer's attention, such as `accessTokenType: JWT` or a non-default `scopeClaim`.

- Startup refuses a hook destination's URL, transport or private range with
  the code and pointer `documentsctl check` reports, such as `config.invalid-value:
  /destinations/hooks/owning-system-events/url: ...` for `https://localhost.:9443/hooks`.
  Before, startup said only that a hook destination binding was invalid.
  BREAKING (Rust API): `HookActivationError` gains `DestinationRefused`,
  `HookActivationError::code` is no longer `const` and returns
  `Option<&str>`, and the new `HookActivationError::pointer` gives the
  refused member's pointer.

- A `destinations.hooks` URL over https to a loopback address literal or the
  exact name `localhost`, such as `https://localhost:9443/hooks`, now
  activates and delivers. Before, `https://localhost` was refused at startup
  and an https loopback literal failed at every delivery. `localhost` is
  delivered to only when every address it resolves to is loopback.
- `documentsctl check` runs the shared hook destination check on each
  `destinations.hooks` entry, so it refuses what startup refuses, at the
  destination's own pointer. For example, `https://localhost.:9443/hooks`
  or a name under `localhost` is now refused by the check with
  `config.invalid-value` at `/destinations/hooks/<id>/url`. Before, it
  passed the check and was refused at startup. A refusal the check already
  reports at that member, such as `documents.runtime.insecure-url`, keeps
  its code.
- BREAKING: an S3 `storage` URL or an http `contentVerification` URL over
  https whose host name answers a loopback, link-local, `0.0.0.0` or cloud
  metadata address is now refused at every request, so document uploads,
  reads and verification fail. Before, such a name was followed wherever it
  answered. An https URL whose host is a cloud metadata or always-denied
  address literal is refused at startup. To reach a store or a verifier on
  the same host, write `https://localhost:<port>` or a loopback literal such
  as `https://127.0.0.1:<port>`, both admitted. `http://localhost` is now
  accepted beside the loopback literals.
  An https URL whose address literal, or an address its name answers, is an
  IPv4-compatible (`::/96`) or 6to4 (`2002::/16`) IPv6 address carrying a
  loopback, link-local, `0.0.0.0` or cloud metadata IPv4 address is now
  refused. To migrate, write the store's or verifier's own IPv4 or native
  IPv6 address, or a name that answers one.

- BREAKING: Document Store hook deliveries use Standard Webhooks. Each POST
  carries `accept`, `content-type`, `webhook-id`, `webhook-timestamp` and
  `webhook-signature`. The signature covers `webhook-id`, the attempt
  timestamp and the exact body bytes. `webhook-id` equals the envelope `id` and
  stays the same on every retry. The Version 1 headers and `Idempotency-Key`
  are no longer sent. A receiver verifies the signature, checks a 300-second
  window, parses the body and compares the envelope `id` with `webhook-id`.
  See [Receive signed deliveries](https://docs.registrystack.org/reference/delivery-signing/).
- Each `destinations.hooks.<id>.hmacSha256KeyRef` must resolve to 32 to 64
  exact bytes. Startup refuses a longer key, a key that starts with `whsec_`,
  an unavailable key, and two destinations that share key bytes. The refusal
  names the full `destinations.hooks.<id>.<member>` paths and never a key
  byte. A trailing newline counts as a key byte, so write a key with
  `openssl rand -hex 32 | tr -d '\n' > key`.
- During rotation, set `destinations.hooks.<id>.previousHmacSha256KeyRef`. The
  Document Store signs with both keys, current first, including retried
  deliveries. The previous reference is outside the binding a pending delivery
  pins. Startup refuses a previous key equal to the current key.

- Activation refusals name their path as a JSON pointer, such as `/database/runtimeUrlRef`, `/identity/databaseId` and `/arguments`. Earlier releases used dotted names for some.

- BREAKING: An undeclared posture is production.
  Migration: Set REGISTRY_STACK_POSTURE=development for laptop and test runs; rstack dev sets it for you.

- BREAKING: `check` reports development settings as errors under the production default.
  Migration: Pass --posture development, or set REGISTRY_STACK_POSTURE, when checking a laptop file.

- BREAKING: Use `loopback-plaintext` for loopback listener placement.
  Migration: Set `tlsTermination` to `loopback-plaintext` for a listener behind a TLS proxy on the same host.

- BREAKING: Issuer `allowInsecureHttp: true` requires development.
  Migration: Delete allowInsecureHttp where the issuer is on loopback: no setting is needed in any posture.

- Development deployments can now set `database.transport` to `private-network-plaintext` for PostgreSQL on the private network.

- BREAKING: Non-loopback HTTP hook receivers are refused in every posture, including with a `development-loopback` listener.
  Migration: Use an HTTPS receiver or a receiver on this host.

- Loopback HTTP storage, content verifier, hook and issuer URLs are accepted in either posture. Non-loopback storage, content verifier and hook URLs require HTTPS. A non-loopback HTTP issuer requires an explicit development opt-in.

- PostgreSQL on the same host can now use `database.transport: loopback-plaintext` in either posture.

- BREAKING: Activation records the declared posture. Startup, plan and apply refuse a different posture. Status reports a finding. Existing rows read production.
  Migration: Recreate development databases: a fresh apply is the way.

- BREAKING: `/ready` returns a JSON object with `posture` and `developmentSettings`.
  Migration: No change for probes that read the status code.

- BREAKING: Audit lines carry `posture`.
  Migration: Audit readers with a closed line parser accept the posture member.

- Development responses carry `Registry-Posture: development`. The Document Store Rust client refuses that mark.

- BREAKING: `contentVerification: {type: disabled}` requires development.
  Migration: Declare development to keep contentVerification: disabled, or configure a verifier.

- BREAKING: `documents.posture.content-verification-disabled` and `platform.database.test-only-plaintext` replace the corresponding runtime refusal codes.
  Migration: Update scripts that match the old codes.

- An issuer entry's `allowedClients` accepts the keyword `from-package`,
  which admits the requester clients of the package's access profiles, so the
  clients are written once, in the package. The member stays required, and an
  omitted member, an empty list and `unrestricted` are still refused. A list
  must now include every client a profile names, or startup is refused with
  `documents.runtime.profile-client-not-allowed`, where before the runtime
  started and the missing client failed at run time. A client named under
  `assertionIssuers` must be an admitted client, or startup is refused with
  `documents.runtime.assertion-issuer-client-not-allowed`.

- The Document Store counts every refused request by the check that refused
  it, in `documents_request_refusals_total{check}` on the metrics listener,
  published at zero for every check. Each refusal writes one `request refused`
  line with `failed_check`, at most five lines per check per minute. A scope
  refusal's line also names the scope claim the deployment configured, the
  scope the access profile requires and the profile's id, as `scope_claim`,
  `required_scope` and `access_profile`, and carries a fixed remedy that names
  `scopeClaim` on the issuer entry. No value from the token is written.
  Refusal statuses, headers and bodies are unchanged.
- A static key set with a private key member or a repeated member name is
  refused at startup, and the error names the rule it broke, and the key's
  position for a rule about one key, never a key value.
- A token verifier that cannot fetch, read or use its key set still answers
  503. A key endpoint the verifier refuses to contact answers the refusal a bad
  credential gets, with its `WWW-Authenticate` header. The operator's record of
  either is the `request refused` line with `failed_check`
  `key-source-unavailable` and the counter, not a warning per request, so
  `DOCUMENTS_LOG=warn` writes no line for it.
- A caller that sees a document and does not hold custody of it is counted
  under `ownership` when it lists or issues grants, as it is when it downloads
  or requests erasure. A custodian without grant authority is counted under
  `operation`. The answer is unchanged.
- `documentsctl provision` creates the migration and runtime login roles and
  the database that the runtime file's two database URLs name, grants both roles
  `CONNECT`, gives the migration role `USAGE` and `CREATE` on the `public`
  schema and the runtime role `USAGE` on it, from a PostgreSQL administrator
  URL. Running it again restores the runtime role's `USAGE`. It creates only
  what is missing,
  refuses a role whose password differs from its URL, refuses an administrator
  URL that names another host or port than the product URLs, and with
  `--print-sql` prints the script without connecting or printing a password.
  `documentsctl apply` still grants the runtime role what serving needs.

- The Rust Documents client accepts a `/health` answer with an empty body or a
  JSON object body of at most 4096 bytes, and ignores the object's members. A
  larger body, or a body that is not a JSON object, is still a body protocol
  failure.

- Accept an optional `project.label` and `project.description` in the project
  block, as the shared project block does. They are display text for
  people and change no compiled output.

- BREAKING: in the runtime configuration, `database.trustedRootCertificateRef` -> `database.caBundleRef`, as a pre-1.0 cleanup, to match the `caBundleRef` the other TLS blocks use. The old key is refused as an unknown key. The value is unchanged: a secret reference to the PEM CA bundle the connection trusts.

- Serve Prometheus metrics on an optional operator-private listener. Set
  `metricsListener.bind` in `runtime.yaml` to a loopback or private address,
  distinct from the serving listener. It is off by default, and the serving
  listener never answers `/metrics`. The series report content verification,
  erasure and hook delivery jobs by state, the age of the oldest overdue item
  of each, the last success of the cleanup pass, and requests by route and
  status class. A failed sample is logged and counted in
  `documents_metrics_sample_failures_total` and its gauges are left out, never
  reported as zero.
- The metrics listener accepts `metricsListener.networkExposure`. Set
  `metricsListener.networkExposure: container-private` to also allow the
  unspecified address (for example `0.0.0.0`), for a container whose network
  is private to the deployment. The default, `private-address`, keeps the
  loopback-or-private rule.

- Each access profile may carry an optional `label` and `description`, accepted for authoring and tooling; the Document Store does not serve them until a view exists. Neither is matched against a caller, and a profile that writes neither reads as before.

- BREAKING: Document Store access profiles rename `role` to `actsAs`; the values are unchanged; the schema definition `AccessRole` is now `ActsAs`. Migration: in each `accessProfiles` entry, write `actsAs: VALUE` where the file wrote `role: VALUE`. A file that still writes `role` is refused with `config.removed-key` naming `actsAs`.

- BREAKING: A runtime configuration file is refused with
  `platform.runtime-config.unsafe-file` when it or an ancestor directory is not
  owned by root or the runtime user, or is writable by group or others. A
  root-owned sticky ancestor stays allowed.
- Adopt the shared platform implementations for the access-token algorithm
  roster (still exactly RS256 and ES256), framework-rejection normalization
  (400, 413, 415 and 422 answer the same `request.*` problem codes) and the
  stop signal. `serve` refuses startup with the signal error when a stop-signal
  handler cannot be installed; SIGINT is now installed at startup alongside
  SIGTERM.

Initial scope of the Document Store: custody of document bytes for an owning
system, exact-version document grants, content verification before release,
scheduled erasure, and after-commit document events, served over `/v1/` with
`documentsctl` for operators. The product is held out of releases until it is
published. Under citizen delivery the reserving system sees a document's
metadata and status only: it cannot grant, read the bytes, or list the grants
(`GET /v1/documents/{documentId}/grants` is the custodian's alone and answers
the reserving system `profile.not-authorized`), so the issuer never learns
whom the citizen shared with.

`documentsctl check --project` reads an optional `check-acceptances.yaml`,
keeps exactly matched warnings visible with their reasons, and excludes only
those accepted warnings from `--deny-warnings`.
