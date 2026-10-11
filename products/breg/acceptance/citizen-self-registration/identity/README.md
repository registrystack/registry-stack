# Native citizen identity

This directory adds the native ThunderID resources used by the live citizen
self-registration acceptance journey. It keeps the generated `citizen-portal`
OAuth client and its secret, then selects native SMS authentication and
registration flows for that application.

Keep `subjectAttribute` absent. In the pinned ThunderID 1.0.1 flow, `sub`
defaults to the persisted native entity UUID. SMS authentication identifies the
existing entity through its unique phone attribute, and authorization code
exchange carries the same UUID into the access token. The live journey asserts
that signup and later login return the same subject. BReg uses this verified
subject for application ownership; no editable profile attribute supplies the
account key.

The owner BReg project must declare `citizen-portal` before its first dev
start. BReg uses that declaration both for its trusted-client allowlist and for
the issuer's application role. A client created only after BReg starts would
still be refused by BReg.

ThunderID 1.0.1 treats the generated application as a declarative resource and
refuses attempts to change it through the administration API. Use retained
state in this order:

1. Start the owner `bregctl dev` session once so it renders and bootstraps the
   issuer state.
2. Stop the session without reset.
3. Construct `NativeIdentity` with the owner project, the generated
   `.breg/dev/issuer/secrets` directory, the host SMS sink URL, and the exact
   BReg audience. Call `bootstrap()`.
4. Restart the owner session.

`bootstrap()` is idempotent and refuses to run while the issuer is reachable.
It resolves the resource-server ID from the configured audience instead of
assuming a generated ID. It places the SMS gateway connection in
`.breg/dev/issuer/registry-schema/connections`, which the restart's existing
bootstrap one-shot imports into ThunderID's mutable notification-sender store.
The issuer deliberately keeps the global
`declarative_resources` mode disabled and enables only narrow per-service
stores, so a gateway placed under `resources/connections` would not be visible
to `SMSExecutor`. The bootstrap writer omits a leading YAML document marker
because ThunderID's recursive bundle loader inserts separators between files.

`signup(phone, otp_for)` and `login(phone, otp_for)` perform a real OAuth 2.0
authorization-code exchange with PKCE. The callback receives the phone number
and returns the next OTP observed by the host SMS sink. ThunderID's custom SMS
transport sends the rendered message body without its resolved recipient, so
the test sink consumes one delivery at a time while the caller drives each phone
flow sequentially. Passing a deliberately wrong callback result exercises OTP
refusal before the provisioning node, so no account or role is created.
Transport failures identify the bounded native stage, such as flow selection,
OTP delivery, or OTP verification, without including submitted inputs, OTPs,
tokens, or response payloads in the exception.

`refuses_staff_scope(phone, otp_for)` performs another native SMS login through
`citizen-portal`, requests only `registration:casework-admin`, and returns true
only when the issuer refuses that OAuth scope or the issued access token has no
staff scope. This probe deliberately bypasses the helper's normal fixed citizen
scope request so it tests ThunderID's authorization boundary. Expected OAuth
scope errors are handled by their sanitized error code; a redirect that merely
omits `authId` remains an identity setup error.

The provisioning node assigns the fixed citizen role natively. That role has
only `registration:self` and `registration:read`; the second scope gives an
approved account the capability needed by the member profile, while BReg's
membership boundary still refuses it before approval. The browser application
and the user must both hold these permissions before ThunderID grants them.

The citizen helper never accepts an actor-kind argument. It supplies `human`
through a hidden flow input, and both the native flow validation and Citizen
schema allow only that exact value. The resulting access token is checked for
the fixed marker, audience, client, subject, and exact requested scopes before
it is returned.
