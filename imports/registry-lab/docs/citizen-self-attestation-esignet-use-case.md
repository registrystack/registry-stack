# eSignet Citizen Self-Attestation Use Case

## Goal

A citizen can request a Registry Witness attestation about themself using an
eSignet-issued OIDC credentials. Registry Witness verifies the access token,
optionally verifies the eSignet ID token for authentication freshness, binds the
requested subject to a verified access-token or UserInfo claim, reads only the
configured registry fact, and returns a bounded attestation result.

## Actors

- Citizen wallet or portal: holds the eSignet access token and calls Registry
  Witness.
- eSignet: authenticates the citizen and issues the OIDC token.
- Registry Witness: verifies the token, enforces self-attestation policy, reads
  Relay, and returns the attestation.
- Registry Relay: exposes the civil registry fact through the evidence source
  API.
- Civil registry source: fixture-backed source of the civil fact.

## Happy Path

1. The citizen authenticates with eSignet through the supported OIDC
   Authorization Code with PKCE flow.
2. eSignet issues a JWT access token. In the simple mode the access token
   includes the bound citizen identifier, for example `national_id=NID-1001`.
   In the eSignet default-style mode, the ID token supplies `auth_time`/`acr`
   and the signed UserInfo JWT supplies the subject-binding claim, for example
   `individual_id=NID-1001`.
3. The wallet or portal calls `POST /claims/evaluate` on the optional
   citizen-facing civil Witness.
4. Registry Witness validates issuer, signature, audience, client, token
   lifetime, configured self-attestation scope, and any configured ID
   token/UserInfo companion JWTs.
5. Registry Witness checks that `subject.id` in the request exactly matches the
   configured token claim, for example `national_id`.
6. Registry Witness reads the civil Relay for the allowed claim
   `person-is-alive`.
7. Registry Witness returns a claim result showing the citizen is alive.

## Security Invariants

- Witness denies before any registry source read when the requested subject does
  not match the token-bound subject.
- Self-attestation can evaluate only explicitly allowed claims, purposes,
  disclosures, formats, and credential profiles.
- A request for another subject, such as `NID-1002`, is rejected even if the
  token is otherwise valid.
- Audit events carry `access_mode=self_attestation` and do not write raw bearer
  tokens or raw citizen identifiers.
- eSignet is treated as the citizen identity proofing authority; Witness does
  not accept unsigned, opaque, shell-decoded, or request-body identity claims
  from the wallet.

## Demo Evidence

The optional smoke script writes artifacts under
`output/citizen-self-attestation/`:

- `citizen-witness-discovery.json`: authenticated Witness discovery.
- `citizen-self-evaluation.json`: successful `person-is-alive` evaluation for
  `NID-1001`.
- `citizen-other-subject-denied.json`: denied evaluation for `NID-1002`.
- `citizen-access-token-claims.json`: decoded non-secret JWT header and claims.
- `citizen-id-token-claims.json`: decoded ID token header and claims when
  `ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token`.
- `citizen-userinfo-claims.json`: decoded UserInfo JWT header and claims when
  `ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo`.
- `citizen-civil-witness.log`: Witness startup and audit output, including
  `access_mode=self_attestation`.

Optional follow-up evidence can add SD-JWT VC issuance from the successful
evaluation once the wallet holder binding is available in the lab.

## Running The Optional Smoke

The first implementation is intentionally not part of `just quick`. It runs only
when requested:

```bash
just generate
just build
just up

ESIGNET_CITIZEN_ACCESS_TOKEN="<jwt-access-token>" \
ESIGNET_SELF_ATTESTATION_SCOPE_POLICY="disabled" \
ESIGNET_SELF_ATTESTATION_SCOPE="self_attestation" \
just citizen-self-attestation
```

The supplied JWT access token must:

- be issued by the configured eSignet issuer;
- be discoverable through `/.well-known/openid-configuration` and JWKS;
- include `national_id=NID-1001`, or the claim configured by
  `ESIGNET_SUBJECT_CLAIM`, unless `ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo`;
- include `auth_time`, because Witness enforces bounded authentication
  freshness for citizen self-attestation, unless
  `ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token`;
- include the configured client identifier in `azp` or `client_id`, or the
  script must be run with `ESIGNET_CLIENT_ID`;
- include the configured scope in its `scope` claim when
  `ESIGNET_SELF_ATTESTATION_SCOPE_POLICY=required`.

`ESIGNET_SELF_ATTESTATION_SCOPE_POLICY` can be `required`, `optional`, or
`disabled`. The live eSignet demo defaults to `disabled` because stock local
eSignet access tokens may omit the OAuth `scope` claim. This does not grant
source access: Witness still requires trusted issuer/JWKS, allowed
client/audience, current authentication assurance, and an exact subject-binding
match before any registry read.

For eSignet deployments that keep civil attributes in UserInfo and assurance
fields in the ID token, run with:

```bash
ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo \
ESIGNET_SUBJECT_CLAIM=individual_id \
ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token \
ESIGNET_CITIZEN_ACCESS_TOKEN="<jwt-access-token>" \
ESIGNET_CITIZEN_ID_TOKEN="<jwt-id-token>" \
just citizen-self-attestation
```

Witness fetches the UserInfo endpoint itself with the access token and verifies
the returned signed JWT before accepting the subject-binding claim. The UserInfo
response must be JWS/JWT, not an encrypted JWE, for this lab path.

If a token is not already available, the script can prepare the Authorization
Code with PKCE request and later exchange the returned code with
private-key-jwt client authentication:

```bash
ESIGNET_ISSUER="https://esignet.example" \
ESIGNET_CLIENT_ID="registry-lab-citizen-client" \
just citizen-self-attestation

ESIGNET_AUTHORIZATION_CODE="<callback-code>" \
ESIGNET_CLIENT_PRIVATE_KEY_FILE="./local/esignet-client-private-key.pem" \
just citizen-self-attestation
```

For local eSignet deployments where discovery is not under the issuer root,
also set `ESIGNET_DISCOVERY_URL`, for example
`http://127.0.0.1:8088/v1/esignet/oidc/.well-known/openid-configuration`.

The first command prints the authorization URL and writes the PKCE verifier to
`output/citizen-self-attestation/esignet-pkce.env`. The second command exchanges
the code and runs the Witness smoke.

## Integration Decision

The simplest integration is access-token subject binding:

- eSignet emits the citizen identifier in the JWT access token, for example
  `national_id`.
- Witness config uses `self_attestation.subject_binding.token_claim:
  national_id`.

If the selected eSignet deployment cannot emit the binding claim in the JWT
access token, use the implemented companion-token path:

- `self_attestation.subject_binding.claim_source: userinfo`
- `self_attestation.token_policy.assurance_claim_source: id_token`
- `auth.oidc.userinfo_endpoint` from eSignet discovery
- `self_attestation.scope_policy: disabled` when the eSignet access token does
  not carry a useful `scope` claim

Do not move the claim binding into an unverified request field.

## Implementation Plan

1. Keep the current Zitadel scenarios as generic OIDC and machine-client demos.
2. Add an optional eSignet citizen flow driven by
   `scripts/smoke-citizen-self-attestation.sh`.
3. Generate a host-side Witness config at
   `output/citizen-self-attestation/citizen-civil-witness.yaml` using the
   eSignet issuer, JWKS URI, UserInfo endpoint when needed, token audience,
   client ID, configured scope, and subject-binding claim.
4. Start the host-side Witness on port `4325` against the existing civil Relay
   on port `4311`.
5. Prove success for `NID-1001`, denial for `NID-1002`, and auditability through
   saved artifacts.
