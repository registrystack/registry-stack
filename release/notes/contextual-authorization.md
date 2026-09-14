# Contextual authorization migration notes

These notes describe unreleased source changes. They do not change the published
v0.30.0 release or select the version of a future release.

## Breaking changes for the release notes

- Registry Mint retired; the `mint` config key and retired CLI flags are refused.
- Grant authority removed: BREG `taskGrant.authority` and task status client
  `authority`, Casework `taskAuthority.id`, and Evidence's `grantAuthority`
  claim name. BREG status clients are keyed by source issuer only.
- Casework task assertions no longer carry `registry_grant_authority` or
  `registry_grant_source_issuer`; ThunderID derives the source issuer from the
  verified `iss`.
- Local dev databases holding grants or drafts from before #1044 no longer load;
  reset local dev state.

## Issuer and local development

Registry Mint is removed from current source and future toolsets. Configure an
OAuth issuer independently; maintained local development uses pinned stock
ThunderID 1.0.1. Mint configuration, its access-token signing custody, and its
pre-response issuance audit are not migrated. Evidence assertion signing and
resource audit remain separate requirements.

Use each product's `dev token` command to obtain a fresh ordinary client token.
Use `dev grant` with an existing Casework-approved grant ID and an explicit,
private connection file for task-bound access. A task grant does not give the
agent the approving person's bearer token or standing access profile.

## Authorization configuration

BREG access profiles use `permissions` in place of `grants`. Contextual authority
uses the declared `registry_*` claim mappings and immutable signed task bounds.
Review generated schemas and update runtime/client configuration together.

Every token the issuer mints by exchange carries `registry_assertion_issuer`,
the verified `iss` of the assertion it was minted from. BREG, Casework, and
Evidence accept an optional `assertionIssuers` map beside `allowedClients`,
keyed by the client its tokens name and listing the assertion authorities that
client may present. A client with an entry there is refused a token whose claim
names any other authority, at the same boundary that reads `allowedClients` and
before any resource policy. A token that carries no such claim, an ordinary
client-credentials token included, is unaffected. Stock ThunderID 1.0.1 applies
no per-client issuer restriction of its own, so a resource server is where the
pairing is stated. Local development derives the map from the exchange clients
each connection registers, and `bregctl dev` and `caseworkctl dev` refuse a
topology whose connections and exchange clients do not name each other.

Casework templates declare the exact agent, client, resource, scopes, purpose,
subject mapping, bounds, and lifetime. Evidence templates additionally declare
requester tags and the relying-party audience. Officers review these values
before approval; the browser cannot supply replacement policy or selectors.

Task-bound BREG mutations use governed change requests and fresh Casework status
checks. Evidence reads enforce the signed grant deadline locally. Re-exchanging
an access token cannot extend that deadline, even when the issuer gives the
JWT a later expiry. Revocation prevents new Casework assertions; already issued
read tokens retain only their documented, bounded validity window.

Citizen federation is deferred and is not part of this delivery. eSignet keeps
its identity-provider role and existing BREG authentication/claim contract; its
provider migration replaces the Mint-specific block with `token_client`.
