# Contextual authorization migration notes

These notes describe unreleased source changes. They do not change the published
v0.30.0 release or select the version of a future release.

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
