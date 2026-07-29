# Representative credential issuance

Registryctl can configure one digitally authenticated person to obtain a
credential for another subject when Registry Relay can prove their exact
relationship. The relationship can come from any registry or service that a
reviewed Relay integration can consult. The example on this page uses a parent
and child, but the authoring contract does not assign meaning to relationship
names or identifier schemes.

## Use the Registryctl authoring surface

Author the relationship evidence as a registry-backed claim. Its consultation
must bind both sides of the relationship:

```yaml
services:
  civil-credential:
    kind: evidence
    version: 1
    purpose: civil-credential-issuance
    legal_basis: public-service-delivery
    consent: not_required
    access:
      scopes: [evidence:civil-credential:issue]
    consultations:
      parent-link:
        integration: civil-relationships
        input:
          parent_id: request.requester.identifiers.national_id
          child_id: request.target.identifiers.civil_registration_id
    claims:
      parent-link:
        cel: parent_link.matched
        disclosure: predicate
      birth-record:
        output: parent_link.record
        disclosure: value
    credential_profiles:
      birth-record:
        format: dc+sd-jwt
        type: https://notary.example.com/credentials/birth-record/v1
        validity: 5m
        claims: [birth-record]
```

The integration named `civil-relationships` owns the source protocol. It may
consult a civil registry, social registry, case-management system, or another
reviewed source. Registry Notary does not connect to that source directly.
For this browser ceremony, the proof consultation must have exactly the two
shown inputs. Registryctl rejects extra identifiers, attributes, or variables
because the target-selection form cannot supply them.

The same input availability rule covers the credential root and every
registry-backed claim in its transitive dependency closure. Each consultation
may read the authenticated requester identifier, the selected target
identifier, or both. Production validation names the claim, consultation,
input, and expected paths when a hand-authored configuration asks for data
that this ceremony cannot supply.

The proof claim and credential claim are separate. Do not add a claim
dependency by hand. Registryctl derives the exact `birth-record ->
parent-link` dependency when representative issuance selects this profile.

Add the compact representative block to the existing OID4VCI environment
binding:

```yaml
oid4vci:
  public_base_url: https://notary.example.com
  credential:
    service: civil-credential
    profile: birth-record
  subject:
    token_claim: individual_id
    id_type: national_id
  representative_issuance:
    relationship: parent
    proof_claim: parent-link
    target_id_type: civil_registration_id
```

`max_proof_age_seconds` is optional and defaults to 300. Its accepted range is
1 through 600. Registryctl raises the generated instance-wide evaluation age
ceiling when necessary, but does not lower unrelated evaluation policy when
this relationship uses a shorter window:

```yaml
  representative_issuance:
    relationship: parent
    proof_claim: parent-link
    target_id_type: civil_registration_id
    max_proof_age_seconds: 180
```

One Registryctl OID4VCI binding supports one relationship. Use a separate
project binding when the same credential needs a different relationship or
proof policy.

The credential claim root must be exclusive to the selected credential
profile. Registryctl rejects a shared root because the generated Notary claim
dependency is claim-wide and must not change another profile's behavior.

Registryctl generates:

- The digitally authenticated representative ceremony
- The root claim's dependency on the relationship proof claim
- The exact delegated claim closure
- A delegation-only root policy, separate from the ordinary subject-bound
  claim allow-list
- Credential status at `<public_base_url>/v1/credentials`
- A production-valid Registry Notary configuration

Run the authoring checks before deployment:

```sh
registryctl check --project-dir <project> --environment <environment>
registryctl test --project-dir <project> --environment <environment>
registryctl build --project-dir <project> --environment <environment>
```

Synthetic fixtures can include `request.requester` as a governed entity. This
lets `project test` prove the requester-to-consultation binding without a live
identity provider or registry:

```yaml
request:
  requester:
    type: Person
    identifiers:
      - scheme: national_id
        value: PARENT-0001
  target:
    type: Person
    identifiers:
      - scheme: civil_registration_id
        value: CHILD-0001
  claims: [birth-record]
  disclosure: value
  format: application/vnd.registry-notary.claim-result+json
  purpose: civil-credential-issuance
```

Fixture values must remain synthetic.

## Browser and wallet ceremony

1. Open the ordinary offer-start URL for the representative-enabled credential:

   ```text
   https://notary.example.com/oid4vci/offer/start?credential_configuration_id=<id>
   ```

2. The representative authenticates with the configured identity provider.
3. Registry Notary displays a no-store target-selection form.
4. The representative enters the represented subject identifier.
5. Registry Notary evaluates the relationship proof first, then the exact
   committed credential dependency closure.
6. Registry Notary renders the pre-authorized offer only after the complete
   evaluation succeeds.
7. The representative transfers the offer to a wallet and completes the normal
   transaction-code and holder-proof flow.
8. The credential endpoint validates the stored transaction and materializes
   the credential without another Relay call.

The representative, represented subject, and wallet holder are separate roles.
The invoking client, browser ceremony, and channel remain audit context. They
are not additional principals.

The relationship evaluation uses the representative's verified identifiers
inside Registry Notary. Before the offer is minted, Notary replaces them with
transaction-bound HMAC handles. Neither the pre-authorized code nor the wallet
access token contains the representative's raw identifiers.

## Where authority comes from

The Relay-backed `proof_claim` is the relationship evidence. The source result
must prove the configured relationship for the authenticated requester and
the selected target under the compiled consultation contract.

The authorization details carried in the Notary-signed access token are a
capability and consistency binding. They bind the relationship name, proof
claim, target identifier, purpose, and claim closure across the untrusted
wallet round trip. They do not prove the relationship.

Registry Notary commits the evaluation, authorization binding, result target
references, credential configuration, profile, signing key metadata, and
Relay provenance into the existing issuance transaction commitment. For a
representative ceremony, that binding also covers the resolved relationship
policy's maximum proof age. The credential endpoint recomputes the commitment
before signer access.

## Freshness, status, and revocation

The relationship proof expires at `max_proof_age_seconds`. Offer and access
token expiry cannot extend beyond that proof expiry. Registry Notary does not
re-run the relationship proof at the credential endpoint. In a hand-authored
Notary configuration, this value must not exceed
`subject_access.token_policy.max_evaluation_age_seconds`; Registryctl derives
a sufficient ceiling from its compact setting.

Representative credentials always include live credential status. If the
relationship ends after issuance, an operator can revoke the credential
through the status admin API. Automatic relationship-change-to-revocation
delivery is tracked by
[GH#568](https://github.com/registrystack/registry-stack/issues/568). Enabling
status alone does not connect a source relationship change to revocation.

## Subject pseudonym key epochs

The represented subject becomes the credential `sub` as a keyed pseudonym over
the configured target identifier type and value. The wallet proof key remains
the holder binding.

The pseudonym is stable only while the Registry Notary audit pseudonym key
stays unchanged. Rotating `audit.hash_secret_env` changes newly computed
subject pseudonyms. Credentials issued before and after that rotation will not
have equal `sub` values for the same represented subject.

Treat audit pseudonym key rotation as a subject-identifier epoch change.
Before rotation, identify relying parties that compare `sub` across
credentials and decide whether outstanding credentials must expire, be
revoked, or be reissued.

The pseudonym input does not include issuer or audience. Cross-issuer
non-correlation depends on separate audit pseudonym keys for separate Notary
authorities.

## Unsupported paths

Representative issuance supports only the issuer-initiated OID4VCI browser
ceremony described on this page. Registry Notary rejects:

- Direct `POST /v1/credentials` representative issuance
- Machine-created representative offers
- Assisted-access ceremonies used as representative authority
- Wallet-selected relationship names, proof claims, or claim closures
- Credential materialization after the relationship proof expires

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `proof_claim` does not exist | The environment names a claim outside the selected service | Select a registry-backed claim in the credential service |
| Proof claim equals credential claim | The relationship proof and issued assertion are not separated | Create a distinct registry-backed proof claim; Registryctl derives the dependency |
| Credential claim is shared by another profile | The derived proof dependency would also change that profile | Use an exclusive root claim or create a representative-specific claim |
| Representative binding is missing | The proof consultation does not read the authenticated requester identifier | Map an input from `request.requester.identifiers.<oid4vci subject id_type>` |
| Represented subject binding is missing | The proof consultation does not read the selected target identifier | Map an input from `request.target.identifiers.<target_id_type>` |
| Proof consultation has another input | The target-selection ceremony cannot populate it | Keep exactly the requester identifier and target identifier inputs |
| Credential dependency has another input | The target-selection ceremony cannot populate a root or transitive consultation field | Map only the requester or selected target identifier, or use a different governed ceremony |
| Offer is not rendered | Authentication, proof evaluation, or a dependency failed | Check value-free Registryctl diagnostics, Notary audit events, and Relay availability |
| Credential redemption is denied | The transaction expired or no longer matches its commitment | Restart the browser ceremony under the active project generation |
| Verifier reports revoked or unavailable status | Lifecycle state is not valid or cannot be checked | Restore the status service or inspect the credential's lifecycle record |
