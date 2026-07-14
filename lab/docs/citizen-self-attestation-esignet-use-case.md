# Citizen self-attestation with eSignet

This optional lab journey demonstrates a source-free Notary deployment. eSignet
authenticates the applicant and supplies the token-bound subject. Registry
Notary evaluates only the applicant's declaration. It does not consult Relay or
receive a registry destination or source credential.

## Security boundary

The Notary accepts the `applicant-declaration` claim only for the subject bound
to the authenticated token. The default positive subject is `NID-2001`. A
request for another identifier, such as `NID-1001`, is denied before claim
evaluation. The claim is a fictional demonstration and must not be treated as
identity, civil-status, or programme-eligibility proof.

The generated configuration keeps these invariants:

- OIDC issuer, audience, client, algorithm, and token lifetime checks happen
  before subject binding.
- Subject binding happens before evaluation.
- Only the `application-processing` purpose and the
  `applicant-declaration` claim are admitted.
- Evaluation and optional holder-bound credential issuance are rate limited.
- Audit output hashes identifiers and never records bearer tokens or signing
  material.
- No Relay consultation or direct source connector exists in the Notary
  configuration.

## Run the journey

Generate local secrets and start eSignet:

```bash
just generate
just esignet-up
just citizen-self-attestation-esignet-login
```

Complete the browser login. Then exchange the returned code and run the
source-free Notary flow:

```bash
ESIGNET_AUTHORIZATION_CODE='<returned code>' \
just citizen-self-attestation-esignet-code
```

If caller-held tokens already exist, use
`just citizen-self-attestation-esignet-token`. Values are loaded from the
process environment and are not printed.

## Expected evidence

The redacted report is written beneath
`output/citizen-self-attestation/`. It records:

- successful discovery of the source-free capability;
- a successful `applicant-declaration` evaluation for `NID-2001`;
- a denied evaluation for `NID-1001`;
- zero source use in evaluation provenance; and
- a sanitized audit excerpt with `access_mode=self_attestation`.

OID4VCI probing remains optional and uses the same source-free claim. See
[Wallet interoperability testing](wallet-interop-testing.md) for the holder
proof flow.
