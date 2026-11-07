# Wallet presentation example

This project issues Evidence assertions from a credential a holder presents
from a wallet. The `evidence-oid4vp` service runs the OpenID4VP exchange and
keeps the verified presentation under a session reference until Evidence reads
it once. Evidence reads it
through the `wallet-presentation-v1` host protocol, derives the answer, and
signs an assertion on the `holder-presented` channel.

| Definition | Purpose | Output |
| --- | --- | --- |
| `credential-possession` | `credential-check` | Boolean: the holder presented a credential of the configured type from a trusted issuer. Nothing else is disclosed. |
| `identity-match` | `identity-check` | Boolean: the presented name equals the expected name from the Evidence request, after `normalise_name("name-match-v1", ...)` and one exact comparison. The profile folds Latin, Greek and Cyrillic accents and drops Arabic vowel signs and Hebrew points, but keeps the marks that are part of a spelling in other scripts (Devanagari virama, nukta and anusvara, Thai tone marks). |

The Evidence caller states the session reference and the applicant principal
in its request. The principal must equal the one that created the session in
`evidence-oid4vp`.

## Files

| Path | Role |
| --- | --- |
| `evidence.yaml` | Project: selector profiles, Functions, Sources, definitions |
| `functions/` | Derivations for the two definitions |
| `adapter-packs/wallet-session/` | Pack with one `wallet-presentation-v1` endpoint per definition, plus the digest-pinned protocol configuration (trusted issuer key, credential type, disclosed claims) |
| `wallet-target.yaml` | Deployment target: token validation, the verifier connection, signer |
| `wallet-authority.yaml` | Access profile and grants |
| `oid4vp-runtime.yaml` | Runtime configuration for `evidence-oid4vp` |

Values such as ports, issuer URLs, secret paths and the audit path are
loopback placeholders. Copy the project, substitute them, generate the keys
with `evidencectl keygen`, then run `evidencectl package` and
`evidence authority activate`.

## How the gate runs it

`crates/registry-evidence-oid4vp/tests/evidence_journey.rs` holds two tests;
the device-run harness shares its deployment code (see Device run).

- `the_example_deployment_is_well_formed` runs on every PR. It checks that the
  runtime passes `evidence-oid4vp check`, that the project, target and
  authority parse, and that the pack digests match the files.
- `a_presented_credential_becomes_a_verified_assertion` is an ignored exact
  gate. With `EVIDENCE_BIN` and `EVIDENCECTL_BIN` set it starts a test
  authorization server, `evidence-oid4vp` and `evidence` on loopback, plays the
  portal and the wallet, verifies each assertion with `registry-evidence-client`
  and runs the negative journeys (untrusted issuer, another principal, Evidence
  called before the wallet posted).

## Device run

The gate uses a simulated wallet. A device run puts a real wallet on a phone in
front of the same deployment and records the result as a receipt. No wallet is
claimed to work until a reviewed receipt for it is committed.

`crates/registry-evidence-oid4vp/tests/device_run.rs` holds the harness. It
plays the portal and the relying party: it starts `evidence-oid4vp` and
`evidence` on loopback from a temporary copy of this project (this directory
stays untouched), creates one session per definition, prints the link the
wallet opens, waits for the presentation, asks Evidence for the assertion,
verifies it with `registry-evidence-client` under a channel policy that accepts
`holder-presented`, prints a value-free summary and writes a receipt draft.

### Prerequisites

1. **A public HTTPS origin** that forwards to the verifier's loopback listener
   (`127.0.0.1:$DEVICE_RUN_LISTEN_PORT`). You provide the tunnel or host; the
   harness opens no tunnel. The origin is the verifier's `publicBaseUrl`, so it
   must be stable for the run. A `did:web` identifier names the host alone, so
   the origin must be on the default HTTPS port and have no path.
2. **A client identifier the wallet supports.**
   - `did-web`: the verifier serves `/.well-known/did.json` and signs EdDSA.
   - `pre-registered`: the wallet operator registers `DEVICE_RUN_CLIENT_ID`, the
     verifier's response URI, and the keys at `/v1/jwks` (served while the
     harness runs). Registration is outside the harness.
   - `x509-san-dns`: supply a PEM chain and the matching private JWK
     (`DEVICE_RUN_X509_CHAIN`, `DEVICE_RUN_X509_KEY`) for a certificate that
     names the origin's host and that the wallet trusts. The harness does not
     generate a certificate a wallet would trust.
3. **An SD-JWT VC (`dc+sd-jwt`) in the wallet** from an issuer you list as
   trusted, for example one that Evidence's own OID4VCI delivery produced. The
   harness pins that issuer's public keys, its `iss`, the credential `vct` and
   the claim that holds the name. The credential must be holder-bound (it
   carries `cnf`), because the verifier requires a key binding JWT.
4. **A response-encrypting wallet.** `evidence-oid4vp` accepts `direct_post.jwt`
   only. A wallet that cannot encrypt the authorization response cannot complete
   the flow, and the receipt records that as a failed run, not as a gap in the
   harness.
5. `EVIDENCE_BIN` and `EVIDENCECTL_BIN` naming built `evidence` and
   `evidencectl` binaries, as for the gate.

### Steps

1. Write the trusted issuer's public key set to a file (a JWKS, or one JWK).
   The harness refuses a file with a private member.
2. Export the variables below. Put the expected name in the environment from a
   prompt or a file you source, not on a shared command line, and use a new
   receipt path: the harness never overwrites a file.
3. Run:

   ```sh
   cargo test --locked -p registry-evidence-oid4vp --test device_run \
     a_real_wallet_presents_to_the_verifier -- --ignored --exact --nocapture
   ```

4. For each definition the harness prints a link, then waits (default 300
   seconds). Render the link as a QR code with a locally installed tool, for
   example `qrencode -t ANSIUTF8 '<link>'` (any QR tool that reads the link from
   its arguments works; the harness adds no dependency), and scan it with the
   wallet. Possession asks for no claim. Identity match asks for the name claim;
   approve it.
5. Read the summary and the receipt draft. A failed run still writes its
   draft, then fails the test.
6. Review the draft with the wallet's own screen and the logs beside it, set
   `status` to `reviewed`, and commit it.

| Variable | Meaning |
| --- | --- |
| `DEVICE_RUN_PUBLIC_URL` | Public HTTPS origin the phone reaches |
| `DEVICE_RUN_LISTEN_PORT` | Loopback port the verifier listens on; the tunnel forwards here |
| `DEVICE_RUN_CLIENT_IDENTIFIER` | `did-web`, `pre-registered` or `x509-san-dns` |
| `DEVICE_RUN_CLIENT_ID` | Registered client id (no `:`), for `pre-registered` |
| `DEVICE_RUN_X509_CHAIN`, `DEVICE_RUN_X509_KEY` | PEM chain and private JWK files, for `x509-san-dns` |
| `DEVICE_RUN_ISSUER` | Trusted issuer, the credential's `iss` |
| `DEVICE_RUN_CREDENTIAL_TYPE` | The credential's `vct` |
| `DEVICE_RUN_ISSUER_JWKS` | File with the issuer's public JWKS or one public JWK |
| `DEVICE_RUN_NAME_CLAIM` | Top-level claim that holds the name |
| `DEVICE_RUN_EXPECTED_NAME` | The name the identity match compares against |
| `DEVICE_RUN_WALLET`, `DEVICE_RUN_WALLET_VERSION` | Wallet label and version for the receipt |
| `DEVICE_RUN_RECEIPT` | New path for the receipt draft |
| `DEVICE_RUN_TIMEOUT_SECONDS` | Optional wait per definition, 30 to 840 (default 300) |
| `DEVICE_RUN_MAX_CREDENTIAL_AGE_SECONDS` | Optional oldest accepted credential (default 86400) |

A missing or invalid variable stops the run before anything starts and names
the variable, never its value.

### What the receipt records

The format is `fixtures/interoperability/oid4vp-device-run/receipt.schema.json`
(`registry.evidence-oid4vp-device-run-receipt/v1`), beside the OID4VCI Inji
receipt, which describes upstream unit tests and cannot express a presentation.
The receipt holds: the schema id, `status` (`draft` or `reviewed`), the date,
the wallet label and version, the client identifier kind, the response mode
(`direct_post.jwt`), the credential format (`dc+sd-jwt`), the overall result,
the outcome of each definition with the failing stage if any, and a claim
boundary. It never holds a claim value, expected name, token, nonce, session
reference, request URI, issuer or origin.

Failing stages: `presentation-not-received` (the wallet never posted),
`verifier-rejected-presentation` (the session failed in `evidence-oid4vp`),
`evidence-refused` (Evidence returned a dependency failure, which collapses
every credential refusal, so read the verifier and Evidence logs for the cause),
`assertion-verification`, `assertion-false`, `assertion-shape`.

A reviewed receipt is committed under
`products/evidence/fixtures/interoperability/oid4vp-device-run/` as
`<wallet>-<version>-<date>.json`. A wallet and version are described as working
only by a reviewed passing receipt there.

### Expected wallet needs

Every row is unverified: it records what the research says each wallet is
expected to need, and it stays unverified until a receipt for that wallet exists.

| Wallet | Client identifier kind expected | Response mode expected | SD-JWT VC | Status |
| --- | --- | --- | --- | --- |
| Inji Wallet | `pre-registered`, `did` or `redirect_uri`; no X.509 client identifier. M1 targets `did-web` and `pre-registered`. 1.0.0-alpha.1 moves to OpenID4VP 1.0 and DCQL | `direct_post.jwt` expected with OpenID4VP 1.0; unverified | Unconfirmed | Unverified |
| EUDI reference wallet | `x509-san-dns` and `x509-hash` expected | `direct_post.jwt` expected | Not stated in release notes | Unverified |
| walt.id wallet | Not established | Not established | Expected (OpenID4VP 1.0, DCQL) | Unverified |
| France Identite | `x509-san-dns` expected | `direct_post.jwt` expected | No: expected to present mdoc only, which this verifier does not request, so a run is expected to fail until mdoc support exists | Unverified |

## Limits

- The issuer key in the protocol configurations is a synthetic test-only
  public key. The matching seed lives only in the gate. Replace both with your
  trusted issuer's key before any real use.
- A device run proves nothing about a wallet until a reviewed receipt exists.
  `a_simulated_wallet_completes_the_device_run_harness` proves only that the
  harness path works with the gate's simulated wallet.
- The identity match reads one top-level disclosed claim. `disclosedClaims`
  holds flat top-level names, so a wallet credential that nests the name or
  splits it (for example `given_name` and `family_name`) needs a pack that
  reads those claims. The example pack names its claim `name`; the device-run
  harness rewrites that name to `DEVICE_RUN_NAME_CLAIM` in its temporary copy.
- The project has no fixtures: a host-protocol credential cannot be replayed
  from a stored response, so the composed gate is the proof of the flow.
