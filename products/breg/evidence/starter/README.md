# Record status from BReg

This editable starter contains two questions and synthetic fixtures. Both questions
reuse `registry-status` and permit either the code or registration-number selector.
Their source, selectors, response schema, fixed fact schema and extraction adapter
come from a reviewed `bregctl generate evidence-source` export. Import that export
before running fixtures. There is no generated source copy to maintain here.

`record-active` returns one boolean. `record-status-pair` returns the complete pair
of complementary booleans for the same two-state vocabulary. The pair demonstrates
complete multi-concept disclosure without revealing another record attribute.
The derivations receive only `status`; the source adapter verifies the chosen
identity before either question runs. A null or missing status is unavailable.

The first fixture uses code and the second uses registration-number, exercising
both alternatives through ordinary reference fixtures. Each covers positive,
negative, missing and null status, exact unresolved lookup, identity refusal,
source failure, output rejection and the duplicate-disclosure-family guard.
Synthetic identity and private label canaries must stay out of assertions and
diagnostics.

The copied `targets/local/settings.yaml` is an explicit loopback teaching target.
Review its authority and source connection, then set its absolute runtime paths.
The fixed `registry` connection uses a dedicated BReg workload credential, separate
from the Evidence caller and the registry operator. After BReg's first start, `bregctl dev export-client ../registry --client source`
can copy its existing ID and key into this project's owner-only secrets directory.
Pass `--client-id-file ./secrets/registry-client-id` and
`--assertion-key-file ./secrets/registry-client-key`; normal stop/start retains this pair.

With the native binaries on PATH, create the target and import the export:

```sh
evidencectl target new ./targets/configured --settings ./targets/local/settings.yaml \
  --signing-public-key ./secrets/signing-p256-public.jwk.json
evidencectl source import ../exports/registry-status --project . --target ./targets/configured
evidencectl fixtures run --project . --target ./targets/configured
evidencectl build --project . --target ./targets/configured --output ../candidate
```

After BReg dev has published the dedicated source credentials, rehearse both live
services with `evidencectl dev --project . --target ./targets/configured --detach`.
This starts Evidence and a separate caller Mint using generated local authority;
it reuses the target's source connections and outbound TLS settings. The target's
caller authentication and service identity remain the explicit build settings.

Fixtures and build use recorded synthetic responses and do not require BReg to be
running or source credentials to be present. Serving the candidate requires the
separate caller issuer, BReg endpoint, source credentials, signing key and audit
storage named in the reviewed target. A production deployment needs its own
reviewed HTTPS target and transit signer.
