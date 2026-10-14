# FHIR Evidence example

This normalized local project returns two fixed administrative assertions from
FHIR R4 resources through a bounded read-through adapter. It uses the ordinary
HTTP source and Rhai Function contracts, without a FHIR-specific runtime fork.

| Definition | Purpose | Boolean Output |
| --- | --- | --- |
| `fhir-coverage-status` | `coverage-record-verification` | The selected Coverage reports active and names the selected Patient as beneficiary. |
| `fhir-healthcare-establishment` | `healthcare-establishment-verification` | The selected Organization is active and has exactly one coding with the standard organization-type system and code `prov`. |

The project owns the reviewed GET paths, selector profiles, response bounds and
projection, private Facts, Functions, and Outputs. The local target owns the
loopback connection and process resources. `dev-authority.yaml` grants each
complete request shape, including both subject roles for coverage and both
permitted signed representations. Client registration selects an existing
profile and does not create authority.

Start from a writable copy in the matching Registry Stack source archive. Use
matching `evidence` and `evidencectl` binaries, Python 3.9 or later, curl, and
Docker. The [FHIR credential tutorial](../../../../docs/site/src/content/docs/tutorials/issue-fhir-evidence-as-vcs.mdx)
owns discovery, the local source, request preparation, SD-JWT VC verification,
and cleanup. Run discovery from the copy's parent directory so its owner-only
selector files stay outside the project. Never commit those files, credentials,
or returned data.

The project's offline lane needs no FHIR service:

```sh
python3 test_source.py
umask 077
evidencectl keygen signing --output-dir .generated/secrets
evidencectl keygen secret --output .generated/secrets/audit-hmac-key
evidencectl keygen secret --output .generated/secrets/subject-binding-hmac-key
evidencectl check . --target local-target.yaml
evidencectl test . --target local-target.yaml --explain
```

The focused synthetic fixtures exercise true and false results, resource and
beneficiary mismatches, missing or invalid data, nested collection bounds,
source failure, and discarded private canaries. The coverage Source receives
only the coverage-record selector. Its patient selector reaches derivation,
where a mismatched beneficiary refuses the assertion rather than returning a
result about another patient. Organization codings retain their system/code
pairs, so values from unrelated codings cannot form a provider match.

Local success proves only the declared cases. Production and evidence-grade
bundles require complete fixture categories, reviewed authenticated HTTPS source
transport, an appropriate signer, and the remaining deployment requirements.
The credential-free source is numeric loopback under local assurance. The
adapter validates resource identity, denies redirects and ambient proxies,
uses system TLS for the public upstream, bounds responses, and suppresses
request logging. `source.openapi.yaml` retains the narrow FHIR reference; the
compiled source contract comes from `evidence.yaml`.

An active Coverage record does not establish insurance eligibility. An active
provider Organization does not establish accreditation or professional
licensing. Neither assertion grants downstream write authority.
