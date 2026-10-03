# Discovery compatibility fixtures

These fixtures pin pre-retirement Evidence wire compatibility and the refusal
of a mixed Evidence and Relay index. Repository text files end with one LF. The
selection and index tests remove that storage LF where the original wire value
did not include it.

`pre-retirement-evidence-description.jsonld` is the exact Evidence description
rendered from commit `e1b8428e2dbc2fb3d09816b5ac4edb663684bc05`. That renderer
applied RFC 8785 canonical JSON and appended one LF. Its SHA-256 is
`b70da47a87a5c7beea9edebd626cf28650906b934b2c53b3acc0b0745914e8ce`.
The baseline source and committed fixture can be compared independently with:

```sh
git show e1b8428e2:products/discovery/fixtures/descriptions/evidence.jsonld \
  | jq -cS . > /tmp/pre-retirement-evidence-description.jsonld
shasum -a 256 /tmp/pre-retirement-evidence-description.jsonld \
  products/discovery/fixtures/compatibility/pre-retirement-evidence-description.jsonld
cmp /tmp/pre-retirement-evidence-description.jsonld \
  products/discovery/fixtures/compatibility/pre-retirement-evidence-description.jsonld
```

All keys and string values in this source fixture are ASCII, so `jq -cS`
produces the same member order and escaping as the baseline RFC 8785 renderer.
