# Record status from a retained BReg project

This one-question starter matches the unmodified `bregctl init` teaching model:
`record-active` uses the `by-code` selector and derives a boolean from status.
Its 11 synthetic cases cover positive and negative answers, absent facts,
identity checks, source failure, output refusal, and disclosure constraints.

Start and use your BReg project before creating Evidence. When ready, stop BReg
normally, create this starter with `evidencectl new`, and export the `evidence-source`
lookup for entity `record`, selector `by-code`, and field `status`, using source ID
`registry-status` and connection `registry`. Import that source into this project.

Export the existing dedicated source pair while BReg is stopped:

```sh
bregctl dev export-client ../registry --client source \
  --client-id-file ./secrets/registry-client-id \
  --assertion-key-file ./secrets/registry-client-key
```

Use `pwd -P` to replace the absolute runtime paths in `targets/local/settings.yaml`:
set the bundle directory to your chosen candidate's `bundle/`, the file secret
root to this project's `secrets/`, and audit storage to `audit/evidence.jsonl`.
The source endpoints use BReg's default ports `8090` and `8091`; match any ports
you selected on the registry's first start. Then, from this Evidence directory:

```sh
evidencectl target new ./targets/configured --settings ./targets/local/settings.yaml \
  --signing-public-key ./secrets/signing-p256-public.jwk.json
evidencectl source import ../exports/registry-status --project . --target ./targets/configured
evidencectl fixtures run --project . --target ./targets/configured
evidencectl build --project . --target ./targets/configured --output ../candidate
bregctl dev start ../registry
evidencectl dev --target ./targets/configured --detach
```

`dev --target` rehearses the source connection using a separate generated local
caller authority. It does not serve the target's complete caller governance.
Use the maintained “Answer questions from Base Registry Engine” tutorial for
record creation, requests, verification, and shutdown. The neighboring `starter/`
input remains the broader two-selector example, requiring its matching registry.
