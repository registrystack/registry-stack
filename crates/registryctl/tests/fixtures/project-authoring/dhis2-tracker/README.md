# DHIS2 child-health evidence Registry Stack project

This starter demonstrates the product-neutral `script` capability with a
synthetic DHIS2 Tracker wire shape. Product and version metadata do not select
the Rhai runtime. The offline fixtures are the deterministic acceptance path;
a reachable live DHIS2 instance is optional compatibility evidence.

```bash
registryctl authoring editor --project-dir .
registryctl test --project-dir . --integration health-record --fixture complete-child-health-evidence --trace
registryctl test --project-dir . --integration health-record --fixture complete-child-health-evidence --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
registryctl authoring xw --format reference
```

`authoring editor`, `test`, `check`, and `build` are human-readable by default. Use `--format json`
with those report commands only for machine consumers. Editor setup uses the five schemas copied
from this `registryctl` build for VS Code and Zed.

Edit the reviewed `adapter.rhai`, integration contract, and synthetic fixtures
together. Keep source credentials in the environment binding.

The authored layers remain separate:

1. Relay performs the bounded DHIS2 request and preserves the starter's
   declared identity, date, programme, reconciliation, and health-status
   outputs. Nullable programme and stage booleans keep `true`, `false`, and
   `null` distinct, including BCG, OPV, and measles dose evidence.
2. Notary discloses those outputs as atomic evidence claims. It does not decide
   outreach, follow-up priority, eligibility, entitlement, or case action.
3. A consuming programme applies its own reviewed rules. For example, a
   programme might first route any `null` evidence to resolution, then derive
   `outreach_required` only from known enrollment and dose evidence. That
   downstream rule is illustrative and is not part of this Registry Stack
   project.

For a matched tracked entity, a completed DHIS2 programme-stage event maps to
`true`, an existing non-completed stage event maps to `false`, and an absent
enrollment or stage maps to `null`. A 404 is a no-match, not negative health
evidence. An upstream rejection and an echoed-subject mismatch are failures
and produce no claims. Ambiguity is explicitly not applicable because the
adapter uses DHIS2's singleton tracked-entity resource.

The demo programme and stage UIDs in `adapter.rhai` are project-owned mappings.
Replace and review them against the deployed DHIS2 metadata without changing
the product-neutral Script runtime or broadening source access.

Record any live compatibility result through the repository root's
`release/conformance/integrations/` evidence flow. Never rewrite the
deterministic offline fixtures to reflect a transient live server result.

The `include_inactive` boolean is a bounded, typed target attribute supplied by
the evaluation caller and forwarded through Notary and Relay. It is request
context only. It is not an authenticated identity or a substitute for the
`dhis2_tracked_entity` identifier used to select the record.
