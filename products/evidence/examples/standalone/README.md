# Standalone Evidence example

This project issues fixed assertions from a synthetic HTTP source. It runs with
Evidence alone under `rstack dev`, which is its own token issuer. Each definition
has an explicit grant ceiling, a pinned Adapter pack route, a derivation Function,
and an output allowlist. The pack owns provider requests and native fact extraction. The person Source
selects the project-owned `projections/person-facts.rhai` and versioned
`schemas/person-facts.json` to retain birth date and region while removing
the source address canary, without changing the pack. Evidence owns grants,
subject binding, derivation, signing and release audit.
Private source facts stay inside Evidence.

| Definition | Purpose | Output |
| --- | --- | --- |
| `adult-status` | `age-check` | Boolean, calculated at the governed observation time in `Asia/Bangkok` |
| `residence-region` | `residence-check` | `north` or `south` |
| `professional-licence-status` | `licence-check` | `active`, `suspended`, or `expired` |
| `legal-parent-relationship` | `relationship-check` | Boolean for the child and candidate-parent roles |

Use an active `rstack` installation that includes the Evidence component. Use
`evidence` and `evidencectl` native tools that match that installation, plus
Python 3. It needs no Docker and no database.
Start from a writable copy outside the repository. Keep the example's generated
credentials and responses private. The commands below run in that copy.
`dev.yaml` is the development plan: the people who may call, and the scenario
in `tests/scenarios.yaml` that the run checks before it reports ready.

```sh
umask 077
evidencectl keygen signing --output-dir .generated/secrets
evidencectl keygen secret --output .generated/secrets/audit-hmac-key
evidencectl keygen secret --output .generated/secrets/subject-binding-hmac-key
evidencectl keygen token --output .generated/secrets/synthetic-source-token
evidencectl check . --target local-target.yaml
evidencectl test . --target local-target.yaml
evidencectl explain . --target local-target.yaml
evidencectl types . --language typescript --output .generated/evidence.ts
```

In another terminal, run the source from the same directory:

```sh
python3 serve-source.py --port 8081
```

Start the run. It packages a copy of the project, starts Evidence on a free port and
reports the address. A caller needs a short-lived token header file, so fetch
one for each call:

```sh
rstack dev check .
rstack --format json dev start . --ttl 2h > run.json
run_id="$(jq -r .run_id run.json)"
evidence_url="$(jq -r .products.evidence run.json)"
runtime_config="$(jq -r .runtimeConfigs.evidence run.json)"
headers_for() {
  rstack dev token "$run_id" --as "$1" | awk '$1 == "evidence" && $2 == "headers" {print $3}'
}
evidencectl request prepare adult-status \
  --evidence-url "$evidence_url" \
  --header @"$(headers_for caller)" \
  --runtime-config "$runtime_config" \
  --purpose age-check --subject subject:record-id=adult --name adult
rstack evidence api /v1/evidence \
  --url "$evidence_url" \
  --header @"$(headers_for caller)" \
  --input .evidence/requests/adult/request.json \
  --accept application/jose+json \
  --output .evidence/requests/adult/response.json
evidencectl verify .evidence/requests/adult/response.json \
  --context .evidence/requests/adult/verification.json \
  --output .evidence/requests/adult/verified.json
```

`request prepare` selects the public Requirement URI and closes verifier pins
before a response exists. `verify` uses that retained context offline and prints
`VERIFIED`. The verified assertion carries the Boolean output, actual definition
revision, subject binding, purpose, issuer, provider and validity. It confers no
review approval or downstream write authority.

Use a new request name for each call. Other synthetic selectors are `minor`,
licence `active`, `suspended`, or `expired`, and child `child` with candidate-parent
`parent` or `unlisted`. A parent request supplies both `--subject
child:record-id=child` and `--subject candidate-parent:record-id=parent`.
`missing` and `ambiguous` return a refusal. The authored fixtures also cover the
Bangkok date boundary, invalid outputs, unavailable sources and private canaries.

To try a conforming substitute, stop only the source and restart it with
`--variant alternate`. Evidence keeps the same source contract and definition
revision. Restarting the source with `--person-source-unavailable` refuses adult
and residence assertions while licence and relationship definitions remain
serviceable.

For a reviewable deployment handoff, package to a new directory outside this
project. `local-target.yaml` declares the stable installed package path; edit its
bindings and `dev-authority.yaml` for the intended environment before packaging.
Production uses the same complete grants with production transport and signer
requirements.

```sh
evidencectl package . --target local-target.yaml --output ../evidence-candidate
```

The candidate contains `bundle/`, `runtime.yaml`, and `compiled-authority.yaml`.
Install the bundle at the path declared in the emitted runtime, provision the
referenced secrets, then activate and check the complete target authority. For
this fresh local project, the generated secrets already exist. Preflight fetches
the token issuer's keys, so run `doctor` where the issuer the target names is
reachable:

```sh
candidate=$(cd ../evidence-candidate && pwd)
cp -R "$candidate/bundle" .generated/package
evidence authority activate --runtime-config "$candidate/runtime.yaml" \
  --document "$candidate/compiled-authority.yaml"
evidencectl doctor --runtime-config "$candidate/runtime.yaml"
```

The immutable bundle digest covers its packaged artifacts. Target authority has
a separately derived revision and durable activation history. Authority changes
require a process restart to adopt the new snapshot; ongoing requests keep their
original snapshot and live task-grant release checks.

Stop the run when finished, then interrupt the source:

```sh
rstack dev stop "$run_id"
```
