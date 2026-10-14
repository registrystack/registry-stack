# Standalone Evidence example

This project issues fixed assertions from a synthetic HTTP source. It runs with
Evidence, a local OAuth issuer, and an independent relying client. Each definition
has an explicit grant ceiling, named extraction and derivation Functions, and an
output allowlist. Private source facts stay inside Evidence.

| Definition | Purpose | Output |
| --- | --- | --- |
| `adult-status` | `age-check` | Boolean, calculated at the governed observation time in `Asia/Bangkok` |
| `residence-region` | `residence-check` | `north` or `south` |
| `professional-licence-status` | `licence-check` | `active`, `suspended`, or `expired` |
| `legal-parent-relationship` | `relationship-check` | Boolean for the child and candidate-parent roles |

Use matching versions of `evidence` and `evidencectl`, Python 3, curl, and Docker.
Start from a writable copy outside the repository. Keep the example's generated
credentials and responses private. The commands below run in that copy.
The tracked `access/clients/example-caller.yaml` demonstrates the public client
format only; the commands create the private local `demo` client used below.

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
evidencectl access client add demo --access-profile standalone-service --generate-local-key
```

In another terminal, run the source from the same directory:

```sh
python3 serve-source.py --port 8081 --token-file .generated/secrets/synthetic-source-token
```

Start Evidence and its local issuer. The first run may fetch the pinned issuer
image. The source uses port 8081 and the issuer uses 8082. If 8080 is occupied,
set `EVIDENCE_PORT=18080` before running this block; select another free Evidence
port when needed.

```sh
EVIDENCE_PORT=${EVIDENCE_PORT:-8080}
evidencectl dev start . --target local-target.yaml --evidence-port "$EVIDENCE_PORT" --issuer-port 8082
evidencectl request prepare adult-status --client demo --purpose age-check --subject subject:record-id=adult --name adult
curl --silent --show-error --fail-with-body \
  --config .evidence/requests/adult/authorization.curl \
  --header 'Content-Type: application/json' \
  --data-binary @.evidence/requests/adult/request.json \
  "http://127.0.0.1:$EVIDENCE_PORT/v1/evidence" > .evidence/requests/adult/response.json
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
this fresh local project, the generated secrets already exist. Keep the local
issuer running until preflight finishes so its verification keys are available:

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

Stop and clean the local services when finished, then interrupt the source:

```sh
evidencectl dev stop .
evidencectl dev clean .
```
