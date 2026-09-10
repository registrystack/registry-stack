# Registry Casework checkpoint

Registry Casework gives a team one accountable inbox for a governed Base
Registry Engine change request. The checkpoint deliberately supports one BReg
source, one review stage with one required approval, one default queue, manual
application, and a passive 48-hour target measured from first observation.

Start with authored inputs and inspect every source-side change before writing
it:

```sh
caseworkctl init ./casework --template professional-review
caseworkctl source add ./registry \
  --project ./casework --source-id professional-register
caseworkctl source add ./registry \
  --project ./casework --source-id professional-register --apply
caseworkctl check ./casework
caseworkctl test ./casework
```

`source add` drives the same-version public `bregctl check` and `bregctl explain
change-requests` interfaces. Preview reports the exact local BReg event and
read-only service grant additions plus a runtime destination candidate. Apply
checks a staged copy before changing the authored registry, writes the imported
source description and runtime candidate, and checks BReg again. It does not
activate a package, provision an identity provider, or infer authority from the
imported metadata. Existing authored content is retained and conflicting ids
are refused.

`check` and `test` are offline. Check prints effective inbox limits and the
passive target default. When source metadata has been imported, it also refuses
anything except the supported single-stage, one-approval, manual-application
contract. Test evaluates the maintained synthetic fixture against those same
effective inputs.

After the operator supplies the separate runtime configuration and credentials,
the local workflow is:

```sh
caseworkctl db migrate ./casework --operator ./casework/operator.yaml
caseworkctl dev start ./casework --operator ./casework/operator.yaml
caseworkctl doctor ./casework --operator ./casework/operator.yaml
caseworkctl dev events ./casework
caseworkctl dev stop ./casework
```

Doctor distinguishes configuration, database, source, issuer, and directory
readiness. Directory setup is an ordinary authenticated Administrator API call;
administrator status does not grant BReg review or application authority.

The `casework` runtime serves plain HTTP behind operator-controlled TLS
termination. Runtime configuration must declare
`tlsTermination: operator-controlled-upstream`; `networkExposure` defaults to
`private-address`, which accepts loopback and private addresses and rejects
public and wildcard binds. A container that needs a wildcard bind must declare
`networkExposure: container-private` and keep the published listener on a
private container network. Browser requests go to the App Kit host, which calls
Casework server to server, so the Casework API does not enable CORS. Apply HSTS
on the proxy's TLS responses. The runtime applies its remaining security
headers and `Cache-Control: no-store` before returning a response.

For direct local development without a proxy, declare
`tlsTermination: development-loopback`. That mode accepts only a loopback
listener with `networkExposure: private-address`; it cannot be combined with a
private LAN address, a wildcard listener, or `container-private`.

Casework accepts Administrator, Supervisor, and Staff credentials only when
the trusted issuer asserts the configured human identity claim. The operator
binding defaults to `humanIdentity: {claim: registry_actor_kind, value: human}`.
Configure the issuer to add that exact assertion only to interactive human
sessions. Client-credentials and other service tokens must omit the claim or
assert another string such as `service`. A missing, different, or non-string
claim is refused even when the token has valid Casework scopes and names a
directory member. Casework does not infer a human actor from a subject, client
identifier, or scope. This boundary relies on the configured trusted issuer to
classify sessions correctly.

The generated source reader has only BReg `get` and `list`, reads only the
target record reference, requests no reviewer reason fields, and carries no
decision or application operation. Human review and application calls use the
person's token and explicitly selected BReg profile.

Synchronization orders observations by the physical BReg record revision. At
the same revision, a changed HTTP representation ETag refreshes the existing
occurrence, including attachment verification changes. The representation ETag
is an equality check, not an ordering value or an action precondition. Periodic
readback repairs missed events while preserving claims, first-observation
timing, and unresolved action recovery.

The HTTP contract is generated deterministically from the Rust-owned problem
catalog and per-operation response table. The generator also checks the exact
router inventory, header constants, request extraction shape, success statuses,
and serialized DTO fields before it writes the document:

```sh
python3 products/casework/scripts/generate_openapi.py
python3 products/casework/scripts/generate_openapi.py --check
```

The local checkpoint wrapper runs that OpenAPI drift check, the dependency
guard, every product script test, and the offline authoring journey. Build
`caseworkctl` first or set `CASEWORKCTL_BIN`:

```sh
products/casework/scripts/check-checkpoint.sh
```

The dependency-direction guard reads Cargo metadata, including transitive
dependencies:

```sh
python3 products/casework/scripts/check_dependency_direction.py
python3 -m unittest products/casework/scripts/test_dependency_direction.py
```

The PostgreSQL checkpoint tests deliberately require two **distinct,
disposable** databases. They reset their schemas and must never point at
retained operator data. Create both databases, export their URLs separately,
and enable the `postgres-test` feature:

```sh
export CASEWORK_TEST_DATABASE_URL=postgresql://localhost/casework_transactions_test
export CASEWORK_VISIBILITY_TEST_DATABASE_URL=postgresql://localhost/casework_visibility_test
cargo test -p registry-casework --features postgres-test --test postgres_transactions --locked
cargo test -p registry-casework --features postgres-test --test service_visibility --locked
```

The two variables must not resolve to the same database. The transaction suite
uses `CASEWORK_TEST_DATABASE_URL`; the disclosure, authorization, pagination,
outage, and HTTP boundary suite uses
`CASEWORK_VISIBILITY_TEST_DATABASE_URL`. A missing variable fails visibly rather
than silently skipping the required proof.

Install the kit dependencies and browser from the [demo prerequisites](demo/README.md),
then run the automated technical checkpoint with the matching App Kit checkout:

```sh
products/casework/demo/run.sh \
  --app-kit-worktree /path/to/registry-app-kit \
  --evidence-dir /path/outside/product/checkouts/checkpoint-evidence
```

The verifier builds the current sources and local client candidate, starts
isolated services, and exercises the authenticated journey against BReg,
PostgreSQL, and the App Kit host. It requires Docker, Rust, Node.js, and Python
3. Keep both source trees unchanged during verification. Store the evidence
outside every Git repository. Automated results do not establish the value
checkpoint or replace its human comparison of the interface and first-use
experience.
