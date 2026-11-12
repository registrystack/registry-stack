# Payment collection project

This project accepts one authoritative BReg bill reference, requests collection
through the Adapter connection `licence-fees`, waits for its named `collection`
completion, and records the exact confirmed receipt. The Adapter owns the
provider attempt and BReg reporting authority. Coordinator supplies only
`billId`, `billVersion`, the saved command identity, and workflow sequencing.

The workflow has three terminal outcomes:

- `receipt-recorded` returns the Adapter's exact `RegistryReceipt`. This is the
  only outcome that may release the paid service.
- `collection-failed` returns the verified failed collection status. It does
  not record a receipt or release the service.
- `collection-unresolved` has no output. A wait timeout, or any accepted,
  pending, or unknown state that reaches the route, takes this outcome. It does
  not prove failure and must not release the service or authorize a new attempt.

An uncertain `request-collection` or `record-receipt` call does not reach a
terminal outcome. Inspect it. Reconcile `request-collection` through its
read-only original-request lookup. Recover `record-receipt` with
`retry-same`, which reuses the saved command and key. Do not start a new run
or send a fresh command. This also applies to an ambiguous
`adapter.payment.provider-protocol` response after dispatch.

## Check and package

From the repository root, use binaries built from this checkout:

```sh
coordinatorctl check --project products/coordinator/examples/payment-collections --explain
coordinatorctl test --project products/coordinator/examples/payment-collections
coordinatorctl package \
  --project products/coordinator/examples/payment-collections \
  --output /absolute/private/payment-collections-package
```

Copy `runtime.yaml` outside the package. Replace its package root and
digest with the package command's output. Set the actual database URLs,
PostgreSQL role, issuer, JWKS source, Adapter and token endpoints, listener,
secret root, and audit path. The loopback values match the neighbouring
synthetic Adapter example, but they name real processes in a joined run, not
HTTP doubles. Then run the normal deployment sequence:

```sh
coordinatorctl --runtime-config /absolute/path/runtime.yaml check --deny-warnings
coordinatorctl --runtime-config /absolute/path/runtime.yaml plan
coordinatorctl --runtime-config /absolute/path/runtime.yaml apply
coordinatorctl --runtime-config /absolute/path/runtime.yaml deployment-status
coordinator --runtime-config /absolute/path/runtime.yaml
```

The runtime's payment connection must select Adapter connection
`licence-fees`. That Adapter connection is bound to BReg institution
`institution-a`, service `licence-issuance`, and a synthetic USD 25.00 bill.
Replace `input.example.json`'s UUID with the root UUID returned by the fixture's
`create-fee-bill` Action. Its protocol `billVersion` is `1`, not the BReg
record revision or HTTP condition.

## Identity requirements

Coordinator's outbound payment credential is a confidential OAuth client:

- The client identifier is `coordinator-payments`, and its private signing JWK
  is available at `secret:file/coordinator-payments-jwk`.
- Its token request asks for resource `urn:registry:payment-adapter` and scope
  `payments:collect`. The issued token's audience must equal Adapter's
  configured audience. The issuer registers the signing key and permits that
  exact grant.
- Adapter verifies that token, resolves the caller as `coordinator-payments`,
  and admits it to `licence-fees`. Coordinator receives no Adapter reporter's
  BReg bill-binding or receipt-reporting grants.

Coordinator's inbound caller tokens are separate:

- The runtime sets `scopeClaim: scope`, so both tokens carry their scopes in
  the standard `scope` claim rather than Coordinator's default
  `registry_scopes` claim.
- The licence service token has Coordinator's configured issuer and audience,
  exact subject `licence-service`, scope `coordinator:start`, and no `act`
  claim. Policy `licence-service` permits `start` and `status` only for
  `payment-collections`.
- The operator token has the same issuer and audience, exact subject
  `payment-operator`, scope `coordinator:operate`, and no `act` claim. Policy
  `payment-operator` permits inspection and exact-command recovery. It is not
  a payment-provider or BReg reporter credential.

If the joined issuer emits different service-account subjects, copy the exact
verified `sub` values into the two policies and use those tokens consistently.
Do not assume a client identifier is also its token subject.

## Start and observe one joined run

Write the actual bill input to a private file. Write a unique logical request
key and each access token to separate regular files with mode `0600`; never put
tokens on the command line. Discover the active revision, then pass that exact
revision to `start`:

```sh
coordinatorctl --format json workflow \
  --workflow payment-collections \
  --url http://127.0.0.1:8108 \
  --token-file /absolute/private/licence-service.token

coordinatorctl --format json start \
  --workflow payment-collections \
  --workflow-revision sha256:<revision-from-workflow> \
  --input /absolute/private/payment-input.json \
  --key-file /absolute/private/payment-run.key \
  --url http://127.0.0.1:8108 \
  --token-file /absolute/private/licence-service.token

coordinatorctl --format json status \
  --run <run-uuid-from-start> \
  --url http://127.0.0.1:8108 \
  --token-file /absolute/private/licence-service.token
```

The same producer subject owns the run and may read its status. Use the
operator token for bounded diagnostics and recovery:

```sh
coordinatorctl --format json inspect \
  --run <run-uuid> \
  --url http://127.0.0.1:8108 \
  --token-file /absolute/private/payment-operator.token

coordinatorctl --format json reconcile \
  --run <run-uuid> \
  --reason joined-payment-response-loss \
  --url http://127.0.0.1:8108 \
  --token-file /absolute/private/payment-operator.token

coordinatorctl --format json retry-same \
  --run <run-uuid> \
  --reason joined-receipt-response-loss \
  --url http://127.0.0.1:8108 \
  --token-file /absolute/private/payment-operator.token
```

Do not use either recovery command merely because collection status is pending
or unknown. The named completion performs read-only status observations at the
configured 60-second floor. Use `reconcile` only for a held
`request-collection`, and `retry-same` only for a held `record-receipt`, as
reported by inspection. After a terminal status,
accept only named outcome `receipt-recorded` and verify its bill ID, bill version,
collection ID, binding revision, exact money, provider reference, simulation
flag, and receipt ID before the service proceeds.
