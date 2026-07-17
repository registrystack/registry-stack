# Deployment hardening runbook

## Before deployment

- Generate product inputs from one reviewed Registry Stack project.
- Confirm the topology is Relay-only, Notary-only, or combined as intended.
- For combined deployments, verify Notary and Relay expect the same semantic
  consultation contracts and hashes.
- Keep source destinations and credentials only in Relay's private environment.
- Keep the Notary workload token, signing keys, audit secret, and store
  credentials in mounted secret files or an approved secret manager.

## Network boundary

Expose only the public Notary listener to application callers. Put admin routes
and metrics on the dedicated operator listener, restrict it at the network
layer, and require the configured operator scopes. A combined deployment
permits Notary to reach only its project's Relay. Notary requires no path to a
registry source.

For a private Relay, admit only exact reviewed CIDRs and retain the platform's
always-denied metadata, loopback, link-local, multicast, and unspecified
address protections. Use TLS in deployed environments.

## Authentication and authorization

- Configure one supported caller authentication mode and fail closed on missing
  credentials.
- Review purpose, legal basis, scopes, relationship, and disclosure together.
- For self-attestation, pin issuer, audience, client, algorithm, token lifetime,
  and exact subject binding.
- For delegated requests, require exact authorization details and proof policy
  before any Relay call.

## State

Install the typed Notary-owned PostgreSQL correctness-state schema for every
production or multi-instance deployment. Run `state doctor` with the restricted
runtime role before admitting traffic. Back up the complete database, role
provisioning, migration set, and sensitive-state key version with their owning
release. Do not share Relay tables, Notary schemas, audit keys, or audit chains.

## Audit and diagnostics

Ship Notary's redacted keyed audit chain to the approved retention system. Keep
access to Notary and Relay audit sinks restricted. Correlate them only through
the bounded evaluation and consultation identifiers.

Review diagnostics and logs for accidental disclosure. They must not contain
tokens, secret paths, selectors, request bodies, source responses, claim
values, credential material, or script values.

### Recover an inconsistent audit chain

Registry Notary verifies the retained audit chain during runtime activation.
A confirmed chain fork or verification failure keeps `/ready` at `503` with
the code `audit.chain.inconsistent`; `/healthz` remains a process-liveness
probe. The readiness response does not expose audit records, paths, hashes, or
verification details.

Recovery is an offline operator action. Registry Notary does not repair the
chain automatically at startup.

1. Stop the Registry Notary process and confirm that no replacement process
   holds the audit volume's single-writer lock.
2. Preserve the audit volume and the off-host copy according to the incident
   evidence procedure.
3. Run the quarantine command with the same configuration and secret sources
   used by the stopped process:

   ```sh
   registry-notary audit quarantine \
     --config <generated-notary.yaml> \
     --reason "<incident-or-change-reference>" \
     --operator "<operator-id>"
   ```

4. Retain every file named with the reported `corrupt-<timestamp>` suffix.
   The command moves the retained chain aside and starts a new segment with a
   keyed `audit.chain.break` record linked to the last verified local record.
5. Start Registry Notary, then verify `/ready` before admitting traffic.

The command refuses to run against `stdout` or `syslog`, and it refuses to run
while the server owns the file sink lock. A signed-bundle acceptance record
must still be written before bundle state is persisted or traffic is served.
An audit failure during that write aborts the governed boot.

## Signing keys

Approve custody for every credential, access-token, or federation signing role
before declaring production readiness. Provider kind is not proof of custody.
Rotate with a new key id and governed project/configuration change unless a
documented same-identity file refresh is specifically supported.

## Rollout

For blue-green rollout, stage a complete Relay and Notary generation without
traffic, verify both products, then switch. For drain-and-restart, stop new
traffic, drain active work, restart both products, verify readiness, and
resume. A mixed semantic contract generation must remain unavailable.

Run:

```sh
registry-notary explain-config --config generated-notary.yaml
registry-notary doctor --config generated-notary.yaml
registry-notary --config generated-notary.yaml state doctor
registry-notary doctor --config generated-notary.yaml --live
```

Then execute the project's offline fixtures and approved end-to-end journey.
Never load secrets through command-line values or retain them in test evidence.

## Incident response

If a workload credential, signing key, caller credential, or audit secret may
be exposed, revoke or rotate it first, stop affected traffic, preserve redacted
audit evidence, and activate a fully compatible generation. Do not restore a
direct source path as a recovery mechanism.
