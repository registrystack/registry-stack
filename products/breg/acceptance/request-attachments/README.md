# Request attachments acceptance

This synthetic local project declares one required PDF slot on a reviewed label
correction request. The target record permits direct creation and requires a
reviewed request for patches. Five explicit development clients distinguish the
operator, request owner, another owner, reviewer and applier. Review and apply
authority is intentionally registry-wide within this disposable fixture; owner
reads and attachment writes remain restricted to the request owner.

`tests/journeys.yaml` uses the maintained journey format to prove that an
incomplete draft can be created and read. Binary uploads use the public HTTP API
in the executable acceptance runner, without extending the fixture language.

From the repository root, build matching binaries and run:

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo build --locked -p registry-breg --features runtime -p registry-bregctl \
  -p registry-mint --bins
python3 products/breg/scripts/test-request-attachments.py
python3 products/breg/scripts/test-request-attachments.py --verification
```

The runner needs Docker. It copies this authored project into an owner-only
temporary directory and invokes `bregctl check` and the maintained `bregctl dev`
lifecycle. Native dev creates its own TLS PostgreSQL container, separate test and
live databases, migration/runtime roles, local issuer, schema-test receipt,
signed package and activated runtime. The runner never modifies another
project's database or services. `--bin-dir DIR` selects another matching binary
installation. `--keep` preserves private reports after success.

The live journey proves required-slot submission refusal, unauthorized owner
access refusal, upload concurrency, server-computed size and hash, exact owner,
reviewer and applier downloads, review, application and operator retention
list/dry-run/erase. It briefly revokes a storage INSERT privilege inside its own
disposable database, verifies that upload fails without retaining content, then
restores the privilege and retries the same upload key and precondition. Erased
bytes become unavailable through the same authenticated download route.

Cleanup uses `bregctl dev stop --remove` for the container and volume created by
this run. Failed runs keep owner-only diagnostics while still reclaiming their
owned database. This journey verifies default PostgreSQL content storage; the
separate S3 storage tests establish optional backend interoperability.

The `--verification` path additionally needs PyYAML. It starts a controlled
loopback HTTP verifier and a second owned BReg listener with an operator
`attachmentVerification` configuration against the activated disposable
database. The original development listener remains idle. The verifier secret
is passed through the child process environment and is never printed or written
to a file.

This path proves that uploads acknowledge while the verifier response is held,
that pending evidence cannot be downloaded or submitted, and that a failed
verification attempt retries before approval releases exact bytes. Approval
changes the response ETag while preserving the request record revision.
Replacement bytes receive their own verdict: rejected evidence stays unavailable, then an
approved replacement completes review, application and retention erasure.
Cleanup stops both additional listeners before removing native development
resources.
