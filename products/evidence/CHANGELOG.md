# Registry Evidence changelog

## Unreleased

- BREAKING: `evidencectl` follows the shared ctl report and exit contract.
  - Under `--format json` every command writes one object on standard output
    and nothing on standard error. It opens with `ok`, `command`, and
    `status`, then the command's own members, and every member name is
    camelCase; a map keyed by authored identifiers, such as
    `selectorProfiles`, keeps those identifiers as its keys.
    The former `operation` member is replaced by `command`. Refusals use the
    same object with `ok: false` and diagnostics that name the next command.
    A command-line error reports `command: "usage"` and `status:
    "usage-error"`.
  - `fixtures run` and `test` reports rename `evaluated_cases`,
    `failing_case`, `expected_class`, and `observed_class` to
    `evaluatedCases`, `failingCase`, `expectedClass`, and `observedClass`.
    A run that evaluated no case carries the diagnostic
    `evidencectl.fixtures.no-case`.
  - `source suggest` notes move from standard error into the report's
    `notes` member, and its equivalent command names the project
    positionally.
  - Exit classes are `0` success, `1` domain refusal or failing fixture, `2`
    usage, and `3` operational failure. A file that cannot be read or a
    missing local dev session now exits `3` instead of `1`.
  - Every command that reads one project takes it as a positional
    `<project>`. The former `--project` flag stays accepted but hidden on
    those commands; `source import`, `source diff`, `source update`, and
    `target new` still document it. `access` and `audit show` still act on
    the current directory and take no positional project.
  - `test` and `fixtures run` accept `--format junit`: one JUnit XML document
    on standard output, one test case per traced case, and the human summary
    on standard error. Other commands refuse it as a usage error.
  - `dev start --name-prefix <prefix>` sets the local issuer container name
    prefix, `evidence-dev` by default, so parallel jobs on one host keep
    their containers apart. A restart without the flag reuses the session's
    prefix, and a different prefix is refused until `dev clean`.
  - To migrate, read `command` instead of `operation`, read the camelCase
    fixture keys, parse JSON reports from standard output alone, treat exit
    `3` as an unavailable dependency, and replace `--project <dir>` with
    `<dir>` in scripts for the commands that now take a positional project.

## v0.35.0 - 2026-09-28

- BREAKING: write audit through the shared platform audit writer instead of
  the keyed hash chain. Every entry is one JSON line with the members
  `schema`, `eventId`, `time`, `phase`, `correlation`, and `record`: an access
  attempt is a `request` entry, every terminal record a `response` entry, and
  `correlation` is the record's `operation`. Entries are not chained; ship
  them to append-only storage for tamper evidence.
  - The entry schemas are `registry.evidence.audit/v2`,
    `registry.evidence.audit.request-batch/v2`, and
    `registry.evidence.audit.authorization-refusal/v2`. The record no longer
    carries a `schema` member, and readers written for the chained `/v1`
    records do not read `/v2` entries.
  - The bundle `audit` section is now `hashKeyRef` and `hashKeyVersion`, both
    required. `format`, `hashSecretRef`, and `failClosed` are refused; every
    audit gate stays fail closed. Pseudonyms keep their
    `hmac-sha256:v<hashKeyVersion>:` prefix and are byte-identical for the same
    master and version.
  - The runtime `auditStorage` block is replaced by `audit`: `destination`
    (`file` by default, or `stdout`), `path` (required for `file`),
    `rotateBytes` (at least 1 MiB, 100 MiB by default), and `retainDays` (1 to
    36,500, 90 by default). Sealed files older than `retainDays` are deleted
    when the writer opens or rotates. `maximumFileBytes` is refused.
    `evidence check --require-audit-under` refuses a `stdout` destination.
  - `evidence verify-audit` is removed, and startup no longer verifies a chain.
    The runtime can no longer detect an audit master replaced without a
    `hashKeyVersion` change; the documented key rotation procedure owns that.
  - The `evidence_audit_segments` and `evidence_audit_bytes` metrics are
    removed.
  - `evidencectl doctor` checks a file audit destination with the audit
    writer's own rule and skips a `stdout` destination. `evidencectl target
    new` and the local bundles and runtime files `evidencectl` renders write
    the new `audit` blocks.
  - To migrate, rewrite the bundle `audit` section to `hashKeyRef` and
    `hashKeyVersion` and the runtime `auditStorage` block to `audit`, archive
    the old chained audit files to append-only storage, and point
    `audit.path` at a fresh file in a directory that holds no old sealed
    segments: retention deletes sealed files under the same name older than
    `retainDays`. Update audit readers to the `/v2` envelope
    before routing traffic to the new runtime.
