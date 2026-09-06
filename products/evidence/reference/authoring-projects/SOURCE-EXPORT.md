# Optional local source exports

Source import is an optional authoring convenience for providers which publish
complete fixed-source artifacts. Existing authored sources and the OpenAPI
authoring workflow need no manifest, import state, or migration.

An export carries ordinary source, selector, schema, and adapter files. It does
not contain question meaning, caller grants, credentials, installation hooks,
or executable setup commands. Import reads local files only. It never contacts
the provider, runs external setup commands, creates authority, or starts a
service. Target validation may execute reviewed bounded adapters against local
synthetic fixtures through the ordinary Evidence evaluator.

## Export manifest version 1

The export directory contains `source-export.json`:

```json
{
  "formatVersion": 1,
  "sourceId": "registry-status",
  "provenance": {
    "producer": "institution-source-exporter",
    "revision": "reviewed-provider-revision"
  },
  "artifacts": [
    {
      "path": "sources/registry-status.yaml",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

The checksum above is illustrative. Each actual `sha256` is the lowercase
64-character SHA-256 checksum of that file's exact UTF-8 bytes. The manifest and
artifact entries are closed objects; unknown fields are refused. The manifest
is at most 1 MiB and inventories 1 to 256 artifacts, each at most 1 MiB and at
most 16 MiB together. `provenance` is a map of 1 to 32 nonempty printable string
pairs, with keys up to 64 bytes and values up to 2048 bytes. Producers should
record their name, provider revision, and the selected technical contract.
Provenance is attribution and review context, never proof of provider authority.

One export inventories exactly `sources/<sourceId>.yaml` and its auxiliary
artifacts under `selectors/`, `schemas/`, and `adapters/`. Source, selector, and
schema files use `.yaml`; adapter files use `.rhai`. YAML files must contain
mapping objects. Names are bounded lowercase authoring names. Paths have
exactly two components and cannot be absolute, contain `.` or `..` components,
backslashes, or symbolic links. Files must be regular files with one hard link.
The ordinary authoring compiler remains the authority for usable document
names, types, references, and adapter contracts.

The `sourceId` and all artifact paths are stable identities. They must not
contain an export directory name, provider revision, or content checksum.
Moving an export directory does not change its identity. Reordering its
manifest inventory has no effect. A shared artifact uses exactly the same path
and bytes in every export which owns it. A conflicting definition is never
silently renamed. Producers namespace source-specific artifacts by the source
ID and shared artifacts by a stable, unambiguous technical identity.

A provider's optional consumed-behavior identity belongs in the source's
ordinary `behaviorRevision: sha256:<64 lowercase hexadecimal characters>`
property. A manifest provenance change alone is not a runtime question
revision. The authoring compiler and runtime own dependency closure and actual
question revision computation.

## Compare and accept

```sh
evidencectl source import ./exports/registry-status --project ./evidence
evidencectl source diff ./exports/registry-status-next --project ./evidence
evidencectl source update ./exports/registry-status-next --project ./evidence
```

Pass several export directories together when changing a shared artifact. The
complete candidate set must agree with every installed owner of that artifact.
Passing only one of two owners with changed shared bytes reports both owners
and refuses application until their definitions agree.

Comparison uses three separate inputs for each stable artifact path:

1. Exact bytes from the previously imported upstream export.
2. Current authored bytes, including local changes or deletion.
3. Exact bytes from the next export.

If upstream is unchanged, current customization is preserved. If current bytes
still match the previous upstream, an upstream change is safe to propose. If
current bytes already match the next upstream, that result is accepted. A
different local edit and upstream change require an explicit resolution. No
program is automatically merged. Existing unowned destinations also require
an explicit choice, even if their bytes are identical.

The report lists additions, changes, deletions, unchanged/customized/retained
artifacts, previous and next owners, content checksums, conflicts, provenance
changes, and structurally affected question names. Checksums identify authored
artifact content, not deployment revisions. An optional `--target` asks the
normal compiler/build path to compare actual question revisions under that
complete target. Without it, the report contains structural impact only.
Structural validation checks the complete source artifact graph and any
existing questions without requiring a target, local credentials, or a first
question. The report identifies its validation kind explicitly. Target
validation runs the ordinary compiled-bundle and fixture checks. If the current
project cannot yet compile with that target, as before an initial source
import, `previousValidation.status` is `unavailable`; the report carries only
actual next revisions and supplies no invented previous revision.

Diff does not change authored files or the imported baseline. A temporary
candidate contains only ordinary authored files and is removed when the
command finishes. The original export directories retain the next generated
files for review. It copies no secret directory, target, access state, local
requests, audit history, or running-service state. Candidates are bounded to
4096 authored files, 64 MiB total, and 16 directory levels.

## Finish a customization conflict

Write an explicit resolution file and supply it to diff or update:

```json
{
  "formatVersion": 1,
  "artifacts": {
    "adapters/registry-status-extract.rhai": {"choice": "keep"},
    "schemas/registry-status-response.yaml": {"choice": "adopt"},
    "adapters/registry-status-prepare.rhai": {
      "choice": "file",
      "path": "reviewed/registry-status-prepare.rhai"
    }
  }
}
```

```sh
evidencectl source diff ./exports/registry-status-next --project ./evidence \
  --resolutions ./source-resolutions.json
evidencectl source update ./exports/registry-status-next --project ./evidence \
  --resolutions ./source-resolutions.json
```

`keep` retains the current authored bytes or deliberate absence. `adopt` accepts
the next generated bytes or deletion. `file` accepts the exact bounded local
file named, resolving relative paths from the resolution file's directory.
The full candidate graph is validated again after resolution. All choices
advance the upstream baseline separately from the exact accepted local bytes,
so a kept customization remains visible on the next upstream change.

Obsolete files are deleted only when previously owned, unchanged or explicitly
adopted for deletion, and no other owner or authored reference needs them. A
conservative exact-reference check retains a file still named elsewhere. It
does not rewrite the referencing document. A local edit is never silently
deleted. Unrelated authored artifacts are preserved byte for byte.

To take over maintenance of an imported source:

```sh
evidencectl source detach registry-status --project ./evidence
```

Detachment keeps every file, upstream provenance, and the accepted authored
snapshot. Later updates of that source ID are refused; continue maintaining
its ordinary files, or publish a distinct source ID. Shared artifacts still
used by the detached source require explicit review before another import
changes them. Detaching is idempotent.

## Local transaction and interrupted recovery

Import and build acquire the same operating-system file lock, keyed by the
canonical project directory. The lock lives in an owner-private temporary
directory, so ordinary builds do not need a writable project or an import
setup step. Concurrent operations fail with an actionable retry message.

Only accepted imports create `.evidence/source-imports/state.json`. It records
each upstream manifest and exact bytes, accepted local content, retained
obsolete artifacts, and detached provenance. No source record or credential
belongs there. Keep this state with the authoring project if future updates
must retain their three-way comparison history.

Before application, the tool validates the complete candidate and rechecks the
entire authored snapshot plus baseline against what was compared. A changed
file requires a fresh comparison. Under the lock it durably writes a bounded
rollback journal, replaces complete files atomically, and advances the baseline
last. Removing the journal commits the complete state. Directory and file
writes are synchronized. This is a local filesystem transaction, not a
runtime deployment, service, database, or workflow engine.

An interrupted transaction leaves the journal. The next import or build
acquires the lock and restores its complete prior state before reading
authored files. Recovery checks all journal entries before changing any file.
The project and `.evidence` directories must be owned and not writable by other
users; the import state directory must be owned mode 0700, and its journal and
baseline must be owned regular mode 0600 files. These checks apply before replay
and do not impose a new project permission requirement when no journal exists.
If an independent edit matches neither the recorded before nor after bytes,
recovery stops and names only the artifact path. Preserve that edit, restore
the recorded before or after content, then retry. The journal remains available
for recovery; unrelated or conflicting content is never overwritten.

Editors and other tools do not take this lock. Content preconditions detect
their edits before application; preserve the project from independent writes
during the short application window. A running Evidence process continues to
serve its previously built immutable bundle throughout authoring updates.
