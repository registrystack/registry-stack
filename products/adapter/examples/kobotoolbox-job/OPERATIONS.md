# Operate a KoboToolbox ingestion job

Use this runbook to initialize and operate one controlled KoboToolbox
ingestion pilot from the maintained example.
The job reads one bounded source page per pass and sends each reviewed
projection to one chosen destination.
The maintained KoboToolbox pack has synthetic fixture coverage. The maintainers
ran the direct job once with synthetic data on a real KoboToolbox 2.026.37c
server, but no run record is committed, and the Coordinator and hook jobs have
no equivalent run. Treat both as unverified until your own pilot repeats them.

## Prerequisites

Install an independently runnable `adapter-job` binary built from the reviewed
Registry Stack source checkout.
The binary is source-build-only and has no numbered-release artifact or
installer path.
Build with exactly one destination feature for the chosen job, plus `job-hook`
for the hook job:

- `direct-breg` for `job.yaml` and `job-runtime.example.yaml`.
- `signed-coordinator-event` for `job.coordinator.yaml` and
  `job-runtime.coordinator.example.yaml`.
- `job-hook,direct-breg` for `job.hook.yaml` and
  `job-runtime.hook.example.yaml`; the hook job needs `job-hook` beside its
  destination feature.

From the reviewed checkout root, build the selected feature into a dedicated
target directory:

```sh
CARGO_TARGET_DIR=<absolute-build-dir> PATH="$HOME/.cargo/bin:$PATH" \
  cargo build --locked --release \
  -p registry-adapter-job \
  --features <direct-breg-or-signed-coordinator-event>
```

Keep the workspace FIPS crypto configuration enabled.
Install the binary with the exact runtime libraries produced by that build.
On macOS, follow the source checkout's `CONTRIBUTING.md` procedure for the
exact AWS-LC FIPS dynamic library rather than copying a library selected by a
path pattern.
A successful Cargo build alone does not establish that the installed binary
can find its runtime libraries.

Provision a dedicated PostgreSQL database, schema, and role outside `adapter-job`.
The command does not create or drop a database, schema namespace, role, or grant.
The role named by `store.runtimeUrlRef` must connect over verified TLS, create
and alter the job tables, and perform the runtime reads and writes.
The same reference serves the job and applies compatible migrations, so the
role retains data definition authority.
This runtime does not implement separate migration and serving roles.

Prepare the source and one destination:

1. Confirm the KoboToolbox deployment matches the probe results and remaining
   limits in the maintained pack README, including stable `_id`, changing
   `_uuid`, sorted keyset reads, edit discovery, and form size.
2. Bind `kobo-api` to the selected form's
   `/api/v2/assets/<asset-uid>/data` URL and give the job a source account
   restricted to that form.
3. For the direct job, configure the reviewed Base Registry Engine (BReg)
   Action, mapping, ingestion access profile, and narrowly scoped BReg
   credential. The [`kobotoolbox-breg`](../kobotoolbox-breg/README.md) example
   is the BReg project that matches the job's mapping and access profile.
4. For the Coordinator job, configure the reviewed event trigger and
   workflow, provision its signing key, and keep the host clock within 30
   seconds of Coordinator's.

Choose one destination before the first pass.
Do not run both jobs against one form, and do not fall back from a refusal to
the other destination.

## Prepare the runtime files

Copy the example directory into the deployment's configuration workspace.
Select one pair and use the same pair in every command:

- Direct BReg Proposal: `job.yaml` and `job-runtime.example.yaml`.
- Coordinator workflow: `job.coordinator.yaml` and
  `job-runtime.coordinator.example.yaml`.

Replace the synthetic origins, identifiers, scopes, and mappings with reviewed
deployment values.
The reusable pack stays outside the example directory at
`products/adapter/packs/kobotoolbox/pack.yaml` in the reviewed checkout.
Pass the example's `profile.yaml` and `project.yaml` explicitly because the
binary otherwise looks beside the pack.

Keep credentials and database URLs outside every YAML file.
The runtime accepts environment secret references such as
`secret:env/ADAPTER_JOB_DB`; inject the referenced values through the service
manager or deployment secret facility.
Do not paste secret values into commands, shell history, checked files, logs,
or review records.

The commands in this runbook use these placeholders:

- `<job-file>` is the selected absolute job path.
- `<runtime-file>` is its matching absolute runtime path.
- `<example-dir>` is the absolute deployment copy of this example.
- `<source-checkout>` is the reviewed Registry Stack checkout used for the
  build.

## Initialize the store

Initialize the existing PostgreSQL database before a preview or observational
command:

```sh
adapter-job init-store --runtime <runtime-file>
```

`init-store` requires only `--runtime`; it needs no job, pack, profile, or
project.
CLI-wide flags remain accepted, but initialization output stays value-free.
`init-store` parses the complete runtime document, resolves only the store
connection and optional store trust reference, and applies embedded schema
versions `100` through the highest this release supports (`status` before
`init-store` names the version) under the migration lock.
The command is idempotent and creates no job-state or item row.
The command does not resolve source or destination credentials and causes no
source or destination effect.

If the store is missing or behind, `status`, `inspect`, and `pass --dry-run`
refuse and name `init-store`; they never migrate the store themselves.
If `init-store` cannot connect or migrate, correct the PostgreSQL authority,
TLS trust, or referenced secret and rerun the same command.

## Check the selected job

Compile the exact deployment artifacts and preflight the source credential:

```sh
adapter-job check <job-file> \
  --pack <source-checkout>/products/adapter/packs/kobotoolbox/pack.yaml \
  --runtime <runtime-file> \
  --profile <example-dir>/profile.yaml \
  --project <example-dir>/project.yaml
```

`check` does not contact KoboToolbox or activate the destination credential.
A successful check establishes that the files compile together, not that the
source or destination is reachable.

Read the fresh store before any pass:

```sh
adapter-job status <job-file> --runtime <runtime-file>
```

A fresh initialized store reports zero item counts and is not overdue.
The read creates no job row.

## Preview one source page

Run one preview against the actual KoboToolbox source:

```sh
adapter-job pass <job-file> \
  --pack <source-checkout>/products/adapter/packs/kobotoolbox/pack.yaml \
  --runtime <runtime-file> \
  --profile <example-dir>/profile.yaml \
  --project <example-dir>/project.yaml \
  --dry-run
```

The preview reads one bounded source page, delivers nothing, and writes no
lease, item, position, or schedule state.
Output omits projected values by default.
Do not add `--show-values` to an operational run unless the projected personal
data has an approved destination and handling procedure.

The preview is not a source snapshot.
Run the first real pass promptly after reviewing the preview, and account for
source edits between the two reads.

## Run a bounded pass

Run one bounded operational pass by removing `--dry-run`:

```sh
adapter-job pass <job-file> \
  --pack <source-checkout>/products/adapter/packs/kobotoolbox/pack.yaml \
  --runtime <runtime-file> \
  --profile <example-dir>/profile.yaml \
  --project <example-dir>/project.yaml
```

One bounded pass is the default; there is no `--once` flag.
The pass reads at most one page, records item outcomes, and moves the source
position only after the page settles under the job's acceptance and refusal
policy.
A stopped pass exits unsuccessfully and leaves the position unchanged.

After each pilot pass, inspect the aggregate state:

```sh
adapter-job status <job-file> --runtime <runtime-file>
```

Inspect a specific item when status reports a refusal or hold:

```sh
adapter-job inspect <job-file> --runtime <runtime-file> --key <item-key>
```

`status` and `inspect` are observational.
They do not retry, release, accept, acknowledge, or migrate anything.
Resolve a BReg outcome in BReg, or a Coordinator Run and linked review in
their owning products.
The Adapter row remains held, and an unchanged held item remains skipped.

The reports contain no source payload by default, but item identifiers and
destination references remain operational data.
Protect the reports and do not put item keys into shared logs or tickets.

## Rescan or run on the interval

KoboToolbox edits may remain behind the saved keyset position, so the
maintained route declares a periodic rescan.
To request one rescan from the first page, run:

```sh
adapter-job rescan <job-file> \
  --pack <source-checkout>/products/adapter/packs/kobotoolbox/pack.yaml \
  --runtime <runtime-file> \
  --profile <example-dir>/profile.yaml \
  --project <example-dir>/project.yaml
```

An ordinary rescan writes the due marker and runs one pass.
Unchanged items skip by digest, refused items retry, and held items remain held
while unchanged.

For a long-running process driven by the job's interval trigger, run:

```sh
adapter-job pass <job-file> \
  --pack <source-checkout>/products/adapter/packs/kobotoolbox/pack.yaml \
  --runtime <runtime-file> \
  --profile <example-dir>/profile.yaml \
  --project <example-dir>/project.yaml \
  --loop
```

Use either one scheduler invoking bounded passes or one `--loop` process for a
job, not both.
`SIGTERM` (what `systemctl stop`, `docker stop` and Kubernetes send) and
`Ctrl+C` stop the loop the same way: a loop that is waiting exits at once with
status 0, and a pass already in progress finishes first (it ends at its page
deadline at the latest), releases its lease, and then the process exits with
status 0. Give the supervisor a stop timeout longer than the job's
`pageDeadlineMilliseconds`; a process killed earlier leaves its lease to expire
before a restart can pass.
A loop whose job store stops answering (a PostgreSQL restart or failover) does
not exit: it prints `adapter.job.store-unreachable cause=<token>` on stderr,
where the token is a SQLSTATE such as `sqlstate-57P01` or a condition such as
`connection-closed`, and reads the store again after one delay.

## Upgrade and recover

Stop the scheduled or looping job before changing its binary or configuration.
Before upgrading a store older than schema 103, drain first: run passes with
the current binary until `adapter-job status` lists no pending items, and take
a database backup. A signed delivery left pending from before 103 has no
recorded receiver or body identity, so the new binary stops it as
`adapter.job.coordinator-identity-unrecorded` before any recipient call; the
recovery is to restore that backup, settle the item with the previous binary,
and upgrade again.
Run the new binary's `init-store` once before restarting passes.
Compatible embedded transitions serialize under the migration lock and can be
repeated safely.
An older binary refuses a store whose schema is newer than that binary supports.

Pre-1.0 formats may change without a compatible transition.
If a source build cannot migrate an older store, retain the existing database
and its backups, provision a separate fresh database, and make an explicit
migration or fresh-install decision.
Do not drop, truncate, or reset the retained store as a recovery step.

Settle pending items before changing `job.version` or the projection. A
pending signed event keeps the body it was first attempted with, so a pass
that would now build a different body stops as
`adapter.job.coordinator-body-changed` before any recipient call (a new body
could start a second Run). `adapter-job status` lists the pending keys. Restore
the previous job definition, let passes settle those items, then ship the
change. A changed receiver stops as `adapter.job.coordinator-receiver-changed`
instead; restoring the original receiver recovers it. A direct BReg job fences
the same way under `adapter.job.breg-body-changed` (the mapped operation
differs), `adapter.job.breg-receiver-changed` (another BReg deployment, caller,
access profile, Action or mode) and `adapter.job.breg-identity-unrecorded`
(staged before schema 103); the recoveries are the same.

A pass that stops as `adapter.job.identity-migration-required` found stored
items that predate the job's item-identity binding (store schema 103). Confirm
the job definition is the one you intend to run, stop any running pass or loop,
then run `adapter-job rebind-identity <job.yaml> --pack <pack> --runtime
<runtime>` once. It binds the current identity, keeps the stored items, prints
a JSON receipt on stdout and an `adapter.job.identity-rebound` audit line on
stderr; the next pass reads the current identity's items as new, so source rows may
be delivered again. To keep the old identity instead, restore the previous
job definition. `pass --dry-run` shows the same stop before reading a page.
The job store keeps no audit row for the rebind: the audit line and the
receipt are the only record, so send both to your log pipeline and retain them
as you would any other operator change record.

A new process reloads secret material behind the same environment reference.
Restoring trusted material behind the same reference is corrected-material
recovery: a later pass retains the pending item's identity.
This mechanism does not establish valid-to-valid issuer key rotation, overlap,
old-key revocation, or provider token lifetime behavior.
Plan those rotations with the source or destination provider and verify them
in the controlled pilot before retiring the predecessor credential.

The [held-item guidance](../../README.md#resolve-held-job-items) describes
which owning product or broker operator acts on each maintained hold code.
