# Exercised upgrade and roll-back: v0.8.3 -> v0.8.4 -> v0.8.3

Run date: 2026-07-07 (local lab host, Apple Silicon macOS, Docker Compose v5.1.2).

## Purpose

Partial evidence for the READINESS gate "Upgrade and rollback documented and
exercised" (issue #203). This run exercises the draft how-to page
`docs/site/src/content/docs/operate/upgrade-and-rollback.mdx` against a real
topology: baseline at v0.8.3, upgrade to v0.8.4, verified roll back to v0.8.3.
It uses source-built release-tag images and does not close the release-artifact,
credential-issuance, metrics, Redis replay/nonce, anti-rollback monotonicity, or
multi-release skip branches. Every place the draft procedure did not match lab
reality is recorded under [Findings](#findings).

## Environment

- Topology: the `lab/` demo compose default profile (4 relays, 3 notaries,
  openfn civil notary + sidecar + mock registry, postgres, redis, zitadel,
  static metadata publisher).
- Relay and Notary were **built from source at the release tags** `v0.8.3` and
  `v0.8.4` (git worktrees of the tags, wired in via the compose
  `*_SOURCE_DIR` build contexts). Release-artifact verification (cosign
  signatures, SLSA provenance) is **not** exercised here; that is covered by
  `release/VERIFY.md`. Version identity of each running phase was proven by
  `--version` output from inside the containers and by image IDs.
- Isolated compose project `registry-upgrade-ex` with every published host
  port remapped (prefix `1`: 4311->14311 ... 4331->14331, zitadel 4380->14380
  via `REGISTRY_LAB_ZITADEL_PORT`, postgres 54329->64329, redis 63799->16379)
  so the run coexisted with the live labs on this host. All remapped ports
  were verified free with `lsof` before start. The port override is committed as
  `lab/compose.upgrade-ex.yaml` in this branch; its `ports:`
  entries use the compose `!override` merge tag because `ports:` lists merge
  by concatenation across compose files.
- Image builds per version (IDs at run time):

  | image | v0.8.3 | v0.8.4 |
  |---|---|---|
  | registry-relay | `f05aa8431240` | `4aa596c50cee` |
  | registry-notary | `4e596c5490b6` | `e09941432870` |
  | registry-notary-openfn-sidecar | `eb1905c12b73` | `595e73fac296` |

  After each build the images were `docker tag`-ed `ex-v0.8.3` / `ex-v0.8.4`
  so the roll back re-used the kept v0.8.3 images without rebuilding, per the
  doc's "keep the old release's image reference" step.
- Secrets: fresh demo credentials from the lab generator. All raw token,
  JWK, and `.env` values are redacted from this document.

Two era mismatches had to be resolved before the baseline could run at all;
both are findings (F1, F7):

- The v0.8.3 lab configs are not the current ones. Baseline used the
  `v0.8.3` tag's `lab/config/{relay,notary,static-metadata}` files plus the
  v0.8.3 secret generator (which writes matching `fingerprint.commitment`
  values into the configs).
- The current `lab/Dockerfile.registry-notary` builds cargo package
  `registry-notary`, which at v0.8.3 was named `registry-notary-bin`; the
  v0.8.3 image was built with a one-line-patched copy of the Dockerfile
  (`-p registry-notary-bin`), kept outside the repo.

## Phase A: baseline v0.8.3

Build (relay + sidecar via `docker compose ... build`, notary via the patched
Dockerfile), then:

```
export REGISTRY_LAB_POSTGRES_PORT=64329 REGISTRY_LAB_REDIS_PORT=16379 REGISTRY_LAB_ZITADEL_PORT=14380
docker compose -p registry-upgrade-ex -f compose.yaml -f compose.upgrade-ex.yaml up -d
```

First attempt with current-main configs crash-looped every relay/notary:

```
ERROR auth.api_keys[0].fingerprint: missing field `commitment` at line 15 column 9
```

(v0.8.3 parser requires `fingerprint.commitment`; it was removed in v0.8.4 —
see F1). After switching to the v0.8.3-era configs, all services became
healthy in under a minute.

Verification (all requests carry the demo bearer tokens from `.env`,
redacted):

```
GET http://127.0.0.1:14311/healthz  -> 200        (civil relay)
GET http://127.0.0.1:14311/ready    -> 200
GET http://127.0.0.1:14321/healthz  -> 200        (civil notary)
GET http://127.0.0.1:14321/ready    -> 200
GET http://127.0.0.1:14312/v1/datasets/social_protection_registry/entities/household/records?limit=1
                                    -> 200        (canary governed read)
POST http://127.0.0.1:14321/v1/evaluations        (canary claim evaluation,
                                    -> 200         person-is-alive, NID-1001)
```

Canary evaluation result (trimmed): `claim_id: person-is-alive`,
`matching.method: configured_lookup`,
`matching.policy_id: notary.source_binding.civil.civil_registry.civil_person`.

Audit records on stdout (the lab's `audit.sink: stdout`), hash chain linking
across records within the container lifetime:

```
{"envelope_id":"01KWWJA8FF3EEQCFK5AYYT1899", ..., "prev_hash":null,  "record_hash":"f663e85b6bf1..."}
{"envelope_id":"01KWX1VTX85VEMGWMDFAKWN0RD", ..., "prev_hash":"f663e85b6bf1...","record_hash":"f6244e36ff4d..."}
```

Anti-rollback state: `config_trust.antirollback_state_path` is configured
(`/var/lib/registry-notary/config-state/civil-notary-config-antirollback.json`)
but the file **does not exist** — the `notary-config-state` volume is empty.
This run did not exercise the governed config-bundle apply flow that would
prove monotonic anti-rollback behavior (F4, F5).

Version self-report from inside the containers:

```
registry-notary --version  -> registry-notary-bin 0.8.3
registry-relay  --version  -> ERROR unknown serve argument: --version   (F6)
```

## Phase B: upgrade to v0.8.4

Build with the `v0.8.4` tag sources (compose build; the current notary
Dockerfile matches the renamed package, no patch needed).

**Doctor pre-check (doc step 3), new binaries against the deployed config**,
run via one-off `compose run --rm --no-deps` containers so mounts and env
parsing match the deployment:

```
registry-notary doctor --config /etc/registry-notary/civil-notary.yaml --format json
  -> error: config YAML parse or validation failed:
     auth.api_keys[0].fingerprint: fingerprint.commitment was removed;
     configure fingerprint.provider with fingerprint.name or fingerprint.path only
registry-relay doctor --config /etc/registry-relay/civil-registry-relay.yaml --format json
  -> code=config.parse_error ... fingerprint.commitment was removed ... (line/column named)
```

The new release **rejects the running config**; the error names the removed
key and the fix, exactly as the doc's troubleshooting section describes. The
task brief expected doctor to pass (holder-binding default change being the
known breaking item); the actually-breaking change for this lab pair is the
`fingerprint.commitment` removal (F1, F2). No holder-binding warnings were
raised because the lab profiles set `holder_binding` explicitly.

**Gap: not every default-profile Notary config went through this gate.** The
pre-check above ran `registry-notary doctor` only against `civil-notary.yaml`
and `registry-relay doctor` only against `civil-registry-relay.yaml`. The
default profile also starts `openfn-civil-notary.yaml` (see Environment), and
v0.8.4 makes a breaking source-adapter connector rename
(`connector: openfn_sidecar` -> `connector: source_adapter_sidecar`; see
`products/notary/CHANGELOG.md`). This run never ran `registry-notary doctor`
against `openfn-civil-notary.yaml`, so whether that config needed the
connector rename, and whether doctor would have caught a missed rename the
way it caught the `fingerprint.commitment` removal, was **not validated**
here (F13).

**Config migration:** restored the v0.8.4-era lab configs (same env var
names, `commitment:` lines gone). Same `.env`, same tokens — no credential
rotation across the upgrade. Doctor re-run:

```
registry-notary doctor -> exit 0; 20 diagnostics: 19 ok, 1 warning
                          (deployment.profile_undeclared)
registry-relay  doctor -> exit 0; 5 diagnostics: 4 info, 1 warning
                          (deployment.profile_undeclared)
```

**Backups (doc step 4):**

- audit "log directory": none exists — sink is stdout, so
  `docker compose logs civil-notary` capture **is** the audit backup (F3);
- anti-rollback state file: absent, recorded as such (F4);
- config + `.env` as deployed: tarball kept outside the repo (this backup is
  what later made the roll back possible).

**Deploy:** `docker compose -p registry-upgrade-ex -f compose.yaml -f compose.upgrade-ex.yaml up -d`
(same exported `REGISTRY_LAB_POSTGRES_PORT`/`REGISTRY_LAB_REDIS_PORT`/`REGISTRY_LAB_ZITADEL_PORT`
as Phase A; no `down`, no `-v`). Compose recreated exactly the 10
relay/notary/sidecar/mock containers whose image changed; postgres, redis,
zitadel and the static publisher kept running untouched.

**Verification:** identical list to Phase A, all 200; canary read and canary
evaluation succeed. Version self-report:

```
registry-relay  --version -> registry-relay 0.8.4
registry-notary --version -> registry-notary 0.8.4
```

**State survival:** the `notary-config-state` volume survived the swap
(still mounted, still empty — nothing existed to survive, F4). Audit records
continue on stdout after the swap, but the first record of the recreated
container starts a **new** hash chain:

```
{"envelope_id":"01KWX2NVRM...", ..., "prev_hash":null, ...}
```

With a stdout sink, chain continuity across an upgrade is only provable from
the captured pre-upgrade logs; the stream itself re-seeds (F3).

## Phase C: roll back to v0.8.3

Per the doc: redeploy the previous release's image with the config that was
running before the upgrade.

- Restored the pre-upgrade (v0.8.3-era) config tree from the Phase B backup
  tarball.
- Repointed the compose image tags at the kept `ex-v0.8.3` images
  (`docker tag registry-relay:ex-v0.8.3 registry-relay:demo`, etc.) — no
  rebuild.
- `docker compose -p registry-upgrade-ex -f compose.yaml -f compose.upgrade-ex.yaml up -d`
  again (same exported port vars as Phase A; no `down`); the same 10 containers
  were recreated.

Verification: all Phase A checks pass again —

```
/healthz, /ready on 14311 and 14321          -> 200
canary governed read (14312)                 -> 200
canary claim evaluation (14321)              -> 200
registry-notary --version                    -> registry-notary-bin 0.8.3
registry-relay --version                     -> unknown serve argument (v0.8.3 behavior)
```

Revert constraints from the doc, as observed in practice:

- **Config sequence not rolled back:** vacuously true — no governed bundle
  was ever applied, the anti-rollback store stayed empty through all three
  phases (F5). The monotonicity rejection path was not exercisable in this
  topology.
- **Audit stream continuous, no truncation:** records flow on stdout after
  the roll back (first record `prev_hash: null` again — same stdout re-seed
  behavior as the upgrade). Nothing was truncated; the captured Phase A and
  Phase B logs retain the full history including the upgrade window.
- **Signing keys:** the upgrade did not rotate keys (same `.env`), so the
  "keep new public keys published" constraint had no work to do.

## Phase D: cleanup

```
export REGISTRY_LAB_POSTGRES_PORT=64329 REGISTRY_LAB_REDIS_PORT=16379 REGISTRY_LAB_ZITADEL_PORT=14380
docker compose -p registry-upgrade-ex -f compose.yaml -f compose.upgrade-ex.yaml down -v
```

0 containers and 0 volumes left for the project; the other compose projects
on the host were never touched. Tag worktrees removed; `ex-*` image tags
removed after repointing the lab's `:demo` tags at the v0.8.4 builds (see
F8 for why the pre-exercise `:demo` images could not be restored).

## Findings

Numbered; F-references above point here.

1. **The doc's implicit "same config runs on both sides" does not hold for
   v0.8.3 -> v0.8.4.** `fingerprint.commitment` was removed in v0.8.4 and its
   parser rejects configs that still carry it, while v0.8.3 requires it. The
   upgrade needed a config migration, and the roll back needed the backed-up
   pre-upgrade config. The doc's step 4 (back up "your config ... as
   currently deployed") is what makes its roll-back step 1 ("with the config
   that was running before the upgrade") possible; the page never says so
   explicitly and should.
2. **Doctor behaves as documented on a removed key.** The v0.8.4 doctor
   failed against the old config with an error naming the removed key and
   the replacement — matching the troubleshooting bullet. After migration it
   passed with only the known `deployment.profile_undeclared` warning.
3. **"Back up the audit log directory" does not map to stdout sinks.** The
   lab's `audit.sink: stdout` has no directory; container log capture is the
   audit backup. Moreover the audit hash chain re-seeds (`prev_hash: null`)
   every time the container is recreated, so the doc's "audit chain must
   stay continuous" constraint cannot be verified from the live stream
   across an upgrade — only from captured logs. The doc should state the
   stdout-sink variant of both the backup step and the continuity check.
4. **The anti-rollback state file was absent in this topology.** With
   `config_trust` enabled but no governed bundle ever applied, the file named
   by `antirollback_state_path` does not exist; the doc's backup step reads as
   if it always exists. "Byte-identical survival" across the upgrade was
   therefore vacuous (empty volume before, empty after, volume itself
   persisted).
5. **Anti-rollback monotonicity was not exercisable** in the default lab
   topology (no signed bundle apply flow); the doc's revert constraint 1 and
   troubleshooting bullet 3 remain unexercised by this run.
6. **v0.8.3 binaries cannot self-report their version** (`registry-relay
   --version` is rejected; notary reports the pre-rename package name
   `registry-notary-bin 0.8.3`). Version identity for the baseline had to be
   proven via image IDs and build provenance. Both v0.8.4 binaries report
   cleanly. (Related READINESS item: "Release binaries self-report the
   release version".)
7. **The lab cannot source-build older releases as-is.** The current
   `lab/Dockerfile.registry-notary` builds cargo package `registry-notary`,
   which does not exist at v0.8.3 (`registry-notary-bin`); a patched
   Dockerfile was required for the baseline build.
8. **`compose.yaml` hardcodes mutable shared image tags** (`registry-relay:demo`
   etc.). Building in an isolated compose project still overwrites those
   host-global tags; the images they previously pointed at were untagged and
   later garbage-collected by the container runtime. Isolated projects share
   the host image namespace — a lab-vs-doc mismatch with the doc's
   prerequisite "pin a version tag or image digest, never `latest`", which
   the mutable `:demo` tag violates in spirit.
9. **Notary services define no compose healthcheck** (relays do), so
   "wait for health" must be done with HTTP probes against `/healthz` for
   notaries; `docker compose ps` health status is not available for them.
10. **`/ready` returns a useful structured body** (check counts, signing
    provider status) on both products; the doc only mentions the status
    code. Worth one sentence in the verification list.
11. **`deployment.profile_undeclared` warning** appears in every doctor run
    on both products (lab leaves the profile undeclared) — pre-existing
    known gap, recorded here because the doc's step 3 says "resolve every
    startup-failure finding"; this one is a warning, not a failure, and did
    not block.
12. Exercise-spec nit: the suggested `REGISTRY_LAB_REDIS_PORT=73799` is not
    a valid TCP port (> 65535); 16379 was used instead.
13. **The doctor gate did not cover every default-profile Notary config.**
    `registry-notary doctor` and `registry-relay doctor` were only run against
    `civil-notary.yaml` and `civil-registry-relay.yaml`. The default profile
    also starts `openfn-civil-notary.yaml`, and v0.8.4 renames the
    source-adapter connector (`connector: openfn_sidecar` ->
    `connector: source_adapter_sidecar`; `products/notary/CHANGELOG.md`).
    This run never doctor-checked `openfn-civil-notary.yaml`, so it does not
    show whether that config needed migration for the rename or whether
    doctor would have caught it.

## Not covered by this run

- Release-artifact verification (cosign, slsa-verifier) — covered by
  `release/VERIFY.md`; this run built from source at the tags.
- Redis-backed replay/nonce state survival — the lab runs Redis with
  persistence disabled (`--save "" --appendonly no`).
- Credential issuance canary (doc's "if you issue credentials" branch) and
  the metrics-flowing check (no monitoring stack in the lab).
- Anti-rollback monotonic rejection (finding 5) and multi-release skip
  upgrades.
- Doctor-gate coverage of non-civil default-profile Notary configs, in
  particular `openfn-civil-notary.yaml` and the v0.8.4 source-adapter
  connector rename (finding 13).

## Result

The draft procedure was partially exercised end to end against a real topology:
v0.8.3 baseline verified; v0.8.4 doctor pre-check correctly caught the
breaking config change on the civil relay/notary path before deployment
(`openfn-civil-notary.yaml` was not doctor-checked in this run, see
finding 13); after config migration the
upgrade deployed via `up -d` with state volumes intact and services verified
healthy on v0.8.4; the roll back to the kept v0.8.3 images plus backed-up
config restored a fully verified v0.8.3 deployment without touching
persistent volumes. This closes the source-built tag exercise only; it does not
close release-artifact verification, credential issuance, metrics, Redis
replay/nonce state survival, anti-rollback monotonic rejection, or multi-release
skip upgrades. The procedure works within that scoped run, with the documented
findings — chiefly the stdout-audit-sink mismatch (finding 3), the absent
anti-rollback file in this topology (finding 4), the need to state
explicitly that config backup enables config roll back (finding 1), and the
incomplete doctor-gate coverage of default-profile Notary configs
(finding 13).
