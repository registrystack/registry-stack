# Registry Stack Load Testing Definition of Done

This definition of done covers load testing across Registry Relay, Registry
Notary, and Registry Lab. It is intentionally split between fast CI smoke and
operator-run stack baselines so the harness catches regressions without turning
pull requests into capacity tests.

## Required Scope

- Relay and Notary product repos have a branch-local CI workflow that builds the
  release binary, generates a small deterministic fixture set, starts the
  service, and runs at least one authenticated k6 scenario against the live
  process.
- The CI smoke profile is short, deterministic, and self-contained. It does not
  depend on remote k6 module imports, hosted demo environments, or committed raw
  secrets.
- Product k6 scenarios keep stricter thresholds for local baselines, while CI
  can set an explicit no-threshold escape hatch when a smoke run is validating
  wiring rather than capacity.
- Registry Lab owns the stack-level scenarios that cross service boundaries:
  Relay reads, Relay-backed Notary evaluations, OpenFn sidecar saturation, and
  OpenFn-backed credential issuance.
- Stack scenarios write machine-readable summaries under `output/perf/` and
  keep raw bearer/API-key material in environment variables only.

## Scenario Coverage

The load-testing program is done when these paths are executable:

- `registry-relay`: hot `200`, cached `304`, auth deny, mixed read, refresh
  under read load, and profile-scaled datasets for local baselines.
- `registry-notary`: authenticated claim listing, extract evaluation, CEL
  evaluation, batch evaluation, auth deny, and the politeness cap observable via
  the source stub.
- `registry-lab`: full-stack Relay reads across civil, social, and health
  registries; Notary evaluations for civil and combined-support claims; OpenFn
  sidecar pressure where expected saturation is counted separately from
  unexpected errors; OpenFn-backed credential issuance through
  `/v1/credentials`.

## Evidence

Every implementation branch should provide:

- `git diff --check` over the files changed by the branch.
- `node --check` over every changed k6 file.
- Python syntax checks over changed helper scripts.
- Product CI smoke workflows updated to run a real small-profile k6 path.
- Registry Lab README instructions for local and Docker k6 execution.
- A note when full stack execution was not run locally, including the missing
  prerequisite such as Docker, k6, release binaries, or a generated lab `.env`.

## Non-Goals

- CI does not establish capacity numbers. It verifies that the load harness
  starts services and exercises real authenticated HTTP paths.
- Hosted load is opt-in. The default commands target loopback lab services and
  should not be pointed at shared hosted environments without an explicit run
  window, target rate, and rollback/stop condition.
- Private release evidence, hosted URLs, and credentials stay outside public
  product repositories.
