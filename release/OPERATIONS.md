# Operate a Registry Stack release

Registry Stack is pre-1.0 Beta software for self-hosted institutional pilots.
An ordinary Beta release protects the exact source, shipped bytes, image
digests, applicable vulnerability decision, and first-run path. It does not
repeat every 1.0-readiness exercise.

The active path uses one release PR, one private candidate built from protected
`main`, one annotated tag, and one publication dispatch from protected `main`.
Publication promotes the candidate bytes and image manifests without rebuilding
them. A normal release should need less than 15 minutes of operator time and
less than one hour elapsed, dominated by the candidate build.

## Prerequisites

Start release preparation when:

- Protected-main CI is green.
- The intended release source and release-control changes are already on
  `main`.
- The release version, GitHub Release destination, and final image tags are
  unused.
- Each final GHCR package is public and grants this repository's Actions
  workflow write access.
- The `npm`, `pypi`, and `pypi-evidence` GitHub environments exist with the
  intended release approvers.

The scheduled release canary is useful maintenance telemetry, but it is not a
Beta release prerequisite.

For the first release under a new image package name, provision the package
once before requesting the candidate. GitHub creates a first-published
container package as private, so publish a clearly non-release bootstrap
artifact without putting a token on the command line:

```sh
package="${PACKAGE:?set PACKAGE to relay, evidence, mint, discovery, or registry-server}"
case "${package}" in
  relay|evidence|mint|discovery|registry-server) ;;
  *) echo "unsupported release image package: ${package}" >&2; exit 1 ;;
esac

bootstrap_dir="$(mktemp -d)"
printf 'Registry Stack %s package bootstrap\n' "${package}" \
  > "${bootstrap_dir}/bootstrap.txt"
printf '%s' "${GHCR_BOOTSTRAP_TOKEN:?set a classic PAT with write:packages}" \
  | oras login ghcr.io \
      --username "${GHCR_BOOTSTRAP_USER:?set the PAT owner}" \
      --password-stdin
oras push \
  --artifact-type application/vnd.registrystack.package-bootstrap.v1 \
  --annotation \
    org.opencontainers.image.source=https://github.com/registrystack/registry-stack \
  "ghcr.io/registrystack/${package}:bootstrap" \
  "${bootstrap_dir}/bootstrap.txt:text/plain"
```

In the organization package settings, change only the selected package to
public and grant `registrystack/registry-stack` Actions access with Write.
Starting with `v0.21.0`, the release requires public `relay`, `evidence`, and
`mint` packages, joined by `discovery` from `v0.24.0` and `registry-server`
from `v0.26.0`. Verify all five before candidate dispatch:

```sh
for package in relay evidence mint discovery registry-server; do
  gh api "/orgs/registrystack/packages/container/${package}" \
    --jq '[.name,.package_type,.visibility]'
done
```

Each result must name the requested package and report `container` and
`public`. Keep each bootstrap version until the first real version is public,
then remove only that bootstrap version. This is a package-identity setup step,
not part of later releases.

A new release image also needs its own reviewed advisory baseline at
`release/security/<name>-advisory-baseline.json` before its first candidate.
The candidate refuses to run without that file, and the pinned Debian 13
runtime carries findings that a baseline with no exception cannot clear. Author
it from a real candidate image, never by copying another service's file: run
the candidate once to publish the private candidate image, regenerate the
scanner and rootfs evidence with the procedure in "Renew an image advisory
fingerprint" below, and record the reviewed runtime block, exception set,
owner, and expiry from that evidence. `discovery` is the first image to need
this since the baselines were introduced.

Enrol a new candidate package in the daily cleanup only after that first
candidate publishes `ghcr.io/registrystack/<name>-candidate`. The cleanup lists
exactly the names in `CANDIDATE_PACKAGES` in
`release/scripts/cleanup-release-candidates.py` and fails closed on a package it
cannot list, so naming an unpublished package would abort the whole scheduled
run. Add `<name>-candidate` to that allowlist with a matching fixture in
`release/scripts/test_cleanup_release_candidates.py`. Also add the public name
to `PUBLIC_PACKAGES` so cleanup can never reach a released image. Registry
Server is already on the public denylist; its candidate name joins the allowlist
after the first private candidate is present.

### Provision client registries

Registry Stack v0.22.0 promotes the exact candidate Evidence and Relay client
packages to npm and PyPI before the GitHub Release becomes public. Registry
Stack v0.23.0 and later also promote the Discovery clients. The npm and PyPI
publication jobs use GitHub-hosted runners and OpenID Connect trusted
publishing. Do not add npm or PyPI write tokens to the repository.

On PyPI, register pending trusted publishers for `registry-discovery-client`,
`registry-evidence-client`, and `registry-relay-client` with these exact values
before requesting the first v0.23.0 or later candidate:

- Owner: `registrystack`
- Repository: `registry-stack`
- Workflow: `release.yml`
- Environment: `pypi` for Discovery and Relay, and `pypi-evidence` for Evidence

Configure the `pypi` and `pypi-evidence` GitHub environments with required
reviewers. PyPI creates each project when its first trusted publication
succeeds.

npm does not provide a pending trusted publisher for an uncreated package.
Each client package therefore needs a one-time bootstrap before its first
release. Evidence and Relay were provisioned for v0.22.0. Before the first
v0.23.0-or-later candidate, provision only the Discovery root and platform
packages:

1. Create inert `0.0.0` root and platform packages for
   `@registrystack/discovery-client`. It has `darwin-arm64`,
   `linux-arm64-gnu`, and `linux-x64-gnu` platform packages. Give every
   bootstrap package only a README, `package.json`, and Apache-2.0 license. Do
   not include executable code.
2. Publish each package with `npm publish --access public --tag bootstrap` and
   a maintainer's two-factor authentication. Verify the resulting tags. npm
   can initialize `latest` when the first package version is created, even
   when the publication names a nondefault tag. Until the first real release
   moves `latest`, a normal install may therefore resolve only the inert
   placeholder.
3. Configure each package to trust `registrystack/registry-stack`, workflow
   `release.yml`, environment `npm`, with `npm publish` permission.
4. Configure the `npm` GitHub environment with required reviewers, disallow
   token publishing for each package, and revoke any bootstrap credential.
5. After the first real version is public, remove the `bootstrap` distribution
   tag. Keep the immutable `0.0.0` records as package-identity history.

The release workflow classifies an existing package version by the SHA-512
integrity of the candidate tarball. Real versions always use trusted
publishing. The workflow retries an exact partial state and stops on any
immutable digest mismatch.

## Prepare one release PR

Start from current protected `main`:

```sh
git fetch origin main
git switch -c release/v<version> origin/main

release/scripts/registry-release prepare \
  --version <version> \
  --release-id <release-id>
```

Review and commit the version, lockfile, changelog, release-note, manifest, and
generated contract changes reported by the planner. Do not mix release-workflow
or release-tool implementation changes into this PR. Merge after the protected
checks pass. The merge commit is the intended candidate source. The exact
protected-main revision accepted by `request-candidate` becomes the candidate
source and future tag target. There is no finalization or closeout PR.

The Node client manifests and their lockfiles deliberately bind no platform
package versions. Those versions name the release being prepared, which is
unpublished for as long as the PR is open, so a tree that carries them records
placeholder lock entries and leaves `npm ci` unsatisfiable on protected `main`
from the moment the release publishes. The candidate binds them into the root
manifest it packs, and `client_registry.py validate-dist` proves the published
root package carries the exact set. The planner rejects a prepared tree that
binds them.

Before opening the release PR, push the prepared branch and run the read-only
Ubuntu rehearsal from that branch:

```sh
rehearsal_branch="$(git branch --show-current)"
rehearsal_request_id="$(openssl rand -hex 16)"
gh workflow run release-rehearsal.yml \
  --repo registrystack/registry-stack \
  --ref "${rehearsal_branch}" \
  -f version=<version> \
  -f release_id=<release-id> \
  -f request_id="${rehearsal_request_id}"

rehearsal_run=""
for _ in $(seq 1 30); do
  rehearsal_run="$(
    gh run list \
      --repo registrystack/registry-stack \
      --workflow release-rehearsal.yml \
      --branch "${rehearsal_branch}" \
      --event workflow_dispatch \
      --limit 100 \
      --json databaseId,displayTitle \
      --jq ".[] | select(.displayTitle | endswith(\"(${rehearsal_request_id})\")) | .databaseId"
  )"
  test -z "${rehearsal_run}" || break
  sleep 2
done
test -n "${rehearsal_run}"
gh run watch "${rehearsal_run}" \
  --repo registrystack/registry-stack \
  --exit-status
```

The rehearsal requires the future tag to remain absent. It validates the
prepared plan, current manifest and source model, reproduces the exact archive
lock on Ubuntu, exercises unpublished-tag archive bootstrap, and checks the
production-shaped `/dev/` documentation links. It publishes nothing and stays
outside the release clock. Require the exact dispatched run to succeed before
opening the PR.

Starting with version `0.19.1`, the release manifest records the committed
identifier catalog path, SHA-256 digest, and active entry count. The planner
checks that binding against the source tree. Live resolver availability remains
an asynchronous publication smoke rather than a candidate-build gate.

Release documentation also resumes with `0.19.1`. Version `0.19.0` remains a
published historical exception and must not be modified after publication.

## Request and verify one candidate

Resolve current protected `main` and request the candidate:

```sh
git fetch origin main
source_sha="$(git rev-parse origin/main)"

release/scripts/registry-release request-candidate \
  --version <version> \
  --release-id <release-id> \
  --source-sha "${source_sha}" \
  --wait-for-ci \
  --wait
```

The command prints the exact candidate run ID and URL immediately after the
dispatch is correlated. `--wait-for-ci` waits only for protected-main `ci.yml`
at the exact source SHA, then refreshes protected `main` again immediately
before dispatch. `--wait` follows only that uniquely identified candidate run.
Both waits print only workflow state changes by default. If a protected
environment is waiting for approval, the command names the environment, links
the exact run, and prints a read-only command for inspecting the pending
deployment. An authorized reviewer must approve it through **Review
deployments** in that run. Add `--verbose-wait` to retain the raw `gh run watch`
display when detailed live job output is useful.
Omit either flag when another operator or monitor owns the corresponding wait.

The request is accepted only when `source_sha` is the exact protected-main
workflow revision and that revision has successful protected-main CI. Request
the candidate immediately after the release PR merges. If `main` advances
before dispatch, the CLI stops without creating a candidate. Inspect the
intervening commits, rerun `prepare` and the applicable validators and
rehearsal against the new tip, and use the new protected-main revision only
when the release identity and notes remain accurate. Otherwise update them in
another release PR. A later `main` advance does not invalidate a candidate that
the workflow already accepted and bound to its exact source. The candidate
workflow then:

- Validates the release identity, manifests, pins, recipes, and destinations.
- Builds the release payloads and OCI images once. Starting with `v0.21.0`, the
  image set is Relay, Evidence Gateway, and Registry Mint. Discovery joins at
  `v0.24.0`, and Registry Server joins at `v0.26.0`.
- Builds the exact locked release documentation archive once and includes it in
  the candidate payload closure.
- Publishes images only to private candidate packages.
- Generates image-specific SPDX and Syft reports, exports each exact candidate
  rootfs, and scans every image digest. A version-4 advisory exception passes
  only when the independently resolved candidate digest agrees with both scan
  reports, its OCI labels name the protected source revision, and the candidate
  retains the complete ordered reference OCI `.rootfs.diff_ids`, component
  layer, and
  exact safe production process configuration. Its definition-digested exposure
  assertion must also match each reviewed file in native Syft evidence and the
  exported rootfs. The full `crane config` document independently confirms that
  Grype and Syft reported the authoritative ordered uncompressed DiffIDs.
  Ordered DiffIDs cover every filesystem input, including
  libraries, interpreters, loader inputs, and symlinks. The Relay reference is an
  official v0.20.1 candidate. Evidence and Mint use explicitly identified local
  v0.20.1 reproductions because official v0.20.x image reports were retained only
  for Relay. Ordered rootfs DiffIDs, rather than the manifest digest, are stored
  in-tree so renewal does not self-reference the revision-bearing config.
- Runs the release payload checks.
- Seals a candidate manifest and bundle that remain promotable for seven days.
- Attests the manifest and bundle after re-verifying their bytes.

### Renew an image advisory fingerprint

Treat a fingerprint failure as a stopped candidate, not as a mechanical digest
update. The failed job does not publish renewal evidence. The exact image stays
in its private candidate package, so an authorized operator can regenerate the
evidence with the scanner versions pinned in the candidate workflow:

```sh
run_id=<failed-run-id>
run_attempt=<failed-run-attempt>
name=relay # or evidence, mint, or discovery
candidate_tag="ghcr.io/registrystack/${name}-candidate:candidate-${run_id}-${run_attempt}"
digest="$(crane digest "${candidate_tag}")"
candidate_ref="ghcr.io/registrystack/${name}-candidate@${digest}"
evidence_dir="advisory-renewal-${name}-${run_id}-${run_attempt}"
mkdir -p "${evidence_dir}/rootfs"
crane config "${candidate_ref}" > "${evidence_dir}/oci-config.json"
docker pull --platform linux/amd64 "${candidate_ref}" >/dev/null
SYFT_FILE_METADATA_SELECTION=all SYFT_FILE_METADATA_DIGESTS=sha256 \
  syft "${candidate_ref}" -o syft-json="${evidence_dir}/syft.json"
grype "${candidate_ref}" -o json > "${evidence_dir}/grype.json"
crane export "${candidate_ref}" - | tar --extract --file=- \
  --directory="${evidence_dir}/rootfs" \
  --no-same-owner --no-same-permissions
```

The pull is what makes the scan admissible, not a convenience. Syft and Grype
fill the `architecture` and `os` fields of their image target only from a
daemon-backed provider. Resolved straight from the registry they leave both
empty, and `check-advisory-baselines.py` rejects that evidence with
`grype image target must be linux/amd64`. On an `amd64` candidate the message
does not mean the architecture is wrong; it means the scan never went through
the daemon. The candidate workflow satisfies this incidentally, by running the
image once to record its `--version` before it scans.

Select the matching baseline and confirm its pinned base is still the exact
prefix of the candidate's authoritative uncompressed DiffIDs:

```sh
baseline=products/relay-v2/security/advisory-baseline.json
# Discovery, Evidence, and Mint use release/security/<name>-advisory-baseline.json.
jq --slurpfile baseline "${baseline}" -e '
  .rootfs.diff_ids[0:($baseline[0].runtime.layer_ids | length)]
    == $baseline[0].runtime.layer_ids
' "${evidence_dir}/oci-config.json"
jq --slurpfile baseline "${baseline}" '
  .rootfs.diff_ids[($baseline[0].runtime.layer_ids | length):]
' "${evidence_dir}/oci-config.json"
```

These are `.rootfs.diff_ids`, not the compressed digests in a manifest's
`.layers` descriptors. Then:

1. Copy the authoritative ordered DiffID suffix into
   `runtime.application_layer_ids` only after confirming the intended base and
   application boundary.
2. Review the candidate OCI process configuration and update `runtime.config`
   only when `User`, `Entrypoint`, `Cmd`, `WorkingDir`, `Env`, `Healthcheck`,
   `ArgsEscaped`, `ExposedPorts`, and `StopSignal` are the intended production
   contract and `Labels` contains exactly the three current OCI identity labels
   plus the fixed `org.registrystack.runtime.uid=65532` and
   `org.registrystack.runtime.gid=65532` labels.
3. Review every assertion file and copy its native Syft SHA-256 only after it
   matches the same path in the exported rootfs. If the verified package model
   moved, update `component_layer_id` from the matching Grype/Syft location.
4. Set every assertion's `reference_image_digest` to the reviewed `${digest}`,
   `reference_source_revision` to the independently copied protected source SHA,
   and `reference_provenance` to the truthful `official_candidate` or
   `local_reproduction` kind. Update each exception rationale to describe that
   same evidence. Then compute the runtime digest with the checker's canonical
   JSON rule and set it in `runtime.definition_digest`, every exception's
   `runtime_definition_digest`, and every assertion's
   `runtime_definition_digest`:

   ```sh
   python3 - "${baseline}" <<'PY'
   import hashlib, json, sys
   data = json.load(open(sys.argv[1], encoding="utf-8"))
   def digest(value):
       payload = {key: item for key, item in value.items() if key != "definition_digest"}
       encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
       return "sha256:" + hashlib.sha256(encoded).hexdigest()
   print(digest(data["runtime"]))
   PY
   ```

   Only after those bindings are saved, recompute each assertion digest. This
   second read-only command prints one line per shared assertion definition:

   ```sh
   python3 - "${baseline}" <<'PY'
   import hashlib, json, sys
   data = json.load(open(sys.argv[1], encoding="utf-8"))
   def digest(value):
       payload = {key: item for key, item in value.items() if key != "definition_digest"}
       encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
       return "sha256:" + hashlib.sha256(encoded).hexdigest()
   seen = set()
   for exception in data["exceptions"]:
       assertion = exception["exposure_assertion"]
       key = digest(assertion)
       if key not in seen:
           print("assertion", key)
           seen.add(key)
   PY
   ```

5. Move the live pins in `release/scripts/test_check_advisory_baselines.py`
   forward by hand: `LIVE_REFERENCE_IMAGE_DIGESTS`,
   `LIVE_REFERENCE_SOURCE_REVISION`, and `LIVE_REVIEW_EVALUATION_DATE`. That
   test restates the reviewed evidence instead of reading it back out of the
   baselines, so a renewal that skips this step fails it. A service renewed for
   the first time also joins `LIVE_BASELINES`, `LIVE_REFERENCE_PROVENANCE`, and
   `LIVE_EXECUTABLES`.
6. Check the edited baseline against the regenerated candidate evidence, then
   rerun the focused advisory tests and candidate workflow. Never invent a
   digest or reuse evidence from a different candidate.

   ```sh
   # Copy this independently from the failed run's protected source_sha.
   source_revision=<protected-source-sha>
   python3 release/scripts/check-advisory-baselines.py \
     grype "${evidence_dir}/grype.json" \
     --baseline "${baseline}" \
     --syft-report "${evidence_dir}/syft.json" \
     --rootfs "${evidence_dir}/rootfs" \
     --candidate-image-digest "${digest}" \
     --source-revision "${source_revision}" \
     --oci-config "${evidence_dir}/oci-config.json" \
     --subject "${name}-image"
   python3 -m unittest release/scripts/test_check_advisory_baselines.py
   ```

Use the successful candidate run ID for local verification:

```sh
release/scripts/registry-release verify-candidate \
  --version <version> \
  --release-id <release-id> \
  --candidate-run <run-id>
```

The command verifies the exact source and workflow ancestry, candidate
attestations, bundle payload hashes, image digests, SPDX SBOMs, scans, and
advisory verdict. For an initial publication it also requires the release tag,
GitHub Release, and final image destinations to be unused.

## Tag and publish

On success, `verify-candidate` prints all three operator commands:

1. Create the exact annotated tag bound to the candidate run, attempt, and
   manifest SHA-256.
2. Push only that tag ref.
3. Dispatch publication from protected `main` with the exact tag.

The final command has this form:

```sh
gh workflow run release.yml \
  --repo registrystack/registry-stack \
  --ref main \
  -f tag=v<version>
```

Run the printed commands without editing the annotation. Inspect the tag before
pushing it. The tag is annotated but not cryptographically signed.

The publication workflow runs from protected `main`, while the candidate and
tag remain bound to the release source commit. This separation permits a
release-workflow repair and exact retry without moving the source tag.
Publication:

1. Verifies the tag binding, source ancestry, seven-day candidate validity, and
   candidate attestations.
2. Creates or reconciles the nonpublic draft GitHub Release with the exact
   candidate payloads.
3. Promotes each private image manifest to the final tag at the candidate
   digest. An absent tag is copied, an existing exact digest is accepted, and a
   mismatch stops publication.
4. Adds `SHA256SUMS` and one keyless Sigstore bundle for the checksum file.
5. Reconciles the exact version-appropriate client wheels on PyPI and root and
   platform packages on npm. v0.22.x includes Evidence and Relay; v0.23.0 and
   later also include Discovery. Absent packages use trusted short-lived
   credentials; existing packages must match the candidate bytes.
6. Rechecks the full asset inventory, checksum signature, image digests, and
   completed client registry jobs, then publishes a public, non-prerelease
   GitHub Release.
7. Dispatches the docs workflow with the exact released documentation digest.
   The same workflow rebuilds `/dev/` on every push to protected `main` while
   retaining the latest authenticated docs-bearing release at the canonical
   and versioned routes.

The candidate attestation and signed checksum chain are the Beta provenance
model. Ordinary Beta publication does not generate a second generic SLSA
provenance asset. Pre-v0.19 release finalizers remain only in their immutable
historical release tags.

After publication, run the minimum public verifier from a checkout whose
`origin` is the Registry Stack repository:

```sh
release/scripts/registry-release verify-public --tag v<version>
```

It verifies the annotated tag target, latest published non-prerelease state,
every downloadable asset against GitHub's digest metadata, the exact
`SHA256SUMS` closure and its protected-main Sigstore identity, the release-body
manifest binding, every final OCI digest, and one maintained binary version
smoke. For v0.22.0 and later, the publication workflow also verifies the npm
SHA-512 integrity and PyPI SHA-256 digest of every version-appropriate client
package before docs promotion. Discovery joins that set at v0.23.0. The public
verifier is read-only and can be rerun independently.

For an interrupted publication after the annotated tag exists, classify the
exact recovery state before retrying:

```sh
release/scripts/registry-release verify-recovery --tag v<version>
```

This command is read-only. For an absent release or a bound draft, it verifies
that the local annotated tag exactly matches `origin`, revalidates the original
candidate and its lifetime, and checks the draft's candidate binding. It then
prints the exact protected-main `release.yml` retry command. The workflow owns
the fail-closed reconciliation of draft assets, OCI digests, npm packages, and
PyPI wheels immediately before each write. If the release is already
published, the command runs `verify-public`, reports the release complete, and
does not recommend a retry. It never approves environments or dispatches a
workflow, and it adds no release gate.

## Failure handling

| Failure state | Response |
| --- | --- |
| Validation failure before a candidate is sealed | Fix the source or metadata, then request a candidate from protected `main` |
| Candidate infrastructure failure before sealing | Rerun the candidate workflow |
| Candidate byte, recipe, scan, or advisory decision changes | Build and verify a new candidate |
| Candidate expires before the tag is pushed | Request and verify a new candidate |
| Bound draft or publication step fails while the candidate remains valid | Fix the workflow on protected `main` if needed, then dispatch `release.yml` again with the same tag |
| Documentation deployment fails after publication | Rerun `docs-pages.yml`; its optional exact tag and digest inputs fail closed if the request is stale |
| One final image tag already has the expected digest | Retry; publication accepts and re-verifies the exact digest |
| npm or PyPI already has every expected client byte | Retry; publication accepts and re-verifies the exact registry state |
| npm or PyPI has only an exact subset of the client packages | Retry; publication uploads only the absent exact packages |
| npm or PyPI publication fails while the GitHub Release is still a draft | Fix the protected workflow if needed, then retry the same exact candidate and tag; the draft remains nonpublic |
| An npm or PyPI package version has different bytes | Stop and patch forward with a new version |
| A final image tag has a different digest, or a published asset differs | Stop and patch forward with a new version |
| Repeatability, canary, Scorecard, telemetry, hosted, or announcement failure | Record follow-up work; do not change the public release result |

Never move a pushed tag, replace a published release asset, or overwrite a
mismatched final image tag. Exact partial state is retryable; incompatible
immutable state requires a new version.

## Asynchronous controls

The following controls stay outside ordinary Beta publication unless the
release changes or explicitly claims their surface:

- Scheduled release canary and clean repeatability proof.
- OpenSSF Scorecard, CodeQL, dependency, and image monitoring.
- Extended provenance or historical archive review.
- Hosted, external conformance, and 1.0-readiness exercises.
- Storage telemetry, retrospective, and announcement work.

Add one of these controls to the release clock only for a named threat or user
claim. Record the invariant, owner, duration, and removal condition.

Candidate promotion validity is seven days. The final candidate artifact and
private candidate images are retained for eight days, leaving one day of
cleanup margin without adding an operator step. Cleanup cannot target public
package names.
