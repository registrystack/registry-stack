# Plan: MVP docs cut (hosted-first on-ramp)

## Goal

We over-published. ~50 pages are live (23 authored here + ~46 aggregated from 6 product repos, ~70k words), which is too much to review and validate. Cut the published set to a reviewable MVP (~25 pages) focused on **single-node use cases** for the priority products (Relay, Notary) plus the global spine, and reorganize onboarding around a **hosted-first ladder** so newcomers "see the power" in ~2 minutes with zero install. Publish only what is ready; defer the rest reversibly.

## Constraints

- **Nothing deleted at source.** Product docs are build artifacts pulled by `scripts/sync-repo-docs.mjs` from each repo at a pinned ref; cutting = trimming the allowlist, not deleting. Authored pages are deferred via `draft`, not removed.
- **OpenAPI stays the source of truth.** `fetch-openapi.mjs` -> `redocly build-docs` -> static Redoc at `public/api/*.html`, linted by `check:openapi`. No new renderer, no new deps.
- **Single-node is the framing.** The hosted lab is a multi-authority federation deployment; we document a single-authority *slice* (one Relay + one Notary -> one credential). Federation, wallet-interop, and cross-authority stay deferred.
- **The build is the validator.** `npm run check` runs frontmatter, markdown, vale, OpenAPI lint, tutorial dry-run, SVG a11y, build, and `check:links:built`. The link check fails on any dangling link, which forces the link sweep to be complete. Ready bar = human-reviewed AND `npm run check` green.
- Match existing conventions: Diataxis `doc_type`, frontmatter schema enforced by `check-doc-frontmatter.mjs`, short sidebar labels, the existing "Excluded" comment pattern in `repo-docs.yaml`.

## Approach

Three coordinated moves: (1) reorganize onboarding into a hosted-first ladder; (2) trim product nav via the `repo-docs.yaml` allowlist; (3) defer not-ready authored pages via `draft` + sidebar removal. The hosted lab (`lab.registrystack.org`, confirmed live, all endpoints 200) already delivers the credential payoff with published demo credentials, so the "see a signed credential" moment costs us almost no new infra and no new local tutorial.

The ladder is the spine:

- **Rung 1 — See it live** (hosted, zero install): new authored page. Open `lab.registrystack.org`, run the wallet flow (demo identity -> `person_is_alive` SD-JWT credential), try the negative control, and `curl` a protected read against `civil-relay`. Tokens/identities referenced from the canonical `public-demo-credentials.json`, not hardcoded.
- **Rung 2 — Run your own** (registryctl, local single node): the three existing registryctl tutorials, kept at claim->status. No new local credential tutorial for MVP.
- **Rung 3 — Go deeper** (product docs): Relay 5 pages, Notary 10 pages.

## Architecture

```
                         docs.registrystack.org (MVP nav)
                                     |
   +---------------------+----------------------+--------------------+
   |   Get started       |     Products         |   Reference        |
   |  (authored here)    |  (aggregated)        |  (authored here)   |
   +---------------------+----------------------+--------------------+
   | Overview (index)    | Relay  (5 pages)     | API refs (3)       |
   | See it live  [NEW]  | Notary (10 pages)    | Glossary           |
   | Where to start      |                      | (Redoc: static)    |
   | When to use         | Manifest/Atlas/      |                    |
   | Spreadsheet API     | Platform/Lab:        | Explanation:       |
   | Registry claim      |   DEFERRED           |  Architecture      |
   | Own API claim       |                      |  Evidence issuance |
   +---------------------+----------------------+--------------------+

   Ladder:  Rung1 See it live (hosted) -> Rung2 registryctl (local) -> Rung3 product docs

Cut mechanism:
  product pages   -> trim src/data/repo-docs.yaml allowlist (move to "Excluded")
                     -> npm run generate regenerates sidebar.json + products/
  authored pages  -> draft: true frontmatter (excluded from prod build)
                     + remove slug from astro.config.mjs sidebar
  validation      -> npm run check ; check:links:built fails on dangling links
```

## Files & components

### New

- `src/content/docs/start/see-it-live.mdx` — Rung 1 hosted-lab walkthrough (doc_type: tutorial).
  - Outline only (executor writes prose): what you'll see; wallet flow (open `lab.registrystack.org` -> sign in as demo identity NID-1001 -> receive `person_is_alive` SD-JWT) ; negative control (NID-1002 -> refused); `curl` protected read against `civil-relay` with a published demo token; "now run your own" pointer to Rung 2.
  - Credentials/identities referenced from `public-demo-credentials.json` / the homepage, not pasted inline.
  - Exact callable request/response shapes to be lifted from the registry-lab Bruno collection (`requests/registry-lab/...`, "Hosted Lab" environment) before writing.

### Modified

- `src/data/repo-docs.yaml` — trim the allowlist:
  - **Relay keep (5):** `index`, `api`, `client-integration`, `configuration`, `evidence-verification`.
  - **Relay defer (6 -> Excluded):** `ops`, `deployment-hardening`, `metadata`, `standards-adapter-operator-guide`, `development`, `use-cases`.
  - **Notary keep (10):** `index`, `architecture-overview`, `api-reference`, `client-sdk-guide`, `source-claim-modeling-guide`, `operator-config-reference`, `signing-key-provider`, `credential-lifecycle-status`, `sd-jwt-vc-conformance-profile`, `identity-and-record-matching`.
  - **Notary defer (8 -> Excluded):** `capability-matrix`, `self-attestation-operator-guide`, `federated-evaluation-operator-guide`, `oid4vci-wallet-interop`, `scenario-patterns`, `opencrvs-dci-standalone-tutorial`, `openspp-disability-dci`, `deployment-hardening-runbook`.
  - **Drop whole repos:** `registry-manifest`, `registry-atlas`, `registry-platform`, `registry-lab` (comment out their blocks, preserve as deferred).
- `astro.config.mjs` — rebuild the hand-defined global sidebar to the keep list:
  - Get started: Overview, **See it live [new]**, Where to start, When to use, Spreadsheet API, Registry claim, Own API claim. (Remove: Your first call, First run.)
  - Explanation: Architecture, Evidence issuance. (Remove: DPI safeguards, Consultation flow, Publishing pipeline, Integration patterns.)
  - Reference: API reference (Overview/Relay/Notary), Glossary. (Remove: Contracts, Standards register, Boundaries and map, Decisions.)
- `src/content/docs/index.mdx` — rewrite "Where to go" around the three-rung ladder; remove links to deferred pages.
- `src/content/docs/start/quickstart.mdx` — trim the "Choose by question" router to surviving routes; add the hosted "See it live" row; drop rows pointing at deferred pages.
- `src/content/docs/start/when-to-use.mdx` — light edit: drop/soften references to deferred products (Manifest/Atlas/Platform/Lab) so it doesn't advertise unpublished pages.
- **Defer authored pages (add `draft: true`, remove from sidebar):**
  - `start/your-first-call`, `tutorials/first-run-with-registry-lab`
  - `explanation/consultation-flow`, `explanation/dpi-safeguards-alignment`, `explanation/integration-patterns`, `explanation/publishing-pipeline`
  - `map/boundaries-and-map`
  - `reference/contracts`, `reference/standards`
  - `decisions/rename-2026-05-23`

### Deferred / not changed

- OpenAPI pipeline (`fetch-openapi.mjs`, `redocly.yaml`, `public/api/*.html`, `reference/apis/*`) — kept as-is.
- Source product repos — untouched; deferred entries remain pullable.

## Decisions

- **Hosted-first ladder.** Rung 1 = hosted lab. Rationale: it is live and purpose-built for public zero-install use (published demo creds, demo identities, negative control), so it delivers the credential "wow" with near-zero new work. Confirmed durable/maintained. Alternatives: local-first with hosted as a teaser link (kept registryctl as hero); hosted-only (dropped local path).
- **Credential payoff via hosted, not a new local tutorial.** Rung 2 registryctl tutorials stay at claim->status. Rationale: hosted already issues the SD-JWT VC; writing a local issuance tutorial (signing keys, DID:web) is the one piece of net-new writing we can avoid. Alternative: extend `verify-claim-own-api` with a local issuance step (more writing, deferred to follow-up).
- **Cut via allowlist + `draft`, not deletion.** Product pages leave the allowlist (reversible one-liners, mirrors existing "Excluded" pattern); authored pages get `draft: true` so they are excluded from the production build, not just hidden from nav. Rationale: "publish only when ready" means not publicly reachable, not merely unlinked. Alternative: sidebar-only removal (leaves orphan URLs).
- **Single-node = a documented slice of a federated lab.** We point at one Relay + one Notary; federation/wallet-interop stays deferred. Rationale: honors the single-node priority without standing up separate infra.
- **Lab onboarding authored here, not aggregated.** "See it live" lives at `start/see-it-live`; no `registry-lab` product pages published. Rationale: the hosted homepage is self-sufficient; keeps the cut clean and the page under our editorial control.
- **OpenAPI -> static Redoc unchanged.** Source of truth, zero new deps. Embedded renderer (Scalar/starlight-openapi) is post-MVP polish.

## Open questions

- **`draft: true` vs the frontmatter checker.** Confirm `check-doc-frontmatter.mjs` and the Starlight schema accept `draft` on these pages (Starlight supports it natively; the repo's custom check may enforce required fields independently). If not, fall back to moving files out of the collection or sidebar-only removal.
- **Relay `api.mdx` vs `reference/apis/registry-relay` + Redoc overlap.** Three API surfaces per product. `api.mdx` is pulled from the source repo (can't edit here). Resolve by reading it: if it substantially re-documents endpoints (against the existing guard), defer it from the allowlist and rely on `reference/apis/*` + Redoc; otherwise keep.
- **Exact hosted callable shapes.** Whether "see a credential" is a browser wallet click-through (OID4VCI `offer_url`) only, or also a curl-able evaluate->credential call. Confirm from the Bruno collection before writing Rung 1.

## Out of scope

- Standing up or changing any hosted infrastructure (lab.registrystack.org is used as-is).
- A local credential-issuance tutorial (follow-up).
- Re-adding Manifest/Atlas (the natural next products) and Platform/Lab.
- Embedded in-site OpenAPI renderer (Scalar).
- Editing source product repos to de-duplicate prose.
- Rewriting `map/boundaries-and-map` to a 3-product map (deferred whole).

## Tasks

- [ ] Read the registry-lab Bruno "Hosted Lab" collection; capture the exact protected-read and claim/credential request+response shapes and the canonical demo identities.
- [ ] Confirm `draft: true` is accepted by `check-doc-frontmatter.mjs` + Starlight schema (resolve the open question; pick fallback if not).
- [ ] Trim `src/data/repo-docs.yaml`: move deferred Relay/Notary entries to "Excluded"; comment out Manifest/Atlas/Platform/Lab repo blocks.
- [ ] Rebuild the global sidebar in `astro.config.mjs` to the keep list (add See it live; remove deferred entries).
- [ ] Add `draft: true` to the 10 deferred authored pages.
- [ ] Write `src/content/docs/start/see-it-live.mdx` (Rung 1 hosted walkthrough).
- [ ] Rewrite `index.mdx` "Where to go" around the ladder; remove deferred links.
- [ ] Trim `start/quickstart.mdx` router table; add the hosted row.
- [ ] Light-edit `start/when-to-use.mdx` to stop advertising deferred products.
- [ ] Resolve the Relay `api.mdx` overlap (keep or defer).
- [ ] `npm run generate` then `npm run check`; fix every dangling link surfaced by `check:links:built` until green.
- [ ] Manual review pass against the ready bar; commit the cut.
