# Guided Demo Scenarios And Data Plan

Page type: implementation spec
Product: Registry Lab
Layer: demo UX, fixtures, Relay, Notary, and credential issuance
Audience: demo operators, maintainers, and integrators

## Goal

Registry Lab should feel credible to a new user before it feels technically
complete. The guided demo surface should explain one realistic public-service
story at a time, hide complex JSON by default, and let users inspect exact
requests, responses, and curl commands when they want the source.

This spec defines the fixture cleanup and scenario set that turn the playground
into a coherent scenario suite for Relay, Notary, and wallet-style
credential issuance.

## Definition Of Done

This work is done only when all criteria below are true and verified in the
owning pull request or change set:

- The demo data has documented, tested personas for every guided scenario:
  selected subject identifiers, names, expected positive or negative outcome,
  and the source fixture rows that justify the outcome.
- Misleading public-facing fixture names are corrected or deliberately
  reframed. In particular, the UI and public docs no longer present
  `civil_status` values such as `child`, `adult`, or `elderly` as civil status.
- The wallet scenario uses a credible adult self-attestation persona, or the
  UI and fixtures explicitly model a caregiver or guardian acting for a child.
- The health scenario does not present a normal facility registry as keyed by
  `national_id`. It is either remodeled by district/facility lookup or clearly
  named as an applicant service-availability projection.
- Public-facing metadata and scenario copy do not present private backend
  hostnames as user-callable hosted endpoints.
- `/scenarios` provides a chooser or equivalent entry point for exactly the
  implemented guided scenarios, and each implemented scenario has a dedicated,
  linkable route.
- Each implemented scenario has ordered steps with: story text, request
  summary, run button, friendly result, reused values where applicable,
  technical request drawer, technical response drawer, and copy-as-curl for
  captured requests.
- All scenario steps call real local or hosted endpoints when the required
  service is available. Any local-only or unavailable service is explicitly
  marked in the UI before the user tries to run it.
- Friendly scenario results explain the domain outcome without requiring the
  user to read JSON.
- Technical drawers include method, URL, headers, request body when present,
  response status, response headers, and response body.
- Public demo tokens appear only where they are intentionally published.
  Runtime-only source connector tokens, container environment tokens, wallet
  proof secrets, and issued credential values are hidden or shown only in an
  explicitly approved playground source view.
- Automated tests cover fixture invariants, scenario payloads, step execution,
  token display policy, copy-as-curl rendering, and page routing.
- Local browser verification has been completed for every implemented scenario,
  including a screenshot or recorded checklist result for desktop and mobile
  widths.
- Hosted verification has been completed for every hosted scenario, or the
  scenario is visibly marked local-only with a tested local path.
- The docs index links the scenario/data spec, and any user-facing README text
  matches the implemented behavior.
- Code review confirms there are no "Partially Implemented" items hidden
  behind green tests; any incomplete scenario remains clearly disabled or
  marked as not yet available.

## Product Principles

- Tell one story per scenario. Do not show a catalogue of unrelated API calls.
- Put the user story before the request. Explain what the request will prove in
  plain language.
- Show friendly results first. Keep raw request and response source available
  in expandable drawers.
- Make every technical step honest: include endpoint, method, headers, request
  body, response status, response body, and copy-as-curl.
- Keep public demo credentials visible when they are intentionally published.
  Keep runtime-only source connector and environment credentials out of the UI.
- Use consistent fictional institutions, purposes, and jurisdictions across all
  public-facing fixtures.
- Do not imply automatic entitlement, automatic permit issuance, or automatic
  credential trust. The lab returns evidence for review.

## Hosted Source Modes

Every hosted guided story should say whether it is using Registry Relay demo
sources or a live upstream adapter before the user runs a step.

- Use **Registry Relay demo source** for the default civil, social protection,
  health projection, agriculture, and wallet stories. These paths call Relay or
  a Notary backed by Relay-managed synthetic fixtures. They do not call real
  FHIR, OpenCRVS, DHIS2, OpenSPP, OpenIMIS, or NAgDI services unless the story
  explicitly says so.
- Use **Live DHIS2 via built-in http_json sidecar** only for the DHIS2
  Programme Participation story. That hosted path calls the DHIS2 Notary, which
  reads the public DHIS2 sandbox through a private built-in source-adapter
  sidecar; Registry Relay is not on the source-read path.
- Treat **OpenCRVS DCI** as a separate live-service tutorial and smoke path
  until a hosted guided OpenCRVS story is added. The hosted CRVS birth and
  marriage evidence cards remain Relay-backed lab fixtures, even when their
  domain language says birth, marriage, or CRVS.
- Treat **FHIR** as the deterministic FHIR fixture-server profile unless a
  future hosted guided story says otherwise. The current FHIR tutorial does not
  call a public clinical FHIR server.

## Credibility Corrections

The fixture and metadata cleanup is part of the demo, not a side quest. These
are the credibility risks the scenario suite must keep resolved:

- Life-stage values such as `child`, `adult`, and `elderly` must be presented
  as life stage, not civil status.
- The hosted wallet story uses `NID-2001`, Maria Santos, an adult demo citizen.
  Miguel remains the child support subject for evidence and eligibility stories.
- Health records are framed as an applicant service-availability projection,
  not as a normal facility registry keyed by a person identifier.
- Hosted-facing metadata must not expose internal service URLs such as
  container-only Notary hostnames. Local-only services are labeled as local-only
  before users try to run them.
- Public-facing IRIs, authorities, countries, and purposes mix
  `demo.example.gov`, `ZZ`, internal hostnames, and domain-specific names. The
  result feels synthetic in the wrong way.

## Fixture Cleanup Plan

### Civil Registry

Use `life_stage` for age/life-stage values. Do not reintroduce a public
`civil_status` field for values such as `child`, `adult`, or `elderly`.

Keep these fields as the stable civil minimum:

- `national_id`
- `given_name`
- `surname`
- `birth_date`
- `age_band` or `life_stage`
- `deceased`
- `district`

Use clear personas:

- `NID-1001`, Miguel Santos: child. Use for child support, caregiver, and
  benefit-review scenarios.
- `NID-2001`, Maria Santos: adult caregiver. Use for wallet self-attestation or
  guardian-oriented flows.
- `NID-1003`, Cara Okafor: deceased negative control.

The wallet self-attestation scenario uses Maria Santos (`NID-2001`) as the
adult subject. If a future story uses Miguel directly, it must be framed as a
caregiver or guardian flow.

### Social Protection Registry

Align household and person rows with the civil personas used in scenarios.

The social protection data should support:

- an active child support enrollment for Miguel;
- an inactive enrollment control;
- a review-required control;
- a priority household aggregate case;
- a row-access boundary case.

Program names and amounts should be believable but clearly synthetic. Avoid
random-looking names in the UI; map them to display labels such as
`Child Support`, `Health-linked Support`, and `Priority Household Support`.

### Health Registry

The current health fixture should not be presented as a normal facility registry
keyed by `national_id`.

For this scenario suite, use the minimal cleanup path: the public-facing entity
and scenario text say "applicant service availability projection." The row
answers whether a suitable licensed service is available for the applicant's
district. A future stronger data model may model facilities by facility or
district directly.

### Agriculture Registry

The agriculture fixture set is the strongest current demo domain and should be
kept.

Use these stable scenario subjects:

- `FARMER-1001`, Amina Kone: positive climate-smart input voucher case.
- `FARMER-1002`: negative control for inactive parcel or supplier-related
  failure.
- `FARMER-1003`: negative control for already redeemed voucher.
- `HERD-2001`: positive livestock movement permit evidence case.
- `HERD-2002` or `HERD-2003`: negative livestock control for expired
  vaccination or active quarantine.

The agriculture story should emphasize that workbook-backed registries can be
published as governed read-only APIs without centralizing all source systems.

### Metadata And Naming

Before adding more public scenarios, normalize public-facing names:

- jurisdiction name;
- authority names;
- purpose IRIs;
- issuer names;
- evidence offering titles;
- hosted endpoint URLs;
- wallet credential display names.

Internal hostnames may remain in local-only source configuration, but public
metadata and scenario UI must use reachable public URLs or clearly label the
route as local-only.

## Scenario Suite

### 1. Evidence Without Row Access

User story: a benefits service needs to know whether Miguel Santos is alive. It
does not need the civil registry row.

Primary subject: `NID-1001`, Miguel Santos.

Steps:

1. Discover the civil evidence offering.
2. Request `person-is-alive` evidence from the Notary.
3. Attempt to read the civil registry row with the same evidence credential and
   show the denial.

Concepts shown:

- Relay metadata and evidence offerings;
- Notary evidence evaluation;
- purpose-bound access;
- evidence credential cannot read rows;
- request and response source inspection.

### 2. Simulated Wallet Credential Explorer

User story: an adult citizen or caregiver receives a signed proof credential and
inspects what the wallet stores.

Preferred subject: adult persona, for example `NID-2001`, unless the story is
explicitly guardian-based.

Steps:

1. Show issuer metadata and supported credential configuration.
2. Build or fetch an OID4VCI credential offer.
3. Simulate wallet holder key creation.
4. Request a nonce.
5. Submit a credential request with holder proof.
6. Display the credential in a wallet-style viewer.

Concepts shown:

- issuer metadata;
- credential offer;
- holder binding;
- nonce and proof;
- SD-JWT VC response;
- wallet-friendly display without requiring a real wallet.

The UI should include a credential explorer with friendly fields first:

- issuer;
- credential type;
- subject binding;
- claim;
- issued at;
- expiry;
- holder DID;
- raw credential drawer.

### 3. Social Aggregate Versus Row Access

User story: a policy analyst needs district-level eligibility counts for
planning, not household rows.

Availability: hosted and local. Hosted runs through the lab homepage against
the hosted social Relay while still displaying public hosted URLs in the
technical request source.

Steps:

1. Discover the social protection dataset and aggregate.
2. Read `households_by_eligibility_band` with the aggregate credential.
3. Attempt a household row read with the aggregate credential and show denial.
4. Optionally read a household row with the row-reader credential and purpose
   header to show the separate boundary.

Concepts shown:

- aggregate access is distinct from row access;
- disclosure controls;
- purpose header;
- row-reader and aggregate-reader credentials are not interchangeable.

### 4. DHIS2 Programme Participation VC

User story: a programme service needs to prove that a child is active in a
DHIS2 programme, then bind that evidence into a wallet-friendly credential.

Primary positive subject: `PQfMcpmXeFE`, the DHIS2 tracked entity used by the
Bruno programme participation walkthrough.

Steps:

1. Discover the DHIS2 Notary claim catalog.
2. Evaluate the six programme participation claims from the Bruno flow.
3. Preview the holder-bound SD-JWT VC request shape.
4. Reconcile with fresh online evidence using the reconciliation reference.
5. Run the inactive tracked-entity control.
6. Render the programme participation evidence as CCCEV JSON-LD.

Concepts shown:

- DHIS2 tracker-backed Notary evidence;
- claim-level value disclosure;
- holder-bound VC request shape;
- fresh online reconciliation;
- positive and negative programme controls;
- CCCEV JSON-LD rendering for developers.

The playground previews the holder-bound VC request because Bruno creates an
Ed25519 proof in Developer Mode. The UI must not fake a failed credential
issuance request or expose holder private-key material.

### 5. Combined Support Eligibility

User story: a caseworker asks one eligibility question that depends on civil,
social protection, and health evidence.

Primary positive subject: `NID-1001` if the health projection remains aligned
with the current matrix.

Steps:

1. Discover the combined support Notary or service route.
2. Evaluate civil subclaim.
3. Evaluate social protection subclaim.
4. Evaluate health service availability subclaim.
5. Evaluate `eligible-for-combined-support`.
6. Run one negative control to show why a similar applicant fails.

Concepts shown:

- Notary composition across multiple authorities;
- subclaims and final decision;
- no source rows copied into the response;
- positive and negative controls.

Health data credibility must be addressed before this scenario is presented as
a production-like service.

### 6. Agriculture Voucher Or Livestock Permit

User story: a service provider checks whether a farmer can redeem a
climate-smart input voucher, or whether a herd has evidence for movement permit
review.

Preferred first path: climate-smart input voucher.

Primary positive subject: `FARMER-1001`, Amina Kone.

Negative controls:

- `FARMER-1002`: inactive parcel or supplier failure.
- `FARMER-1003`: voucher already redeemed.

Steps:

1. Discover the agriculture Relay metadata.
2. Discover or select the voucher evidence offering.
3. Evaluate `eligible-for-climate-smart-input-voucher`.
4. Show reason code or contributing facts in a friendly way.
5. Issue or preview a holder-bound voucher evidence credential.
6. Optionally show aggregate market sizing without individual farmer rows.

Concepts shown:

- workbook-backed Relay;
- purpose-bound evidence;
- reason codes;
- row minimization;
- optional credential issuance;
- aggregate planning without row export.

## UX Requirements

Each scenario page should use the same notebook-like shape:

1. Story introduction.
2. Current actor and subject.
3. Boundary statement: what the requester is allowed to know and what is not
   allowed.
4. Step cards in order.
5. Friendly request summary.
6. Run button.
7. Friendly result.
8. Values reused by the next step.
9. Technical request drawer with copy-as-curl.
10. Technical response drawer.
11. Final receipt explaining what the scenario proved.

The scenario chooser at `/scenarios` should list the implemented stories with a short
"what this proves" line. Each story should open at `/scenarios/<scenario-id>`
or an equivalent dedicated route.

## Implementation Plan

### Phase 1: Spec And Fixture Invariants

- Add this spec.
- Add fixture invariant tests for selected personas and expected outcomes.
- Add checks that public-facing labels do not regress to misleading names such
  as `civil_status = child`.
- Decide the wallet persona before implementing the wallet scenario.

### Phase 2: Scenario Infrastructure

Refactor the current single-file MVP into a small scenario module structure:

```text
scripts/lab_homepage_scenarios/
  __init__.py
  common.py
  civil_alive.py
  wallet_vc.py
  social_aggregate.py
  combined_support.py
  agriculture_voucher.py
```

Keep `scripts/lab-homepage-server.py` thin. It should route scenario page and
API requests, not contain scenario content.

Shared helpers should cover:

- public demo credential lookup;
- request execution;
- request and response source capture;
- token display policy;
- friendly facts;
- curl generation;
- JSON formatting;
- scenario receipts.

### Phase 3: Implement Wallet Scenario

Implement the simulated wallet scenario first after persona cleanup because it
adds the most tangible user-facing value.

Minimum viable wallet explorer:

- issuer metadata step;
- offer step;
- simulated holder DID step;
- nonce step;
- credential request step;
- credential display panel;
- raw credential drawer.

The scenario may simulate the wallet client but should call real lab endpoints
where local or hosted services support them.

### Phase 4: Implement Social And Combined Scenarios

Implement social aggregate next because the current data already supports a
clear access-boundary story. Promote it to hosted only after live hosted
validation shows aggregate-reader success and row-reader denial.

Implement combined support after health naming or model cleanup. Do not present
health as a normal facility registry keyed by `national_id`.

### Phase 5: Implement Agriculture Scenario

Add the agriculture scenario once the UI can support either local-only services
or a clear "requires local agriculture profile" state.

The agriculture scenario can be the most advanced story, with richer facts and
optional credential issuance, because the fixture data already contains strong
positive and negative controls.

## Verification Plan

Automated checks:

- fixture invariant tests for civil, social, health, and agriculture selected
  subjects;
- scenario payload tests for all implemented stories;
- mocked step execution tests for each scenario;
- token display policy tests;
- copy-as-curl rendering tests;
- page shell tests for chooser and dedicated scenario routes.

Manual or browser checks:

- run each scenario locally;
- confirm default UI hides raw JSON;
- confirm request and response drawers are readable;
- confirm copy-as-curl works for GET and POST bodies;
- confirm friendly results explain the outcome without requiring technical
  knowledge;
- confirm public tokens appear only where intentionally published;
- confirm runtime-only secrets do not appear in source drawers.

Hosted checks:

- mark local-only scenarios clearly if the hosted environment does not run the
  required services;
- verify hosted metadata does not advertise unreachable internal URLs as if
  they were user-callable endpoints;
- verify the wallet scenario uses hosted issuer URLs when hosted.

## Settled Decisions And Deferred Cleanup

- Wallet scenario: adult self-attestation using `NID-2001`, Maria Santos.
- Health scenario: minimal rename to applicant service-availability projection.
- Agriculture scenario: visible as local-only until a hosted agriculture profile
  exists.
- Social aggregate and combined support scenarios: hosted via the lab homepage,
  with internal service URLs used only by the server-side runner.
- `/scenarios`: chooser for the implemented stories. Each story has a
  dedicated route under `/scenarios/<scenario-id>`.
- Deferred cleanup: generic `ZZ` and `demo.example.gov` identifiers remain in
  some low-level metadata until a separate jurisdiction naming pass replaces
  them consistently.

## Recommended Build Order

1. Fix civil persona and wallet story credibility.
2. Refactor current scenario into reusable scenario infrastructure.
3. Implement simulated wallet VC explorer.
4. Implement social aggregate versus row access.
5. Clean up health naming/model and implement combined support.
6. Implement agriculture voucher scenario.

Keep fixture cleanup ahead of new scenario behavior. Adding stories on top of
unclear personas or misleading labels would multiply credibility issues instead
of resolving them.

## Delivery Waves

Use parallel workers only for independent work. Workers must not edit the same
files at the same time.

### Wave 0: Baseline Review And Test Harness

Parallel work:

- Worker A audits civil, social, health, agriculture, and wallet fixtures and
  records the selected scenario subjects.
- Worker B audits scenario UI/server structure and identifies reusable helpers.
- Worker C audits hosted versus local service availability and metadata URL
  exposure.

Definition of done:

- A fixture matrix exists in docs or tests with one row per planned scenario
  subject, expected outcome, and source fixture file.
- Test command list is documented from the repo's existing tooling.
- No code or fixture behavior is changed in this wave.

Code-review checkpoint:

- Review the fixture matrix and service availability notes.
- Confirm the next wave has no unresolved persona or endpoint ambiguity.

### Wave 1: Fixture Credibility Cleanup

Parallel work:

- Worker A fixes civil naming/persona credibility.
- Worker B fixes or reframes health service availability data.
- Worker C normalizes public-facing metadata and scenario labels.

Definition of done:

- Fixture invariant tests pass for all selected civil, social, health, and
  agriculture subjects.
- Wallet persona is either adult self-attestation or explicit caregiver flow.
- Public-facing scenario/docs copy no longer uses misleading civil or health
  labels.
- Hosted-facing metadata no longer shows private backend hostnames as if they
  are public endpoints.

Code-review checkpoint:

- Review fixture diffs and invariant tests before any new scenario UI is added.
- Reject the wave if any scenario outcome depends on undocumented fixture
  assumptions.

### Wave 2: Scenario Infrastructure

Parallel work:

- Worker A extracts shared scenario execution helpers.
- Worker B builds the scenario chooser and dedicated scenario route shell.
- Worker C adds shared source drawers, copy-as-curl, token display policy, and
  page tests.

Definition of done:

- `scripts/lab-homepage-server.py` only routes scenario pages and APIs.
- Scenario definitions live in dedicated scenario modules.
- Existing civil alive scenario still passes its local browser flow.
- Page routing tests cover `/scenarios` and at least one dedicated scenario
  route.
- Token display policy tests cover public demo tokens and runtime-only hidden
  tokens.

Code-review checkpoint:

- Review architecture before adding new scenario behavior.
- Confirm the refactor is behavior-preserving for the existing scenario.

### Wave 3: Wallet And Social Scenarios

Parallel work:

- Worker A implements the simulated wallet credential explorer.
- Worker B implements social aggregate versus row access.
- Worker C adds browser verification scripts or checklists for both.

Definition of done:

- Wallet scenario shows issuer metadata, offer, simulated holder DID, nonce,
  credential request, and wallet-style credential viewer.
- Social scenario shows aggregate success and row-access denial with the
  correct credentials.
- Both scenarios have mocked step execution tests and local browser
  verification.
- Raw credential values and proof secrets are not exposed unless the UI labels
  the view as an approved playground source view.

Code-review checkpoint:

- Review wallet credential display and secret-handling boundaries.
- Review social access-control claims against actual HTTP statuses.

### Wave 4: Combined Support Scenario

Parallel work:

- Worker A implements combined support scenario steps.
- Worker B validates health cleanup against the combined scenario.
- Worker C adds positive and negative control tests.

Definition of done:

- Scenario evaluates civil, social, health, and final combined support claims.
- Friendly UI shows subclaim outcomes and the final decision.
- Positive and negative controls match the fixture matrix.
- Response source confirms no raw source rows are embedded in the final result.

Code-review checkpoint:

- Review health model credibility and subclaim explanations before marking the
  scenario available.

### Wave 5: Agriculture Scenario

Parallel work:

- Worker A implements climate-smart input voucher flow.
- Worker B implements optional aggregate market-sizing or livestock extension.
- Worker C adds local-only or hosted availability handling.

Definition of done:

- Agriculture scenario runs against available local or hosted agriculture
  services, or is clearly marked local-only before execution.
- Positive and negative farmer outcomes match fixture invariant tests.
- Friendly UI shows contributing facts or reason codes.
- Optional credential issuance is tested if exposed in the UI.

Code-review checkpoint:

- Review whether the agriculture scenario is suitable for hosted visibility.
- Confirm local-only labeling is accurate if hosted services are unavailable.

### Wave 6: End-To-End Hardening

Parallel work:

- Worker A runs full automated verification.
- Worker B performs desktop browser verification for all implemented scenarios.
- Worker C performs mobile browser verification and hosted smoke checks.

Definition of done:

- All relevant lint, typecheck, tests, and build commands pass, or skipped
  commands are documented with exact reasons.
- Every implemented scenario has local browser verification evidence.
- Hosted scenarios pass hosted checks; local-only scenarios are visibly marked.
- Docs and README text match implemented behavior.
- No unrelated dirty files are mixed into the scenario change set.

Code-review checkpoint:

- Final review compares the implementation against the Definition Of Done in
  this document.
- No feature is marked done unless its tests, browser checks, and documentation
  are complete.
