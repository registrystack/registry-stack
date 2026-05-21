// SPDX-License-Identifier: Apache-2.0
// Scenario: evidence verification decision path load test.
//
// Exercises POST /evidence-offerings/{offering_id}/verifications across
// all three decision paths. Weighted distribution:
//
//   30% - expected match    (success path; baseline for signing latency)
//   50% - expected mismatch (dominant adversarial workload; most important to baseline)
//   20% - expected ambiguous (rare but a known timing outlier worth isolating)
//
// Rationale for the weights: mismatch is the highest-volume real-world case
// because automated callers submit facts for people who may not be in the
// registry. Match is the happy path that exercises HMAC + Ed25519 signing.
// Ambiguous is uncommon but the spec deliberately does not normalize its
// timing against mismatch, so we need enough volume here to detect regressions.
//
// Stage profile: 30s ramp 0->20 VUs, 2min steady 20 VUs, 30s ramp-down.
// Lower than the read scenarios because this is a write+sign path (HMAC,
// DataFusion candidate scan, and Ed25519 receipt sign on every request).
//
// Rulesets:
//   facility-identity-v1  -- candidate_lookup on id (unique); drives match/mismatch
//   facility-region-v1    -- candidate_lookup on region_code (non-unique, ~5k hits);
//                            drives ambiguous with expose_ambiguous: true
//
// Fixture values (seed 42, row 0):
//   fac-000000: region_code=R002, category=hospital
//
// Match claim:    {id: "fac-000000", category: "hospital"}    -> exactly 1 hit, all fields match
// Mismatch claim: {id: "fac-000000", category: "clinic"}      -> candidate found, category wrong -> 0 matches
// Ambiguous claim:{region_code: "R002", category: "hospital"} -> many rows in R002 with category=hospital -> ambiguous
//
// Signed receipt path: the scenario requests
// `application/vnd.registry-relay.evidence-verification+jwt`, so the handler
// returns a compact-serialized Ed25519-signed JWS. The decision is checked
// by base64url-decoding the JWS payload segment and reading its `decision`
// claim. The signature is NOT verified by k6: we trust the in-process
// signer and use k6 only for end-to-end latency.
//
// Env vars:
//   REGISTRY_RELAY_BASE_URL          (default: http://127.0.0.1:18080)
//   REGISTRY_RELAY_DATASET_ID        (default: clinic_capacity)
//   REGISTRY_RELAY_ENTITY            (default: facility)
//   REGISTRY_RELAY_TOKEN_EVIDENCE_VERIFICATION  -- required; must carry clinic_capacity:evidence_verification scope
//
// Setup prerequisite: run generate_perf_keys.py to emit
// REGISTRY_RELAY_TOKEN_EVIDENCE_VERIFICATION and REGISTRY_RELAY_PROVENANCE_JWK,
// then start the server with a perf config that includes both the
// metadata, claim_verification matching-engine, and provenance blocks (all
// three perf/config/*.yaml files have them).

import http from 'k6/http';
import { check, fail, group } from 'k6';
import encoding from 'k6/encoding';
import {
  baseUrl,
  dataset,
  entity,
  handleSummaryFor,
  trackResponse,
  logScenarioStart,
  thresholdsFor,
} from './lib/common.js';

const RECEIPT_MEDIA_TYPE = 'application/vnd.registry-relay.evidence-verification+jwt';
const IDENTITY_OFFERING_ID = __ENV.REGISTRY_RELAY_IDENTITY_EVIDENCE_OFFERING_ID || 'facility_identity_evidence_offering';
const REGION_OFFERING_ID = __ENV.REGISTRY_RELAY_REGION_EVIDENCE_OFFERING_ID || 'facility_region_evidence_offering';

// ---------------------------------------------------------------------------
// Token helper
// ---------------------------------------------------------------------------

function evidenceVerificationToken() {
  const token = __ENV.REGISTRY_RELAY_TOKEN_EVIDENCE_VERIFICATION || '';
  if (!token) {
    fail('Required env var REGISTRY_RELAY_TOKEN_EVIDENCE_VERIFICATION is not set.');
  }
  return token;
}

// ---------------------------------------------------------------------------
// JWS payload decoder
// ---------------------------------------------------------------------------

// Returns the parsed JSON payload of a compact JWS, or null on any parse
// failure. Does NOT verify the signature: this is for perf only.
function decodeJwsPayload(compactJws) {
  if (typeof compactJws !== 'string') return null;
  const segments = compactJws.split('.');
  if (segments.length !== 3) return null;
  try {
    const json = encoding.b64decode(segments[1], 'rawurl', 's');
    return JSON.parse(json);
  } catch (_) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// Per-decision thresholds. These are first-pass targets based on the
// claim_verification_bench microbench (HMAC ~2us, Ed25519 sign ~16us on M5
// Max) plus headroom for DataFusion candidate scan, axum routing, and JSON
// serialization. Tighten after a baseline run.
export const options = {
  stages: [
    { duration: '30s', target: 20 },
    { duration: '2m',  target: 20 },
    { duration: '30s', target: 0  },
  ],
  tags: { scenario: 'evidence_verification', expected_status: 'false' },
  thresholds: Object.assign(
    {
      'http_req_duration{decision_expected:match}':     ['p(95)<50',  'p(99)<150'],
      'http_req_duration{decision_expected:mismatch}':  ['p(95)<50',  'p(99)<150'],
      'http_req_duration{decision_expected:ambiguous}': ['p(95)<150', 'p(99)<400'],
    },
    thresholdsFor('evidence_verification'),
  ),
};

// ---------------------------------------------------------------------------
// Setup: capture token once and log start metadata
// ---------------------------------------------------------------------------

export function setup() {
  const token = evidenceVerificationToken();
  logScenarioStart({
    scenario: 'evidence_verification',
    expectedResponse: '200 application/vnd.registry-relay.evidence-verification+jwt',
    vus: 20,
    duration: '3m',
  });
  return { token };
}

// ---------------------------------------------------------------------------
// Per-decision sender
// ---------------------------------------------------------------------------

function runCase(ctx, label, expectedDecision, offeringId, body) {
  const url = `${baseUrl()}/evidence-offerings/${offeringId}/verifications`;
  const headers = {
    'Authorization': `Bearer ${ctx.token}`,
    'Content-Type': 'application/json',
    'Accept': RECEIPT_MEDIA_TYPE,
    'Data-Purpose': 'https://perf.example.test/purpose/load-test',
  };
  group(label, () => {
    const res = http.post(url, JSON.stringify(body), {
      headers,
      tags: { decision_expected: expectedDecision },
    });
    check(res, {
      [`${label}: status 200`]: (r) => r.status === 200,
      [`${label}: content-type is signed receipt`]: (r) =>
        (r.headers['Content-Type'] || '').toLowerCase().startsWith(RECEIPT_MEDIA_TYPE),
    });
    if (res.status === 200) {
      check(res, {
        [`${label}: receipt decision matches`]: (r) => {
          const payload = decodeJwsPayload(r.body);
          return payload !== null && payload.decision === expectedDecision;
        },
      });
    }
    trackResponse(res);
  });
}

// ---------------------------------------------------------------------------
// Default function: weighted dispatch across three decision paths
// ---------------------------------------------------------------------------

export default function (ctx) {
  const roll = Math.random();

  if (roll < 0.30) {
    // 30%: expected match
    // fac-000000 has category=hospital in the seed-42 fixture.
    // candidate_lookup on id finds exactly one candidate; all match_fields agree.
    runCase(ctx, 'match', 'match', IDENTITY_OFFERING_ID, {
      claims: { id: 'fac-000000', category: 'hospital' },
    });
  } else if (roll < 0.80) {
    // 50%: expected mismatch
    // fac-000000 exists with category=hospital; submitting category=clinic
    // fails match_fields -> 0 matches -> mismatch.
    runCase(ctx, 'mismatch', 'mismatch', IDENTITY_OFFERING_ID, {
      claims: { id: 'fac-000000', category: 'clinic' },
    });
  } else {
    // 20%: expected ambiguous
    // R002 contains ~5000 rows; category=hospital matches a large fraction.
    // candidate_lookup on region_code returns many candidates; all match the
    // submitted category -> ambiguous. expose_ambiguous: true on
    // facility-region-v1 means the response reports "ambiguous" instead of
    // collapsing to "mismatch".
    runCase(ctx, 'ambiguous', 'ambiguous', REGION_OFFERING_ID, {
      claims: { region_code: 'R002', category: 'hospital' },
    });
  }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  return handleSummaryFor('evidence_verification', data);
}
