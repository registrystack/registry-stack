// SPDX-License-Identifier: Apache-2.0
// Shared helpers for registry-relay k6 load test scenarios.
//
// Protocol notes:
//   HTTP version: k6 defaults to HTTP/1.1 with connection keepalive. Do not override.
//   Compression: no Accept-Encoding override. k6 defaults to identity encoding.
//     If the server later adds compression, run compressed and identity profiles separately.
//   Auth: Authorization: Bearer <token> by default. X-Api-Key is tested in auth_deny.js.

import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.2/index.js';
import { Counter, Rate } from 'k6/metrics';
import { fail } from 'k6';

// ---------------------------------------------------------------------------
// Custom metrics shared across scenarios
// ---------------------------------------------------------------------------

// Counts unexpected failures: non-2xx/3xx responses that were not tagged as
// expected 401 or 403. Each scenario asserts this equals 0.
export const unexpectedFailures = new Rate('unexpected_failures');

// Counts 5xx responses. Each scenario asserts this equals 0.
export const serverErrors5xx = new Counter('server_errors_5xx');

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

export function baseUrl() {
  return __ENV.REGISTRY_RELAY_BASE_URL || 'http://127.0.0.1:18080';
}

export function dataset() {
  return __ENV.REGISTRY_RELAY_DATASET_ID || 'clinic_capacity';
}

export function entity() {
  return __ENV.REGISTRY_RELAY_ENTITY || 'facility';
}

export function aggregateId() {
  return __ENV.REGISTRY_RELAY_AGGREGATE_ID || 'by_region';
}

export function auditSink() {
  return __ENV.REGISTRY_RELAY_AUDIT_SINK || 'file';
}

export function profile() {
  return __ENV.REGISTRY_RELAY_PROFILE || 'medium';
}

const loggedTokenLabels = new Set();

function logTokenPresenceOnce(label, message) {
  if (__ENV.REGISTRY_RELAY_LOG_TOKENS !== '1') {
    return;
  }
  if (!loggedTokenLabels.has(label)) {
    loggedTokenLabels.add(label);
    console.log(message);
  }
}

function requireToken(envVar, label) {
  const token = __ENV[envVar] || '';
  if (!token) {
    fail(`Required env var ${envVar} (${label}) is not set. token present: no`);
  }
  logTokenPresenceOnce(label, `${label}: token present: yes`);
  return token;
}

export function rowsToken() {
  return requireToken('REGISTRY_RELAY_TOKEN', 'rows token');
}

export function metadataToken() {
  return requireToken('REGISTRY_RELAY_TOKEN_METADATA', 'metadata token');
}

export function aggregateToken() {
  return requireToken('REGISTRY_RELAY_TOKEN_AGGREGATE', 'aggregate token');
}

export function noScopeToken() {
  return requireToken('REGISTRY_RELAY_TOKEN_NO_SCOPE', 'no-scope token');
}

export function invalidToken() {
  // Invalid token is expected to be a synthetic value. We do not fail-fast
  // because a blank invalid token still exercises the 401 path.
  const token = __ENV.REGISTRY_RELAY_TOKEN_INVALID || 'invalid-token-value';
  logTokenPresenceOnce('invalid token', 'invalid token: token present: yes (synthetic)');
  return token;
}

// Base request headers using Authorization: Bearer (default auth path).
export function baseHeaders() {
  const token = __ENV.REGISTRY_RELAY_TOKEN || '';
  return {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/json',
  };
}

export function headersForToken(token) {
  return {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/json',
  };
}

export function headersXApiKey(token) {
  return {
    'X-Api-Key': token,
    'Accept': 'application/json',
  };
}

// ---------------------------------------------------------------------------
// Threshold definitions
// All scenarios import their key from this table so future edits happen here.
// ---------------------------------------------------------------------------

const THRESHOLDS = {
  // Cached 304 small dataset: Moderate, 20 VU, 100 RPS
  'cached_304_small': {
    'http_req_duration{expected_status:false}': ['p(95)<10', 'p(99)<25'],
  },
  // Cached 304 large dataset: Moderate, 20 VU, 100 RPS
  'cached_304_large': {
    'http_req_duration{expected_status:false}': ['p(95)<15', 'p(99)<40'],
  },
  // Hot 200 around 100 KB: Moderate, 20 VU, 100 RPS
  'hot_200_100kb': {
    'http_req_duration{expected_status:false}': ['p(95)<25', 'p(99)<75'],
  },
  // Hot 200 around 1 MB: Moderate, 20 VU, 50 RPS
  'hot_200_1mb': {
    'http_req_duration{expected_status:false}': ['p(95)<50', 'p(99)<150'],
  },
  // Hot 200 around 10 MB: Light, 5 VU, 10 RPS
  'hot_200_10mb': {
    'http_req_duration{expected_status:false}': ['p(95)<250', 'p(99)<750'],
  },
  // Hot 200 around 50 MB: Single user, 1 VU, 1 RPS
  'hot_200_50mb': {
    'http_req_duration{expected_status:false}': ['p(95)<1500', 'p(99)<5000'],
  },
  // Health and readiness: Heavy, 50 VU, 250 RPS
  'health': {
    'http_req_duration{expected_status:false}': ['p(95)<5', 'p(99)<20'],
  },
  // Mixed read: Moderate 20 VU (uses 100kb profile as baseline)
  'mixed_read': {
    'http_req_duration{expected_status:false}': ['p(95)<50', 'p(99)<150'],
  },
  // Mixed read on the large 1M-row profile. Aggregates and hot reads do
  // real DataFusion work over the larger fixture, so the medium budget is
  // intentionally not reused for long soak runs.
  'mixed_read_large': {
    'http_req_duration{expected_status:false}': ['p(95)<100', 'p(99)<200'],
  },
  // Evidence verification: write+sign path (HMAC + DataFusion candidate scan +
  // Ed25519 receipt sign per request). The aggregate threshold here is a
  // backstop; per-decision-path budgets are set inline in
  // evidence verification scenario via tagged thresholds and are tighter for the
  // unique-lookup paths (match / mismatch).
  'claim_verification': {
    'http_req_duration{expected_status:false}': ['p(95)<200', 'p(99)<500'],
  },
};

// Global thresholds appended to every scenario.
const GLOBAL_THRESHOLDS = {
  // Exclude tagged expected 401/403 from the built-in failure rate metric.
  'http_req_failed{expected_status:false}': ['rate<0.001'],
  // Our custom metric must be 0 -- zero unexpected failures.
  'unexpected_failures': ['rate==0'],
  // No 5xx responses during normal load.
  'server_errors_5xx': ['count==0'],
};

export function thresholdsFor(key) {
  const specific = THRESHOLDS[key] || {};
  return Object.assign({}, specific, GLOBAL_THRESHOLDS);
}

// ---------------------------------------------------------------------------
// Scenario / options factory
// ---------------------------------------------------------------------------

export function commonOptions(opts) {
  const {
    scenario,
    thresholdKey,
    defaultVus,
    defaultDuration,
    defaultRate,
    scenarioType,
    extraTags,
  } = opts;

  const vus = parseInt(__ENV.REGISTRY_RELAY_VUS || String(defaultVus || 20), 10);
  const duration = __ENV.REGISTRY_RELAY_DURATION || defaultDuration || '30s';

  // Default tag so {expected_status:false} threshold filters select normal
  // requests. Per-request tags (e.g. expected_status: '401' in auth_deny)
  // override this and are excluded from the filter as intended.
  const tags = Object.assign({ scenario, expected_status: 'false' }, extraTags || {});

  if (scenarioType === 'constant-arrival-rate') {
    const rate = parseInt(__ENV.REGISTRY_RELAY_RATE || String(defaultRate || 100), 10);
    return {
      scenarios: {
        [scenario]: {
          executor: 'constant-arrival-rate',
          rate,
          timeUnit: '1s',
          duration,
          preAllocatedVUs: vus,
          maxVUs: vus * 2,
          tags,
        },
      },
      thresholds: thresholdsFor(thresholdKey || scenario),
    };
  }

  return {
    vus,
    duration,
    tags,
    thresholds: thresholdsFor(thresholdKey || scenario),
  };
}

// ---------------------------------------------------------------------------
// Response tracking helpers
// ---------------------------------------------------------------------------

// Call this after every request that is NOT intentionally expected to fail.
// Returns true if the response was successful (2xx/3xx).
export function trackResponse(res) {
  const status = res.status;
  if (status >= 500) {
    serverErrors5xx.add(1);
    unexpectedFailures.add(1);
    return false;
  }
  if (status >= 400) {
    unexpectedFailures.add(1);
    return false;
  }
  unexpectedFailures.add(0);
  return true;
}

// Call this for requests where a 401 or 403 is the intended outcome.
// Tags the request so it is excluded from http_req_failed counting.
export function tagExpected(status) {
  return { tags: { expected_status: String(status) } };
}

// After a tagged-expected request, verify no 5xx slipped through.
export function trackExpectedDenyResponse(res, expectedStatus) {
  if (res.status >= 500) {
    serverErrors5xx.add(1);
  }
  const expected = expectedStatus === '4xx'
    ? (res.status >= 400 && res.status < 500)
    : res.status === expectedStatus;
  unexpectedFailures.add(expected ? 0 : 1);
  return expected;
}

export function trackExpectedStatus(res, expectedStatus) {
  if (res.status >= 500) {
    serverErrors5xx.add(1);
  }
  const expected = res.status === expectedStatus;
  unexpectedFailures.add(expected ? 0 : 1);
  return expected;
}

// ---------------------------------------------------------------------------
// handleSummary factory
// ---------------------------------------------------------------------------

export function handleSummaryFor(scenarioName, data) {
  const ts = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').split('Z')[0] + 'Z';
  const base = `target/perf/reports/${scenarioName}-${ts}`;
  return {
    [`${base}.json`]: JSON.stringify(data, null, 2),
    [`${base}.txt`]: textSummary(data, { indent: ' ', enableColors: false }),
  };
}

// ---------------------------------------------------------------------------
// Startup metadata log
// ---------------------------------------------------------------------------

export function logScenarioStart(opts) {
  console.log(JSON.stringify({
    event: 'scenario_start',
    scenario: opts.scenario,
    dataset_id: dataset(),
    entity: entity(),
    expected_response: opts.expectedResponse || 'unknown',
    vus: opts.vus,
    duration: opts.duration,
    audit_sink: auditSink(),
    profile: profile(),
    http_version: 'HTTP/1.1',
    keepalive: true,
    compression: 'identity',
  }));
}
