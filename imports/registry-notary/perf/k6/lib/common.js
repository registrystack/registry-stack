// SPDX-License-Identifier: Apache-2.0
// Shared helpers for registry-witness k6 load test scenarios.
//
// Protocol notes:
//   HTTP version: k6 defaults to HTTP/1.1 with connection keepalive. Do not override.
//   Compression: no Accept-Encoding override. k6 defaults to identity encoding.
//   Auth: Authorization: Bearer <token> on the hot path. X-Api-Key is exercised
//     in auth_deny.js to verify both header forms reach the same code path.

import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.2/index.js';
import { Counter, Rate } from 'k6/metrics';
import { fail } from 'k6';

// ---------------------------------------------------------------------------
// Custom metrics shared across scenarios
// ---------------------------------------------------------------------------

// Non-2xx responses that were not tagged as expected 401/403. Asserted ==0.
export const unexpectedFailures = new Rate('unexpected_failures');

// 5xx responses. Asserted ==0.
export const serverErrors5xx = new Counter('server_errors_5xx');

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

export function baseUrl() {
  return __ENV.REGISTRY_WITNESS_BASE_URL || 'http://127.0.0.1:14255';
}

export function profile() {
  return __ENV.REGISTRY_WITNESS_PROFILE || 'medium';
}

export function batchSize() {
  return parseInt(__ENV.REGISTRY_WITNESS_BATCH_SIZE || '10', 10);
}

export function subjectCount() {
  return parseInt(__ENV.REGISTRY_WITNESS_SUBJECT_COUNT || '100000', 10);
}

export function extractClaim() {
  return __ENV.REGISTRY_WITNESS_CLAIM_EXTRACT || 'date-of-birth';
}

export function celClaim() {
  return __ENV.REGISTRY_WITNESS_CLAIM_CEL || 'farmer-under-4ha';
}

const loggedTokenLabels = new Set();

function logTokenPresenceOnce(label, message) {
  if (__ENV.REGISTRY_WITNESS_LOG_TOKENS !== '1') {
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

export function bearerToken() {
  return requireToken('REGISTRY_WITNESS_BEARER_TOKEN', 'bearer token');
}

export function apiKeyToken() {
  return requireToken('REGISTRY_WITNESS_API_KEY', 'api key');
}

export function noScopeToken() {
  return requireToken('REGISTRY_WITNESS_NO_SCOPE_TOKEN', 'no-scope token');
}

export function invalidToken() {
  // Invalid token is a synthetic value. A blank value still exercises 401,
  // so we do not fail-fast.
  const token = __ENV.REGISTRY_WITNESS_TOKEN_INVALID || 'invalid-token-value';
  logTokenPresenceOnce('invalid token', 'invalid token: token present: yes (synthetic)');
  return token;
}

// Accept header for claim evaluate / batch-evaluate responses.
// Witness requires this specific media type; generic application/json returns 406.
export const CLAIM_RESULT_ACCEPT = 'application/vnd.registry-witness.claim-result+json';

export function bearerHeaders(token, opts) {
  const o = opts || {};
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Accept': o.accept || 'application/json',
  };
  if (o.json) {
    headers['Content-Type'] = 'application/json';
  }
  if (o.purpose) {
    headers['data-purpose'] = o.purpose;
  }
  return headers;
}


export function apiKeyHeaders(token, opts) {
  const o = opts || {};
  const headers = {
    'X-Api-Key': token,
    'Accept': 'application/json',
  };
  if (o.json) {
    headers['Content-Type'] = 'application/json';
  }
  if (o.purpose) {
    headers['data-purpose'] = o.purpose;
  }
  return headers;
}

// Subject id derived from a k6 VU/iteration index. Matches the stub's pool.
export function subjectIdFor(index) {
  const count = subjectCount();
  // Zero-padded to 7 digits — enough headroom for subj-9999999 (10M+).
  const wrapped = ((index % count) + count) % count;
  return `subj-${String(wrapped).padStart(7, '0')}`;
}

// Cycle subject ids across (vu, iter) so VUs don't collide on cache lines
// but still hit a deterministic pool for reproducibility.
export function nextSubjectId(vu, iter) {
  // Spread VUs by a large prime so adjacent VUs do not land on adjacent ids.
  const stride = 9973;
  return subjectIdFor(vu * stride + iter);
}

// ---------------------------------------------------------------------------
// Threshold definitions
// ---------------------------------------------------------------------------

const THRESHOLDS = {
  // Catalog read: no source IO, no signing. Cheap auth + JSON serialization.
  'list_claims': {
    'http_req_duration{expected_status:false}': ['p(95)<15', 'p(99)<40'],
  },
  // Single-claim evaluate over the stub: one DCI POST + extract rule + audit.
  'evaluate_extract': {
    'http_req_duration{expected_status:false}': ['p(95)<75', 'p(99)<200'],
  },
  // CEL evaluate (depends_on => one extra extract + CEL execution).
  'evaluate_cel': {
    'http_req_duration{expected_status:false}': ['p(95)<150', 'p(99)<400'],
  },
  // Batch evaluate: N subjects per request, default REGISTRY_WITNESS_BATCH_SIZE=10.
  'batch_evaluate': {
    'http_req_duration{expected_status:false}': ['p(95)<500', 'p(99)<1500'],
  },
  // Auth deny paths share the cheap-path budget (no source IO).
  'auth_deny': {
    'http_req_duration{expected_status:false}': ['p(95)<15', 'p(99)<40'],
  },
};

const GLOBAL_THRESHOLDS = {
  'http_req_failed{expected_status:false}': ['rate<0.001'],
  'unexpected_failures': ['rate==0'],
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

  const vus = parseInt(__ENV.REGISTRY_WITNESS_VUS || String(defaultVus || 10), 10);
  const duration = __ENV.REGISTRY_WITNESS_DURATION || defaultDuration || '30s';

  const tags = Object.assign({ scenario, expected_status: 'false' }, extraTags || {});

  if (scenarioType === 'constant-arrival-rate') {
    const rate = parseInt(__ENV.REGISTRY_WITNESS_RATE || String(defaultRate || 50), 10);
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

export function tagExpected(status) {
  return { tags: { expected_status: String(status) } };
}

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

// Write a stable (non-timestamped) result file consumed by the baseline
// capture script. Each scenario overwrites its own slot so the latest run is
// always available at a predictable path.
export function handleResultsFor(scenarioName, data) {
  const ts = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').split('Z')[0] + 'Z';
  const base = `target/perf/reports/${scenarioName}-${ts}`;
  const stable = `target/perf/results/${scenarioName}`;
  return {
    [`${base}.json`]: JSON.stringify(data, null, 2),
    [`${base}.txt`]: textSummary(data, { indent: ' ', enableColors: false }),
    [`${stable}.json`]: JSON.stringify(data, null, 2),
    [`${stable}.txt`]: textSummary(data, { indent: ' ', enableColors: false }),
  };
}

// ---------------------------------------------------------------------------
// Startup metadata log
// ---------------------------------------------------------------------------

export function logScenarioStart(opts) {
  console.log(JSON.stringify({
    event: 'scenario_start',
    scenario: opts.scenario,
    expected_response: opts.expectedResponse || 'unknown',
    vus: opts.vus,
    duration: opts.duration,
    profile: profile(),
    subject_count: subjectCount(),
    http_version: 'HTTP/1.1',
    keepalive: true,
    compression: 'identity',
  }));
}
