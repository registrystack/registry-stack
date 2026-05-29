// SPDX-License-Identifier: Apache-2.0
// Scenario: sustained-rate politeness assertion across two concurrent inbound requests.
//
// Sends exactly two concurrent batch_evaluate requests repeatedly. After each
// iteration pair, queries the stub's /_stats endpoint to observe peak_in_flight.
// The raw peak is recorded as a custom metric so the baseline captures the
// actual outbound concurrency the sequential implementation drives.
//
// Stage 1 DoD: after the process-global semaphore lands, re-run this scenario
// and assert peak_in_flight <= max_in_flight (default 8). Stage 0 establishes
// the pre-semaphore baseline that Stage 1 regresses against.
//
// Stub endpoint: GET <EVIDENCE_SOURCE_STUB_BIND>/_stats
//   Returns: {"in_flight": N, "peak_in_flight": M, "total": T}
//
// Environment:
//   EVIDENCE_SOURCE_STUB_BIND (default 127.0.0.1:14256) -- stub host:port
//   REGISTRY_NOTARY_BASE_URL  (default http://127.0.0.1:14255)
//   REGISTRY_NOTARY_BEARER_TOKEN -- required
//   REGISTRY_NOTARY_CLAIM_EXTRACT (default date-of-birth)

import http from 'k6/http';
import { check } from 'k6';
import { Gauge, Counter } from 'k6/metrics';
import {
  baseUrl,
  bearerToken,
  bearerHeaders,
  CLAIM_RESULT_ACCEPT,
  extractClaim,
  nextSubjectId,
  handleResultsFor,
  logScenarioStart,
} from './lib/common.js';

// Peak outbound concurrency observed at the stub across the whole run.
const peakInFlightGauge = new Gauge('stub_peak_in_flight');
// Samples collected from /_stats.
const statsSamples = new Counter('stub_stats_samples');

const CONCURRENT_BATCH_SIZE = 10;

function stubStatsUrl() {
  const bind = __ENV.EVIDENCE_SOURCE_STUB_BIND || '127.0.0.1:14256';
  return `http://${bind}/_stats`;
}

export const options = {
  // Two VUs simulate two concurrent inbound notary requests.
  vus: 2,
  duration: __ENV.REGISTRY_NOTARY_DURATION || '30s',
  tags: { scenario: 'politeness_concurrent', expected_status: 'false' },
  thresholds: {
    // No 5xx from notary.
    'http_req_failed{expected_status:false}': ['rate<0.001'],
  },
};

function buildSubjects(vuId, iter) {
  const subjects = new Array(CONCURRENT_BATCH_SIZE);
  for (let i = 0; i < CONCURRENT_BATCH_SIZE; i++) {
    subjects[i] = {
      id: nextSubjectId(vuId, iter * CONCURRENT_BATCH_SIZE + i),
      id_type: 'NATIONAL_ID',
    };
  }
  return subjects;
}

export function setup() {
  const token = bearerToken();
  const claim = extractClaim();
  // Reset the stub counter so baseline reflects only this run.
  const bind = __ENV.EVIDENCE_SOURCE_STUB_BIND || '127.0.0.1:14256';
  http.post(`http://${bind}/_stats/reset`);
  logScenarioStart({
    scenario: 'politeness_concurrent',
    expectedResponse: '200',
    vus: 2,
    duration: options.duration,
  });
  return { token, claim };
}

export default function (ctx) {
  // Each VU fires one batch_evaluate. Because VUs run in parallel, two
  // concurrent batches hit the stub at the same time.
  const subjects = buildSubjects(__VU, __ITER);
  const payload = JSON.stringify({ subjects, claims: [ctx.claim] });

  const res = http.post(`${baseUrl()}/claims/batch-evaluate`, payload, {
    headers: bearerHeaders(ctx.token, { json: true, purpose: 'perf', accept: CLAIM_RESULT_ACCEPT }),
    timeout: '120s',
  });

  check(res, { 'status is 200': (r) => r.status === 200 });

  // Poll /_stats to capture current peak. Only VU 1 polls to avoid double-counting.
  if (__VU === 1) {
    const statsRes = http.get(stubStatsUrl(), { tags: { expected_status: 'stats' } });
    if (statsRes.status === 200) {
      try {
        const stats = JSON.parse(statsRes.body);
        peakInFlightGauge.add(stats.peak_in_flight);
        statsSamples.add(1);
      } catch (_) {
        // ignore parse errors; stub may not have started yet
      }
    }
  }
}

export function handleSummary(data) {
  return handleResultsFor('politeness_concurrent', data);
}
