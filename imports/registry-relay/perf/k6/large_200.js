// SPDX-License-Identifier: Apache-2.0
// Scenario: 200 reads against the large fixture profile (1M rows).
//
// Single user by default (DATA_GATE_PROFILE=large). The response body is
// large; latency thresholds are set accordingly.
//
// Threshold key is chosen by DATA_GATE_PROFILE:
//   large (default): hot_200_1mb  (p95 < 50ms, p99 < 150ms)
//   large-wide:      hot_200_10mb (p95 < 250ms, p99 < 750ms)
//   large-full:      hot_200_50mb (p95 < 1500ms, p99 < 5000ms)
//
// Run against the large config:
//   op run --env-file=target/perf/perf.env -- \
//     target/release/data_gate --config perf/config/large.yaml
//
// Then:
//   DATA_GATE_PROFILE=large k6 run perf/k6/large_200.js

import http from 'k6/http';
import { check } from 'k6';
import {
  commonOptions,
  baseUrl,
  dataset,
  entity,
  rowsToken,
  handleSummaryFor,
  trackResponse,
  logScenarioStart,
  profile,
} from './lib/common.js';

function resolveThresholdKey() {
  switch (profile()) {
    case 'large-wide': return 'hot_200_10mb';
    case 'large-full': return 'hot_200_50mb';
    default: return 'hot_200_1mb';
  }
}

export const options = commonOptions({
  scenario: 'large_200',
  thresholdKey: resolveThresholdKey(),
  defaultVus: 1,
  defaultDuration: '5m',
});

export function setup() {
  const token = rowsToken();
  logScenarioStart({
    scenario: 'large_200',
    expectedResponse: '200 (large body)',
    vus: 1,
    duration: options.duration,
  });
  return { token };
}

export default function (ctx) {
  // No pagination limit to force a large response. The server's default_limit
  // (100) applies unless overridden. For a genuine large-body test, use
  // max_limit (1000) via ?limit=1000, or remove the limit to get the default.
  const url = `${baseUrl()}/datasets/${dataset()}/${entity()}?limit=1000`;
  const res = http.get(url, {
    headers: {
      'Authorization': `Bearer ${ctx.token}`,
      'Accept': 'application/json',
    },
    // Increase timeout for large responses.
    timeout: '120s',
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has ETag': (r) => !!(r.headers['Etag'] || r.headers['ETag']),
    'body is non-empty': (r) => !!r.body && r.body.length > 0,
  });

  if (res.body) {
    console.log(`large_200: response size = ${res.body.length} bytes`);
  }

  trackResponse(res);
}

export function handleSummary(data) {
  return handleSummaryFor('large_200', data);
}
