// SPDX-License-Identifier: Apache-2.0
// Scenario: large dataset 304 revalidation loop.
//
// Warms up to capture the current ETag, then sends If-None-Match in a tight
// loop expecting 304 responses.
//
// Intentional regression target: the current implementation routes 304
// through read_collection, meaning 304 latency scales with row count.
// The threshold (cached_304_large: p95 < 15ms, p99 < 40ms) is expected to
// FAIL against a 1M-row dataset today. That failure is the signal. A future
// metadata-only ETag path should make this threshold green.
//
// This script uses cached_304_large thresholds. If you want to observe the
// raw timing without failing the run, set REGISTRY_RELAY_NO_THRESHOLD=1 to skip
// the threshold gate.

import http from 'k6/http';
import { check, fail } from 'k6';
import {
  commonOptions,
  baseUrl,
  dataset,
  entity,
  rowsToken,
  handleSummaryFor,
  trackExpectedStatus,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'large_304',
  thresholdKey: 'cached_304_large',
  defaultVus: 20,
  defaultDuration: '30s',
});

export function setup() {
  const token = rowsToken();
  logScenarioStart({
    scenario: 'large_304',
    expectedResponse: '304 (intentional regression target for large datasets)',
    vus: options.vus,
    duration: options.duration,
  });

  // Warm-up: fetch once to obtain the ETag. This request itself will be slow
  // on the large fixture; that cost is outside the measured loop.
  const url = `${baseUrl()}/v1/datasets/${dataset()}/entities/${entity()}/records`;
  console.log('large_304: warming up (fetching ETag from large dataset)...');
  const res = http.get(url, {
    headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
    timeout: '300s',
  });

  if (res.status !== 200) {
    fail(`large_304 setup: expected 200 to capture ETag, got ${res.status}`);
  }
  const etag = res.headers['Etag'] || res.headers['ETag'] || '';
  if (!etag) {
    fail('large_304 setup: ETag absent from large-dataset response; cannot run 304 scenario');
  }
  console.log(`large_304: ETag captured (length=${etag.length}). Warm-up done.`);
  return { etag, token };
}

export default function (ctx) {
  const url = `${baseUrl()}/v1/datasets/${dataset()}/entities/${entity()}/records`;
  const res = http.get(url, {
    headers: {
      'Authorization': `Bearer ${ctx.token}`,
      'Accept': 'application/json',
      'If-None-Match': ctx.etag,
    },
  });

  check(res, {
    'status is 304': (r) => r.status === 304,
    'body is empty': (r) => !r.body || r.body.length === 0,
  });

  trackExpectedStatus(res, 304);
}

export function handleSummary(data) {
  return handleSummaryFor('large_304', data);
}
