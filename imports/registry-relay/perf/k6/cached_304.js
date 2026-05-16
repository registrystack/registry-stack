// SPDX-License-Identifier: Apache-2.0
// Scenario: cached 304 revalidation on the collection endpoint.
//
// Warm-up step captures the current ETag via a normal 200 GET.
// Each iteration sends If-None-Match with that ETag and expects a 304 body-less
// response. This is the critical regression path: the server should not
// serialize the full collection to decide the data is unchanged.
//
// Threshold key: cached_304_small (p95 < 10ms, p99 < 25ms at 20 VU / 100 RPS)
// For the large profile, set DATA_GATE_PROFILE=large; the script uses
// cached_304_large thresholds when that env var is set.

import http from 'k6/http';
import { check, fail, group } from 'k6';
import {
  commonOptions,
  baseUrl,
  dataset,
  entity,
  rowsToken,
  handleSummaryFor,
  trackExpectedStatus,
  logScenarioStart,
  profile,
} from './lib/common.js';

const thresholdKey = (__ENV.DATA_GATE_PROFILE === 'large') ? 'cached_304_large' : 'cached_304_small';

export const options = commonOptions({
  scenario: 'cached_304',
  thresholdKey,
  defaultVus: 20,
  defaultDuration: '30s',
});

export function setup() {
  const token = rowsToken();
  logScenarioStart({
    scenario: 'cached_304',
    expectedResponse: '304',
    vus: options.vus,
    duration: options.duration,
  });

  const url = `${baseUrl()}/datasets/${dataset()}/${entity()}`;
  const res = http.get(url, { headers: headersForToken(token) });

  if (res.status !== 200) {
    fail(`setup: expected 200 to capture ETag, got ${res.status}`);
  }
  const etag = res.headers['Etag'] || res.headers['ETag'] || '';
  if (!etag) {
    fail('setup: ETag header absent on collection response; cannot run 304 scenario');
  }
  console.log(`setup: captured ETag (length=${etag.length})`);
  return { etag, token };
}

function headersForToken(token) {
  return {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/json',
  };
}

export default function (ctx) {
  const url = `${baseUrl()}/datasets/${dataset()}/${entity()}`;
  const res = http.get(url, {
    headers: Object.assign({}, headersForToken(ctx.token), {
      'If-None-Match': ctx.etag,
    }),
  });

  const ok = check(res, {
    'status is 304': (r) => r.status === 304,
    'body is empty': (r) => !r.body || r.body.length === 0,
  });

  trackExpectedStatus(res, 304);
}

export function handleSummary(data) {
  return handleSummaryFor('cached_304', data);
}
