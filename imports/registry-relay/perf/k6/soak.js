// SPDX-License-Identifier: Apache-2.0
// Scenario: 30-minute (default) soak test with mixed traffic and audit sink enabled.
//
// Traffic mix mirrors mixed_read.js exactly:
//   55% - cached 304
//   20% - hot 200 list
//   10% - single record
//    5% - schema
//    5% - aggregate
//    3% - catalog
//    2% - expected auth failures (tagged, excluded from failure rate)
//
// Soak-specific checks:
//   - No sustained memory growth (observed externally; k6 reports bytes received
//     as a proxy for response size stability).
//   - p95 and p99 do not rise over time (use the k6 JSON report trend graphs).
//   - No 5xx during the full run.
//   - Audit sink (REGISTRY_RELAY_AUDIT_SINK) is tagged in the report.
//
// Memory growth measurement is done externally (ps / metrics endpoint). k6
// cannot sample server-side RSS directly. The k6 report records bytes_received
// which should remain stable at constant load.
//
// Duration default: 30m (REGISTRY_RELAY_DURATION overrides).

import http from 'k6/http';
import { check, group } from 'k6';
import {
  commonOptions,
  baseUrl,
  dataset,
  entity,
  aggregateId,
  rowsToken,
  metadataToken,
  aggregateToken,
  noScopeToken,
  invalidToken,
  auditSink,
  handleSummaryFor,
  trackResponse,
  trackExpectedDenyResponse,
  logScenarioStart,
  profile,
} from './lib/common.js';

const thresholdKey = profile() === 'large' ? 'mixed_read_large' : 'mixed_read';

export const options = commonOptions({
  scenario: 'soak',
  thresholdKey,
  defaultVus: 20,
  defaultDuration: '30m',
});

export function setup() {
  const token = rowsToken();
  const metaToken = metadataToken();
  const aggToken = aggregateToken();
  logScenarioStart({
    scenario: 'soak',
    expectedResponse: 'mixed (55/20/10/5/5/3/2 blend)',
    vus: options.vus,
    duration: options.duration,
  });
  console.log(`audit sink: ${auditSink()}`);

  // Capture ETag for cached 304 path.
  const url = `${baseUrl()}/datasets/${dataset()}/${entity()}`;
  const res = http.get(url, {
    headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
  });
  const etag = (res.status === 200)
    ? (res.headers['Etag'] || res.headers['ETag'] || '')
    : '';

  // Capture a record id for single-record reads.
  let recordId = '';
  if (res.status === 200 && res.body) {
    try {
      const body = JSON.parse(res.body);
      if (body && body.data && body.data.length > 0) {
        recordId = body.data[0].id || '';
      }
    } catch (_) {}
  }

  return { token, metaToken, aggToken, etag, recordId };
}

export default function (ctx) {
  const roll = Math.random();
  const ds = dataset();
  const ent = entity();
  const base = baseUrl();
  const authHdr = { 'Authorization': `Bearer ${ctx.token}`, 'Accept': 'application/json' };
  const metaAuthHdr = { 'Authorization': `Bearer ${ctx.metaToken}`, 'Accept': 'application/json' };
  const aggAuthHdr = { 'Authorization': `Bearer ${ctx.aggToken}`, 'Accept': 'application/json' };

  if (roll < 0.55) {
    group('cached_304', () => {
      const res = http.get(`${base}/datasets/${ds}/${ent}`, {
        headers: Object.assign({}, authHdr, { 'If-None-Match': ctx.etag || '"missing"' }),
      });
      check(res, { 'soak 304: 304 or 200': (r) => r.status === 304 || r.status === 200 });
      if (res.status >= 500) trackResponse(res);
    });
  } else if (roll < 0.75) {
    group('hot_200', () => {
      const res = http.get(`${base}/datasets/${ds}/${ent}`, { headers: authHdr });
      check(res, { 'soak hot: 200': (r) => r.status === 200 });
      trackResponse(res);
    });
  } else if (roll < 0.85) {
    group('single_record', () => {
      const id = ctx.recordId || 'unknown';
      const res = http.get(`${base}/datasets/${ds}/${ent}/${id}`, { headers: authHdr });
      check(res, { 'soak record: 200 or 404': (r) => r.status === 200 || r.status === 404 });
      if (res.status >= 500) trackResponse(res);
    });
  } else if (roll < 0.90) {
    group('schema', () => {
      const res = http.get(`${base}/datasets/${ds}/${ent}/schema`, { headers: metaAuthHdr });
      check(res, { 'soak schema: 200': (r) => r.status === 200 });
      trackResponse(res);
    });
  } else if (roll < 0.95) {
    group('aggregate', () => {
      const res = http.get(`${base}/datasets/${ds}/${ent}/aggregates/${aggregateId()}`, {
        headers: aggAuthHdr,
      });
      check(res, { 'soak aggregate: 200': (r) => r.status === 200 });
      trackResponse(res);
    });
  } else if (roll < 0.98) {
    group('catalog', () => {
      const res = http.get(`${base}/catalog`, { headers: metaAuthHdr });
      check(res, { 'soak catalog: 200': (r) => r.status === 200 });
      trackResponse(res);
    });
  } else {
    group('auth_deny', () => {
      if (Math.random() < 0.5) {
        const res = http.get(`${base}/datasets/${ds}/${ent}`, {
          headers: { 'Authorization': `Bearer ${invalidToken()}`, 'Accept': 'application/json' },
          tags: { expected_status: '401' },
        });
        check(res, { 'soak deny: 401': (r) => r.status === 401 });
        trackExpectedDenyResponse(res, 401);
      } else {
        const res = http.get(`${base}/datasets/${ds}/${ent}`, {
          headers: { 'Authorization': `Bearer ${noScopeToken()}`, 'Accept': 'application/json' },
          tags: { expected_status: '403' },
        });
        check(res, { 'soak deny: 403': (r) => r.status === 403 });
        trackExpectedDenyResponse(res, 403);
      }
    });
  }
}

export function handleSummary(data) {
  return handleSummaryFor('soak', data);
}
