// SPDX-License-Identifier: Apache-2.0
// Scenario: mixed read traffic.
//
// Weighted dispatch per the spec:
//   55% - cached dataset reads (304 path, with If-None-Match)
//   20% - hot dataset list reads (200, no cache header)
//   10% - single-record reads (200)
//    5% - schema reads (200)
//    5% - aggregate reads (200)
//    3% - catalog reads (200)
//    2% - expected auth failures (401 / 403, tagged so they do not count as failures)
//
// Expected auth failures are intentional and tagged with expected_status.
// They do not contribute to unexpected_failures or http_req_failed.

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
  handleSummaryFor,
  trackResponse,
  trackExpectedDenyResponse,
  tagExpected,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'mixed_read',
  thresholdKey: 'mixed_read',
  defaultVus: 20,
  defaultDuration: '30s',
});

// ETag captured during setup for the 304 path.
let cachedEtag = null;
// A known record id captured during setup for single-record reads.
let knownRecordId = null;

export function setup() {
  const token = rowsToken();
  const metaToken = metadataToken();
  const aggToken = aggregateToken();
  logScenarioStart({
    scenario: 'mixed_read',
    expectedResponse: 'mixed',
    vus: options.vus,
    duration: options.duration,
  });

  // Capture ETag for 304 path.
  const collectionUrl = `${baseUrl()}/v1/datasets/${dataset()}/entities/${entity()}/records`;
  const collectionRes = http.get(collectionUrl, {
    headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
  });
  const etag = collectionRes.headers['Etag'] || collectionRes.headers['ETag'] || '';

  // Capture a record id for single-record path.
  let recordId = '';
  if (collectionRes.status === 200 && collectionRes.body) {
    try {
      const body = JSON.parse(collectionRes.body);
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
    // 55%: cached 304 read
    group('cached_304', () => {
      const res = http.get(`${base}/v1/datasets/${ds}/entities/${ent}/records`, {
        headers: Object.assign({}, authHdr, { 'If-None-Match': ctx.etag || '"missing"' }),
      });
      check(res, {
        'cached read: 304 or 200': (r) => r.status === 304 || r.status === 200,
      });
      if (res.status >= 500) trackResponse(res);
    });
  } else if (roll < 0.75) {
    // 20%: hot 200 dataset list
    group('hot_200', () => {
      const res = http.get(`${base}/v1/datasets/${ds}/entities/${ent}/records`, { headers: authHdr });
      check(res, { 'hot read: 200': (r) => r.status === 200 });
      trackResponse(res);
    });
  } else if (roll < 0.85) {
    // 10%: single-record read
    group('single_record', () => {
      const id = ctx.recordId || 'unknown';
      const res = http.get(`${base}/v1/datasets/${ds}/entities/${ent}/records/${id}`, { headers: authHdr });
      check(res, { 'record read: 200 or 404': (r) => r.status === 200 || r.status === 404 });
      if (res.status >= 500) trackResponse(res);
    });
  } else if (roll < 0.90) {
    // 5%: schema read (requires metadata scope)
    group('schema', () => {
      const res = http.get(`${base}/v1/datasets/${ds}/entities/${ent}/schema`, { headers: metaAuthHdr });
      check(res, { 'schema: 200': (r) => r.status === 200 });
      trackResponse(res);
    });
  } else if (roll < 0.95) {
    // 5%: aggregate read (requires aggregate scope)
    group('aggregate', () => {
      const res = http.get(`${base}/v1/datasets/${ds}/aggregates/${aggregateId()}`, {
        headers: aggAuthHdr,
      });
      check(res, { 'aggregate: 200': (r) => r.status === 200 });
      trackResponse(res);
    });
  } else if (roll < 0.98) {
    // 3%: catalog read (requires metadata scope)
    group('catalog', () => {
      const res = http.get(`${base}/metadata/catalog`, { headers: metaAuthHdr });
      check(res, { 'catalog: 200': (r) => r.status === 200 });
      trackResponse(res);
    });
  } else {
    // 2%: expected auth failure (alternates between invalid token and no-scope token)
    group('auth_deny', () => {
      if (Math.random() < 0.5) {
        const res = http.get(`${base}/v1/datasets/${ds}/entities/${ent}/records`, {
          headers: { 'Authorization': `Bearer ${invalidToken()}`, 'Accept': 'application/json' },
          tags: { expected_status: '401' },
        });
        check(res, { 'invalid token: 401': (r) => r.status === 401 });
        trackExpectedDenyResponse(res, 401);
      } else {
        const res = http.get(`${base}/v1/datasets/${ds}/entities/${ent}/records`, {
          headers: { 'Authorization': `Bearer ${noScopeToken()}`, 'Accept': 'application/json' },
          tags: { expected_status: '403' },
        });
        check(res, { 'no-scope token: 403': (r) => r.status === 403 });
        trackExpectedDenyResponse(res, 403);
      }
    });
  }
}

export function handleSummary(data) {
  return handleSummaryFor('mixed_read', data);
}
