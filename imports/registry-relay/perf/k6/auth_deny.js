// SPDX-License-Identifier: Apache-2.0
// Scenario: authorization deny paths.
//
// Four sub-cases exercised via group():
//   1. Missing token       -> 401
//   2. Invalid token       -> 401
//   3. Valid token missing required scope (no-scope token) -> 403
//   4. Valid token with metadata scope only hitting rows endpoint -> 403
//
// Each request is tagged with expected_status so it is excluded from the
// built-in http_req_failed metric. The custom unexpected_failures Rate
// metric stays 0 as long as no 5xx appears and the expected status matches.
//
// Compatibility check: case 2 sends X-Api-Key instead of Authorization:Bearer
// to verify that both header forms reject invalid credentials the same way.
// (The server accepts both headers per src/auth/api_key.rs.)

import http from 'k6/http';
import { check, group } from 'k6';
import {
  commonOptions,
  baseUrl,
  dataset,
  entity,
  invalidToken,
  noScopeToken,
  metadataToken,
  handleSummaryFor,
  trackExpectedDenyResponse,
  serverErrors5xx,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'auth_deny',
  thresholdKey: 'hot_200_100kb',
  defaultVus: 5,
  defaultDuration: '30s',
});

export function setup() {
  // Eagerly resolve tokens so setup fails fast on missing env vars.
  const inv = invalidToken();
  const noScope = noScopeToken();
  const meta = metadataToken();
  logScenarioStart({
    scenario: 'auth_deny',
    expectedResponse: '401 and 403 only',
    vus: options.vus,
    duration: options.duration,
  });
  return { inv, noScope, meta };
}

export default function (ctx) {
  const url = `${baseUrl()}/datasets/${dataset()}/${entity()}`;
  const jsonAccept = { 'Accept': 'application/json' };

  // Case 1: missing token -> 401
  group('missing_token_401', () => {
    const res = http.get(url, {
      headers: jsonAccept,
      tags: { expected_status: '401' },
    });
    check(res, { 'missing token: 401': (r) => r.status === 401 });
    if (res.status >= 500) serverErrors5xx.add(1);
    trackExpectedDenyResponse(res, 401);
  });

  // Case 2: invalid token via X-Api-Key header -> 401
  // This also covers the X-Api-Key compatibility surface from the spec.
  group('invalid_token_xapikey_401', () => {
    const res = http.get(url, {
      headers: Object.assign({}, jsonAccept, { 'X-Api-Key': ctx.inv }),
      tags: { expected_status: '401' },
    });
    check(res, { 'invalid token X-Api-Key: 401': (r) => r.status === 401 });
    if (res.status >= 500) serverErrors5xx.add(1);
    trackExpectedDenyResponse(res, 401);
  });

  // Case 3: valid token with wrong scope (other:metadata) -> 403
  group('no_scope_403', () => {
    const res = http.get(url, {
      headers: Object.assign({}, jsonAccept, { 'Authorization': `Bearer ${ctx.noScope}` }),
      tags: { expected_status: '403' },
    });
    check(res, { 'no-scope token: 403': (r) => r.status === 403 });
    if (res.status >= 500) serverErrors5xx.add(1);
    trackExpectedDenyResponse(res, 403);
  });

  // Case 4: valid token with metadata scope hitting rows endpoint -> 403
  // (metadata scope does not grant read_scope = clinic_capacity:rows)
  group('metadata_scope_on_rows_403', () => {
    const res = http.get(url, {
      headers: Object.assign({}, jsonAccept, { 'Authorization': `Bearer ${ctx.meta}` }),
      tags: { expected_status: '403' },
    });
    check(res, { 'metadata-only token on rows endpoint: 403': (r) => r.status === 403 });
    if (res.status >= 500) serverErrors5xx.add(1);
    trackExpectedDenyResponse(res, 403);
  });
}

export function handleSummary(data) {
  return handleSummaryFor('auth_deny', data);
}
