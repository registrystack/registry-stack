// SPDX-License-Identifier: Apache-2.0
// Scenario: authorization deny paths.
//
// Three sub-cases exercised via group():
//   1. Missing token              -> 401
//   2. Invalid token via X-Api-Key -> 401   (verifies both header forms reject)
//   3. Valid no-scope token        -> 403   (scope missing for evaluate)
//
// Each request is tagged with expected_status so it is excluded from the
// built-in http_req_failed metric. unexpected_failures stays 0 as long as no
// 5xx appears and the expected status matches.

import http from 'k6/http';
import { check, group } from 'k6';
import {
  commonOptions,
  baseUrl,
  bearerHeaders,
  apiKeyHeaders,
  invalidToken,
  noScopeToken,
  targetForSubjectId,
  handleResultsFor,
  trackExpectedDenyResponse,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'auth_deny',
  defaultVus: 5,
  defaultDuration: '30s',
});

export function setup() {
  // Resolve tokens up front so setup fails fast on missing env vars.
  const inv = invalidToken();
  const noScope = noScopeToken();
  logScenarioStart({
    scenario: 'auth_deny',
    expectedResponse: '401 and 403 only',
    vus: options.vus,
    duration: options.duration,
  });
  return { inv, noScope };
}

export default function (ctx) {
  const claimsUrl = `${baseUrl()}/v1/claims`;
  const evaluateUrl = `${baseUrl()}/v1/evaluations`;
  const evaluatePayload = JSON.stringify({
    target: targetForSubjectId('subj-0000000'),
    claims: ['date-of-birth'],
  });

  // Case 1: missing token -> 401
  group('missing_token_401', () => {
    const res = http.get(claimsUrl, {
      headers: { 'Accept': 'application/json' },
      tags: { expected_status: '401' },
    });
    check(res, { 'missing token: 401': (r) => r.status === 401 });
    trackExpectedDenyResponse(res, 401);
  });

  // Case 2: invalid token via X-Api-Key -> 401
  group('invalid_token_xapikey_401', () => {
    const res = http.get(claimsUrl, {
      headers: apiKeyHeaders(ctx.inv),
      tags: { expected_status: '401' },
    });
    check(res, { 'invalid X-Api-Key: 401': (r) => r.status === 401 });
    trackExpectedDenyResponse(res, 401);
  });

  // Case 3: valid no-scope token on evaluate -> 403
  // (Notary checks required_scope on the claim's source binding before
  // any source IO, so this stays on the cheap deny path.)
  group('no_scope_403', () => {
    const res = http.post(evaluateUrl, evaluatePayload, {
      headers: bearerHeaders(ctx.noScope, { json: true, purpose: 'perf' }),
      tags: { expected_status: '403' },
    });
    check(res, { 'no-scope token: 403': (r) => r.status === 403 });
    trackExpectedDenyResponse(res, 403);
  });
}

export function handleSummary(data) {
  return handleResultsFor('auth_deny', data);
}
