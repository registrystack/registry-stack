// SPDX-License-Identifier: Apache-2.0
// Scenario: catalog read.
//
// Repeatedly GETs /v1/claims to baseline the auth + JSON-serialize path with no
// source IO. Useful as a control: regressions here indicate auth/audit or
// runtime listing cost, not upstream behavior.

import http from 'k6/http';
import { check } from 'k6';
import {
  commonOptions,
  baseUrl,
  bearerToken,
  bearerHeaders,
  handleResultsFor,
  trackResponse,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'list_claims',
  defaultVus: 20,
  defaultDuration: '30s',
});

export function setup() {
  const token = bearerToken();
  logScenarioStart({
    scenario: 'list_claims',
    expectedResponse: '200',
    vus: options.vus,
    duration: options.duration,
  });
  return { token };
}

export default function (ctx) {
  const res = http.get(`${baseUrl()}/v1/claims`, {
    headers: bearerHeaders(ctx.token),
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'body has data array': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return Array.isArray(parsed.data);
      } catch (_) {
        return false;
      }
    },
  });

  trackResponse(res);
}

export function handleSummary(data) {
  return handleResultsFor('list_claims', data);
}
