// SPDX-License-Identifier: Apache-2.0
// Scenario: CEL-derived claim evaluation.
//
// POST /v1/evaluations with the CEL claim (default: farmer-under-4ha). The
// claim depends on farmed-land-size, so notary performs:
//   1. DCI POST to fetch farmed_land_size_hectares (extract claim)
//   2. CEL evaluation of `claims.farmed_land_size.value < 4.0`
//   3. Audit emit
// Compared with evaluate_extract this isolates the dependency + CEL cost.

import http from 'k6/http';
import { check } from 'k6';
import {
  commonOptions,
  baseUrl,
  bearerToken,
  bearerHeaders,
  CLAIM_RESULT_ACCEPT,
  celClaim,
  nextSubjectId,
  targetForSubjectId,
  handleResultsFor,
  trackResponse,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'evaluate_cel',
  defaultVus: 10,
  defaultDuration: '30s',
});

export function setup() {
  const token = bearerToken();
  const claim = celClaim();
  logScenarioStart({
    scenario: 'evaluate_cel',
    expectedResponse: '200',
    vus: options.vus,
    duration: options.duration,
  });
  return { token, claim };
}

export default function (ctx) {
  const subjectId = nextSubjectId(__VU, __ITER);
  const payload = JSON.stringify({
    target: targetForSubjectId(subjectId),
    claims: [ctx.claim],
    disclosure: 'predicate',
  });

  const res = http.post(`${baseUrl()}/v1/evaluations`, payload, {
    headers: bearerHeaders(ctx.token, { json: true, purpose: 'perf', accept: CLAIM_RESULT_ACCEPT }),
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has results array': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return Array.isArray(parsed.results) && parsed.results.length === 1;
      } catch (_) {
        return false;
      }
    },
  });

  trackResponse(res);
}

export function handleSummary(data) {
  return handleResultsFor('evaluate_cel', data);
}
