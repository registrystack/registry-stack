// SPDX-License-Identifier: Apache-2.0
// Scenario: single-claim extract evaluation.
//
// POST /v1/evaluations with the extract claim (default: date-of-birth).
// Hot path: auth, single DCI POST to the stub, extract rule, audit emit.

import http from 'k6/http';
import { check } from 'k6';
import {
  commonOptions,
  baseUrl,
  bearerToken,
  bearerHeaders,
  CLAIM_RESULT_ACCEPT,
  extractClaim,
  nextSubjectId,
  targetForSubjectId,
  handleResultsFor,
  trackResponse,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'evaluate_extract',
  defaultVus: 10,
  defaultDuration: '30s',
});

export function setup() {
  const token = bearerToken();
  const claim = extractClaim();
  logScenarioStart({
    scenario: 'evaluate_extract',
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
  return handleResultsFor('evaluate_extract', data);
}
