// SPDX-License-Identifier: Apache-2.0
// Scenario: CEL-derived claim evaluation.
//
// POST /claims/evaluate with the CEL claim (default: farmer-under-4ha). The
// claim depends on farmed-land-size, so witness performs:
//   1. DCI POST to fetch farmed_land_size_hectares (extract claim)
//   2. CEL evaluation of `claims.farmed_land_size.value < 4.0`
//   3. Audit emit
// Compared with evaluate_extract this isolates the dependency + CEL cost.

import http from 'k6/http';
import { check, vu } from 'k6';
import {
  commonOptions,
  baseUrl,
  bearerToken,
  bearerHeaders,
  celClaim,
  nextSubjectId,
  handleSummaryFor,
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
  const subjectId = nextSubjectId(vu.idInTest, vu.iterationInScenario);
  const payload = JSON.stringify({
    subject: { id: subjectId, id_type: 'NATIONAL_ID' },
    claims: [ctx.claim],
    disclosure: 'predicate',
  });

  const res = http.post(`${baseUrl()}/claims/evaluate`, payload, {
    headers: bearerHeaders(ctx.token, { json: true, purpose: 'perf' }),
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
  return handleSummaryFor('evaluate_cel', data);
}
