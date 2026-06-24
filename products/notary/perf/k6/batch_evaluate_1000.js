// SPDX-License-Identifier: Apache-2.0
// Scenario: batch_evaluate with a fixed batch size of 1000 subjects.
//
// Uses the extract claim. See batch_evaluate_10.js for rationale.
//
// Note: the perf configs set inline_batch_limit: 100. Sending 1000 subjects
// in a single request causes notary to reject it with 413 (batch too
// large) unless the claim's max_subjects is raised. This scenario is
// included so the harness has a reference point once the limit is relaxed;
// expect 413 responses with the current config. See Known Gaps in README.md.

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

const BATCH_SIZE = 1000;

export const options = commonOptions({
  scenario: 'batch_evaluate_1000',
  defaultVus: 1,
  defaultDuration: '30s',
});

function buildItems(vuId, iter) {
  const items = new Array(BATCH_SIZE);
  for (let i = 0; i < BATCH_SIZE; i++) {
    items[i] = {
      target: targetForSubjectId(nextSubjectId(vuId, iter * BATCH_SIZE + i)),
    };
  }
  return items;
}

export function setup() {
  const token = bearerToken();
  const claim = extractClaim();
  logScenarioStart({
    scenario: 'batch_evaluate_1000',
    expectedResponse: '200 (400 expected with current inline_batch_limit: 100; see Known Gaps)',
    vus: options.vus,
    duration: options.duration,
  });
  return { token, claim };
}

export default function (ctx) {
  const items = buildItems(__VU, __ITER);
  const payload = JSON.stringify({ items, claims: [ctx.claim] });

  const res = http.post(`${baseUrl()}/v1/batch-evaluations`, payload, {
    headers: bearerHeaders(ctx.token, { json: true, purpose: 'perf', accept: CLAIM_RESULT_ACCEPT }),
    timeout: '300s',
  });

  // Accept 413 here: the current config enforces inline_batch_limit: 100.
  // A 200 would indicate the config has been updated; check items count then.
  const ok200 = res.status === 200;
  const expectedLimit = res.status === 413;

  check(res, {
    'status is 200 or 413 (batch limit)': (r) => r.status === 200 || r.status === 413,
    'items count matches (if 200)': (r) => {
      if (r.status !== 200 || !r.body) return true; // skip check on expected 400
      try {
        const parsed = JSON.parse(r.body);
        return Array.isArray(parsed.items) && parsed.items.length === BATCH_SIZE;
      } catch (_) {
        return false;
      }
    },
  });

  if (res.status >= 500) {
    trackResponse(res);
  }
  // Do not flag 400 as unexpected: it is the current expected outcome.
  _ = ok200; _ = expectedLimit;
}

export function handleSummary(data) {
  return handleResultsFor('batch_evaluate_1000', data);
}
