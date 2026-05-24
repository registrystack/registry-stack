// SPDX-License-Identifier: Apache-2.0
// Scenario: batch_evaluate with a fixed batch size of 100 subjects.
//
// Uses the extract claim. See batch_evaluate_10.js for rationale.
// Batch size 100 matches the inline_batch_limit in the perf configs, so
// witness will not split the request internally.

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
  handleResultsFor,
  trackResponse,
  logScenarioStart,
} from './lib/common.js';

const BATCH_SIZE = 100;

export const options = commonOptions({
  scenario: 'batch_evaluate_100',
  defaultVus: 2,
  defaultDuration: '30s',
});

function buildSubjects(vuId, iter) {
  const subjects = new Array(BATCH_SIZE);
  for (let i = 0; i < BATCH_SIZE; i++) {
    subjects[i] = {
      id: nextSubjectId(vuId, iter * BATCH_SIZE + i),
      id_type: 'NATIONAL_ID',
    };
  }
  return subjects;
}

export function setup() {
  const token = bearerToken();
  const claim = extractClaim();
  logScenarioStart({
    scenario: 'batch_evaluate_100',
    expectedResponse: '200',
    vus: options.vus,
    duration: options.duration,
  });
  return { token, claim };
}

export default function (ctx) {
  const subjects = buildSubjects(__VU, __ITER);
  const payload = JSON.stringify({ subjects, claims: [ctx.claim] });

  const res = http.post(`${baseUrl()}/claims/batch-evaluate`, payload, {
    headers: bearerHeaders(ctx.token, { json: true, purpose: 'perf', accept: CLAIM_RESULT_ACCEPT }),
    timeout: '120s',
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'items count matches': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return Array.isArray(parsed.items) && parsed.items.length === BATCH_SIZE;
      } catch (_) {
        return false;
      }
    },
  });

  trackResponse(res);
}

export function handleSummary(data) {
  return handleResultsFor('batch_evaluate_100', data);
}
