// SPDX-License-Identifier: Apache-2.0
// Scenario: batch_evaluate with a fixed batch size of 10 subjects.
//
// Uses the extract claim. Batch size is hardcoded to 10 so each of the
// three batch scenarios (10/100/1000) produces independent baselines that
// can be compared directly without re-running with different env vars.

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

const BATCH_SIZE = 10;

export const options = commonOptions({
  scenario: 'batch_evaluate_10',
  defaultVus: 5,
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
    scenario: 'batch_evaluate_10',
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
  return handleResultsFor('batch_evaluate_10', data);
}
