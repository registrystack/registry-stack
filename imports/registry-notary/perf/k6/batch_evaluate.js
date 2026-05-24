// SPDX-License-Identifier: Apache-2.0
// Scenario: batch evaluate over N subjects.
//
// POST /claims/batch-evaluate with REGISTRY_WITNESS_BATCH_SIZE distinct
// subjects. Uses the extract claim by default to keep the per-subject work
// directly comparable to evaluate_extract.

import http from 'k6/http';
import { check } from 'k6';
import {
  commonOptions,
  baseUrl,
  bearerToken,
  bearerHeaders,
  CLAIM_RESULT_ACCEPT,
  extractClaim,
  batchSize,
  nextSubjectId,
  handleResultsFor,
  trackResponse,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'batch_evaluate',
  defaultVus: 5,
  defaultDuration: '30s',
});

function buildSubjects(vuId, iter, size) {
  const subjects = new Array(size);
  for (let i = 0; i < size; i++) {
    subjects[i] = {
      id: nextSubjectId(vuId, iter * size + i),
      id_type: 'NATIONAL_ID',
    };
  }
  return subjects;
}

export function setup() {
  const token = bearerToken();
  const claim = extractClaim();
  const size = batchSize();
  logScenarioStart({
    scenario: 'batch_evaluate',
    expectedResponse: '200',
    vus: options.vus,
    duration: options.duration,
  });
  return { token, claim, size };
}

export default function (ctx) {
  const subjects = buildSubjects(__VU, __ITER, ctx.size);
  const payload = JSON.stringify({
    subjects,
    claims: [ctx.claim],
  });

  const res = http.post(`${baseUrl()}/claims/batch-evaluate`, payload, {
    headers: bearerHeaders(ctx.token, { json: true, purpose: 'perf', accept: CLAIM_RESULT_ACCEPT }),
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'items count matches': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return Array.isArray(parsed.items) && parsed.items.length === ctx.size;
      } catch (_) {
        return false;
      }
    },
  });

  trackResponse(res);
}

export function handleSummary(data) {
  return handleResultsFor('batch_evaluate', data);
}
