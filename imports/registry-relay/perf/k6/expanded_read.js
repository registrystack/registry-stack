// SPDX-License-Identifier: Apache-2.0
// Scenario: collection with ?expand=<rel> query parameter.
//
// STUB: The perf config (small.yaml, medium.yaml, large.yaml) declares
//   allowed_expansions: []
// for the facility entity. There are no configured expansions.
//
// Behavior: the server returns 400/422 when an unknown expansion is requested
// (FilterError::NotAllowed, from require_expansion_access). This script
// verifies that the server returns a non-5xx error for an unsupported
// expansion and documents the latency of that validation path.
//
// When a future config adds an expansion, set DATA_GATE_EXPAND to the
// relationship name; the script will then expect 200 instead of 400.

import http from 'k6/http';
import { check } from 'k6';
import {
  commonOptions,
  baseUrl,
  dataset,
  entity,
  rowsToken,
  handleSummaryFor,
  trackResponse,
  trackExpectedDenyResponse,
  logScenarioStart,
} from './lib/common.js';

// When a real expansion is configured, set DATA_GATE_EXPAND to its name.
const expandParam = __ENV.DATA_GATE_EXPAND || '';
const hasExpansion = expandParam !== '';

export const options = commonOptions({
  scenario: 'expanded_read',
  thresholdKey: 'hot_200_100kb',
  defaultVus: 5,
  defaultDuration: '30s',
});

export function setup() {
  const token = rowsToken();
  logScenarioStart({
    scenario: 'expanded_read',
    expectedResponse: hasExpansion ? '200' : '400 (no expansion configured)',
    vus: options.vus,
    duration: options.duration,
  });
  if (!hasExpansion) {
    console.log(
      'expanded_read: DATA_GATE_EXPAND not set. The perf config has no allowed_expansions. ' +
      'Verifying that unsupported expand returns non-5xx.'
    );
  }
  return { token };
}

export default function (ctx) {
  const expand = hasExpansion ? expandParam : 'nonexistent_rel';
  const url = `${baseUrl()}/datasets/${dataset()}/${entity()}?expand=${encodeURIComponent(expand)}`;
  const res = http.get(url, {
    headers: {
      'Authorization': `Bearer ${ctx.token}`,
      'Accept': 'application/json',
    },
    tags: hasExpansion ? { expected_status: 'false' } : { expected_status: '4xx' },
  });

  if (hasExpansion) {
    check(res, {
      'status is 200': (r) => r.status === 200,
      'has ETag': (r) => !!(r.headers['Etag'] || r.headers['ETag']),
    });
    trackResponse(res);
  } else {
    // Expect a 4xx (not 5xx). The server rejects unknown expansions with
    // FilterError::NotAllowed which maps to a 4xx problem+json response.
    check(res, {
      'unsupported expand: not 5xx': (r) => r.status < 500,
      'unsupported expand: 4xx': (r) => r.status >= 400 && r.status < 500,
    });
    trackExpectedDenyResponse(res, '4xx');
  }
}

export function handleSummary(data) {
  return handleSummaryFor('expanded_read', data);
}
