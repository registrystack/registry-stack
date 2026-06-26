// SPDX-License-Identifier: Apache-2.0
// Scenario: hot 200 collection read.
//
// Repeatedly GETs the entity collection endpoint without caching headers.
// Measures latency for authenticated reads under moderate concurrency.
//
// Threshold key is selected from REGISTRY_RELAY_PROFILE:
//   small / medium (default): hot_200_100kb  (p95 < 25ms, p99 < 75ms)
//   large:                    hot_200_1mb    (p95 < 50ms, p99 < 150ms)
//   large-wide:               hot_200_10mb   (p95 < 250ms, p99 < 750ms)
//   large-full:               hot_200_50mb   (p95 < 1500ms, p99 < 5000ms)

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
  logScenarioStart,
  profile,
} from './lib/common.js';

function resolveThresholdKey() {
  switch (profile()) {
    case 'large': return 'hot_200_1mb';
    case 'large-wide': return 'hot_200_10mb';
    case 'large-full': return 'hot_200_50mb';
    default: return 'hot_200_100kb';
  }
}

function resolveDefaults() {
  switch (profile()) {
    case 'large-wide': return { vus: 5, rate: 10 };
    case 'large-full': return { vus: 1, rate: 1 };
    case 'large': return { vus: 20, rate: 50 };
    default: return { vus: 20, rate: 100 };
  }
}

const defaults = resolveDefaults();

export const options = commonOptions({
  scenario: 'hot_200',
  thresholdKey: resolveThresholdKey(),
  defaultVus: defaults.vus,
  defaultDuration: '30s',
});

export function setup() {
  const token = rowsToken();
  logScenarioStart({
    scenario: 'hot_200',
    expectedResponse: '200',
    vus: options.vus,
    duration: options.duration,
  });
  return { token };
}

export default function (ctx) {
  const url = `${baseUrl()}/v1/datasets/${dataset()}/entities/${entity()}/records`;
  const res = http.get(url, {
    headers: {
      'Authorization': `Bearer ${ctx.token}`,
      'Accept': 'application/json',
    },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has ETag': (r) => !!r.headers['Etag'] || !!r.headers['ETag'],
    'body is JSON object': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return typeof parsed === 'object' && parsed !== null;
      } catch (_) {
        return false;
      }
    },
  });

  trackResponse(res);
}

export function handleSummary(data) {
  return handleSummaryFor('hot_200', data);
}
