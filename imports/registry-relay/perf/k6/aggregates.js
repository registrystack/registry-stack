// SPDX-License-Identifier: Apache-2.0
// Scenario: GET /datasets/<id>/<entity>/aggregates/<aggregate_id>
//
// Aggregate id from perf config (medium.yaml): by_region
//   group_by: [region_code]
//   measures: facility_count (count/id), total_capacity (sum/capacity)
//
// Requires clinic_capacity:aggregate scope (REGISTRY_RELAY_TOKEN_AGGREGATE).
// Override the aggregate id via REGISTRY_RELAY_AGGREGATE_ID.

import http from 'k6/http';
import { check } from 'k6';
import {
  commonOptions,
  baseUrl,
  dataset,
  entity,
  aggregateId,
  aggregateToken,
  handleSummaryFor,
  trackResponse,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'aggregates',
  thresholdKey: 'hot_200_100kb',
  defaultVus: 5,
  defaultDuration: '30s',
});

export function setup() {
  const token = aggregateToken();
  const aggId = aggregateId();
  logScenarioStart({
    scenario: 'aggregates',
    expectedResponse: '200 with rows and suppressed_groups',
    vus: options.vus,
    duration: options.duration,
  });
  console.log(`aggregate id: ${aggId}`);
  return { token, aggId };
}

export default function (ctx) {
  const url = `${baseUrl()}/datasets/${dataset()}/${entity()}/aggregates/${ctx.aggId}`;
  const res = http.get(url, {
    headers: {
      'Authorization': `Bearer ${ctx.token}`,
      'Accept': 'application/json',
    },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'body has aggregate_id': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return typeof parsed.aggregate_id === 'string';
      } catch (_) {
        return false;
      }
    },
    'body has rows': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return Array.isArray(parsed.rows);
      } catch (_) {
        return false;
      }
    },
    'body has suppressed_groups': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return typeof parsed.suppressed_groups === 'number';
      } catch (_) {
        return false;
      }
    },
  });

  trackResponse(res);
}

export function handleSummary(data) {
  return handleSummaryFor('aggregates', data);
}
