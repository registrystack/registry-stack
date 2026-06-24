// SPDX-License-Identifier: Apache-2.0
// Scenario: collection with a filter applied.
//
// Filter syntax confirmed by reading src/api/entity.rs (collection_query_from_params,
// parse_filter_name):
//   - Plain field name  -> eq filter:  ?region_code=R001
//   - field.in          -> in filter:  ?region_code.in=R001,R002
//   - field.gte / .lte  -> range
//   - field.between     -> range pair
//
// The perf config (medium.yaml) declares:
//   allowed_filters:
//     - field: region_code, ops: [eq, in]
//     - field: category,    ops: [eq, in]
//
// This scenario uses ?region_code=R001 (eq) as the primary filter.
// REGISTRY_RELAY_FILTER_FIELD and REGISTRY_RELAY_FILTER_VALUE can override at runtime.

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
} from './lib/common.js';

const filterField = __ENV.REGISTRY_RELAY_FILTER_FIELD || 'region_code';
const filterValue = __ENV.REGISTRY_RELAY_FILTER_VALUE || 'R001';

export const options = commonOptions({
  scenario: 'filtered_read',
  thresholdKey: 'hot_200_100kb',
  defaultVus: 20,
  defaultDuration: '30s',
});

export function setup() {
  const token = rowsToken();
  logScenarioStart({
    scenario: 'filtered_read',
    expectedResponse: '200',
    vus: options.vus,
    duration: options.duration,
  });
  console.log(`filter: ${filterField}=${filterValue}`);
  return { token };
}

export default function (ctx) {
  // Plain field name -> eq filter. Encoded as ?region_code=R001.
  const url = `${baseUrl()}/v1/datasets/${dataset()}/entities/${entity()}/records?${filterField}=${encodeURIComponent(filterValue)}`;
  const res = http.get(url, {
    headers: {
      'Authorization': `Bearer ${ctx.token}`,
      'Accept': 'application/json',
    },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has ETag': (r) => !!(r.headers['Etag'] || r.headers['ETag']),
    'body has data field': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return Array.isArray(parsed.data);
      } catch (_) {
        return false;
      }
    },
  });

  trackResponse(res);
}

export function handleSummary(data) {
  return handleSummaryFor('filtered_read', data);
}
