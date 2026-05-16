// SPDX-License-Identifier: Apache-2.0
// Scenario: GET /catalog/dcat-ap.jsonld
//
// Route confirmed in src/api/catalog.rs:
//   .route("/catalog/dcat-ap.jsonld", get(dcat_ap))
// Response: Content-Type: application/ld+json, body is JSON-LD.
// Requires a metadata-scoped token (clinic_capacity:metadata).

import http from 'k6/http';
import { check } from 'k6';
import {
  commonOptions,
  baseUrl,
  metadataToken,
  handleSummaryFor,
  trackResponse,
  logScenarioStart,
} from './lib/common.js';

export const options = commonOptions({
  scenario: 'dcat_catalog',
  thresholdKey: 'hot_200_100kb',
  defaultVus: 5,
  defaultDuration: '30s',
});

export function setup() {
  const token = metadataToken();
  logScenarioStart({
    scenario: 'dcat_catalog',
    expectedResponse: '200 application/ld+json',
    vus: options.vus,
    duration: options.duration,
  });
  return { token };
}

export default function (ctx) {
  const url = `${baseUrl()}/catalog/dcat-ap.jsonld`;
  const res = http.get(url, {
    headers: {
      'Authorization': `Bearer ${ctx.token}`,
      'Accept': 'application/ld+json, application/json',
    },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'Content-Type includes application/ld+json': (r) => {
      const ct = r.headers['Content-Type'] || '';
      return ct.includes('application/ld+json');
    },
    'has ETag': (r) => !!(r.headers['Etag'] || r.headers['ETag']),
    'body is valid JSON': (r) => {
      if (!r.body) return false;
      try {
        JSON.parse(r.body);
        return true;
      } catch (_) {
        return false;
      }
    },
    'body has @context': (r) => {
      if (!r.body) return false;
      try {
        const parsed = JSON.parse(r.body);
        return '@context' in parsed || '@graph' in parsed || '@type' in parsed;
      } catch (_) {
        return false;
      }
    },
  });

  trackResponse(res);
}

export function handleSummary(data) {
  return handleSummaryFor('dcat_catalog', data);
}
