// SPDX-License-Identifier: Apache-2.0
// Scenario: walk pages 1 through K using the returned next_cursor.
//
// Response shape from src/api/entity.rs (paginated_body):
//   { data: [...], pagination: { has_more: bool, next_cursor?: string } }
// next_cursor is present when has_more is true; absent on the final page.
//
// This scenario is sequential by nature (each page depends on the previous
// cursor) and runs single-VU by default. Cap at REGISTRY_RELAY_CURSOR_MAX_PAGES
// pages (default 50) to bound iteration time.
//
// Thresholds use hot_200_100kb as the baseline since each page is a bounded
// page read, not a full-collection read.

import http from 'k6/http';
import { check, fail } from 'k6';
import { Trend } from 'k6/metrics';
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

const maxPages = parseInt(__ENV.REGISTRY_RELAY_CURSOR_MAX_PAGES || '50', 10);
const pageSize = parseInt(__ENV.REGISTRY_RELAY_CURSOR_PAGE_SIZE || '100', 10);

// Per-page latency trend for reporting.
const pageLatency = new Trend('cursor_page_latency_ms');

export const options = commonOptions({
  scenario: 'cursor_walk',
  thresholdKey: 'hot_200_100kb',
  defaultVus: 1,
  defaultDuration: '2m',
});

export function setup() {
  const token = rowsToken();
  logScenarioStart({
    scenario: 'cursor_walk',
    expectedResponse: '200 per page, final page has no next_cursor',
    vus: 1,
    duration: options.duration,
  });
  return { token };
}

export default function (ctx) {
  const ds = dataset();
  const ent = entity();
  const base = baseUrl();
  const headers = {
    'Authorization': `Bearer ${ctx.token}`,
    'Accept': 'application/json',
  };

  let cursor = null;
  let pageIndex = 0;
  let totalRows = 0;

  while (pageIndex < maxPages) {
    const qs = cursor
      ? `?limit=${pageSize}&cursor=${encodeURIComponent(cursor)}`
      : `?limit=${pageSize}`;

    const res = http.get(`${base}/v1/datasets/${ds}/entities/${ent}/records${qs}`, { headers });

    const ok = check(res, {
      [`page ${pageIndex + 1}: status is 200`]: (r) => r.status === 200,
    });

    pageLatency.add(res.timings.duration);

    if (!ok) {
      trackResponse(res);
      break;
    }

    let body;
    try {
      body = JSON.parse(res.body);
    } catch (_) {
      fail(`page ${pageIndex + 1}: response body is not valid JSON`);
    }

    const rows = (body && Array.isArray(body.data)) ? body.data : [];
    totalRows += rows.length;

    const pagination = (body && body.pagination) ? body.pagination : {};
    const hasMore = !!pagination.has_more;
    const nextCursor = pagination.next_cursor || null;

    pageIndex++;

    if (!hasMore || !nextCursor) {
      // Final page: verify next_cursor is absent.
      check(res, {
        'final page: next_cursor absent': () => !nextCursor,
      });
      console.log(`cursor_walk: completed ${pageIndex} pages, ${totalRows} total rows`);
      break;
    }

    cursor = nextCursor;
  }

  if (pageIndex >= maxPages && cursor) {
    console.log(`cursor_walk: capped at ${maxPages} pages (cursor still present); ${totalRows} rows read`);
  }
}

export function handleSummary(data) {
  return handleSummaryFor('cursor_walk', data);
}
