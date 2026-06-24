// SPDX-License-Identifier: Apache-2.0
// Scenario: moderate read traffic with periodic admin reload trigger.
//
// Admin reload endpoint (from src/api/admin.rs):
//   POST /admin/v1/datasets/{dataset_id}/tables/{table_id}/reload
//   POST /admin/v1/reload
//
// Auth requirement (require_admin_scope in admin.rs):
//   scope: "admin"
//
// The perf key generator (generate_perf_keys.py) emits scoped credentials for:
//   clinic_capacity:rows, clinic_capacity:metadata, clinic_capacity:aggregate,
//   clinic_capacity:evidence_verification, other:metadata (deny path), admin,
//   and an invalid token.
//
// This script expects REGISTRY_RELAY_TOKEN_ADMIN. If an older env file lacks
// that variable, the reload trigger step is skipped and a warning is logged.
// The read load portion still runs and measures p99 stability.
//
// Table id from the perf config: facility_table
// Override via REGISTRY_RELAY_TABLE_ID.

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

const tableId = __ENV.REGISTRY_RELAY_TABLE_ID || 'facility_table';
// Reload interval in seconds. Default: trigger a reload every 30 seconds.
const reloadIntervalSec = parseInt(__ENV.REGISTRY_RELAY_RELOAD_INTERVAL || '30', 10);

// Admin token is optional. If missing, reload step is skipped.
const adminToken = __ENV.REGISTRY_RELAY_TOKEN_ADMIN || '';

export const options = commonOptions({
  scenario: 'refresh_under_read_load',
  thresholdKey: 'hot_200_100kb',
  defaultVus: 20,
  defaultDuration: '2m',
});

export function setup() {
  const token = rowsToken();
  logScenarioStart({
    scenario: 'refresh_under_read_load',
    expectedResponse: '200 reads stable; reloads trigger 200',
    vus: options.vus,
    duration: options.duration,
  });

  if (!adminToken) {
    console.warn(
      'refresh_under_read_load: REGISTRY_RELAY_TOKEN_ADMIN is not set. ' +
      'The admin reload step will be skipped. To test reload under load, ' +
      'regenerate target/perf/perf.env with perf/scripts/generate_perf_keys.py.'
    );
  } else {
    console.log('refresh_under_read_load: admin token present: yes');
  }

  console.log(`reload target: POST /admin/v1/datasets/${dataset()}/tables/${tableId}/reload`);
  console.log(`reload interval: ${reloadIntervalSec}s`);
  return { token };
}

// Track when the last reload was attempted (in seconds from epoch).
let lastReloadAt = 0;

export default function (ctx) {
  const ds = dataset();
  const ent = entity();
  const base = baseUrl();
  const now = Date.now() / 1000;

  // Read traffic: GET the entity collection (primary workload).
  const res = http.get(`${base}/v1/datasets/${ds}/entities/${ent}/records`, {
    headers: {
      'Authorization': `Bearer ${ctx.token}`,
      'Accept': 'application/json',
    },
  });

  check(res, {
    'read: 200 during refresh cycle': (r) => r.status === 200,
  });
  trackResponse(res);

  // Reload trigger: k6 gives each VU its own JS isolate, so keep reloads
  // on VU 1 to avoid every VU firing independently.
  if (__VU === 1 && adminToken && (now - lastReloadAt) >= reloadIntervalSec) {
    lastReloadAt = now;
    const reloadRes = http.post(
      `${base}/admin/v1/datasets/${ds}/tables/${tableId}/reload`,
      null,
      {
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Accept': 'application/json',
        },
      }
    );
    check(reloadRes, {
      'reload: 200': (r) => r.status === 200,
      'reload: not 5xx': (r) => r.status < 500,
    });
    if (reloadRes.status >= 500) {
      trackResponse(reloadRes);
    }
    console.log(`reload triggered: status=${reloadRes.status}`);
  }
}

export function handleSummary(data) {
  return handleSummaryFor('refresh_under_read_load', data);
}
