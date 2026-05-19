// SPDX-License-Identifier: Apache-2.0
// Scenario: moderate read traffic with periodic admin reload trigger.
//
// Admin reload endpoint (from src/api/admin.rs):
//   POST /admin/datasets/{dataset_id}/tables/{table_id}/reload
//   POST /admin/reload
//
// Auth requirement (require_admin_scope in admin.rs):
//   scope: "admin"
//
// GAP: The perf key generator (generate_perf_keys.py) emits five scopes:
//   clinic_capacity:rows, clinic_capacity:metadata, clinic_capacity:aggregate,
//   other:metadata (no-scope), and an invalid token.
// None of these carry the "admin" scope required by POST /admin/reload.
//
// This script expects an additional env var REGISTRY_RELAY_TOKEN_ADMIN carrying
// a key with scope "admin". If it is absent, the reload trigger step is
// skipped and a warning is logged. The read load portion still runs and
// measures p99 stability.
//
// Table id from the perf config: facility_table
// Override via REGISTRY_RELAY_TABLE_ID.

import http from 'k6/http';
import { check, sleep } from 'k6';
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
      'generate a key with scope "admin" and set REGISTRY_RELAY_TOKEN_ADMIN. ' +
      'Note: the perf key generator does not currently emit an admin-scoped key.'
    );
  } else {
    console.log('refresh_under_read_load: admin token present: yes');
  }

  console.log(`reload target: POST /admin/datasets/${dataset()}/tables/${tableId}/reload`);
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
  const res = http.get(`${base}/datasets/${ds}/${ent}`, {
    headers: {
      'Authorization': `Bearer ${ctx.token}`,
      'Accept': 'application/json',
    },
  });

  check(res, {
    'read: 200 during refresh cycle': (r) => r.status === 200,
  });
  trackResponse(res);

  // Reload trigger: one VU per interval fires the admin reload. Because all
  // VUs share the same outer loop, the first one past the interval boundary
  // fires it. This is approximate but sufficient for soak-style testing.
  if (adminToken && (now - lastReloadAt) >= reloadIntervalSec) {
    lastReloadAt = now;
    const reloadRes = http.post(
      `${base}/admin/datasets/${ds}/tables/${tableId}/reload`,
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
