// Proves the stock per-principal limit is live: one principal sends more
// requests than its burst allows, back to back, and must see 429 refusals.
// Both 200 and 429 are expected; the threshold requires at least one of each.

import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS } from '../../../../scripts/loadtest/k6/config.js';
import { writeSummary } from '../../../../scripts/loadtest/k6/summary.js';
import { Workload, firstAuthorization } from '../lib/workload.js';

// Twice the stock burst of 10, sent faster than the one-per-second refill.
const ITERATIONS = 20;

export const options = {
  scenarios: {
    limiter: { executor: 'shared-iterations', vus: 4, iterations: ITERATIONS, maxDuration: '30s' },
  },
  thresholds: {
    checks: ['rate==1'],
    http_req_failed: ['rate==0'],
    'http_reqs{status:200}': ['count>0'],
    'http_reqs{status:429}': ['count>0'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
};

const workload = new Workload(__ENV.EVIDENCE_URL);

export default function () {
  workload.assertLimited(firstAuthorization());
}

export const handleSummary = writeSummary;
