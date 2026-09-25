// A handful of sequential requests that prove the harness end to end: signed
// assertions for held subjects and the expected refusal for unknown ones.

import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS } from '../../../../scripts/loadtest/k6/config.js';
import { writeSummary } from '../../../../scripts/loadtest/k6/summary.js';
import exec from 'k6/execution';
import { Workload } from '../lib/workload.js';

const ITERATIONS = 12;

export const options = {
  scenarios: {
    smoke: { executor: 'shared-iterations', vus: 1, iterations: ITERATIONS, maxDuration: '60s' },
  },
  thresholds: {
    checks: ['rate==1'],
    http_req_failed: ['rate==0'],
    'http_reqs{name:evidence_assert}': ['count>=10'],
    'http_reqs{name:evidence_absent}': ['count>=2'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
};

const workload = new Workload(__ENV.EVIDENCE_URL);

export default function () {
  // Every sixth iteration asks about a subject the source does not hold.
  if (exec.scenario.iterationInTest % 6 === 5) {
    workload.assertAbsent();
  } else {
    workload.assertPresent();
  }
}

export const handleSummary = writeSummary;
