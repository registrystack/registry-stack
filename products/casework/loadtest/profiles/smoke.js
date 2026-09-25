// One full review lifecycle against the live runtime: a producer submits a
// request, Staff find its task by following the inbox continuation past the
// read pool, claim it, save a private draft, decide it, and the producer polls
// the answered result. The counters prove each stage executed rather than
// trusting the workload source shape.

import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS } from '../../../../scripts/loadtest/k6/config.js';
import { writeSummary } from '../../../../scripts/loadtest/k6/summary.js';
import { Workload } from '../lib/workload.js';

export const options = {
  scenarios: {
    smoke: { executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: '2m' },
  },
  thresholds: {
    http_req_failed: ['rate==0'],
    checks: ['rate==1'],
    lifecycles_completed: ['count==1'],
    task_pages_followed: ['count>0'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
};

const workload = new Workload(__ENV.CASEWORK_URL);

export default function () {
  workload.lifecycle();
}

export const handleSummary = writeSummary;
