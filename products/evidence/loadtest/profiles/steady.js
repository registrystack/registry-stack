// Steady assertion workload at a fixed offered operation rate.

import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS, positiveNumber } from '../../../../scripts/loadtest/k6/config.js';
import { writeSummary } from '../../../../scripts/loadtest/k6/summary.js';
import { Workload } from '../lib/workload.js';

const ops = positiveNumber('OPS', __ENV.OPS, 20);
const duration = __ENV.DURATION || '2m';

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: ops,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: Math.min(500, Math.max(20, Math.ceil(ops * 2))),
      maxVUs: Math.max(200, Math.ceil(ops * 12)),
    },
  },
  thresholds: {
    dropped_iterations: ['count==0'],
    checks: ['rate==1'],
    http_req_failed: ['rate==0'],
    'http_reqs{status:429}': ['count==0'],
    'http_req_duration{name:evidence_assert}': ['p(99)<250'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
  noConnectionReuse: false,
};

const workload = new Workload(__ENV.EVIDENCE_URL);

export default function () {
  workload.step();
}

export const handleSummary = writeSummary;
