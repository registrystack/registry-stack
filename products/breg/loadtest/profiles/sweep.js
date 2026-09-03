// One held read-only rate. run.sh executes this profile once per RATES entry
// so every rate has isolated DB statistics and an independently useful result.

import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS, positiveNumber } from '../lib/config.js';
import { writeSummary } from '../lib/summary.js';
import { Workload, READ_MIX } from '../lib/workload.js';

const ops = positiveNumber('OPS', __ENV.OPS, 50);
const duration = __ENV.DURATION || '2m';

export const options = {
  scenarios: {
    held_rate: {
      executor: 'constant-arrival-rate',
      rate: ops,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: Math.min(500, Math.max(20, Math.ceil(ops))),
      maxVUs: Math.max(1000, Math.ceil(ops * 12)),
    },
  },
  thresholds: {
    dropped_iterations: ['count==0'],
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(99)<1000'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
  noConnectionReuse: false,
};

const workload = new Workload(__ENV.BREG_URL, __ENV.TOKEN_URL, __ENV.CLIENT_ID, __ENV.CLIENT_SECRET);

export default function () {
  workload.step(workload.token(), READ_MIX);
}

export const handleSummary = writeSummary;
