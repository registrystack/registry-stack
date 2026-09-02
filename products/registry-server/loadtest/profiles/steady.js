// Steady mixed workload at a fixed offered operation rate.

import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS, positiveNumber } from '../lib/config.js';
import { writeSummary } from '../lib/summary.js';
import { Workload, STEADY_MIX } from '../lib/workload.js';

const ops = positiveNumber('OPS', __ENV.OPS, 50);
const duration = __ENV.DURATION || '10m';

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: ops,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: Math.min(500, Math.max(20, Math.ceil(ops * 2))),
      maxVUs: Math.max(1000, Math.ceil(ops * 12)),
    },
  },
  thresholds: {
    dropped_iterations: ['count==0'],
    http_req_failed: ['rate==0'],
    http_req_duration: ['p(99)<250'],
    'http_req_duration{name:lookup_by_code}': ['p(99)<250'],
    'http_req_duration{name:get_establishment}': ['p(99)<250'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
  noConnectionReuse: false,
};

const workload = new Workload(__ENV.SERVER_URL, __ENV.TOKEN_URL, __ENV.CLIENT_ID, __ENV.CLIENT_SECRET);

export default function () {
  workload.step(workload.token(), STEADY_MIX);
}

export const handleSummary = writeSummary;
