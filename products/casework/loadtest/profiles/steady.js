// Steady inbox workload at a fixed offered operation rate. FLOW_OPS of the
// offered operations are full decision flows over the seeded flow pool (one
// tenth of OPS by default, at least one per second); the rest follow the inbox
// mix.

import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS, positiveInteger } from '../../../../scripts/loadtest/k6/config.js';
import { writeSummary } from '../../../../scripts/loadtest/k6/summary.js';
import { Workload, INBOX_MIX } from '../lib/workload.js';

const ops = positiveInteger('OPS', __ENV.OPS, 20);
if (ops < 2) throw new Error('OPS must be at least 2 so both the inbox mix and decision flows run');
const flowOps = positiveInteger('FLOW_OPS', __ENV.FLOW_OPS, Math.max(1, Math.round(ops / 10)));
if (flowOps >= ops) throw new Error('FLOW_OPS must be below OPS so the inbox mix still runs');
const inboxOps = ops - flowOps;
const duration = __ENV.DURATION || '2m';

// A request can wait up to 5s for one of the runtime's 32 pool connections,
// so preallocate enough VUs to hold six seconds of arrivals. k6 drops
// arrivals while it initializes VUs mid-run, which would otherwise show up as
// harness drops rather than service behavior.
function capacity(rate) {
  return {
    preAllocatedVUs: Math.min(600, Math.max(20, rate * 6)),
    maxVUs: Math.max(200, rate * 12),
  };
}

export const options = {
  scenarios: {
    inbox: {
      executor: 'constant-arrival-rate',
      rate: inboxOps,
      timeUnit: '1s',
      duration,
      exec: 'inboxStep',
      ...capacity(inboxOps),
    },
    decisions: {
      executor: 'constant-arrival-rate',
      rate: flowOps,
      timeUnit: '1s',
      duration,
      exec: 'decisionFlow',
      ...capacity(flowOps),
    },
  },
  thresholds: {
    dropped_iterations: ['count==0'],
    // Every expected status in this profile is 2xx (201 create, 202 pending
    // result, 204 decision), so the default response callback already treats
    // them as successes and any other status is a real failure.
    http_req_failed: ['rate==0'],
    checks: ['rate==1'],
    decision_flows_completed: ['count>0'],
    // Roughly twice the worst p99 of two 1-minute release-build runs at 10 and
    // 20 operations/s on an Apple Silicon laptop with PostgreSQL under
    // OrbStack; see README.md, "Interpreting results". They catch a
    // regression, not an SLO.
    'http_req_duration{name:get_task}': ['p(99)<100'],
    'http_req_duration{name:get_request}': ['p(99)<150'],
    'http_req_duration{name:list_tasks}': ['p(99)<750'],
    'http_req_duration{name:decide_task}': ['p(99)<500'],
    http_req_duration: ['p(99)<750'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
  noConnectionReuse: false,
};

const workload = new Workload(__ENV.CASEWORK_URL);

export function inboxStep() {
  workload.step(INBOX_MIX);
}

export function decisionFlow() {
  workload.decisionFlow();
}

export const handleSummary = writeSummary;
