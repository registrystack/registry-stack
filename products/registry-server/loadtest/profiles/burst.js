// Campaign burst with named phases so recovery is measured separately.
// Defaults: 50 ops/s baseline, ramp to 250, hold 30s, return to 50, recover 3m.

import {
  SAFE_SYSTEM_TAGS,
  SUMMARY_TREND_STATS,
  durationMilliseconds,
  positiveNumber,
  startTime,
} from '../lib/config.js';
import { writeSummary } from '../lib/summary.js';
import { Workload, READ_MIX } from '../lib/workload.js';

const baselineOps = positiveNumber('OPS', __ENV.OPS, 50);
const peakOps = positiveNumber('PEAK_OPS', __ENV.PEAK_OPS, 250);
if (peakOps <= baselineOps) throw new Error('PEAK_OPS must be greater than OPS');

const baselineDuration = __ENV.BASELINE_DURATION || '2m';
const rampDuration = __ENV.RAMP_DURATION || '30s';
const peakDuration = __ENV.PEAK_DURATION || '30s';
const recoveryDuration = __ENV.RECOVERY_DURATION || '3m';
const baselineMs = durationMilliseconds('BASELINE_DURATION', baselineDuration);
const rampMs = durationMilliseconds('RAMP_DURATION', rampDuration);
const peakMs = durationMilliseconds('PEAK_DURATION', peakDuration);

function capacity(rate) {
  return {
    preAllocatedVUs: Math.min(500, Math.max(50, Math.ceil(rate))),
    // The server timeout is 10s. Leave enough VU headroom to keep the offered
    // rate independent of that timeout, then treat any drops as a test failure.
    maxVUs: Math.max(1000, Math.ceil(peakOps * 12)),
  };
}

export const options = {
  scenarios: {
    baseline: {
      executor: 'constant-arrival-rate',
      rate: baselineOps,
      timeUnit: '1s',
      duration: baselineDuration,
      gracefulStop: '15s',
      exec: 'campaignStep',
      ...capacity(baselineOps),
    },
    ramp_up: {
      executor: 'ramping-arrival-rate',
      startTime: startTime(baselineMs),
      startRate: baselineOps,
      timeUnit: '1s',
      stages: [{ duration: rampDuration, target: peakOps }],
      gracefulStop: '15s',
      exec: 'campaignStep',
      ...capacity(peakOps),
    },
    peak: {
      executor: 'constant-arrival-rate',
      startTime: startTime(baselineMs, rampMs),
      rate: peakOps,
      timeUnit: '1s',
      duration: peakDuration,
      gracefulStop: '15s',
      exec: 'campaignStep',
      ...capacity(peakOps),
    },
    ramp_down: {
      executor: 'ramping-arrival-rate',
      startTime: startTime(baselineMs, rampMs, peakMs),
      startRate: peakOps,
      timeUnit: '1s',
      stages: [{ duration: rampDuration, target: baselineOps }],
      gracefulStop: '15s',
      exec: 'campaignStep',
      ...capacity(peakOps),
    },
    recovery: {
      executor: 'constant-arrival-rate',
      startTime: startTime(baselineMs, rampMs, peakMs, rampMs),
      rate: baselineOps,
      timeUnit: '1s',
      duration: recoveryDuration,
      gracefulStop: '15s',
      exec: 'campaignStep',
      ...capacity(baselineOps),
    },
  },
  thresholds: {
    dropped_iterations: ['count==0'],
    http_req_failed: ['rate<0.01'],
    'http_req_failed{scenario:recovery}': ['rate==0'],
    'http_req_duration{scenario:recovery}': ['p(99)<250'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
  noConnectionReuse: false,
};

const workload = new Workload(__ENV.SERVER_URL, __ENV.TOKEN_URL, __ENV.CLIENT_ID, __ENV.CLIENT_SECRET);

export function campaignStep() {
  workload.step(workload.token(), READ_MIX);
}

export const handleSummary = writeSummary;
