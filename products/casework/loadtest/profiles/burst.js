// Campaign burst over the inbox mix with named phases so recovery is measured
// separately. Defaults fit one fresh development token: 30s baseline, 15s
// ramps, a 30s peak, and 90s recovery. Decision flows are excluded so a burst
// never consumes the seeded flow pool.

import {
  SAFE_SYSTEM_TAGS,
  SUMMARY_TREND_STATS,
  durationMilliseconds,
  positiveInteger,
  startTime,
} from '../../../../scripts/loadtest/k6/config.js';
import { writeSummary } from '../../../../scripts/loadtest/k6/summary.js';
import { Workload, INBOX_MIX } from '../lib/workload.js';

const baselineOps = positiveInteger('OPS', __ENV.OPS, 20);
const peakOps = positiveInteger('PEAK_OPS', __ENV.PEAK_OPS, 100);
if (peakOps <= baselineOps) throw new Error('PEAK_OPS must be greater than OPS');

const baselineDuration = __ENV.BASELINE_DURATION || '30s';
const rampDuration = __ENV.RAMP_DURATION || '15s';
const peakDuration = __ENV.PEAK_DURATION || '30s';
const recoveryDuration = __ENV.RECOVERY_DURATION || '90s';
const baselineMs = durationMilliseconds('BASELINE_DURATION', baselineDuration);
const rampMs = durationMilliseconds('RAMP_DURATION', rampDuration);
const peakMs = durationMilliseconds('PEAK_DURATION', peakDuration);
durationMilliseconds('RECOVERY_DURATION', recoveryDuration);

function capacity(rate) {
  return {
    // The runtime pool waits up to 5s for a connection. Preallocate six
    // seconds of arrivals and leave VU headroom beyond that, so the offered
    // rate stays independent of that wait, then treat any drops as a test
    // failure.
    preAllocatedVUs: Math.min(600, Math.max(50, rate * 6)),
    maxVUs: Math.max(500, peakOps * 12),
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
    checks: ['rate>0.99'],
    'http_req_failed{scenario:recovery}': ['rate==0'],
    'checks{scenario:recovery}': ['rate==1'],
    'http_req_duration{scenario:recovery}': ['p(99)<500'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
  noConnectionReuse: false,
};

const workload = new Workload(__ENV.CASEWORK_URL);

export function campaignStep() {
  workload.step(INBOX_MIX);
}

export const handleSummary = writeSummary;
