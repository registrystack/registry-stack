// Steady-state profile: "a Tuesday" at a national-registry scale.
//
// Constant arrival rate (default 50 TPS, tunable) for a fixed duration
// (default 10m; pass DURATION=8h for a soak) over the mixed workload.
// Thresholds: no failed requests, p99 under 250ms.

import { sleep } from 'k6';
import execution from 'k6/execution';
import { Workload, STEADY_MIX } from '../lib/workload.js';

const tps = Number(__ENV.TPS || 50);
const duration = __ENV.DURATION || '10m';

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: tps,
      timeUnit: '1s',
      duration: duration,
      preAllocatedVUs: Math.min(500, Math.max(20, Math.ceil(tps * 2))),
      maxVUs: Math.max(1000, Math.ceil(tps * 10)),
    },
  },
  thresholds: {
    http_req_failed: ['rate==0'],
    http_req_duration: ['p(99)<250'],
    'http_req_duration{name:lookup_by_code}': ['p(99)<250'],
    'http_req_duration{name:get_establishment}': ['p(99)<250'],
  },
  noConnectionReuse: false,
};

const workload = new Workload(__ENV.SERVER_URL, __ENV.TOKEN_URL, __ENV.CLIENT_ID, __ENV.CLIENT_SECRET);

export default function () {
  workload.step(workload.token(), STEADY_MIX);
  // constant-arrival-rate drives the pace; this only avoids a hot spin in
  // over-provisioned iterations.
  sleep(0.05);
}

export function handleSummary(data) {
  return {
    stdout: textSummary(data),
  };
}

function textSummary(data) {
  const metrics = data.metrics;
  const lines = [`steady profile: ${tps} TPS for ${duration}`];
  for (const [name, metric] of Object.entries(metrics)) {
    if (metric.values) {
      const values = metric.values;
      const parts = [];
      if ('p(99)' in values) parts.push(`p99=${values['p(99)'].toFixed(1)}ms`);
      if ('rate' in values) parts.push(`rate=${values.rate.toFixed(4)}`);
      if ('count' in values) parts.push(`count=${values.count}`);
      if (parts.length) lines.push(`  ${name}: ${parts.join(' ')}`);
    }
  }
  lines.push(`  iterations: ${execution.scenario.iterationInInstance || 0}`);
  return lines.join('\n') + '\n';
}
