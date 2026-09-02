// Ceiling-sweep profile: find the throughput knee.
//
// Steps the arrival rate from START_TPS (default 10) to MAX_TPS (default
// 600) in equal stages over the ramp, read-only so repeated runs have no
// write side effects. The knee is where p99 departs from its plateau and
// 504 request.timeout responses first appear; thresholds are advisory
// (abort-on-failure is deliberately off).

import { sleep } from 'k6';
import { Workload, READ_MIX } from '../lib/workload.js';

const startTps = Number(__ENV.START_TPS || 10);
const maxTps = Number(__ENV.MAX_TPS || 600);
const stages = Number(__ENV.STAGES || 10);
const stageDuration = __ENV.STAGE_DURATION || '1m';

const stageStep = Math.max(1, Math.ceil((maxTps - startTps) / stages));
const rampStages = [];
for (let rate = startTps; rate <= maxTps; rate += stageStep) {
  rampStages.push({ duration: stageDuration, target: rate });
}

export const options = {
  scenarios: {
    sweep: {
      executor: 'ramping-arrival-rate',
      startRate: startTps,
      timeUnit: '1s',
      preAllocatedVUs: Math.min(500, Math.max(20, Math.ceil(maxTps))),
      maxVUs: Math.max(1000, Math.ceil(maxTps * 2)),
      stages: rampStages,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
  noConnectionReuse: false,
};

const workload = new Workload(__ENV.SERVER_URL, __ENV.TOKEN_URL, __ENV.CLIENT_ID, __ENV.CLIENT_SECRET);

export default function () {
  workload.step(workload.token(), READ_MIX);
  sleep(0.05);
}
