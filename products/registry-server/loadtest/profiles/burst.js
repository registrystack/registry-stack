// Burst profile: a campaign day.
//
// Holds the campaign plateau (default 250 TPS) with short spikes at twice
// the plateau, modeling the surge a registration drive or month-end
// reporting batch produces on top of business-hours traffic.

import { sleep } from 'k6';
import { Workload, READ_MIX } from '../lib/workload.js';

const plateau = Number(__ENV.TPS || 250);
const spike = Number(__ENV.SPIKE_MULTIPLIER || 2) * plateau;
const spikeSeconds = Number(__ENV.SPIKE_SECONDS || 30);

export const options = {
  scenarios: {
    campaign: {
      executor: 'ramping-arrival-rate',
      startRate: Math.ceil(plateau / 5),
      timeUnit: '1s',
      preAllocatedVUs: Math.min(500, Math.max(50, Math.ceil(spike))),
      maxVUs: Math.max(1000, Math.ceil(spike * 2)),
      stages: [
        { duration: '2m', target: plateau },
        { duration: `${spikeSeconds}s`, target: spike },
        { duration: '1m', target: plateau },
        { duration: `${spikeSeconds}s`, target: spike },
        { duration: '1m', target: plateau },
        { duration: '2m', target: Math.ceil(plateau / 5) },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(99)<1000'],
  },
  noConnectionReuse: false,
};

const workload = new Workload(__ENV.SERVER_URL, __ENV.TOKEN_URL, __ENV.CLIENT_ID, __ENV.CLIENT_SECRET);

export default function () {
  workload.step(workload.token(), READ_MIX);
  sleep(0.05);
}
