// Thundering-herd profile: every client re-authenticates at once.
//
// Measures Registry Mint's token endpoint and the server's steady JWT
// verification when N virtual users (default 200) all present fresh tokens
// simultaneously, as after a coordinated client restart. Each iteration
// acquires a token (no cache) and performs one read to prove it.
//
// This profile targets Mint as much as Registry Server; keep it out of
// steady-state measurements.

import http from 'k6/http';
import { check } from 'k6';
import { driverToken } from '../lib/token.js';

const vus = Number(__ENV.VUS || 200);
const duration = __ENV.DURATION || '1m';

export const options = {
  scenarios: {
    herd: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '5s', target: vus },
        { duration: duration, target: vus },
        { duration: '5s', target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate==0'],
    'http_req_duration{name:mint_token}': ['p(99)<500'],
  },
  noConnectionReuse: false,
};

export default function () {
  const token = driverToken(__ENV.TOKEN_URL, __ENV.CLIENT_ID, __ENV.CLIENT_SECRET, { herd: true });
  const response = http.get(
    `${__ENV.SERVER_URL}/v1/records/establishments?accessProfile=business-operator&$top=1`,
    { headers: { Authorization: `Bearer ${token}` }, tags: { name: 'herd_read' } }
  );
  check(response, { 'herd read status 200': (r) => r.status === 200 });
}
