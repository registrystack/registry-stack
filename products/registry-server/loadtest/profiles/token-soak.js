// Sustained token-endpoint exercise, kept separate from the one-shot herd.

import http from 'k6/http';
import { check } from 'k6';
import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS, positiveInteger } from '../lib/config.js';
import { writeSummary } from '../lib/summary.js';
import { driverToken } from '../lib/token.js';

const vus = positiveInteger('VUS', __ENV.VUS, 200);
const duration = __ENV.DURATION || '1m';

export const options = {
  scenarios: {
    token_soak: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '5s', target: vus },
        { duration, target: vus },
        { duration: '5s', target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate==0'],
    'http_req_duration{name:mint_token}': ['p(99)<500'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
  noConnectionReuse: false,
};

export default function () {
  const token = driverToken(__ENV.TOKEN_URL, __ENV.CLIENT_ID, __ENV.CLIENT_SECRET, { herd: true });
  const response = http.get(
    `${__ENV.SERVER_URL}/v1/records/establishments?accessProfile=business-operator&$top=1`,
    { headers: { Authorization: `Bearer ${token}` }, tags: { name: 'token_soak_read' } }
  );
  check(response, { 'token soak read status 200': (r) => r.status === 200 });
}

export const handleSummary = writeSummary;
