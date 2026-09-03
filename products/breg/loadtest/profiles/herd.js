// A true coordinated restart: every virtual user authenticates once and then
// performs one protected read. per-vu-iterations starts the users together.

import http from 'k6/http';
import { check } from 'k6';
import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS, positiveInteger } from '../lib/config.js';
import { writeSummary } from '../lib/summary.js';
import { driverToken } from '../lib/token.js';

const vus = positiveInteger('VUS', __ENV.VUS, 200);
const maxDuration = __ENV.DURATION || '30s';

export const options = {
  scenarios: {
    coordinated_restart: {
      executor: 'per-vu-iterations',
      vus,
      iterations: 1,
      maxDuration,
    },
  },
  thresholds: {
    dropped_iterations: ['count==0'],
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
    `${__ENV.BREG_URL}/v1/records/establishments?accessProfile=business-operator&$top=1`,
    { headers: { Authorization: `Bearer ${token}` }, tags: { name: 'herd_read' } }
  );
  check(response, { 'herd read status 200': (r) => r.status === 200 });
}

export const handleSummary = writeSummary;
