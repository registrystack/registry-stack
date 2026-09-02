// One live list request plus its continuation. The threshold proves page two
// was executed, rather than merely trusting the workload source shape.

import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS } from '../lib/config.js';
import { writeSummary } from '../lib/summary.js';
import { Workload } from '../lib/workload.js';

export const options = {
  scenarios: {
    cursor_smoke: { executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: '30s' },
  },
  thresholds: {
    http_req_failed: ['rate==0'],
    cursor_pages_followed: ['count>0'],
  },
  systemTags: SAFE_SYSTEM_TAGS,
  summaryTrendStats: SUMMARY_TREND_STATS,
};

const workload = new Workload(__ENV.SERVER_URL, __ENV.TOKEN_URL, __ENV.CLIENT_ID, __ENV.CLIENT_SECRET);

export default function () {
  workload.filteredList(workload.token());
}

export const handleSummary = writeSummary;
