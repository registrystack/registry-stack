// One live list request plus its continuation. The threshold proves page two
// was executed, rather than merely trusting the workload source shape.

import { SAFE_SYSTEM_TAGS, SUMMARY_TREND_STATS } from '../../../../scripts/loadtest/k6/config.js';
import { writeSummary } from '../../../../scripts/loadtest/k6/summary.js';
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

const workload = new Workload(__ENV.BREG_URL);

export default function () {
  workload.filteredList(workload.token());
}

export const handleSummary = writeSummary;
