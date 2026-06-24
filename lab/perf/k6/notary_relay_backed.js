import http from 'k6/http';
import { check } from 'k6';
import {
  CLAIM_RESULT,
  commonOptions,
  env,
  evaluationPayload,
  jsonHeaders,
  parseJson,
  profiledScenario,
  recordStatus,
  requiredEnv,
  sleepIfConfigured,
  summaryFor,
} from './lib/common.js';

const civilNotaryUrl = env('CIVIL_NOTARY_URL', 'http://127.0.0.1:4321');
const sharedNotaryUrl = env('SHARED_NOTARY_URL', 'http://127.0.0.1:4323');
const civilToken = requiredEnv('CIVIL_EVIDENCE_CLIENT_BEARER');
const sharedToken = requiredEnv('SHARED_EVIDENCE_CLIENT_BEARER');

const subjects = ['NID-1001', 'NID-1002', 'NID-1003', 'NID-1004', 'NID-1005', 'NID-1006'];

export const options = {
  ...commonOptions({
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1500'],
  }),
  scenarios: {
    notary_relay_backed: profiledScenario({
      rateDefault: 200,
      preAllocatedVusDefault: 64,
      maxVusDefault: 400,
      stages: [
        { duration: '1m', target: 100 },
        { duration: '1m', target: 200 },
        { duration: '1m', target: 400 },
        { duration: '30s', target: 0 },
      ],
    }),
  },
};

export default function () {
  const subject = subjects[(__VU + __ITER) % subjects.length];
  const cases = [
    {
      name: 'civil_alive',
      url: `${civilNotaryUrl}/v1/evaluations`,
      token: civilToken,
      claim: 'person-is-alive',
    },
    {
      name: 'shared_combined_support',
      url: `${sharedNotaryUrl}/v1/evaluations`,
      token: sharedToken,
      claim: 'eligible-for-combined-support',
    },
  ];
  const item = cases[(__VU + __ITER) % cases.length];
  const response = http.post(
    item.url,
    evaluationPayload(subject, item.claim),
    { headers: jsonHeaders(item.token, undefined, CLAIM_RESULT) },
  );
  const body = parseJson(response);
  const ok = check(response, {
    [`${item.name} returned 200`]: (r) => r.status === 200,
    [`${item.name} returned results`]: () => Array.isArray(body.results) && body.results.length > 0,
  });
  recordStatus(ok, response, 200);
  sleepIfConfigured();
}

export const handleSummary = summaryFor('notary_relay_backed');
