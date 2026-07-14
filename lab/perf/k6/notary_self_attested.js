import http from 'k6/http';
import { check } from 'k6';
import {
  CLAIM_RESULT,
  commonOptions,
  env,
  parseJson,
  profiledScenario,
  recordStatus,
  requiredEnv,
  sleepIfConfigured,
  summaryFor,
} from './lib/common.js';

const notaryUrl = env('SELF_ATTESTED_NOTARY_URL', 'http://127.0.0.1:4321');
const token = requiredEnv('SELF_ATTESTED_EVIDENCE_CLIENT_TOKEN');

export const options = {
  ...commonOptions({
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1500'],
  }),
  scenarios: {
    notary_self_attested: profiledScenario({
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
  const response = http.post(
    `${notaryUrl}/v1/evaluations`,
    JSON.stringify({
      target: {
        type: 'Person',
        identifiers: [{ scheme: 'application_reference', value: 'SYNTHETIC-APPLICATION-001' }],
      },
      claims: ['applicant-declaration'],
      disclosure: 'predicate',
      format: CLAIM_RESULT,
    }),
    {
      headers: {
        Accept: CLAIM_RESULT,
        'Content-Type': 'application/json',
        'Data-Purpose': 'application-processing',
        'x-api-key': token,
      },
    },
  );
  const body = parseJson(response);
  const results = body.results || body.claim_results || [];
  const ok = check(response, {
    'self-attested evaluation returned 200': (r) => r.status === 200,
    'self-attested evaluation returned a result': () => Array.isArray(results) && results.length > 0,
  });
  recordStatus(ok, response, 200);
  sleepIfConfigured();
}

export const handleSummary = summaryFor('notary_self_attested');
