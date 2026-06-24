import http from 'k6/http';
import { check } from 'k6';
import { Counter, Rate } from 'k6/metrics';
import {
  CLAIM_RESULT,
  OPENFN_PURPOSE,
  commonOptions,
  env,
  evaluationPayload,
  jsonHeaders,
  parseJson,
  profiledScenario,
  recordHttpStatus,
  recordStatus,
  requiredEnv,
  sleepIfConfigured,
  summaryFor,
} from './lib/common.js';

const openfnNotaryUrl = env('OPENFN_NOTARY_URL', 'http://127.0.0.1:4324');
const token = requiredEnv('CIVIL_EVIDENCE_CLIENT_BEARER');

const expectedRateLimited = new Counter('registry_lab_openfn_expected_rate_limited_total');
const openfnSuccessRate = new Rate('registry_lab_openfn_success_rate');

export const options = {
  ...commonOptions({
    registry_lab_openfn_success_rate: ['rate>0.50'],
  }),
  scenarios: {
    openfn_sidecar_saturation: profiledScenario({
      rateDefault: 25,
      preAllocatedVusDefault: 16,
      maxVusDefault: 80,
      stages: [
        { duration: '1m', target: 10 },
        { duration: '1m', target: 25 },
        { duration: '1m', target: 50 },
        { duration: '30s', target: 0 },
      ],
    }),
  },
};

export default function () {
  const response = http.post(
    `${openfnNotaryUrl}/v1/evaluations`,
    evaluationPayload('person-123', 'date-of-birth', 'value', CLAIM_RESULT),
    { headers: jsonHeaders(token, OPENFN_PURPOSE, CLAIM_RESULT) },
  );
  const body = parseJson(response);
  if (response.status === 503 || response.status === 429) {
    recordHttpStatus(response);
    expectedRateLimited.add(1, { status: String(response.status) });
    openfnSuccessRate.add(false);
    sleepIfConfigured();
    return;
  }
  const ok = check(response, {
    'openfn evaluation returned 200': (r) => r.status === 200,
    'openfn evaluation returned results': () => Array.isArray(body.results) && body.results.length > 0,
  });
  openfnSuccessRate.add(ok);
  recordStatus(ok, response, 200);
  sleepIfConfigured();
}

export const handleSummary = summaryFor('openfn_sidecar_saturation');
