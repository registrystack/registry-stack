import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import {
  OPENFN_PURPOSE,
  SD_JWT,
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

const openfnNotaryUrl = env('OPENFN_NOTARY_URL', 'http://127.0.0.1:4324');
const token = requiredEnv('CIVIL_EVIDENCE_CLIENT_BEARER');
const issuedCredentials = new Counter('registry_lab_openfn_credentials_issued_total');

export const options = {
  ...commonOptions({
    http_req_failed: ['rate<0.02'],
    http_req_duration: ['p(95)<2500'],
    registry_lab_openfn_credentials_issued_total: ['count>0'],
  }),
  scenarios: {
    openfn_credential_issuance: profiledScenario({
      rateDefault: 20,
      preAllocatedVusDefault: 32,
      maxVusDefault: 160,
      stages: [
        { duration: '1m', target: 10 },
        { duration: '1m', target: 20 },
        { duration: '1m', target: 40 },
        { duration: '30s', target: 0 },
      ],
    }),
  },
};

export default function () {
  const evaluate = http.post(
    `${openfnNotaryUrl}/v1/evaluations`,
    evaluationPayload('person-123', 'date-of-birth', 'value', SD_JWT),
    { headers: jsonHeaders(token, OPENFN_PURPOSE, SD_JWT) },
  );
  const evaluationBody = parseJson(evaluate);
  const evaluationId = evaluationBody.results && evaluationBody.results[0] && evaluationBody.results[0].evaluation_id;
  const evaluated = check(evaluate, {
    'credential-bound evaluation returned 200': (r) => r.status === 200,
    'credential-bound evaluation returned evaluation_id': () => typeof evaluationId === 'string' && evaluationId.length > 0,
  });
  recordStatus(evaluated, evaluate, 200);
  if (!evaluated) {
    sleepIfConfigured();
    return;
  }

  const issue = http.post(
    `${openfnNotaryUrl}/v1/credentials`,
    JSON.stringify({
      evaluation_id: evaluationId,
      credential_profile: 'openfn_civil_sd_jwt',
      format: SD_JWT,
      claims: ['date-of-birth'],
      disclosure: 'value',
    }),
    { headers: jsonHeaders(token, OPENFN_PURPOSE, 'application/json') },
  );
  const issueBody = parseJson(issue);
  const issued = check(issue, {
    'credential issuance returned 200': (r) => r.status === 200,
    'credential issuance returned credential': () => typeof issueBody.credential === 'string' && issueBody.credential.length > 0,
  });
  recordStatus(issued, issue, 200);
  if (issued) {
    issuedCredentials.add(1);
  }
  sleepIfConfigured();
}

export const handleSummary = summaryFor('openfn_credential_issuance');
