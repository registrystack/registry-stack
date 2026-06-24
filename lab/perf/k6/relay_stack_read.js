import http from 'k6/http';
import { check } from 'k6';
import {
  bearerHeaders,
  commonOptions,
  env,
  profiledScenario,
  recordStatus,
  requiredEnv,
  sleepIfConfigured,
  summaryFor,
} from './lib/common.js';

const civilUrl = env('CIVIL_RELAY_URL', 'http://127.0.0.1:4311');
const socialUrl = env('SOCIAL_RELAY_URL', 'http://127.0.0.1:4312');
const healthUrl = env('HEALTH_RELAY_URL', 'http://127.0.0.1:4313');

const civilRowToken = requiredEnv('CIVIL_ROW_READER_RAW');
const civilMetadataToken = requiredEnv('CIVIL_METADATA_CLIENT_RAW');
const socialRowToken = requiredEnv('SOCIAL_ROW_READER_RAW');
const socialAggregateToken = requiredEnv('SOCIAL_AGGREGATE_READER_RAW');
const healthRowToken = requiredEnv('HEALTH_ROW_READER_RAW');
const healthMetadataToken = requiredEnv('HEALTH_METADATA_CLIENT_RAW');

export const options = {
  ...commonOptions({
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<750'],
  }),
  scenarios: {
    relay_stack_read: profiledScenario({
      rateDefault: 1000,
      preAllocatedVusDefault: 256,
      maxVusDefault: 1200,
      stages: [
        { duration: '1m', target: 1000 },
        { duration: '1m', target: 2000 },
        { duration: '1m', target: 5000 },
        { duration: '30s', target: 0 },
      ],
    }),
  },
};

export default function () {
  const routes = [
    {
      name: 'civil_row',
      url: `${civilUrl}/v1/datasets/civil_registry/entities/civil_person/records?limit=1`,
      token: civilRowToken,
    },
    {
      name: 'civil_metadata',
      url: `${civilUrl}/metadata/catalog`,
      token: civilMetadataToken,
    },
    {
      name: 'social_row',
      url: `${socialUrl}/v1/datasets/social_protection_registry/entities/household/records?limit=1`,
      token: socialRowToken,
    },
    {
      name: 'social_aggregate',
      url: `${socialUrl}/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band`,
      token: socialAggregateToken,
    },
    {
      name: 'health_row',
      url: `${healthUrl}/v1/datasets/health_registry/entities/health_facility/records?limit=1`,
      token: healthRowToken,
    },
    {
      name: 'health_metadata',
      url: `${healthUrl}/metadata/catalog`,
      token: healthMetadataToken,
    },
  ];

  const route = routes[(__VU + __ITER) % routes.length];
  const response = http.get(route.url, { headers: bearerHeaders(route.token) });
  const ok = check(response, {
    [`${route.name} returned 200`]: (r) => r.status === 200,
  });
  recordStatus(ok, response, 200);
  sleepIfConfigured();
}

export const handleSummary = summaryFor('relay_stack_read');
