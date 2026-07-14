import { Counter, Rate } from 'k6/metrics';
import { sleep } from 'k6';

export const PURPOSE = 'https://demo.example.gov/purpose/decentralized-evidence-demo';
export const CLAIM_RESULT = 'application/vnd.registry-notary.claim-result+json';
export const SD_JWT = 'application/dc+sd-jwt';

export const unexpectedStatus = new Counter('registry_lab_unexpected_status_total');
export const checkFailureRate = new Rate('registry_lab_check_failure_rate');
export const httpStatusTotal = new Counter('registry_lab_http_status_total');
export const httpStatus200 = new Counter('registry_lab_http_status_200_total');
export const httpStatus201 = new Counter('registry_lab_http_status_201_total');
export const httpStatus204 = new Counter('registry_lab_http_status_204_total');
export const httpStatus400 = new Counter('registry_lab_http_status_400_total');
export const httpStatus401 = new Counter('registry_lab_http_status_401_total');
export const httpStatus403 = new Counter('registry_lab_http_status_403_total');
export const httpStatus404 = new Counter('registry_lab_http_status_404_total');
export const httpStatus409 = new Counter('registry_lab_http_status_409_total');
export const httpStatus422 = new Counter('registry_lab_http_status_422_total');
export const httpStatus429 = new Counter('registry_lab_http_status_429_total');
export const httpStatus500 = new Counter('registry_lab_http_status_500_total');
export const httpStatus502 = new Counter('registry_lab_http_status_502_total');
export const httpStatus503 = new Counter('registry_lab_http_status_503_total');
export const httpStatus504 = new Counter('registry_lab_http_status_504_total');
export const httpStatusOther = new Counter('registry_lab_http_status_other_total');

export function env(name, fallback = '') {
  const value = __ENV[name];
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  return value;
}

export function requiredEnv(name) {
  const value = env(name);
  if (value === '') {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

export function duration() {
  return env('REGISTRY_LAB_DURATION', '30s');
}

export function profile() {
  return env('REGISTRY_LAB_PROFILE', 'smoke');
}

export function vus(fallback = 4) {
  return Number(env('REGISTRY_LAB_VUS', String(fallback)));
}

export function rate(fallback = 8) {
  return Number(env('REGISTRY_LAB_RATE', String(fallback)));
}

export function preAllocatedVus(fallback = 8) {
  return Number(env('REGISTRY_LAB_PRE_ALLOCATED_VUS', String(fallback)));
}

export function maxVus(fallback = 32) {
  return Number(env('REGISTRY_LAB_MAX_VUS', String(fallback)));
}

export function thinkTimeSeconds() {
  const fallback = profile() === 'smoke' ? '0.1' : '0';
  return Number(env('REGISTRY_LAB_THINK_TIME_SECONDS', fallback));
}

export function commonOptions(thresholds = {}) {
  return {
    discardResponseBodies: false,
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    thresholds: {
      checks: ['rate>=0.99'],
      registry_lab_check_failure_rate: ['rate<0.01'],
      registry_lab_unexpected_status_total: ['count==0'],
      ...thresholds,
    },
  };
}

export function sleepIfConfigured() {
  const seconds = thinkTimeSeconds();
  if (seconds > 0) {
    sleep(seconds);
  }
}

export function loopScenario(extra = {}) {
  const { vusDefault, rateDefault, preAllocatedVusDefault, maxVusDefault, stages, ...scenario } = extra;
  return {
    executor: 'constant-vus',
    vus: vus(vusDefault || 4),
    duration: duration(),
    gracefulStop: '10s',
    ...scenario,
  };
}

export function arrivalScenario(extra = {}) {
  const { rateDefault, preAllocatedVusDefault, maxVusDefault, stages, ...scenario } = extra;
  return {
    executor: 'constant-arrival-rate',
    rate: rate(rateDefault || 8),
    timeUnit: '1s',
    duration: duration(),
    preAllocatedVUs: preAllocatedVus(preAllocatedVusDefault || 8),
    maxVUs: maxVus(maxVusDefault || 32),
    gracefulStop: '10s',
    ...scenario,
  };
}

export function rampingArrivalScenario(extra = {}) {
  const { rateDefault, preAllocatedVusDefault, maxVusDefault, stages: defaultStages, ...scenario } = extra;
  const stages = parseStages(
    env('REGISTRY_LAB_STAGES'),
    defaultStages || [
      { duration: '1m', target: rate(rateDefault || 8) },
      { duration: '1m', target: rate(rateDefault || 8) * 2 },
      { duration: '1m', target: rate(rateDefault || 8) * 4 },
      { duration: '30s', target: 0 },
    ],
  );
  return {
    executor: 'ramping-arrival-rate',
    startRate: Number(env('REGISTRY_LAB_START_RATE', '0')),
    timeUnit: '1s',
    stages,
    preAllocatedVUs: preAllocatedVus(preAllocatedVusDefault || 8),
    maxVUs: maxVus(maxVusDefault || 32),
    gracefulStop: '10s',
    ...scenario,
  };
}

export function profiledScenario(extra = {}) {
  switch (profile()) {
    case 'capacity':
      return arrivalScenario(extra);
    case 'breakpoint':
      return rampingArrivalScenario(extra);
    case 'smoke':
      return loopScenario(extra);
    default:
      throw new Error(`unsupported REGISTRY_LAB_PROFILE ${profile()}`);
  }
}

function parseStages(value, fallback) {
  if (!value) {
    return fallback;
  }
  return value.split(',').map((stage) => {
    const [durationValue, targetValue] = stage.split(':');
    if (!durationValue || !targetValue) {
      throw new Error(`invalid REGISTRY_LAB_STAGES entry ${stage}; expected duration:target`);
    }
    return {
      duration: durationValue,
      target: Number(targetValue),
    };
  });
}

export function bearerHeaders(token, purpose = PURPOSE, accept = 'application/json') {
  return {
    Authorization: `Bearer ${token}`,
    Accept: accept,
    'Data-Purpose': purpose,
    'X-Request-Id': requestId(),
  };
}

export function jsonHeaders(token, purpose = PURPOSE, accept = CLAIM_RESULT) {
  return {
    ...bearerHeaders(token, purpose, accept),
    'Content-Type': 'application/json',
  };
}

export function requestId() {
  return `registry-lab-perf-${__VU}-${__ITER}-${Date.now()}`;
}

export function target(subjectId) {
  return {
    type: 'Person',
    identifiers: [{ scheme: 'national_id', value: subjectId }],
  };
}

export function evaluationPayload(subjectId, claim, disclosure = 'predicate', format = CLAIM_RESULT) {
  return JSON.stringify({
    target: target(subjectId),
    claims: [claim],
    disclosure,
    format,
  });
}

export function parseJson(response) {
  try {
    return response.json();
  } catch (_) {
    return {};
  }
}

export function recordStatus(ok, response, expected) {
  recordHttpStatus(response);
  checkFailureRate.add(!ok);
  if (!ok) {
    unexpectedStatus.add(1, {
      status: String(response.status),
      expected: Array.isArray(expected) ? expected.join(',') : String(expected),
    });
  }
}

export function recordHttpStatus(response) {
  const status = Number(response.status);
  httpStatusTotal.add(1, { status: String(status) });
  switch (status) {
    case 200:
      httpStatus200.add(1);
      break;
    case 201:
      httpStatus201.add(1);
      break;
    case 204:
      httpStatus204.add(1);
      break;
    case 400:
      httpStatus400.add(1);
      break;
    case 401:
      httpStatus401.add(1);
      break;
    case 403:
      httpStatus403.add(1);
      break;
    case 404:
      httpStatus404.add(1);
      break;
    case 409:
      httpStatus409.add(1);
      break;
    case 422:
      httpStatus422.add(1);
      break;
    case 429:
      httpStatus429.add(1);
      break;
    case 500:
      httpStatus500.add(1);
      break;
    case 502:
      httpStatus502.add(1);
      break;
    case 503:
      httpStatus503.add(1);
      break;
    case 504:
      httpStatus504.add(1);
      break;
    default:
      httpStatusOther.add(1);
      break;
  }
}

function metricLine(name, metric) {
  if (!metric || !metric.values) {
    return `${name}: {}`;
  }
  const values = metric.values;
  const fields = [];
  for (const [label, key] of [
    ['count', 'count'],
    ['rate', 'rate'],
    ['value', 'value'],
    ['avg', 'avg'],
    ['min', 'min'],
    ['med', 'med'],
    ['p90', 'p(90)'],
    ['p95', 'p(95)'],
    ['p99', 'p(99)'],
    ['max', 'max'],
  ]) {
    if (values[key] !== undefined) {
      fields.push(`${label}=${formatMetricValue(values[key])}`);
    }
  }
  if (fields.length === 0) {
    return `${name}: ${JSON.stringify(values)}`;
  }
  return `${name}: ${fields.join(' ')}`;
}

function formatMetricValue(value) {
  if (typeof value !== 'number') {
    return String(value);
  }
  if (Number.isInteger(value)) {
    return String(value);
  }
  return value.toFixed(4);
}

export function summaryFor(name) {
  return (data) => {
    const lines = [
      `${name} summary`,
      `profile: ${profile()}`,
      `think_time_seconds: ${thinkTimeSeconds().toFixed(3)}`,
    ];
    const metricNames = Object.keys(data.metrics || {}).sort();
    for (const metricName of metricNames) {
      lines.push(metricLine(metricName, data.metrics[metricName]));
    }
    return {
      stdout: `${lines.join('\n')}\n`,
      [`output/perf/results/${name}.json`]: JSON.stringify(data, null, 2),
      [`output/perf/reports/${name}.txt`]: `${lines.join('\n')}\n`,
    };
  };
}
