// Evidence assertion workload over the synthetic adult-status question.
//
// Every iteration asks for one signed assertion about one synthetic subject.
// A small share asks about a subject the source does not hold, which exercises
// the refusal path. Subjects come from the seed pools written by up.sh and
// carry no real-world identifiers.
//
// The stock development bundle limits each principal to 60 requests per
// minute with a burst of 10, and `evidencectl dev` offers no way to raise that
// limit. up.sh therefore registers a set of load clients, and this workload
// spreads iterations over them round-robin so that each principal stays under
// its limit while the runtime sees the full offered rate.

import http from 'k6/http';
import encoding from 'k6/encoding';
import exec from 'k6/execution';
import { check } from 'k6';
import { SharedArray } from 'k6/data';

// Percentage of iterations that ask about a subject the source does not hold.
export const ABSENT_PERCENT = 3;

const requirement = required('REQUIREMENT');
const selectorProfile = required('SELECTOR_PROFILE');
const purpose = required('PURPOSE');

const authorizations = new SharedArray('authorizations', function () {
  const values = [];
  for (const path of open(required('HEADER_FILES_LIST'), 'r').split('\n')) {
    if (path.trim() === '') continue;
    const header = open(path.trim(), 'r').trim();
    if (!header.startsWith('Authorization: Bearer ') || header.split('.').length !== 3) {
      throw new Error('HEADER_FILES_LIST must name evidencectl dev Authorization header files');
    }
    values.push(header.slice('Authorization: '.length));
  }
  if (values.length === 0) {
    throw new Error('HEADER_FILES_LIST names no authorization headers');
  }
  return values;
});

export const subjects = new SharedArray('subjects', function () {
  return sharedLines(required('SUBJECTS_FILE'));
});

export const absentSubjects = new SharedArray('absentSubjects', function () {
  return sharedLines(required('ABSENT_FILE'));
});

function required(name) {
  const value = __ENV[name];
  if (!value) {
    throw new Error(`${name} is required; start the profile through run.sh`);
  }
  return value;
}

function sharedLines(path) {
  const values = [];
  for (const line of open(path, 'r').split('\n')) {
    const value = line.trim();
    if (value !== '') values.push(value);
  }
  if (values.length === 0) {
    throw new Error(`subject pool ${path} is empty; run up.sh first`);
  }
  return values;
}

function nonce() {
  // The request contract requires 32 fresh random bytes as unpadded base64url.
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return encoding.b64encode(bytes.buffer, 'rawurl');
}

function jsonBody(response) {
  try {
    return JSON.parse(response.body);
  } catch (error) {
    return null;
  }
}

function isFlattenedJws(response) {
  const contentType = response.headers['Content-Type'] || '';
  if (!contentType.startsWith('application/jose+json')) return false;
  const body = jsonBody(response);
  if (!body || typeof body.protected !== 'string' || typeof body.payload !== 'string') return false;
  if (typeof body.signature !== 'string' || body.signature.length === 0) return false;
  try {
    const header = JSON.parse(encoding.b64decode(body.protected, 'rawurl', 's'));
    const payload = JSON.parse(encoding.b64decode(body.payload, 'rawurl', 's'));
    return header.alg === 'ES256' && payload !== null && typeof payload === 'object';
  } catch (error) {
    return false;
  }
}

function problemCode(response) {
  const contentType = response.headers['Content-Type'] || '';
  if (!contentType.startsWith('application/problem+json')) return null;
  const body = jsonBody(response);
  return body && typeof body.code === 'string' ? body.code : null;
}

export class Workload {
  constructor(baseUrl) {
    this.endpoint = `${baseUrl}/v1/evidence`;
    this.randomState = 0;
  }

  random() {
    if (this.randomState === 0) {
      const configuredSeed = Number(__ENV.RANDOM_SEED || 20260925) >>> 0;
      this.randomState = (configuredSeed ^ Math.imul(__VU || 1, 0x9e3779b1)) >>> 0;
      if (this.randomState === 0) this.randomState = 1;
    }
    this.randomState = (Math.imul(this.randomState, 1664525) + 1013904223) >>> 0;
    return this.randomState / 0x100000000;
  }

  // Round-robin over the load clients keeps every principal's share of the
  // offered rate equal, so the per-principal limit is reached only when the
  // offered rate exceeds what run.sh allows for the registered client count.
  authorization() {
    return authorizations[exec.scenario.iterationInTest % authorizations.length];
  }

  request(subject, authorization, tagName, expected) {
    const body = JSON.stringify({
      purpose,
      requestNonce: nonce(),
      requirement,
      subjects: [{ role: 'person', selector: { profile: selectorProfile, values: { person_id: subject } } }],
    });
    return http.post(this.endpoint, body, {
      headers: {
        Authorization: authorization,
        'Content-Type': 'application/json',
        Accept: 'application/jose+json',
      },
      tags: { name: tagName },
      responseCallback: http.expectedStatuses(...expected),
    });
  }

  assertPresent(authorization = this.authorization()) {
    const subject = subjects[Math.floor(this.random() * subjects.length)];
    const response = this.request(subject, authorization, 'evidence_assert', [200]);
    check(response, {
      'assert status 200': (r) => r.status === 200,
      'assert is a flattened ES256 JWS': (r) => r.status === 200 && isFlattenedJws(r),
    });
    return response;
  }

  // The compact OpenAPI question treats a source 404 as a source protocol
  // failure, so an unknown subject is refused with 503 source.unavailable.
  // Only that exact problem is expected; any other 503 still fails the run.
  assertAbsent(authorization = this.authorization()) {
    const subject = absentSubjects[Math.floor(this.random() * absentSubjects.length)];
    const response = this.request(subject, authorization, 'evidence_absent', [503]);
    check(response, {
      'absent refused as source.unavailable': (r) => r.status === 503 && problemCode(r) === 'source.unavailable',
    });
    return response;
  }

  // Drives one principal past its burst; both outcomes are expected.
  assertLimited(authorization) {
    const subject = subjects[Math.floor(this.random() * subjects.length)];
    const response = this.request(subject, authorization, 'evidence_limited', [200, 429]);
    check(response, {
      'limited status is 200 or 429': (r) => r.status === 200 || r.status === 429,
    });
    return response;
  }

  step() {
    if (this.random() * 100 < ABSENT_PERCENT) {
      return this.assertAbsent();
    }
    return this.assertPresent();
  }
}

export function firstAuthorization() {
  return authorizations[0];
}
