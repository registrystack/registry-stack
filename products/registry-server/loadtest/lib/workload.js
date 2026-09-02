// Weighted workload mix over the business-establishments surfaces.
//
// The mix models registry-shaped traffic: reads dominate (point lookups by
// unique code, point gets by record id, filtered collections with cursor
// pagination), with a thin write tail (creates with idempotency keys and
// preconditioned patches). All record ids and codes come from the seed pools;
// nothing here carries real-world identifiers.

import http from 'k6/http';
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import { driverToken } from './token.js';

export const establishmentIds = new SharedArray('establishmentIds', function () {
  return sharedLines(__ENV.ESTABLISHMENT_IDS_FILE, 'id');
});

export const establishmentCodes = new SharedArray('establishmentCodes', function () {
  return sharedLines(__ENV.ESTABLISHMENT_IDS_FILE, 'code');
});

function sharedLines(path, column) {
  const file = open(path, 'r');
  const values = [];
  for (const line of file.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2) {
      values.push(column === 'id' ? parts[0] : parts[1]);
    }
  }
  if (values.length === 0) {
    throw new Error(`seed pool ${path} is empty; run seed.py first`);
  }
  return values;
}

function headers(token, extra = {}) {
  return Object.assign({ Authorization: `Bearer ${token}` }, extra);
}

export class Workload {
  constructor(baseUrl, tokenUrl, clientId, clientSecret) {
    this.baseUrl = baseUrl;
    this.tokenUrl = tokenUrl;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.createCounter = 0;
  }

  token() {
    return driverToken(this.tokenUrl, this.clientId, this.clientSecret);
  }

  lookupByCode(token) {
    const code = establishmentCodes[Math.floor(Math.random() * establishmentCodes.length)];
    // The de-duplication search shape: find one record by its unique code.
    const filter = encodeURIComponent(`establishmentCode eq '${code}'`);
    const response = http.get(
      `${this.baseUrl}/v1/records/establishments?accessProfile=business-operator&$filter=${filter}&$top=1`,
      { headers: headers(token), tags: { name: 'lookup_by_code' } }
    );
    check(response, { 'lookup status 200': (r) => r.status === 200 });
    return response;
  }

  getEstablishment(token) {
    const id = establishmentIds[Math.floor(Math.random() * establishmentIds.length)];
    const response = http.get(
      `${this.baseUrl}/v1/records/establishments/${id}?accessProfile=business-operator`,
      { headers: headers(token), tags: { name: 'get_establishment' } }
    );
    check(response, { 'get status 200': (r) => r.status === 200 });
    return response;
  }

  filteredList(token) {
    // The monitoring shape: a filtered, sorted collection page.
    const kind = ['production', 'warehouse', 'office'][Math.floor(Math.random() * 3)];
    const filter = encodeURIComponent(`establishmentKind eq '${kind}'`);
    const response = http.get(
      `${this.baseUrl}/v1/records/establishments?accessProfile=business-operator&$filter=${filter}&$orderby=establishmentCode&$top=50`,
      { headers: headers(token), tags: { name: 'filtered_list' } }
    );
    check(response, { 'list status 200': (r) => r.status === 200 });
    if (response.status === 200 && __ENV.FOLLOW_CURSOR === '1') {
      const body = response.json();
      const next = body && (body.next || (body.links && body.links.next));
      if (next) {
        const follow = http.get(next, { headers: headers(token), tags: { name: 'filtered_list_page2' } });
        check(follow, { 'page-2 status 200': (r) => r.status === 200 });
      }
    }
    return response;
  }

  createEstablishment(token) {
    this.createCounter += 1;
    const code = `LT-K6-${__VU}-${this.createCounter}-${Date.now()}`;
    const body = JSON.stringify({
      data: {
        establishmentCode: code,
        siteName: `Loadtest Create ${this.createCounter}`,
        locality: 'central-loadtest',
        establishmentKind: 'office',
        operatingStatus: 'operating',
      },
    });
    const response = http.post(
      `${this.baseUrl}/v1/records/establishments?accessProfile=business-operator`,
      body,
      {
        headers: headers(token, {
          'Content-Type': 'application/json',
          'Idempotency-Key': `loadtest-k6-${code}`,
        }),
        tags: { name: 'create_establishment' },
      }
    );
    check(response, { 'create status 201': (r) => r.status === 201 });
    return response;
  }

  patchEstablishment(token) {
    const id = establishmentIds[Math.floor(Math.random() * establishmentIds.length)];
    const fetched = http.get(
      `${this.baseUrl}/v1/records/establishments/${id}?accessProfile=business-operator`,
      { headers: headers(token), tags: { name: 'patch_prefetch' } }
    );
    if (fetched.status !== 200) {
      check(fetched, { 'patch prefetch ok': () => false });
      return fetched;
    }
    const etag = fetched.headers['Etag'] || fetched.headers['etag'] || fetched.headers['ETag'];
    if (!etag) {
      check(fetched, { 'patch etag present': () => false });
      return fetched;
    }
    const body = JSON.stringify([{ op: 'replace', path: '/data/siteName', value: `Loadtest Patch ${Date.now()}` }]);
    const response = http.patch(
      `${this.baseUrl}/v1/records/establishments/${id}?accessProfile=business-operator`,
      body,
      {
        headers: headers(token, {
          'Content-Type': 'application/json-patch+json',
          'Idempotency-Key': `loadtest-k6-patch-${id}-${Date.now()}`,
          'If-Match': etag,
        }),
        tags: { name: 'patch_establishment' },
      }
    );
    check(response, { 'patch status 200': (r) => r.status === 200 });
    return response;
  }

  step(token, weights) {
    const roll = Math.random() * 100;
    let cumulative = 0;
    for (const [weight, action] of weights) {
      cumulative += weight;
      if (roll < cumulative) {
        return action.call(this, token);
      }
    }
    return this.getEstablishment(token);
  }
}

// The steady-state mix: 40% code lookup, 30% point get, 20% filtered list,
// 7% create, 3% preconditioned patch.
export const STEADY_MIX = [
  [40, Workload.prototype.lookupByCode],
  [30, Workload.prototype.getEstablishment],
  [20, Workload.prototype.filteredList],
  [7, Workload.prototype.createEstablishment],
  [3, Workload.prototype.patchEstablishment],
];

// Read-only variant for ceiling sweeps: no write side effects at any load.
export const READ_MIX = [
  [45, Workload.prototype.lookupByCode],
  [35, Workload.prototype.getEstablishment],
  [20, Workload.prototype.filteredList],
];
