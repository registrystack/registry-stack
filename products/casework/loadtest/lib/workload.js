// Weighted workload over the Registry Casework unified review surfaces.
//
// The mix models an inbox-shaped deployment: Staff list and open tasks far
// more often than they decide them, producers poll their requests and results,
// and a thin tail of producers submit new requests. Decision flows (claim,
// save a private draft, decide, poll the answered result) run in their own
// scenario over the seeded flow pool, one pool entry per iteration, so no two
// iterations race for the same task and the run carries no expected conflicts.
// All task and request identifiers come from the seed pools; every generated
// value is synthetic.

import http from 'k6/http';
import exec from 'k6/execution';
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import { Counter } from 'k6/metrics';

export const taskPagesFollowed = new Counter('task_pages_followed');
export const lifecyclesCompleted = new Counter('lifecycles_completed');
export const decisionFlowsCompleted = new Counter('decision_flows_completed');

const STAFF = 'staff';
const PRODUCER = 'requester';
const MAXIMUM_SCAN_PAGES = 500;

function authorizationFrom(variable) {
  const path = __ENV[variable];
  if (!path) {
    throw new Error(`${variable} must name one caseworkctl dev Authorization header file`);
  }
  const header = open(path, 'r').trim();
  if (!header.startsWith('Authorization: Bearer ') || header.split('.').length !== 3) {
    throw new Error(`${variable} must contain one caseworkctl dev Authorization header`);
  }
  return header.slice('Authorization: '.length);
}

const staffAuthorization = authorizationFrom('STAFF_HEADER_FILE');
const producerAuthorization = authorizationFrom('PRODUCER_HEADER_FILE');

const runNonce = __ENV.RUN_NONCE || '';
if (!/^[A-Za-z0-9-]{1,48}$/.test(runNonce)) {
  throw new Error('RUN_NONCE must be one bounded run identifier');
}

function poolLines(path) {
  const values = [];
  for (const line of open(path, 'r').split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2) {
      values.push({ taskId: parts[0], requestId: parts[1] });
    }
  }
  if (values.length === 0) {
    throw new Error(`seed pool ${path} is empty; run seed.py first`);
  }
  return values;
}

export const readTasks = new SharedArray('readTasks', function () {
  return poolLines(__ENV.READ_TASKS_FILE);
});

const flowTasks = __ENV.FLOW_TASKS_FILE
  ? new SharedArray('flowTasks', function () {
      return poolLines(__ENV.FLOW_TASKS_FILE);
    })
  : null;
const flowOffset = Number(__ENV.FLOW_OFFSET || 0);
if (!Number.isInteger(flowOffset) || flowOffset < 0) {
  throw new Error('FLOW_OFFSET must be a non-negative integer');
}

function params(authorization, profile, name, extra = {}) {
  return {
    headers: Object.assign({ Authorization: authorization, 'Registry-Casework-Profile': profile }, extra),
    tags: { name },
  };
}

function jsonBody(response) {
  try {
    return response.json();
  } catch (_) {
    return null;
  }
}

export class Workload {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.randomState = 0;
  }

  random() {
    if (this.randomState === 0) {
      const configuredSeed = Number(__ENV.RANDOM_SEED || 20260902) >>> 0;
      this.randomState = (configuredSeed ^ Math.imul(__VU || 1, 0x9e3779b1)) >>> 0;
      if (this.randomState === 0) this.randomState = 1;
    }
    this.randomState = (Math.imul(this.randomState, 1664525) + 1013904223) >>> 0;
    return this.randomState / 0x100000000;
  }

  readTask() {
    return readTasks[Math.floor(this.random() * readTasks.length)];
  }

  // A unique, synthetic subject per iteration: the runtime admits one request
  // per producer subject round, so a repeated subject would be refused.
  subjectReference() {
    return `lt-${runNonce}-${exec.scenario.name}-${exec.vu.idInTest}-${exec.scenario.iterationInTest}`;
  }

  syntheticDigest() {
    let hex = '';
    for (let word = 0; word < 8; word += 1) {
      hex += (Math.floor(this.random() * 0x100000000) >>> 0).toString(16).padStart(8, '0');
    }
    return `sha256:${hex}`;
  }

  idempotencyKey(action) {
    return `lt-${runNonce}-${action}-${exec.scenario.name}-${exec.vu.idInTest}-${exec.scenario.iterationInTest}`;
  }

  createRequest() {
    const reference = this.subjectReference();
    const body = JSON.stringify({
      kind: 'decision',
      subject: { source: 'standalone', type: 'batch', id: reference, version: '1', digest: this.syntheticDigest() },
      requesterReference: reference,
      context: {
        strategy: 'submitted',
        snapshot: { reference, summary: 'Synthetic load-test batch' },
      },
    });
    const response = http.post(
      `${this.baseUrl}/v1/review-requests`,
      body,
      params(producerAuthorization, PRODUCER, 'create_request', {
        'Content-Type': 'application/json',
        'Idempotency-Key': this.idempotencyKey('create'),
      })
    );
    check(response, { 'create status 201': (r) => r.status === 201 });
    return response;
  }

  listTasks() {
    const response = http.get(
      `${this.baseUrl}/v1/review-tasks?queue=decisions&limit=25`,
      params(staffAuthorization, STAFF, 'list_tasks')
    );
    check(response, { 'list status 200': (r) => r.status === 200 });
    if (response.status === 200 && __ENV.FOLLOW_CURSOR === '1') {
      const page = jsonBody(response);
      const cursor = page && page.nextCursor;
      if (cursor) {
        const follow = http.get(
          `${this.baseUrl}/v1/review-tasks?queue=decisions&limit=25&cursor=${encodeURIComponent(cursor)}`,
          params(staffAuthorization, STAFF, 'list_tasks_page2')
        );
        check(follow, { 'page-2 status 200': (r) => r.status === 200 });
        if (follow.status === 200) taskPagesFollowed.add(1);
      }
    }
    return response;
  }

  getTask() {
    const task = this.readTask();
    const response = http.get(
      `${this.baseUrl}/v1/review-tasks/${task.taskId}`,
      params(staffAuthorization, STAFF, 'get_task')
    );
    check(response, { 'task status 200': (r) => r.status === 200 });
    return response;
  }

  getTaskContext() {
    const task = this.readTask();
    const response = http.get(
      `${this.baseUrl}/v1/review-tasks/${task.taskId}/context`,
      params(staffAuthorization, STAFF, 'get_task_context')
    );
    check(response, { 'context status 200': (r) => r.status === 200 });
    return response;
  }

  getRequest() {
    const task = this.readTask();
    const response = http.get(
      `${this.baseUrl}/v1/review-requests/${task.requestId}`,
      params(producerAuthorization, PRODUCER, 'get_request')
    );
    check(response, { 'request status 200': (r) => r.status === 200 });
    return response;
  }

  // Read-pool requests are never decided, so their result is always pending.
  pollPendingResult() {
    const task = this.readTask();
    const response = http.get(
      `${this.baseUrl}/v1/review-requests/${task.requestId}/result`,
      params(producerAuthorization, PRODUCER, 'poll_result_pending')
    );
    check(response, { 'pending result status 202': (r) => r.status === 202 });
    return response;
  }

  // Claim, save a private draft, decide, and poll the answered result for one
  // open task whose current revision is known. Returns true when every step
  // succeeded.
  decide(task, revision) {
    const claim = http.post(
      `${this.baseUrl}/v1/review-tasks/${task.taskId}/claim`,
      null,
      params(staffAuthorization, STAFF, 'claim_task', {
        'If-Match': `"${revision}"`,
        'Idempotency-Key': this.idempotencyKey('claim'),
      })
    );
    const claimed = jsonBody(claim);
    if (!check(claim, { 'claim status 200': (r) => r.status === 200 }) || !claimed) return false;
    const draft = http.put(
      `${this.baseUrl}/v1/review-tasks/${task.taskId}/draft`,
      JSON.stringify({ body: { note: 'Synthetic load-test draft' } }),
      params(staffAuthorization, STAFF, 'save_draft', {
        'Content-Type': 'application/json',
        'If-Match': `"${claimed.revision}"`,
        'Idempotency-Key': this.idempotencyKey('draft'),
      })
    );
    if (!check(draft, { 'draft status 200': (r) => r.status === 200 })) return false;
    // Saving a draft advances the task revision by one.
    const decision = http.post(
      `${this.baseUrl}/v1/review-tasks/${task.taskId}/decisions`,
      JSON.stringify({ decision: { type: 'answer', outcome: 'confirmed' } }),
      params(staffAuthorization, STAFF, 'decide_task', {
        'Content-Type': 'application/json',
        'If-Match': `"${claimed.revision + 1}"`,
        'Idempotency-Key': this.idempotencyKey('decide'),
      })
    );
    if (!check(decision, { 'decision status 204': (r) => r.status === 204 })) return false;
    const result = http.get(
      `${this.baseUrl}/v1/review-requests/${task.requestId}/result`,
      params(producerAuthorization, PRODUCER, 'poll_result_answered')
    );
    const answered = jsonBody(result);
    return check(result, {
      'answered result status 200': (r) => r.status === 200,
      'answered result confirmed': () => answered !== null && answered.outcome === 'confirmed',
    });
  }

  // One seeded flow-pool task per iteration of the calling scenario.
  decisionFlow() {
    if (flowTasks === null) {
      exec.test.abort('FLOW_TASKS_FILE is required for decision flows');
    }
    const index = flowOffset + exec.scenario.iterationInTest;
    if (index >= flowTasks.length) {
      exec.test.abort('the seeded flow pool is exhausted; start a fresh environment with a larger seed');
    }
    if (this.decide(flowTasks[index], 1)) decisionFlowsCompleted.add(1);
  }

  // Create one request, find its task by following the Staff inbox, then run
  // the full decision flow. The request is newer than every read-pool task, so
  // reaching it proves the inbox continuation works.
  lifecycle() {
    const created = this.createRequest();
    const accepted = jsonBody(created);
    if (created.status !== 201 || !accepted || !accepted.requestId) return;
    const requested = http.get(
      `${this.baseUrl}/v1/review-requests/${accepted.requestId}`,
      params(producerAuthorization, PRODUCER, 'get_request')
    );
    check(requested, { 'request status 200': (r) => r.status === 200 });
    const pending = http.get(
      `${this.baseUrl}/v1/review-requests/${accepted.requestId}/result`,
      params(producerAuthorization, PRODUCER, 'poll_result_pending')
    );
    check(pending, { 'pending result status 202': (r) => r.status === 202 });

    let cursor = null;
    let found = null;
    for (let page = 0; page < MAXIMUM_SCAN_PAGES && found === null; page += 1) {
      const suffix = cursor ? `&cursor=${encodeURIComponent(cursor)}` : '';
      const listed = http.get(
        `${this.baseUrl}/v1/review-tasks?queue=decisions&limit=100${suffix}`,
        params(staffAuthorization, STAFF, page === 0 ? 'list_tasks' : 'list_tasks_scan')
      );
      if (!check(listed, { 'list status 200': (r) => r.status === 200 })) return;
      if (page > 0) taskPagesFollowed.add(1);
      const body = jsonBody(listed);
      const items = (body && body.items) || [];
      found = items.find((item) => item.requestId === accepted.requestId) || null;
      cursor = body && body.nextCursor;
      if (found === null && !cursor) break;
    }
    if (!check(found, { 'created task listed': (value) => value !== null })) return;

    const task = { taskId: found.taskId, requestId: accepted.requestId };
    const opened = http.get(`${this.baseUrl}/v1/review-tasks/${task.taskId}`, params(staffAuthorization, STAFF, 'get_task'));
    check(opened, { 'task status 200': (r) => r.status === 200 });
    const context = http.get(
      `${this.baseUrl}/v1/review-tasks/${task.taskId}/context`,
      params(staffAuthorization, STAFF, 'get_task_context')
    );
    check(context, { 'context status 200': (r) => r.status === 200 });
    if (this.decide(task, found.revision)) lifecyclesCompleted.add(1);
  }

  step(weights) {
    const roll = this.random() * 100;
    let cumulative = 0;
    for (const [weight, action] of weights) {
      cumulative += weight;
      if (roll < cumulative) {
        return action.call(this);
      }
    }
    return this.getTask();
  }
}

// The inbox mix: 35% list the Staff inbox (optionally following one
// continuation), 20% open a task, 10% open its context, 15% producer request
// reads, 10% pending-result polls, and 10% new producer submissions.
export const INBOX_MIX = [
  [35, Workload.prototype.listTasks],
  [20, Workload.prototype.getTask],
  [10, Workload.prototype.getTaskContext],
  [15, Workload.prototype.getRequest],
  [10, Workload.prototype.pollPendingResult],
  [10, Workload.prototype.createRequest],
];
