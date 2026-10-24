import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMauticPageview,
  createSharedTrackingClient,
  getSharedTrackingClient,
  trackingDeniedByBrowser,
} from '../src/lib/shared-tracking-client.mjs';

const bridgeUrl = 'https://registrystack.org/tracking-bridge/';
const unknown = { choice: null, generation: null, expiresAt: null, revision: 0 };
const generation = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const accepted = { choice: 'accepted', generation, expiresAt: Date.now() + 60_000, revision: 10 };
const rejected = { choice: 'rejected', generation: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', expiresAt: Date.now() + 60_000, revision: 11 };
const envelope = { protocol: 'registrystack-tracking', version: 2 };
const localRefusalKey = 'registrystack.tracking-local-refusal.v2';

function fixture(options = {}) {
  const {
    factory = createSharedTrackingClient,
    initialValues = [],
    sendFailures = 0,
    ...clientOptions
  } = options;
  const listeners = new Map();
  const documentListeners = new Map();
  const sent = [];
  const frames = [];
  const values = new Map(initialValues);
  const storage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  };
  let frame;
  let autoLoad = options.autoLoad !== false;
  let remainingSendFailures = sendFailures;
  const window = {
    location: { origin: 'https://docs.registrystack.org' },
    localStorage: storage,
    navigator: { doNotTrack: '0' },
    crypto: { randomUUID: () => crypto.randomUUID() },
    addEventListener: (type, listener) => listeners.set(type, listener),
    removeEventListener: type => listeners.delete(type),
    setTimeout,
    clearTimeout,
  };
  const document = {
    createElement: tag => {
      assert.equal(tag, 'iframe');
      const frameListeners = new Map();
      frame = {
        contentWindow: { postMessage: (data, origin) => {
          if (remainingSendFailures > 0) {
            remainingSendFailures -= 1;
            throw new Error('Fixture postMessage failure.');
          }
          sent.push({ data, origin });
        } },
        setAttribute() {},
        addEventListener: (type, listener) => frameListeners.set(type, listener),
        fireLoad: () => frameListeners.get('load')?.(),
        fireError: () => frameListeners.get('error')?.(),
        remove() { this.removed = true; },
      };
      frames.push(frame);
      return frame;
    },
    body: { append: element => { if (autoLoad) queueMicrotask(() => element.fireLoad()); } },
    addEventListener: (type, listener) => documentListeners.set(type, listener),
    removeEventListener: type => documentListeners.delete(type),
    visibilityState: 'visible',
  };
  const failures = [];
  const changes = [];
  const client = factory({
    bridgeUrl, window, document, navigator: window.navigator,
    timeoutMs: 100, onFailure: error => failures.push(error),
    onStateChange: (state, confirmed) => changes.push({ state, confirmed }), ...clientOptions,
  });
  const message = (data, overrides = {}) => listeners.get('message')?.({
    origin: 'https://registrystack.org', source: overrides.source ?? frame.contentWindow, data, ...overrides,
  });
  const reply = (state, extra = {}) => {
    const request = sent.at(-1).data;
    message({ ...envelope, id: request.id, ok: true, state, ...extra });
  };
  return {
    client,
    get frame() { return frame; },
    frames,
    sent,
    message,
    reply,
    failures,
    changes,
    values,
    setAutoLoad(value) { autoLoad = value; },
    pageshow: () => listeners.get('pageshow')?.(),
    visibilitychange: () => documentListeners.get('visibilitychange')?.(),
    storageEvent: event => listeners.get('storage')?.(event),
  };
}

async function nextRequest(run) {
  const promise = run();
  await new Promise(resolve => setImmediate(resolve));
  return { promise };
}

test('reads shared consent through one fixed iframe without a parent tracking script', async () => {
  const f = fixture();
  const { promise } = await nextRequest(() => f.client.read());
  assert.equal(f.frame.src, bridgeUrl);
  assert.equal(f.frame.hidden, true);
  assert.equal(f.frame.referrerPolicy, 'no-referrer');
  assert.equal(f.sent[0].origin, 'https://registrystack.org');
  assert.equal(f.sent[0].data.type, 'read');
  f.reply(unknown);
  assert.deepEqual(await promise, unknown);
  assert.equal(f.values.size, 0);
  f.client.close();
});

test('concurrent startup and resume reads share one request and confirm an unchanged remote state', async (t) => {
  const f = fixture();
  t.after(() => f.client.close());
  const first = f.client.read();
  const second = f.client.read();
  f.pageshow();
  await new Promise(resolve => setImmediate(resolve));

  for (const { data } of [...f.sent]) {
    f.message({ ...envelope, id: data.id, ok: true, state: unknown });
  }
  assert.deepEqual(await first, unknown);
  assert.deepEqual(await second, unknown);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.length, 1);
  assert.deepEqual(f.changes, [{ state: unknown, confirmed: true }]);
  assert.equal(f.client.readRetryReason, null);
});

test('ignores messages from another origin or frame and never accepts surplus response fields', async () => {
  const f = fixture();
  const { promise } = await nextRequest(() => f.client.read());
  const response = { ...envelope, id: f.sent[0].data.id, ok: true, state: accepted };
  f.message(response, { origin: 'https://attacker.example' });
  f.message(response, { source: {} });
  assert.deepEqual(f.client.state, unknown);
  f.reply(unknown);
  assert.deepEqual(await promise, unknown);
  const invalid = await nextRequest(() => f.client.read());
  f.reply(accepted, { extra: 'refuse me' });
  await assert.rejects(invalid.promise, /tracking/i);
  f.client.close();
});

test('a withdrawal push supersedes an older accepted response', async () => {
  const f = fixture();
  const first = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await first.promise;
  const pending = await nextRequest(() => f.client.associate(generation));
  const id = f.sent.at(-1).data.id;
  f.message({ ...envelope, type: 'changed', state: rejected });
  f.message({ ...envelope, id, ok: true, state: accepted, deviceId: 'a'.repeat(23) });
  await assert.rejects(pending.promise, /tracking/i);
  assert.deepEqual(f.client.state, rejected);
  assert.equal(f.values.has('mautic_device_id'), false);
  f.client.close();
});

test('withdrawal discards the native realm and cancels old pageviews without suspending the new state', async () => {
  const f = fixture();
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  const oldFrame = f.frame;
  const oldView = await nextRequest(() => f.client.pageview({
    page_url: 'https://docs.registrystack.org/', page_title: 'Docs', page_referrer: '',
  }));
  assert.equal(f.sent.at(-1).data.expectedGeneration, generation);
  f.message({ ...envelope, type: 'changed', state: rejected });
  await assert.rejects(oldView.promise, /tracking/i);
  assert.equal(oldFrame.removed, true);
  assert.deepEqual(f.client.state, rejected);
  assert.equal(f.failures.length, 0);
  const reconsent = await nextRequest(() => f.client.choose('accepted'));
  assert.notEqual(f.frame, oldFrame);
  const renewed = { ...accepted, generation: 'ffffffff-ffff-4fff-8fff-ffffffffffff', revision: 12 };
  f.reply(renewed);
  assert.deepEqual(await reconsent.promise, renewed);
  f.client.close();
});

test('an authoritative newer push acknowledges its matching choice before the old frame is discarded', async () => {
  const f = fixture();
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  const refusal = await nextRequest(() => f.client.choose('rejected'));
  const oldFrame = f.frame;
  f.message({ ...envelope, type: 'changed', state: rejected });
  assert.deepEqual(await refusal.promise, rejected);
  assert.equal(oldFrame.removed, true);
  assert.equal(f.failures.length, 0);
  f.client.close();
});

test('a stale rejected choice cannot discard a follow-up frame created by a confirmed push', async (t) => {
  const renewed = { ...accepted, generation: 'ffffffff-ffff-4fff-8fff-ffffffffffff', revision: 12 };
  let followup;
  let f;
  f = fixture({
    onStateChange: state => {
      if (state.generation !== renewed.generation || followup) return;
      followup = f.client.read();
      void followup.catch(() => {});
    },
  });
  t.after(() => f.client.close());
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  const refusal = await nextRequest(() => f.client.choose('rejected'));
  const refusalOutcome = refusal.promise.then(value => ({ value }), error => ({ error }));
  const oldFrame = f.frame;

  f.message({ ...envelope, type: 'changed', state: renewed });
  const followupFrame = f.frame;
  assert.notEqual(followupFrame, oldFrame);
  assert.match((await refusalOutcome).error?.message, /tracking/i);
  await new Promise(resolve => setImmediate(resolve));
  assert.notEqual(followupFrame.removed, true);
  assert.equal(f.frame, followupFrame);
});

test('a validated generation change settles a readiness-waiting read before it is sent', async (t) => {
  const f = fixture();
  t.after(() => f.client.close());
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  const oldFrame = f.frame;
  const sentBeforeRead = f.sent.length;

  const waitingRead = f.client.read();
  f.message({ ...envelope, type: 'changed', state: rejected });

  assert.deepEqual(await waitingRead, rejected);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.length, sentBeforeRead);
  assert.equal(oldFrame.removed, true);
  assert.deepEqual(f.client.state, rejected);
  assert.equal(f.failures.length, 0);
});

test('a validated generation change settles only its matching readiness-waiting choice', async (t) => {
  const matching = fixture();
  t.after(() => matching.client.close());
  const initial = await nextRequest(() => matching.client.read());
  matching.reply(accepted);
  await initial.promise;

  const matchingSentBeforeChoice = matching.sent.length;
  const refusal = matching.client.choose('rejected');
  matching.message({ ...envelope, type: 'changed', state: rejected });
  assert.deepEqual(await refusal, rejected);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(matching.sent.length, matchingSentBeforeChoice);
  assert.equal(matching.values.has(localRefusalKey), false);
  assert.equal(matching.failures.length, 0);
});

test('a readiness-waiting acceptance cannot override a validated rejection', async (t) => {
  const conflicting = fixture();
  t.after(() => conflicting.client.close());
  const initial = await nextRequest(() => conflicting.client.read());
  conflicting.reply(accepted);
  await initial.promise;
  const conflictingSentBeforeChoice = conflicting.sent.length;
  const acceptance = conflicting.client.choose('accepted');
  conflicting.message({ ...envelope, type: 'changed', state: rejected });
  await assert.rejects(acceptance, error => (
    error?.code === 'frame-replaced' && /tracking/i.test(error.message)
  ));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(conflicting.sent.length, conflictingSentBeforeChoice);
  assert.deepEqual(conflicting.client.state, rejected);
  assert.equal(conflicting.failures.length, 0);
});

test('a visible rejected tab recreates its essential bridge and observes another tab reaccepting', async () => {
  const f = fixture();
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  const oldFrame = f.frame;
  f.message({ ...envelope, type: 'changed', state: rejected });
  assert.equal(oldFrame.removed, true);

  f.pageshow();
  await new Promise(resolve => setImmediate(resolve));
  assert.notEqual(f.frame, oldFrame);
  assert.equal(f.sent.at(-1).data.type, 'read');
  const renewed = { ...accepted, generation: 'ffffffff-ffff-4fff-8fff-ffffffffffff', revision: 12 };
  f.reply(renewed);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.client.state, renewed);
  f.client.close();
});

test('accept never overrides a newer rejection without another explicit click', async () => {
  const f = fixture();
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  f.message({ ...envelope, type: 'changed', state: rejected });

  const choice = f.client.choose('accepted');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.at(-1).data.expectedRevision, rejected.revision);
  f.message({ ...envelope, id: f.sent.at(-1).data.id, ok: false, error: 'unavailable' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.at(-1).data.type, 'read');
  const newerRejection = { ...rejected, generation: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', revision: 12 };
  f.reply(newerRejection);
  await assert.rejects(choice, /tracking/i);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.filter(({ data }) => data.type === 'choose').length, 1);
  assert.equal(f.client.state.choice, null);
  assert.equal(f.client.state.revision, newerRejection.revision);
  assert.equal(f.failures.length, 1);

  const explicitRetry = f.client.choose('accepted');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.at(-1).data.type, 'choose');
  assert.equal(f.sent.at(-1).data.expectedRevision, newerRejection.revision);
  const renewed = { ...accepted, generation: 'ffffffff-ffff-4fff-8fff-ffffffffffff', revision: 13 };
  f.reply(renewed);
  assert.deepEqual(await explicitRetry, renewed);
  f.client.close();
});

test('accept reconciles remote acceptance without sending another mutation', async () => {
  const f = fixture();
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  f.message({ ...envelope, type: 'changed', state: rejected });

  const choice = f.client.choose('accepted');
  await new Promise(resolve => setImmediate(resolve));
  f.message({ ...envelope, id: f.sent.at(-1).data.id, ok: false, error: 'unavailable' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.at(-1).data.type, 'read');
  const renewed = { ...accepted, generation: 'ffffffff-ffff-4fff-8fff-ffffffffffff', revision: 12 };
  f.reply(renewed);

  assert.deepEqual(await choice, renewed);
  assert.equal(f.sent.filter(({ data }) => data.type === 'choose').length, 1);
  assert.equal(f.failures.length, 0);
  f.client.close();
});

test('an essential read retries one failed frame without exposing the transient failure', async (t) => {
  const f = fixture({ autoLoad: false });
  t.after(() => f.client.close());
  const first = f.client.read();
  const outcome = first.then(value => ({ value }), error => ({ error }));
  const oldFrame = f.frame;
  oldFrame.fireError();
  await new Promise(resolve => setImmediate(resolve));

  const currentFrame = f.frame;
  assert.notEqual(currentFrame, oldFrame);
  assert.equal(oldFrame.removed, true);
  assert.equal(f.failures.length, 0);
  assert.equal(f.client.readRetryReason, 'frame-load-failed');
  oldFrame.fireLoad();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.length, 0);
  currentFrame.fireLoad();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.at(-1).data.type, 'read');
  f.reply(unknown);
  assert.deepEqual(await outcome, { value: unknown });
  assert.equal(f.failures.length, 0);
  assert.throws(() => { f.client.readRetryReason = 'send-failed'; }, TypeError);
});

test('an essential read retries one frame-load timeout within the same call', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture({ autoLoad: false, timeoutMs: 80 });
  t.after(() => f.client.close());
  const first = f.client.read();
  const outcome = first.then(value => ({ value }), error => ({ error }));
  const oldFrame = f.frame;
  t.mock.timers.tick(80);
  await new Promise(resolve => setImmediate(resolve));
  const retryFrame = f.frame;
  assert.notEqual(retryFrame, oldFrame);
  assert.equal(oldFrame.removed, true);
  assert.equal(f.client.readRetryReason, 'frame-load-timeout');
  assert.equal(f.failures.length, 0);

  retryFrame.fireLoad();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.at(-1).data.type, 'read');
  f.reply(unknown);
  assert.deepEqual(await outcome, { value: unknown });
  assert.equal(f.failures.length, 0);
});

test('iframe startup does not consume the broker response timeout', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture({ autoLoad: false, timeoutMs: 80 });
  t.after(() => f.client.close());
  const pending = f.client.read();
  const outcome = pending.then(value => ({ value }), error => ({ error }));
  const requestFrame = f.frame;

  t.mock.timers.tick(50);
  requestFrame.fireLoad();
  await new Promise(resolve => setImmediate(resolve));
  const request = f.sent.at(-1).data;

  t.mock.timers.tick(50);
  f.message({ ...envelope, id: request.id, ok: true, state: unknown }, {
    source: requestFrame.contentWindow,
  });
  const result = await outcome;
  assert.equal(result.error, undefined);
  assert.deepEqual(result.value, unknown);
});

test('an essential read retries one response timeout with a fresh frame', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture({ timeoutMs: 80 });
  t.after(() => f.client.close());
  const first = f.client.read();
  const outcome = first.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));
  const oldFrame = f.frame;
  assert.equal(f.sent.at(-1).data.type, 'read');
  t.mock.timers.tick(80);
  await new Promise(resolve => setImmediate(resolve));
  const retryFrame = f.frame;
  assert.notEqual(retryFrame, oldFrame);
  assert.equal(oldFrame.removed, true);
  assert.equal(f.sent.at(-1).data.type, 'read');
  f.reply(unknown);
  assert.deepEqual(await outcome, { value: unknown });
  assert.equal(f.client.readRetryReason, 'response-timeout');
  assert.equal(f.failures.length, 0);
});

test('an essential read surfaces the second genuine frame failure once', async (t) => {
  const f = fixture({ autoLoad: false });
  t.after(() => f.client.close());
  const read = f.client.read();
  const outcome = read.then(value => ({ value }), error => ({ error }));
  const firstFrame = f.frame;
  firstFrame.fireError();
  await new Promise(resolve => setImmediate(resolve));
  const secondFrame = f.frame;
  assert.notEqual(secondFrame, firstFrame);

  secondFrame.fireError();
  const result = await outcome;
  assert.equal(result.value, undefined);
  assert.match(result.error?.message, /tracking/i);
  assert.equal(result.error?.code, 'frame-load-failed');
  assert.equal(f.client.readRetryReason, 'frame-load-failed');
  assert.deepEqual(f.failures, [result.error]);
  assert.equal(f.frames.length, 2);
});

test('an essential read retries one unavailable broker response with a fresh frame', async (t) => {
  const f = fixture();
  t.after(() => f.client.close());
  const read = f.client.read();
  const outcome = read.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));
  const firstFrame = f.frame;
  const firstRequest = f.sent.at(-1).data;
  f.message({ ...envelope, id: firstRequest.id, ok: false, error: 'unavailable' });
  await new Promise(resolve => setImmediate(resolve));

  assert.notEqual(f.frame, firstFrame);
  assert.equal(firstFrame.removed, true);
  assert.equal(f.sent.at(-1).data.type, 'read');
  f.reply(unknown);
  assert.deepEqual(await outcome, { value: unknown });
  assert.equal(f.client.readRetryReason, 'broker-unavailable');
  assert.equal(f.failures.length, 0);
});

test('a transient read failure suspends accepted state until the retry confirms it', async (t) => {
  const f = fixture();
  t.after(() => f.client.close());
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  f.changes.length = 0;

  const read = f.client.read();
  const readOutcome = read.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));
  const firstRequest = f.sent.at(-1).data;
  f.message({ ...envelope, id: firstRequest.id, ok: false, error: 'unavailable' });
  await new Promise(resolve => setImmediate(resolve));

  assert.equal(f.client.state.choice, null);
  assert.equal(f.failures.length, 0);
  assert.equal(f.changes.length, 0);
  assert.equal(f.sent.at(-1).data.type, 'read');

  f.reply(accepted);
  assert.deepEqual(await readOutcome, { value: accepted });
  assert.deepEqual(f.client.state, accepted);
  assert.deepEqual(f.changes.at(-1), { state: accepted, confirmed: true });
  assert.equal(f.failures.length, 0);
});

test('an essential read retries one failed send with a fresh frame', async (t) => {
  const f = fixture({ sendFailures: 1 });
  t.after(() => f.client.close());
  const read = f.client.read();
  const outcome = read.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));

  assert.equal(f.frames.length, 2);
  assert.equal(f.frames[0].removed, true);
  assert.equal(f.sent.length, 1);
  assert.equal(f.sent[0].data.type, 'read');
  f.reply(unknown);
  assert.deepEqual(await outcome, { value: unknown });
  assert.equal(f.client.readRetryReason, 'send-failed');
  assert.equal(f.failures.length, 0);
});

test('closing the client rejects an essential read without retrying', async () => {
  const f = fixture({ autoLoad: false });
  const read = f.client.read();
  const outcome = read.then(value => ({ value }), error => ({ error }));
  f.client.close();
  const result = await outcome;
  assert.equal(result.value, undefined);
  assert.equal(result.error?.code, 'client-closed');
  assert.equal(f.frames.length, 1);
  assert.equal(f.client.readRetryReason, null);
  assert.equal(f.failures.length, 0);
});

test('invalid and prohibited broker responses fail without retrying', async (t) => {
  const cases = [
    {
      name: 'invalid response',
      response: id => ({ ...envelope, id, ok: true, state: { ...unknown, extra: true } }),
      code: 'invalid-response',
    },
    {
      name: 'not allowed',
      response: id => ({ ...envelope, id, ok: false, error: 'not-allowed' }),
      code: 'broker-not-allowed',
    },
    {
      name: 'invalid request',
      response: id => ({ ...envelope, id, ok: false, error: 'invalid-request' }),
      code: 'broker-invalid-request',
    },
  ];
  for (const item of cases) {
    await t.test(item.name, async () => {
      const f = fixture();
      try {
        const read = await nextRequest(() => f.client.read());
        const request = f.sent.at(-1).data;
        f.message(item.response(request.id));
        const result = await read.promise.then(value => ({ value }), error => ({ error }));
        assert.equal(result.value, undefined);
        assert.equal(result.error?.code, item.code);
        assert.equal(f.frames.length, 1);
        assert.equal(f.sent.length, 1);
        assert.equal(f.client.readRetryReason, null);
        assert.deepEqual(f.failures, [result.error]);
      } finally {
        f.client.close();
      }
    });
  }
});

test('an exhausted read retry resolves harmlessly without discarding a newer explicit choice', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture({ timeoutMs: 80 });
  t.after(() => f.client.close());
  const read = f.client.read();
  const readOutcome = read.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));
  const firstFrame = f.frame;

  t.mock.timers.tick(80);
  await new Promise(resolve => setImmediate(resolve));
  const choiceFrame = f.frame;
  assert.notEqual(choiceFrame, firstFrame);
  assert.equal(f.sent.at(-1).data.type, 'read');

  t.mock.timers.tick(40);
  const choice = f.client.choose('accepted');
  const choiceOutcome = choice.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));
  const choiceRequest = f.sent.at(-1).data;
  assert.equal(choiceRequest.type, 'choose');
  t.mock.timers.tick(40);
  await new Promise(resolve => setImmediate(resolve));

  assert.equal(choiceFrame.removed, undefined);
  assert.equal(f.frame, choiceFrame);
  const renewed = { ...accepted, generation: 'ffffffff-ffff-4fff-8fff-ffffffffffff', revision: 12 };
  f.message({ ...envelope, id: choiceRequest.id, ok: true, state: renewed });
  assert.deepEqual(await choiceOutcome, { value: renewed });
  assert.deepEqual(await readOutcome, { value: unknown });
  assert.equal(f.failures.length, 0);
  assert.deepEqual(f.client.state, renewed);
});

test('a retained-refusal read superseded by a newer accepted choice resolves without failure', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture({
    initialValues: [[localRefusalKey, 'rejected']],
    timeoutMs: 80,
  });
  t.after(() => f.client.close());
  const read = f.client.read();
  const readOutcome = read.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));
  const requestFrame = f.frame;
  assert.equal(f.sent.at(-1).data.type, 'read');

  t.mock.timers.tick(40);
  const choice = f.client.choose('accepted');
  await new Promise(resolve => setImmediate(resolve));
  const choiceRequest = f.sent.at(-1).data;
  assert.equal(choiceRequest.type, 'choose');
  const renewed = { ...accepted, generation: 'ffffffff-ffff-4fff-8fff-ffffffffffff', revision: 12 };
  f.message({ ...envelope, id: choiceRequest.id, ok: true, state: renewed });
  assert.deepEqual(await choice, renewed);

  t.mock.timers.tick(40);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(await readOutcome, { value: renewed });
  assert.equal(f.sent.filter(({ data }) => data.type === 'read').length, 1);
  assert.equal(f.frame, requestFrame);
  assert.equal(requestFrame.removed, undefined);
  assert.equal(f.failures.length, 0);
});

test('association timeout bounds frame readiness and prevents a late identifier request', async () => {
  const f = fixture({ timeoutMs: 100 });
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  f.setAutoLoad(false);
  const renewed = { ...accepted, generation: 'ffffffff-ffff-4fff-8fff-ffffffffffff', revision: 11 };
  f.message({ ...envelope, type: 'changed', state: renewed });

  let outcome = 'pending';
  const association = f.client.associate(renewed.generation, { timeoutMs: 5 });
  association.then(() => { outcome = 'resolved'; }, () => { outcome = 'rejected'; });
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(outcome, 'rejected');
  const lateFrame = f.frame;
  lateFrame.fireLoad();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.some(({ data }) => data.type === 'associate'), false);
  await assert.rejects(association, /tracking/i);
  assert.deepEqual(f.client.state, renewed);
  assert.equal(f.failures.length, 0);
  f.client.close();
});

test('an unavailable association falls back without suspending accepted consent', async () => {
  const f = fixture();
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;

  const association = await nextRequest(() => f.client.associate(generation));
  const associationRequest = f.sent.at(-1).data;
  assert.equal(associationRequest.type, 'associate');
  f.message({
    ...envelope,
    id: associationRequest.id,
    ok: false,
    error: 'unavailable',
  });

  await assert.rejects(association.promise, error => (
    error?.code === 'broker-unavailable' && /tracking/i.test(error.message)
  ));
  assert.deepEqual(f.client.state, accepted);
  assert.equal(f.failures.length, 0);
  assert.equal('deviceId' in f.client.state, false);
  assert.equal(f.values.has('mautic_device_id'), false);
  f.client.close();
});

test('device disclosure is returned once and is never persisted or retained on client state', async () => {
  const f = fixture();
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  const pending = await nextRequest(() => f.client.associate(generation));
  assert.equal(f.sent.at(-1).data.expectedGeneration, generation);
  f.reply(accepted, { deviceId: 'a'.repeat(23) });
  assert.equal((await pending.promise).deviceId, 'a'.repeat(23));
  assert.equal('deviceId' in f.client.state, false);
  assert.equal(f.values.has('mautic_device_id'), false);
  f.client.close();
});

test('an unavailable broker fails closed and never silently authorizes tracking', async () => {
  const f = fixture({ timeoutMs: 5 });
  await assert.rejects(f.client.read(), /tracking/i);
  assert.notEqual(f.client.state.choice, 'accepted');
  assert.equal(f.failures.length, 1);
  f.client.close();
});

test('an exhausted resumed read publishes only an unconfirmed error fallback', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture({ timeoutMs: 80 });
  t.after(() => f.client.close());
  const initial = await nextRequest(() => f.client.read());
  f.reply(rejected);
  await initial.promise;
  f.changes.length = 0;

  f.pageshow();
  await new Promise(resolve => setImmediate(resolve));
  t.mock.timers.tick(80);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.frames.length, 2);
  assert.equal(f.sent.at(-1).data.type, 'read');
  t.mock.timers.tick(80);
  await new Promise(resolve => setImmediate(resolve));

  assert.equal(f.failures.length, 1);
  assert.equal(f.client.readRetryReason, 'response-timeout');
  assert.equal(f.changes.at(-1)?.confirmed, false);
  assert.equal(f.changes.at(-1)?.state.choice, null);
  assert.equal(f.changes.some(change => change.confirmed === true), false);
});

test('the shared singleton retains failure and state listeners registered after the form creates it', async () => {
  const f = fixture({ factory: getSharedTrackingClient, timeoutMs: 5 });
  const failures = [];
  const states = [];
  assert.equal(getSharedTrackingClient({
    onFailure: error => failures.push(error),
    onStateChange: state => states.push(state),
  }), f.client);
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  assert.equal(states.at(-1)?.choice, 'accepted');
  await assert.rejects(f.client.read(), /tracking/i);
  assert.equal(failures.length, 1);
  f.client.close();
});

test('browser privacy signals override shared acceptance', async () => {
  for (const navigator of [{ doNotTrack: '1' }, { globalPrivacyControl: true }]) {
    assert.equal(trackingDeniedByBrowser({ navigator }), true);
    const f = fixture({ navigator });
    const pending = await nextRequest(() => f.client.read());
    assert.equal(f.sent[0].data.type, 'read');
    f.reply(rejected);
    assert.equal((await pending.promise).choice, 'rejected');
    await assert.rejects(f.client.choose('accepted'), error => (
      error?.code === 'unavailable' && /tracking/i.test(error.message)
    ));
    assert.equal(f.sent.length, 1, 'The essential bridge must persist revocation of earlier shared consent.');
    f.client.close();
  }
});

test('a choice carries the revision observed when the choice was made', async () => {
  const f = fixture();
  const initial = await nextRequest(() => f.client.read());
  f.reply(unknown);
  await initial.promise;
  const choice = await nextRequest(() => f.client.choose('accepted'));
  assert.equal(f.sent.at(-1).data.expectedRevision, 0);
  f.reply(accepted);
  assert.equal((await choice.promise).choice, 'accepted');
  f.client.close();
});

test('a same-origin outage refusal gates an already-open tab and is relayed to the shared bridge', async () => {
  const f = fixture();
  const initial = await nextRequest(() => f.client.read());
  f.reply(accepted);
  await initial.promise;
  f.changes.length = 0;
  f.storageEvent({ key: 'registrystack.tracking-local-refusal.v2', newValue: 'rejected' });
  assert.equal(f.client.state.choice, 'rejected');
  assert.deepEqual(f.changes[0], {
    state: { ...accepted, choice: 'rejected' },
    confirmed: false,
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.at(-1).data.type, 'choose');
  assert.equal(f.sent.at(-1).data.choice, 'rejected');
  f.reply(rejected);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.client.state.choice, 'rejected');
  assert.ok(f.changes.some(change => (
    change.confirmed === true && change.state.generation === rejected.generation
  )));
  f.client.close();
});

test('a retained local refusal reads the shared revision before replaying rejection', async (t) => {
  const f = fixture({ initialValues: [[localRefusalKey, 'rejected']] });
  t.after(() => f.client.close());
  const recovery = f.client.read();
  const outcome = recovery.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));

  const readRequest = f.sent[0].data;
  assert.equal(readRequest.type, 'read');
  f.message({ ...envelope, id: readRequest.id, ok: true, state: accepted });
  await new Promise(resolve => setImmediate(resolve));

  assert.equal(f.client.state.choice, 'rejected');
  await assert.rejects(f.client.pageview({
    page_url: 'https://docs.registrystack.org/', page_title: 'Docs', page_referrer: '',
  }), /tracking/i);
  assert.equal(f.sent.some(({ data }) => data.type === 'pageview'), false);
  const replay = f.sent[1].data;
  assert.equal(replay.type, 'choose');
  assert.equal(replay.choice, 'rejected');
  assert.equal(replay.expectedRevision, accepted.revision);
  f.message({ ...envelope, id: replay.id, ok: true, state: rejected });

  assert.deepEqual(await outcome, { value: rejected });
  assert.equal(f.values.has(localRefusalKey), false);
  assert.equal(f.failures.length, 0);
});

test('an explicit acceptance supersedes a delayed startup refusal replay', async (t) => {
  const f = fixture({ initialValues: [[localRefusalKey, 'rejected']] });
  t.after(() => f.client.close());
  const startup = f.client.read();
  const startupOutcome = startup.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));
  const readRequest = f.sent[0].data;
  assert.equal(readRequest.type, 'read');

  const explicit = await nextRequest(() => f.client.choose('accepted'));
  const acceptRequest = f.sent[1].data;
  assert.equal(acceptRequest.type, 'choose');
  assert.equal(acceptRequest.choice, 'accepted');
  f.message({ ...envelope, id: acceptRequest.id, ok: true, state: accepted });
  assert.deepEqual(await explicit.promise, accepted);

  f.message({ ...envelope, id: readRequest.id, ok: true, state: accepted });
  assert.deepEqual(await startupOutcome, { value: accepted });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(
    f.sent.filter(({ data }) => data.type === 'choose' && data.choice === 'rejected').length,
    0,
  );
  assert.equal(f.values.has(localRefusalKey), false);
  assert.equal(f.failures.length, 0);
});

test('an explicit acceptance reconciles a stale revision while a retained refusal masks startup', async (t) => {
  const f = fixture({ initialValues: [[localRefusalKey, 'rejected']] });
  t.after(() => f.client.close());
  const startup = f.client.read();
  const startupOutcome = startup.then(value => ({ value }), error => ({ error }));
  await new Promise(resolve => setImmediate(resolve));
  const startupRead = f.sent[0].data;

  const explicit = await nextRequest(() => f.client.choose('accepted'));
  const explicitOutcome = explicit.promise.then(value => ({ value }), error => ({ error }));
  const acceptRequest = f.sent[1].data;
  assert.equal(acceptRequest.expectedRevision, 0);
  f.message({ ...envelope, id: acceptRequest.id, ok: false, error: 'unavailable' });
  await new Promise(resolve => setImmediate(resolve));
  const recoveryRead = f.sent[2].data;
  assert.equal(recoveryRead.type, 'read');
  assert.equal(f.client.state.choice, 'rejected');
  f.message({ ...envelope, id: recoveryRead.id, ok: true, state: accepted });

  assert.deepEqual(await explicitOutcome, { value: accepted });
  f.message({ ...envelope, id: startupRead.id, ok: true, state: accepted });
  assert.deepEqual(await startupOutcome, { value: accepted });
  assert.equal(f.sent.filter(({ data }) => data.type === 'choose').length, 1);
  assert.equal(f.values.has(localRefusalKey), false);
  assert.equal(f.failures.length, 0);
});

test('a later refusal survives an older acceptance reconciliation and a failed rejection request', async (t) => {
  const f = fixture({ initialValues: [[localRefusalKey, 'rejected']] });
  t.after(() => f.client.close());
  const acceptance = await nextRequest(() => f.client.choose('accepted'));
  const acceptanceOutcome = acceptance.promise.then(value => ({ value }), error => ({ error }));
  f.message({ ...envelope, id: f.sent[0].data.id, ok: false, error: 'unavailable' });
  await new Promise(resolve => setImmediate(resolve));
  const recoveryRead = f.sent[1].data;
  assert.equal(recoveryRead.type, 'read');

  const refusal = await nextRequest(() => f.client.choose('rejected'));
  const refusalOutcome = refusal.promise.then(value => ({ value }), error => ({ error }));
  const rejectionRequest = f.sent[2].data;
  f.message({ ...envelope, id: recoveryRead.id, ok: true, state: accepted });
  assert.equal((await acceptanceOutcome).value?.choice, 'rejected');
  assert.equal(f.values.get(localRefusalKey), 'rejected');

  f.message({ ...envelope, id: rejectionRequest.id, ok: false, error: 'unavailable' });
  assert.match((await refusalOutcome).error?.message, /tracking/i);
  assert.equal(f.client.state.choice, 'rejected');
  assert.equal(f.values.get(localRefusalKey), 'rejected');
  await assert.rejects(f.client.pageview({
    page_url: 'https://docs.registrystack.org/', page_title: 'Docs', page_referrer: '',
  }), /tracking/i);
  assert.equal(f.sent.some(({ data }) => data.type === 'pageview'), false);
});

test('page data preserves external acquisition and removes identity, search, and internal handoff parameters', () => {
  const page = buildMauticPageview({
    canonicalUrl: 'https://docs.registrystack.org/tutorials/first-registry/?search=private#record',
    currentUrl: 'https://docs.registrystack.org/tutorials/first-registry/?utm_source=partner&utm_medium=referral&utm_campaign=pilot&email=private@example.org',
    pageTitle: '  Your first registry  ', referrer: 'https://partner.example/private?q=secret',
  });
  assert.deepEqual(page, {
    page_url: 'https://docs.registrystack.org/tutorials/first-registry/', page_title: 'Your first registry',
    page_referrer: 'https://partner.example', utm_source: 'partner', utm_medium: 'referral', utm_campaign: 'pilot',
  });
  const internal = buildMauticPageview({
    canonicalUrl: 'https://docs.registrystack.org/', pageTitle: 'Docs',
    currentUrl: 'https://docs.registrystack.org/?utm_source=registrystack&utm_medium=site&utm_campaign=cross_site&utm_content=home',
    referrer: 'https://registrystack.org/pricing/',
  });
  assert.deepEqual(internal, { page_url: 'https://docs.registrystack.org/', page_title: 'Docs', page_referrer: 'https://registrystack.org' });
});
