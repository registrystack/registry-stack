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
  const { factory = createSharedTrackingClient, initialValues = [], ...clientOptions } = options;
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
        contentWindow: { postMessage: (data, origin) => sent.push({ data, origin }) },
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
    onStateChange: state => changes.push(state), ...clientOptions,
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

test('a failed initial bridge can be retried and a late old load cannot win', async () => {
  const f = fixture({ autoLoad: false });
  const first = f.client.read();
  const oldFrame = f.frame;
  oldFrame.fireError();
  await assert.rejects(first, /tracking/i);
  assert.equal(oldFrame.removed, true);

  const retry = f.client.read();
  const currentFrame = f.frame;
  assert.notEqual(currentFrame, oldFrame);
  oldFrame.fireLoad();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.length, 0);
  currentFrame.fireLoad();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.at(-1).data.type, 'read');
  f.reply(unknown);
  assert.deepEqual(await retry, unknown);
  f.client.close();
});

test('a timed-out initial bridge is removed and the next request can recover', async () => {
  const f = fixture({ autoLoad: false, timeoutMs: 5 });
  const first = f.client.read();
  const oldFrame = f.frame;
  await assert.rejects(first, /tracking/i);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(oldFrame.removed, true);

  f.setAutoLoad(true);
  const retry = await nextRequest(() => f.client.read());
  assert.notEqual(f.frame, oldFrame);
  assert.equal(f.sent.at(-1).data.type, 'read');
  f.reply(unknown);
  assert.deepEqual(await retry.promise, unknown);
  assert.equal(f.failures.length, 1);
  f.client.close();
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

test('an unresponsive loaded bridge is discarded so the next request can recover', async () => {
  const f = fixture({ timeoutMs: 5 });
  const first = await nextRequest(() => f.client.read());
  const oldFrame = f.frame;
  assert.equal(f.sent.at(-1).data.type, 'read');
  await assert.rejects(first.promise, /tracking/i);
  assert.equal(oldFrame.removed, true);

  const retry = await nextRequest(() => f.client.read());
  assert.notEqual(f.frame, oldFrame);
  assert.equal(f.sent.at(-1).data.type, 'read');
  f.reply(unknown);
  assert.deepEqual(await retry.promise, unknown);
  assert.equal(f.failures.length, 1);
  f.client.close();
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

  await assert.rejects(association.promise, /tracking/i);
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
    await assert.rejects(f.client.choose('accepted'), /tracking/i);
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
  f.storageEvent({ key: 'registrystack.tracking-local-refusal.v2', newValue: 'rejected' });
  assert.equal(f.client.state.choice, 'rejected');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sent.at(-1).data.type, 'choose');
  assert.equal(f.sent.at(-1).data.choice, 'rejected');
  f.reply(rejected);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.client.state.choice, 'rejected');
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
