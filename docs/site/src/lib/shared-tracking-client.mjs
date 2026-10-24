import {
  SHARED_TRACKING_BRIDGE_URL,
  createTrackingRequest,
  parseTrackingChanged,
  parseTrackingResponse,
} from './tracking-protocol.mjs';

export { SHARED_TRACKING_BRIDGE_URL } from './tracking-protocol.mjs';

const EMPTY_STATE = Object.freeze({ choice: null, generation: null, expiresAt: null, revision: 0 });
const LOCAL_REFUSAL_KEY = 'registrystack.tracking-local-refusal.v2';
const UTM_KEYS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term'];
const UTM_VALUE = /^[a-z0-9][a-z0-9._-]{0,79}$/i;

/** @param {{navigator?: {doNotTrack?: string | null, globalPrivacyControl?: boolean}}} [environment] */
export function trackingDeniedByBrowser({ navigator: currentNavigator = globalThis.navigator } = {}) {
  const dnt = currentNavigator?.doNotTrack?.toLowerCase();
  return currentNavigator?.globalPrivacyControl === true || dnt === '1' || dnt === 'yes';
}

export function buildMauticPageview({ canonicalUrl, currentUrl, pageTitle, referrer }) {
  const current = new URL(currentUrl);
  const canonical = new URL(canonicalUrl, current);
  if (canonical.protocol !== 'https:' || canonical.username || canonical.password) {
    throw new Error('Tracking requires a public HTTPS canonical URL.');
  }
  let referringOrigin = '';
  try {
    const referring = new URL(referrer);
    if (['http:', 'https:'].includes(referring.protocol)) referringOrigin = referring.origin;
  } catch {
    // An absent or non-URL referrer contains no usable attribution.
  }
  const pageview = {
    page_url: `${canonical.origin}${canonical.pathname.slice(0, 1024)}`,
    page_title: pageTitle.replace(/\s+/g, ' ').trim().slice(0, 200),
    page_referrer: referringOrigin,
  };
  // Earlier released pages may still add this internal handoff tuple. It is
  // navigation context, never a new external acquisition source.
  const internalHandoff = current.searchParams.get('utm_campaign') === 'cross_site' &&
    ['registrystack', 'registry_docs'].includes(current.searchParams.get('utm_source'));
  if (!internalHandoff) {
    for (const key of UTM_KEYS) {
      const values = current.searchParams.getAll(key);
      if (values.length === 1 && UTM_VALUE.test(values[0])) pageview[key] = values[0];
    }
  }
  return pageview;
}

const FAILURE_CODES = new Set([
  'frame-load-failed', 'frame-load-timeout', 'response-timeout', 'frame-replaced',
  'client-closed', 'invalid-response', 'broker-unavailable', 'broker-not-allowed',
  'broker-invalid-request', 'send-failed', 'unavailable',
]);

export function trackingFailureReason(error) {
  return FAILURE_CODES.has(error?.code) ? error.code : 'unavailable';
}

function trackingError(code = 'unavailable') {
  return Object.assign(new Error('Shared tracking is unavailable. Tracking remains off.'), { code });
}

/**
 * A consent client contains no visitor identity. The bridge owns the native
 * tracker and returns an identifier only for one immediate form association.
 */
export function createSharedTrackingClient(options = {}) {
  const currentWindow = options.window ?? globalThis.window;
  const currentDocument = options.document ?? globalThis.document;
  const currentNavigator = options.navigator ?? currentWindow?.navigator ?? globalThis.navigator;
  const now = options.now ?? Date.now;
  const timeoutMs = options.timeoutMs ?? 6500;
  const bridge = new URL(options.bridgeUrl ?? SHARED_TRACKING_BRIDGE_URL);
  if (bridge.protocol !== 'https:' || bridge.username || bridge.password ||
      bridge.pathname !== '/tracking-bridge/' || bridge.search || bridge.hash) {
    throw new Error('Invalid shared tracking bridge URL.');
  }
  const pending = new Map();
  const subscribers = new Set();
  const failureSubscribers = new Set();
  if (options.onStateChange) subscribers.add(options.onStateChange);
  if (options.onFailure) failureSubscribers.add(options.onFailure);
  let state = { ...EMPTY_STATE };
  let frame;
  let frameReady;
  let frameReadyCancel;
  let closed = false;
  let suspended = false;
  let localRefusal = false;
  let choiceIntent = 0;
  let pendingRead;
  let readRetryReason = null;
  let expiryTimer;
  try {
    localRefusal = currentWindow?.localStorage?.getItem(LOCAL_REFUSAL_KEY) === 'rejected';
  } catch {
    suspended = true;
  }

  const denied = () => trackingDeniedByBrowser({ navigator: currentNavigator });
  const effectiveState = () => {
    if (denied() || localRefusal) return { ...state, choice: 'rejected' };
    if (suspended || (state.expiresAt !== null && state.expiresAt <= now())) {
      return { ...state, choice: null };
    }
    return { ...state };
  };
  const notify = (confirmed = false) => {
    const snapshot = effectiveState();
    for (const subscriber of subscribers) subscriber(snapshot, confirmed);
  };
  const fail = (code = 'unavailable') => {
    suspended = true;
    const error = trackingError(code);
    for (const subscriber of failureSubscribers) subscriber(error);
    return error;
  };
  const recoverableFailures = new WeakSet();
  const recoverableFailure = code => {
    const error = trackingError(code);
    recoverableFailures.add(error);
    return error;
  };
  const discardFrame = () => {
    if (frameReadyCancel) {
      const cancel = frameReadyCancel;
      frameReadyCancel = undefined;
      cancel();
      return;
    }
    frame?.remove();
    frame = undefined;
    frameReady = undefined;
  };
  const dropFailedFrame = failedFrame => {
    if (!failedFrame || frame !== failedFrame) return;
    discardFrame();
    for (const [id, item] of [...pending]) {
      if (item.frame !== failedFrame) continue;
      pending.delete(id);
      clearTimeout(item.timer);
      item.reject(trackingError('frame-replaced'));
    }
  };
  const replaceNativeRealm = next => {
    discardFrame();
    for (const [id, item] of [...pending]) {
      pending.delete(id);
      clearTimeout(item.timer);
      if (item.type === 'read' || (item.type === 'choose' &&
          next.choice === item.choice && next.revision > item.expectedRevision)) {
        item.resolve(effectiveState());
      } else {
        item.reject(trackingError('frame-replaced'));
      }
    }
  };
  const update = next => {
    if (next.revision < state.revision) return false;
    if (next.revision === state.revision && next.generation !== state.generation) return false;
    const previousGeneration = state.generation;
    state = { ...next };
    suspended = false;
    if (previousGeneration !== null && previousGeneration !== state.generation) {
      // Destroying the old frame also destroys native listeners and pending
      // callbacks before a later consent generation can create an identity.
      replaceNativeRealm(state);
    }
    clearTimeout(expiryTimer);
    if (state.expiresAt !== null) {
      expiryTimer = setTimeout(() => {
        notify();
        void client.read().catch(() => notify());
      }, Math.min(Math.max(1, state.expiresAt - now()), 2_147_483_647));
      expiryTimer.unref?.();
    }
    for (const [id, item] of pending) {
      if (item.type === 'associate' &&
          (state.choice !== 'accepted' || item.expectedGeneration !== state.generation)) {
        pending.delete(id);
        clearTimeout(item.timer);
        item.reject(trackingError());
      }
    }
    // Even an unchanged validated read confirms recovery from an earlier error.
    notify(true);
    return true;
  };

  const receive = event => {
    if (closed || event.origin !== bridge.origin || event.source !== frame?.contentWindow) return;
    const changed = parseTrackingChanged(event.data);
    if (changed) {
      update(changed.state);
      return;
    }
    const id = event.data?.id;
    const item = pending.get(id);
    if (!item) return;
    pending.delete(id);
    clearTimeout(item.timer);
    const response = parseTrackingResponse(event.data);
    if (!response || (response.deviceId && item.type !== 'associate')) {
      item.reject(item.failure('invalid-response'));
      return;
    }
    if (!response.ok) {
      item.reject(item.failure(`broker-${response.error}`, response.error === 'unavailable'));
      return;
    }
    const current = update(response.state);
    if (item.type === 'associate') {
      if (!current || effectiveState().choice !== 'accepted' ||
          response.state.generation !== item.expectedGeneration || !response.deviceId) {
        item.reject(trackingError());
        return;
      }
      item.resolve({ state: effectiveState(), deviceId: response.deviceId });
    } else {
      item.resolve(effectiveState());
    }
  };
  currentWindow?.addEventListener('message', receive);

  const ensureFrame = () => {
    if (closed || !currentWindow || !currentDocument) {
      return Promise.reject(trackingError(closed ? 'client-closed' : 'unavailable'));
    }
    if (frameReady) return frameReady;
    const candidate = currentDocument.createElement('iframe');
    candidate.src = bridge.href;
    candidate.hidden = true;
    candidate.title = 'Shared tracking preferences';
    candidate.referrerPolicy = 'no-referrer';
    candidate.setAttribute('aria-hidden', 'true');
    candidate.setAttribute('tabindex', '-1');
    let settled = false;
    let resolveReady;
    let rejectReady;
    const ready = new Promise((resolve, reject) => {
      resolveReady = resolve;
      rejectReady = reject;
    });
    frame = candidate;
    frameReady = ready;
    const reset = (code = 'frame-replaced') => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (frame === candidate) frame = undefined;
      if (frameReady === ready) frameReady = undefined;
      if (frameReadyCancel === reset) frameReadyCancel = undefined;
      candidate.remove();
      rejectReady(trackingError(code));
    };
    const timer = setTimeout(() => reset('frame-load-timeout'), timeoutMs);
    frameReadyCancel = reset;
    candidate.addEventListener('load', () => {
      if (settled) return;
      if (closed || frame !== candidate || frameReady !== ready) {
        reset();
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (frameReadyCancel === reset) frameReadyCancel = undefined;
      resolveReady(candidate);
    }, { once: true });
    candidate.addEventListener('error', () => reset('frame-load-failed'), { once: true });
    try {
      currentDocument.body.append(candidate);
    } catch {
      reset('frame-load-failed');
    }
    return ready;
  };
  const request = (type, payload = {}, requestOptions = {}) => {
    const message = createTrackingRequest(type, payload, () => currentWindow.crypto.randomUUID());
    return new Promise((resolve, reject) => {
      let settled = false;
      let requestFrame;
      const resolveOnce = value => {
        if (settled) return;
        settled = true;
        pending.delete(message.id);
        clearTimeout(timer);
        resolve(value);
      };
      const rejectOnce = error => {
        if (settled) return;
        settled = true;
        pending.delete(message.id);
        clearTimeout(timer);
        reject(error);
      };
      let timer;
      const failure = (code, recoverable = false) => {
        if (requestOptions.essentialRead) {
          return recoverable ? recoverableFailure(code) : trackingError(code);
        }
        return recoverable && requestOptions.recoverUnavailable
          ? recoverableFailure(code) : fail(code);
      };
      const startTimer = () => setTimeout(() => {
        pending.delete(message.id);
        if (!requestOptions.essentialRead && !requestOptions.recoverUnavailable) {
          dropFailedFrame(requestFrame);
        }
        rejectOnce(failure('response-timeout', true));
      }, requestOptions.timeoutMs ?? timeoutMs);
      // An association has one total budget so attribution never delays the
      // form. Other requests get a response budget after the bounded load.
      if (requestOptions.timeoutMs !== undefined) timer = startTimer();
      let readiness;
      try {
        readiness = ensureFrame();
      } catch {
        rejectOnce(failure('frame-load-failed', true));
        return;
      }
      // Generation replacement must also settle operations awaiting readiness.
      const item = {
        resolve: resolveOnce,
        reject: rejectOnce,
        timer,
        type,
        frame,
        recoverUnavailable: requestOptions.recoverUnavailable === true,
        failure,
        ...payload,
      };
      pending.set(message.id, item);
      readiness.then(readyFrame => {
        if (settled) return;
        if (closed || readyFrame !== frame) {
          rejectOnce(trackingError(closed ? 'client-closed' : 'frame-replaced'));
          return;
        }
        requestFrame = readyFrame;
        if (requestOptions.timeoutMs === undefined) timer = startTimer();
        item.frame = readyFrame;
        item.timer = timer;
        try {
          readyFrame.contentWindow.postMessage(message, bridge.origin);
        } catch {
          pending.delete(message.id);
          if (!requestOptions.essentialRead) dropFailedFrame(readyFrame);
          rejectOnce(failure('send-failed', true));
        }
      }, error => {
        const code = trackingFailureReason(error);
        const recoverable = ['frame-load-failed', 'frame-load-timeout'].includes(code);
        if (!settled) rejectOnce(failure(code, recoverable));
      });
    });
  };

  const resume = () => {
    if (!closed && currentDocument.visibilityState !== 'hidden') {
      void client.read().catch(() => notify());
    }
  };
  currentWindow?.addEventListener('pageshow', resume);
  currentDocument?.addEventListener('visibilitychange', resume);
  const receiveLocalRefusal = event => {
    if (event.key !== LOCAL_REFUSAL_KEY || event.newValue !== 'rejected' || closed) return;
    localRefusal = true;
    notify();
    // Another tab may have a working bridge even when the tab where refusal
    // was chosen could not load it. Relay the refusal through that connection.
    if (frame) void client.choose('rejected').catch(() => notify());
  };
  currentWindow?.addEventListener('storage', receiveLocalRefusal);

  const client = {
    get state() { return effectiveState(); },
    get readRetryReason() { return readRetryReason; },
    subscribe(listener) { subscribers.add(listener); return () => subscribers.delete(listener); },
    subscribeFailure(listener) { failureSubscribers.add(listener); return () => failureSubscribers.delete(listener); },
    read() {
      if (pendingRead) return pendingRead;
      const intent = choiceIntent;
      readRetryReason = null;
      const read = async () => {
        for (let attempt = 0; attempt < 2; attempt += 1) {
          const reading = request('read', {}, { essentialRead: true });
          const readingFrame = frame;
          try {
            await reading;
            break;
          } catch (error) {
            if (closed) throw error;
            // An older read must not interrupt or reopen errors over a newer
            // explicit choice, including one using this same frame.
            if (choiceIntent !== intent) return effectiveState();
            suspended = true;
            if (recoverableFailures.has(error)) {
              dropFailedFrame(readingFrame);
              if (attempt === 0) {
                readRetryReason = trackingFailureReason(error);
                continue;
              }
            }
            throw fail(trackingFailureReason(error));
          }
        }
        // Keep a retained refusal active until the shared revision is known.
        // A newer explicit choice always takes precedence over reconciliation.
        if (localRefusal && choiceIntent === intent) return client.choose('rejected');
        return effectiveState();
      };
      pendingRead = read().finally(() => { pendingRead = undefined; });
      return pendingRead;
    },
    async choose(choice) {
      if (!['accepted', 'rejected'].includes(choice) || (choice === 'accepted' && denied())) {
        throw trackingError();
      }
      const intent = ++choiceIntent;
      const expectedRevision = state.revision;
      let choiceFrame;
      if (choice === 'rejected') {
        localRefusal = true;
        try { currentWindow?.localStorage?.setItem(LOCAL_REFUSAL_KEY, 'rejected'); } catch { suspended = true; }
        notify();
      }
      try {
        const choosing = request(
          'choose',
          { choice, expectedRevision },
          { recoverUnavailable: choice === 'accepted' },
        );
        choiceFrame = frame;
        await choosing;
      } catch (error) {
        if (choice === 'rejected' && choiceIntent === intent && frame === choiceFrame) discardFrame();
        if (choice !== 'accepted' || !recoverableFailures.has(error)) throw error;
        await request('read');
        // A retained refusal masks the shared state until this explicit
        // acceptance finishes reconciling. Privacy signals still take priority.
        if (state.choice !== 'accepted' || denied() ||
            (state.expiresAt !== null && state.expiresAt <= now())) throw fail();
      }
      // A refusal that could not reach the bridge remains local and visible as
      // an error, rather than allowing an older shared acceptance to return.
      if (choiceIntent !== intent) return effectiveState();
      localRefusal = false;
      try { currentWindow?.localStorage?.removeItem(LOCAL_REFUSAL_KEY); } catch { suspended = true; }
      notify();
      return effectiveState();
    },
    async pageview(pageview) {
      if (effectiveState().choice !== 'accepted') throw trackingError();
      return request('pageview', { expectedGeneration: state.generation, pageview });
    },
    async associate(expectedGeneration, requestOptions = {}) {
      if (effectiveState().choice !== 'accepted' || state.generation !== expectedGeneration) throw trackingError();
      return request('associate', { expectedGeneration }, { ...requestOptions, recoverUnavailable: true });
    },
    close() {
      closed = true;
      clearTimeout(expiryTimer);
      for (const item of pending.values()) { clearTimeout(item.timer); item.reject(trackingError('client-closed')); }
      pending.clear();
      currentWindow?.removeEventListener('message', receive);
      currentWindow?.removeEventListener('pageshow', resume);
      currentDocument?.removeEventListener('visibilitychange', resume);
      currentWindow?.removeEventListener('storage', receiveLocalRefusal);
      discardFrame();
    },
  };
  return client;
}

let sharedClient;
export function getSharedTrackingClient(options = {}) {
  if (!sharedClient) sharedClient = createSharedTrackingClient(options);
  else {
    if (options.onStateChange) sharedClient.subscribe(options.onStateChange);
    if (options.onFailure) sharedClient.subscribeFailure(options.onFailure);
  }
  return sharedClient;
}
