export const TRACKING_PROTOCOL = 'registrystack-tracking';
export const TRACKING_PROTOCOL_VERSION = 2;
export const TRACKING_ALLOWED_ORIGINS = Object.freeze([
  'https://registrystack.org',
  'https://docs.registrystack.org',
]);
export const TRACKING_ASSOCIATION_ORIGIN = 'https://registrystack.org';
export const SHARED_TRACKING_BRIDGE_URL = 'https://registrystack.org/tracking-bridge/';
export const TRACKING_CONSENT_STORAGE_KEY = 'registrystack.shared-marketing-tracking.v2';
export const TRACKING_IDENTITY_STORAGE_KEY = 'registrystack.shared-mautic-identity.v2';
export const TRACKING_LOCAL_REFUSAL_STORAGE_KEY = 'registrystack.tracking-local-refusal.v2';
export const TRACKING_CONSENT_LIFETIME_MS = 180 * 24 * 60 * 60 * 1000;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DEVICE_ID_PATTERN = /^[a-z0-9]{23}$/;
const UTM_VALUE_PATTERN = /^[a-z0-9][a-z0-9._-]{0,79}$/i;
const UTM_KEYS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term'];
const ERROR_CODES = new Set(['invalid-request', 'not-allowed', 'unavailable']);

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isUuid(value) {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

function isRevision(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isTrackingState(value) {
  if (!exactKeys(value, ['choice', 'generation', 'expiresAt', 'revision'])) return false;
  if (!isRevision(value.revision)) return false;
  if (value.choice === null) {
    return value.expiresAt === null && (
      (value.generation === null && value.revision === 0) ||
      (isUuid(value.generation) && value.revision > 0)
    );
  }
  return (
    (value.choice === 'accepted' || value.choice === 'rejected') &&
    isUuid(value.generation) &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > value.revision &&
    value.revision > 0
  );
}

function isCanonicalPageUrl(value) {
  if (typeof value !== 'string' || value.length > 1400) return false;
  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      url.pathname.length <= 1024
    );
  } catch (_error) {
    return false;
  }
}

function isReferrerOrigin(value) {
  if (value === '') return true;
  if (typeof value !== 'string' || value.length > 300) return false;
  try {
    const url = new URL(value);
    return (
      (url.protocol === 'https:' || url.protocol === 'http:') &&
      !url.username &&
      !url.password &&
      value === url.origin
    );
  } catch (_error) {
    return false;
  }
}

function parsePageview(value) {
  if (!isRecord(value)) return null;
  const optionalKeys = UTM_KEYS.filter((key) => Object.hasOwn(value, key));
  if (!exactKeys(value, ['page_url', 'page_title', 'page_referrer', ...optionalKeys])) return null;
  if (!isCanonicalPageUrl(value.page_url)) return null;
  if (
    typeof value.page_title !== 'string' ||
    value.page_title.length < 1 ||
    value.page_title.length > 200 ||
    value.page_title !== value.page_title.replace(/\s+/g, ' ').trim()
  ) return null;
  if (!isReferrerOrigin(value.page_referrer)) return null;
  if (optionalKeys.some((key) => typeof value[key] !== 'string' || !UTM_VALUE_PATTERN.test(value[key]))) {
    return null;
  }
  return { ...value };
}

function validEnvelope(value) {
  return (
    isRecord(value) &&
    value.protocol === TRACKING_PROTOCOL &&
    value.version === TRACKING_PROTOCOL_VERSION &&
    isUuid(value.id)
  );
}

export function trackingRequestId(value) {
  return validEnvelope(value) ? value.id : null;
}

export function parseTrackingRequest(value) {
  if (!validEnvelope(value) || typeof value.type !== 'string') return null;
  const base = ['protocol', 'version', 'id', 'type'];
  if (value.type === 'read' && exactKeys(value, base)) return { ...value };
  if (
    value.type === 'choose' &&
    exactKeys(value, [...base, 'choice', 'expectedRevision']) &&
    (value.choice === 'accepted' || value.choice === 'rejected') &&
    isRevision(value.expectedRevision)
  ) return { ...value };
  if (value.type === 'associate' && exactKeys(value, [...base, 'expectedGeneration']) && isUuid(value.expectedGeneration)) {
    return { ...value };
  }
  if (
    value.type === 'pageview' &&
    exactKeys(value, [...base, 'expectedGeneration', 'pageview']) &&
    isUuid(value.expectedGeneration)
  ) {
    const pageview = parsePageview(value.pageview);
    return pageview ? { ...value, pageview } : null;
  }
  return null;
}

export function createTrackingRequest(type, payload = {}, randomUUID = () => globalThis.crypto.randomUUID()) {
  const request = {
    protocol: TRACKING_PROTOCOL,
    version: TRACKING_PROTOCOL_VERSION,
    id: randomUUID(),
    type,
    ...payload,
  };
  const parsed = parseTrackingRequest(request);
  if (!parsed) throw new TypeError('Invalid tracking request.');
  return parsed;
}

export function parseTrackingResponse(value) {
  if (!validEnvelope(value) || typeof value.ok !== 'boolean') return null;
  if (value.ok === false) {
    if (!exactKeys(value, ['protocol', 'version', 'id', 'ok', 'error']) || !ERROR_CODES.has(value.error)) {
      return null;
    }
    return { ...value };
  }

  const hasDevice = Object.hasOwn(value, 'deviceId');
  if (!exactKeys(value, ['protocol', 'version', 'id', 'ok', 'state', ...(hasDevice ? ['deviceId'] : [])])) {
    return null;
  }
  if (!isTrackingState(value.state)) return null;
  if (hasDevice && (typeof value.deviceId !== 'string' || !DEVICE_ID_PATTERN.test(value.deviceId))) return null;
  return { ...value, state: { ...value.state } };
}

export function parseTrackingChanged(value) {
  if (!exactKeys(value, ['protocol', 'version', 'type', 'state'])) return null;
  if (
    value.protocol !== TRACKING_PROTOCOL ||
    value.version !== TRACKING_PROTOCOL_VERSION ||
    value.type !== 'changed' ||
    !isTrackingState(value.state)
  ) return null;
  return { ...value, state: { ...value.state } };
}
