'use strict';

// The package's actual entry point. `index.js`/`index.d.ts` are regenerated
// by `napi build --platform` on every build (see `package.json`'s `build`
// and `build:debug` scripts) and stay untouched here; this file sits on top
// of them so a hand edit never gets silently overwritten by the next build.

const native = require('./index');

/**
 * The stable eight-kind error envelope every mapped Evidence Node failure
 * carries (see `crates/registry-evidence-client-node/src/convert.rs`'s
 * `map_client_error`), as properties on a thrown `Error` rather than as JSON
 * text a caller has to `JSON.parse` out of `.message`.
 *
 * `kind` is always present; `status`, `code`, `traceId`,
 * `retryAfterSeconds`, `transportKind`, and `tokenKind` are present only when
 * the underlying failure carries them.
 */
class EvidenceClientError extends Error {
  constructor(envelope) {
    super(envelope.message);
    this.name = 'EvidenceClientError';
    this.kind = envelope.kind;
    for (const field of [
      'status',
      'code',
      'traceId',
      'retryAfterSeconds',
      'transportKind',
      'tokenKind',
    ]) {
      if (envelope[field] !== undefined) {
        this[field] = envelope[field];
      }
    }
  }
}

/**
 * The native layer throws every mapped Evidence failure as an ordinary
 * `Error` whose `message` is the JSON envelope described above
 * (`src/lib.rs`'s `to_napi_error`). Every other native failure (a
 * serialization defect, a caught panic, napi's own argument-type checking)
 * throws a plain, non-JSON reason instead, and is left exactly as thrown:
 * only a recognized envelope becomes an `EvidenceClientError`, so a caller
 * cannot mistake "some other native failure" for one of the eight stable
 * kinds.
 */
function normalize(error) {
  if (!(error instanceof Error) || typeof error.message !== 'string') {
    return error;
  }
  let envelope;
  try {
    envelope = JSON.parse(error.message);
  } catch {
    return error;
  }
  if (envelope === null || typeof envelope !== 'object' || typeof envelope.kind !== 'string') {
    return error;
  }
  return new EvidenceClientError(envelope);
}

function wrapSync(prototype, name) {
  const original = prototype[name];
  prototype[name] = function (...args) {
    try {
      return original.apply(this, args);
    } catch (error) {
      throw normalize(error);
    }
  };
}

function wrapAsync(prototype, name) {
  const original = prototype[name];
  prototype[name] = function (...args) {
    return original.apply(this, args).catch((error) => {
      throw normalize(error);
    });
  };
}

// The public Node API exposes the opaque native result directly, with the
// encoding tag next to its artifact, so the one-call tutorial can read
// `result.value`. Its getters stay native: notably, only reading an ambiguous
// `value` fails.
function wrapProgressiveRequest(prototype) {
  const original = prototype.request;
  prototype.request = function (...args) {
    try {
      return original.apply(this, args).then(
        (result) => result,
        (error) => {
          throw normalize(error);
        },
      );
    } catch (error) {
      throw normalize(error);
    }
  };
}

function wrapGetter(prototype, name) {
  const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
  const originalGet = descriptor.get;
  Object.defineProperty(prototype, name, {
    ...descriptor,
    get() {
      try {
        return originalGet.call(this);
      } catch (error) {
        throw normalize(error);
      }
    },
  });
}

// Patch the native prototypes directly, in place, rather than wrapping
// instances in a delegating object or a `Proxy`: only the throw/reject path
// is touched here, so every argument and return value crossing these methods
// keeps its exact native identity. This matters concretely for `send`'s
// single-send guard: it depends on the `PreparedEvidenceRequest` object
// handed back to a later `send`/`verify` call being the very same native
// object `prepare` returned, not a copy or a wrapper around it (see
// `__test__/happy-path.test.js`'s single-send-guard test, which asserts this
// identity directly).
wrapSync(native.EvidenceClient.prototype, 'prepare');
wrapSync(native.EvidenceClient.prototype, 'prepareBatch');
wrapAsync(native.EvidenceClient.prototype, 'discover');
wrapAsync(native.EvidenceClient.prototype, 'fetchJwks');
wrapAsync(native.EvidenceClient.prototype, 'send');
wrapAsync(native.EvidenceClient.prototype, 'sendBatch');
wrapSync(native.EvidenceClient.prototype, 'verify');
wrapSync(native.EvidenceClient.prototype, 'verifyBatch');
wrapAsync(native.EvidenceClient.prototype, 'requestAndVerify');
wrapAsync(native.EvidenceClient.prototype, 'requestAndVerifyBatch');
wrapProgressiveRequest(native.EvidenceClient.prototype);
wrapAsync(native.EvidenceClient.prototype, 'refreshMetadata');
wrapSync(native.EvidenceClient.prototype, 'verifyAsOf');
wrapSync(native.EvidenceClient.prototype, 'verifyBatchAsOf');

wrapGetter(native.PreparedEvidenceRequest.prototype, 'requestNonce');
wrapGetter(native.PreparedEvidenceRequest.prototype, 'policyDocument');
wrapGetter(native.PreparedEvidenceRequest.prototype, 'subjectExpectations');

wrapGetter(native.PreparedEvidenceRequestBatch.prototype, 'requestNonces');
wrapGetter(native.PreparedEvidenceRequestBatch.prototype, 'policyDocuments');
wrapGetter(native.PreparedEvidenceRequestBatch.prototype, 'subjectExpectations');
wrapGetter(native.PreparedEvidenceRequestBatch.prototype, 'count');

wrapGetter(native.RawEvidenceResponse.prototype, 'body');
wrapGetter(native.RawEvidenceResponse.prototype, 'traceId');

wrapGetter(native.RawEvidenceRequestBatchResponse.prototype, 'body');
wrapGetter(native.RawEvidenceRequestBatchResponse.prototype, 'traceId');

for (const name of [
  'responseFormat',
  'evidence',
  'traceId',
  'assertion',
  'credential',
  'values',
  'value',
  'subjectContinuity',
]) {
  wrapGetter(native.AudienceScopedResult.prototype, name);
}

wrapSync(native.SdJwtVcBatchResponse.prototype, 'credentialForHolderKey');
wrapGetter(native.SdJwtVcBatchResponse.prototype, 'credentials');
wrapGetter(native.SdJwtVcBatchResponse.prototype, 'count');

/**
 * The two classes this module wraps rather than patches in place: a
 * constructor's own throw happens before any instance exists, so there is no
 * prototype method to patch ahead of time the way there is for every other
 * method above.
 *
 * Subclassing is safe here in a way it would not be for
 * `PreparedEvidenceRequest`: nothing hands an `EvidenceClient` or an
 * `SdJwtVcBatchResponse` back into a later native call for an identity check
 * to depend on, and every prototype member above is already patched on the
 * native prototype, which these subclasses inherit unchanged, so
 * `instanceof native.EvidenceClient` still holds for their instances.
 */
class EvidenceClient extends native.EvidenceClient {
  constructor(config) {
    try {
      super(config);
    } catch (error) {
      throw normalize(error);
    }
  }

  /**
   * Construct the progressive client from an application-owned profile.
   *
   * The native implementation reads the profile, resolves any secret
   * reference, discovers metadata, and owns every trust decision. Keeping
   * that work below this wrapper is intentional: JavaScript never receives a
   * key set or a subject-continuity store to accidentally retain.
   */
  static fromProfile(path, privateKeyJwk) {
    try {
      const client = privateKeyJwk === undefined
        ? native.EvidenceClient.fromProfile(path)
        : native.EvidenceClient.fromProfile(path, privateKeyJwk);
      Object.setPrototypeOf(client, this.prototype);
      return client;
    } catch (error) {
      throw normalize(error);
    }
  }
}

class SdJwtVcBatchResponse extends native.SdJwtVcBatchResponse {
  constructor(body) {
    try {
      super(body);
    } catch (error) {
      throw normalize(error);
    }
  }
}

module.exports = {
  EvidenceClient,
  EvidenceClientError,
  PreparedEvidenceRequest: native.PreparedEvidenceRequest,
  PreparedEvidenceRequestBatch: native.PreparedEvidenceRequestBatch,
  RawEvidenceResponse: native.RawEvidenceResponse,
  RawEvidenceRequestBatchResponse: native.RawEvidenceRequestBatchResponse,
  AudienceScopedResult: native.AudienceScopedResult,
  SdJwtVcBatchResponse,
};
