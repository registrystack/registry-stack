'use strict';

const crypto = require('node:crypto');

// Mirrors `registry-evidence-verifier`'s own wire constants
// (`EVIDENCE_JWS_TYP`, `EVIDENCE_JWS_CTY`, `EVIDENCE_SCHEMA_V1`). Neither that
// crate nor `registry-evidence-client` exposes them outside `cfg(test)`, so
// this file states them again rather than reaching into a private module.
const EVIDENCE_JWS_TYP = 'evidence+jws';
const EVIDENCE_JWS_CTY = 'application/evidence+json';
const EVIDENCE_SCHEMA_V1 = 'registry.assertion-evidence/v1';
const EVIDENCE_JWS_MEDIA_TYPE = 'application/jose+json';

/**
 * A fresh P-256 signing key for one stub deployment.
 *
 * Neither crate that can sign a real Evidence response
 * (`registry-evidence-verifier`, `registry-evidence-client`) exposes its test
 * signer outside `cfg(test)`, so a JS test that needs a live, nonce-matched
 * response signs its own with Node's built-in `crypto`, the same way
 * `tests/golden_fixture.rs` signs its committed fixture with
 * `registry-platform-crypto` on the Rust side. This key is generated fresh
 * per test and never written anywhere.
 */
function generateSigningKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const jwk = publicKey.export({ format: 'jwk' });
  const thumbprintInput = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const kid = crypto.createHash('sha256').update(thumbprintInput).digest('base64url');
  return {
    kid,
    privateKey,
    jwks: { keys: [{ ...jwk, kid, alg: 'ES256' }] },
  };
}

/** Sign an Evidence payload as a flattened JWS, matching the wire format `verify_flattened_jws` expects. */
function signEvidence(evidence, signingKey) {
  const protectedHeader = {
    alg: 'ES256',
    kid: signingKey.kid,
    typ: EVIDENCE_JWS_TYP,
    cty: EVIDENCE_JWS_CTY,
  };
  const protectedSegment = Buffer.from(JSON.stringify(protectedHeader)).toString('base64url');
  const payloadSegment = Buffer.from(JSON.stringify(evidence)).toString('base64url');
  const signingInput = `${protectedSegment}.${payloadSegment}`;
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key: signingKey.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return {
    protected: protectedSegment,
    payload: payloadSegment,
    signature: signature.toString('base64url'),
  };
}

/**
 * A request specification whose every policy expectation (but the nonce, and
 * the subject binding, which `subjectExpectations: "acceptFirstUse"` leaves
 * to the response) is fixed and known ahead of the request, so a stub
 * handler can build a matching, currently valid `Evidence` answer once it
 * reads the nonce off the prepared request.
 */
function requestSpec() {
  return {
    requirement: 'urn:example:node-test:requirement:status:v1',
    purpose: 'example-decision',
    audience: 'urn:example:node-test:audience',
    evidenceType: 'urn:example:node-test:evidence-type:status:v1',
    issuedBy: 'urn:example:node-test:issuer',
    providedBy: 'urn:example:node-test:provider',
    configurationRevision: `sha256:${'0'.repeat(64)}`,
    expectedAssuranceProfile: 'local',
    subjects: [
      {
        role: 'subject',
        selectorProfile: 'record-lookup-v1',
        selectorValues: { record_reference: 'R-001' },
      },
    ],
    expectedOutputs: [{ concept: 'urn:example:node-test:concept:status-holds', form: 'boolean' }],
    maximumAssertionLifetimeSeconds: 300,
    clockSkewSeconds: 60,
    subjectExpectations: 'acceptFirstUse',
  };
}

/** The subject binding `evidenceFor` issues, for a test to assert first-use
 * acceptance pinned exactly this. The Evidence payload contract requires a
 * subject binding to match `urn:evidence:subject:v<generation>_<43 base64url
 * characters>`, the same shape `prepare()` uses for a request nonce, so this
 * is a fixed, schema-valid value rather than an arbitrary label. */
const SUBJECT_BINDING = `urn:evidence:subject:v1_${crypto.randomBytes(32).toString('base64url')}`;

/** An `Evidence` payload matching every expectation `requestSpec()` closes, for the given live request nonce. */
function evidenceFor(spec, nonce) {
  const issuedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const validUntil = new Date(Date.now() + 60_000).toISOString().replace(/\.\d+Z$/, 'Z');
  return {
    schema: EVIDENCE_SCHEMA_V1,
    assuranceProfile: spec.expectedAssuranceProfile,
    requestNonce: nonce,
    id: 'urn:example:node-test:evidence:1',
    type: 'Evidence',
    supportsRequirement: spec.requirement,
    isConformantTo: spec.evidenceType,
    issuedBy: spec.issuedBy,
    providedBy: spec.providedBy,
    issuedAt,
    observedAt: issuedAt,
    validUntil,
    purpose: spec.purpose,
    audience: spec.audience,
    configurationRevision: spec.configurationRevision,
    subjects: [{ role: 'subject', binding: SUBJECT_BINDING }],
    supportedValues: [{ providesValueFor: 'urn:example:node-test:concept:status-holds', value: true }],
  };
}

module.exports = {
  generateSigningKey,
  signEvidence,
  requestSpec,
  evidenceFor,
  SUBJECT_BINDING,
  EVIDENCE_JWS_MEDIA_TYPE,
};
