#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

const crypto = require('crypto');

function usage() {
  console.error(
    'usage: generate-holder-proof.js --audience <service-id> --evaluation-id <id> --credential-profile <profile> --disclosure <mode> --claims-json <json-array>',
  );
}

function arg(name) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1 || index + 1 >= process.argv.length) {
    usage();
    process.exit(2);
  }
  return process.argv[index + 1];
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signJwt(header, payload, privateKey) {
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(
    JSON.stringify(payload),
  )}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

const claims = JSON.parse(arg('claims-json'));
if (!Array.isArray(claims) || claims.some((claim) => typeof claim !== 'string')) {
  console.error('--claims-json must be a JSON array of strings');
  process.exit(2);
}

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const publicJwk = publicKey.export({ format: 'jwk' });
const holderId = `did:jwk:${base64url(JSON.stringify(publicJwk))}`;
const now = Math.floor(Date.now() / 1000);
const disclosure = arg('disclosure');
const disclosureHash = crypto
  .createHash('sha256')
  .update(disclosure)
  .digest('base64url');

const proof = signJwt(
  {
    alg: 'EdDSA',
    typ: 'kb+jwt',
    kid: holderId,
  },
  {
    sub: holderId,
    aud: arg('audience'),
    iat: now,
    exp: now + 60,
    jti: `dhis2-holder-proof-${crypto.randomUUID()}`,
    evaluation_id: arg('evaluation-id'),
    credential_profile: arg('credential-profile'),
    disclosure: disclosureHash,
    claims,
  },
  privateKey,
);

process.stdout.write(
  `${JSON.stringify(
    {
      holder_id: holderId,
      holder: {
        binding: 'did',
        id: holderId,
        proof,
      },
    },
    null,
    2,
  )}\n`,
);
