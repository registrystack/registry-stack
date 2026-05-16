#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Operator-facing verifier for Registry Relay VC-JWT compact credentials.
// It intentionally uses only public artifacts: the compact JWS, a DID
// Document containing publicKeyJwk, and an optional credentialSubject schema.

import { createPublicKey, verify as verifySignature } from "node:crypto";
import { readFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import { fileURLToPath } from "node:url";

const SUPPORTED_ALGS = new Set(["EdDSA"]);
const ANNOTATION_SCHEMA_KEYWORDS = new Set([
  "$comment",
  "$defs",
  "$id",
  "$schema",
  "description",
  "examples",
  "title",
]);
const SUPPORTED_SCHEMA_KEYWORDS = new Set([
  ...ANNOTATION_SCHEMA_KEYWORDS,
  "additionalProperties",
  "const",
  "enum",
  "format",
  "items",
  "maxLength",
  "maximum",
  "minItems",
  "minLength",
  "minimum",
  "oneOf",
  "properties",
  "required",
  "type",
]);

class VerificationError extends Error {}

function usage() {
  return `Usage:
  node scripts/verify_vc_jwt.mjs \\
    --jwt-file vc.jwt \\
    --did-document did.json \\
    --issuer did:web:data.example.gov \\
    --claim-type VerifyResult \\
    --schema-id https://data.example.gov/schemas/verify-result/v1.json \\
    --schema verify-result.schema.json

Inputs may be local paths, file:// URLs, or http(s) URLs.

Options:
  --jwt <compact>          Compact VC-JWT string.
  --jwt-file <path>        File containing the compact VC-JWT.
  --did-document <source>  DID Document JSON. If omitted, resolves did:web from kid.
  --issuer <did>           Expected issuer DID.
  --claim-type <type>      Expected VC claim type, e.g. VerifyResult.
  --schema-id <id>         Expected credentialSchema.id.
  --schema <source>        JSON Schema for credentialSubject.
  --now <unix-or-rfc3339>  Verification time. Defaults to current wall clock.
  --quiet                  Print only errors.
  --help                   Show this help.`;
}

function parseArgs(argv) {
  const args = {
    jwt: undefined,
    jwtFile: undefined,
    didDocument: undefined,
    issuer: undefined,
    claimType: undefined,
    schemaId: undefined,
    schema: undefined,
    now: undefined,
    quiet: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (arg === "--quiet") {
      args.quiet = true;
      continue;
    }

    const takesValue = [
      "--claim-type",
      "--did-document",
      "--issuer",
      "--jwt",
      "--jwt-file",
      "--now",
      "--schema",
      "--schema-id",
    ];
    if (!takesValue.includes(arg)) {
      throw new VerificationError(`unknown option: ${arg}`);
    }
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) {
      throw new VerificationError(`missing value for ${arg}`);
    }
    i += 1;
    if (arg === "--claim-type") args.claimType = value;
    if (arg === "--did-document") args.didDocument = value;
    if (arg === "--issuer") args.issuer = value;
    if (arg === "--jwt") args.jwt = value;
    if (arg === "--jwt-file") args.jwtFile = value;
    if (arg === "--now") args.now = value;
    if (arg === "--schema") args.schema = value;
    if (arg === "--schema-id") args.schemaId = value;
  }

  if (!args.help && Number(Boolean(args.jwt)) + Number(Boolean(args.jwtFile)) !== 1) {
    throw new VerificationError("provide exactly one of --jwt or --jwt-file");
  }
  return args;
}

function parseNow(value) {
  if (!value) return Math.floor(Date.now() / 1000);
  if (/^-?\d+$/.test(value)) return Number.parseInt(value, 10);
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    throw new VerificationError(`invalid --now value: ${value}`);
  }
  return Math.floor(parsed / 1000);
}

async function readText(source, accept = "application/json") {
  if (source.startsWith("http://") || source.startsWith("https://")) {
    return readUrl(source, accept);
  }
  if (source.startsWith("file://")) {
    return readFile(fileURLToPath(source), "utf8");
  }
  return readFile(source, "utf8");
}

function readUrl(source, accept) {
  return new Promise((resolve, reject) => {
    const client = source.startsWith("https://") ? https : http;
    const request = client.get(source, { headers: { Accept: accept } }, (response) => {
      const status = response.statusCode ?? 0;
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        if (status < 200 || status >= 300) {
          reject(new VerificationError(`GET ${source} returned HTTP ${status}: ${body}`));
          return;
        }
        resolve(body);
      });
    });
    request.setTimeout(30_000, () => {
      request.destroy(new VerificationError(`GET ${source} timed out`));
    });
    request.on("error", reject);
  });
}

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new VerificationError(`${label} is not valid JSON: ${error.message}`);
  }
}

function decodeBase64UrlJson(part, label) {
  try {
    return parseJson(Buffer.from(part, "base64url").toString("utf8"), label);
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    throw new VerificationError(`${label} is not valid base64url JSON: ${error.message}`);
  }
}

function splitCompactJws(jws) {
  const parts = jws.trim().split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new VerificationError("compact VC-JWT must have exactly three non-empty segments");
  }
  return parts;
}

function checkJoseHeader(header) {
  if (!header || typeof header !== "object" || Array.isArray(header)) {
    throw new VerificationError("JOSE header must be a JSON object");
  }
  if (!SUPPORTED_ALGS.has(header.alg)) {
    throw new VerificationError(`unsupported JOSE alg: ${String(header.alg)}`);
  }
  if (header.typ !== "vc+jwt") {
    throw new VerificationError(`JOSE typ must be vc+jwt, got ${String(header.typ)}`);
  }
  if (header.cty !== "vc") {
    throw new VerificationError(`JOSE cty must be vc, got ${String(header.cty)}`);
  }
  if (typeof header.kid !== "string" || header.kid.length === 0) {
    throw new VerificationError("JOSE kid must be a non-empty string");
  }
  if (Object.hasOwn(header, "crit")) {
    throw new VerificationError("JOSE crit headers are not supported by this verifier");
  }
}

function didWebUrl(did) {
  if (!did.startsWith("did:web:")) {
    throw new VerificationError(`cannot auto-resolve non-did:web DID: ${did}`);
  }
  const encoded = did.slice("did:web:".length);
  if (!encoded) throw new VerificationError("did:web identifier is empty");
  const parts = encoded.split(":").map((part) => decodeURIComponent(part));
  const host = parts[0];
  if (!host) throw new VerificationError(`did:web host is empty: ${did}`);
  if (parts.length === 1) {
    return `https://${host}/.well-known/did.json`;
  }
  return `https://${host}/${parts.slice(1).join("/")}/did.json`;
}

async function loadDidDocument(source, kid) {
  const did = kid.split("#", 1)[0];
  const location = source ?? didWebUrl(did);
  return parseJson(await readText(location, "application/did+json, application/json"), location);
}

function methodCandidates(didDocument) {
  const candidates = [];
  const verificationMethods = didDocument.verificationMethod;
  if (Array.isArray(verificationMethods)) {
    candidates.push(...verificationMethods.filter((entry) => typeof entry === "object" && entry));
  } else if (verificationMethods && typeof verificationMethods === "object") {
    candidates.push(verificationMethods);
  }

  for (const relationship of [
    "assertionMethod",
    "authentication",
    "capabilityDelegation",
    "capabilityInvocation",
  ]) {
    const entries = didDocument[relationship];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (entry && typeof entry === "object") candidates.push(entry);
    }
  }
  return candidates;
}

function findPublicJwk(didDocument, kid) {
  const method = methodCandidates(didDocument).find((entry) => entry.id === kid);
  if (!method) {
    throw new VerificationError(`DID Document does not contain verificationMethod id ${kid}`);
  }
  const publicJwk = method.publicKeyJwk;
  if (!publicJwk || typeof publicJwk !== "object" || Array.isArray(publicJwk)) {
    throw new VerificationError(`verificationMethod ${kid} does not contain publicKeyJwk`);
  }
  if (Object.hasOwn(publicJwk, "d")) {
    throw new VerificationError(`publicKeyJwk for ${kid} must not contain private parameter d`);
  }
  if (publicJwk.kid && publicJwk.kid !== kid) {
    throw new VerificationError(`publicKeyJwk.kid does not match JOSE kid ${kid}`);
  }
  return publicJwk;
}

function assertDidBinding(didDocument, kid) {
  const kidDid = kid.split("#", 1)[0];
  if (!didDocument || typeof didDocument !== "object" || Array.isArray(didDocument)) {
    throw new VerificationError("DID Document must be a JSON object");
  }
  if (typeof didDocument.id !== "string" || didDocument.id.length === 0) {
    throw new VerificationError("DID Document id must be a non-empty string");
  }
  if (didDocument.id !== kidDid) {
    throw new VerificationError(`DID Document id ${didDocument.id} does not match kid DID ${kidDid}`);
  }
}

function verifyJwsSignature(alg, signingInput, signature, publicJwk) {
  if (publicJwk.alg && publicJwk.alg !== alg) {
    throw new VerificationError(`publicKeyJwk alg ${publicJwk.alg} does not match JOSE alg ${alg}`);
  }

  let key;
  try {
    key = createPublicKey({ key: publicJwk, format: "jwk" });
  } catch (error) {
    throw new VerificationError(`publicKeyJwk cannot be imported: ${error.message}`);
  }

  const input = Buffer.from(signingInput, "utf8");
  let ok = false;
  if (alg === "EdDSA") {
    ok = verifySignature(null, input, key, signature);
  }

  if (!ok) {
    throw new VerificationError("JWS signature did not verify with DID publicKeyJwk");
  }
}

function checkClaims(payload, didDocument, expected) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new VerificationError("VC-JWT payload must be a JSON object");
  }

  const issuer = expected.issuer ?? didDocument.id;
  if (payload.iss !== issuer) {
    throw new VerificationError(`payload iss must be ${issuer}, got ${String(payload.iss)}`);
  }
  if (payload.issuer !== issuer) {
    throw new VerificationError(`payload issuer must be ${issuer}, got ${String(payload.issuer)}`);
  }
  if (payload.issuer !== payload.iss) {
    throw new VerificationError("payload issuer and iss must match");
  }

  if (!Number.isInteger(payload.nbf)) {
    throw new VerificationError("payload nbf must be an integer NumericDate");
  }
  if (!Number.isInteger(payload.iat)) {
    throw new VerificationError("payload iat must be an integer NumericDate");
  }
  if (!Number.isInteger(payload.exp)) {
    throw new VerificationError("payload exp must be an integer NumericDate");
  }
  if (payload.nbf > payload.iat) {
    throw new VerificationError("payload nbf must not be later than iat");
  }
  if (payload.nbf > expected.now) {
    throw new VerificationError(`credential is not valid before nbf ${payload.nbf}`);
  }
  if (expected.now >= payload.exp) {
    throw new VerificationError(`credential expired at exp ${payload.exp}`);
  }
  if (payload.exp <= payload.iat) {
    throw new VerificationError("payload exp must be later than iat");
  }

  if (typeof payload.jti !== "string" || !payload.jti.startsWith("urn:uuid:")) {
    throw new VerificationError("payload jti must be a urn:uuid string");
  }
  if (payload.id !== payload.jti) {
    throw new VerificationError("payload id must match jti");
  }
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new VerificationError("payload sub must be a non-empty string");
  }

  if (!Array.isArray(payload.type) || payload.type[0] !== "VerifiableCredential") {
    throw new VerificationError("payload type must start with VerifiableCredential");
  }
  if (expected.claimType && payload.type[1] !== expected.claimType) {
    throw new VerificationError(
      `payload type[1] must be ${expected.claimType}, got ${String(payload.type[1])}`,
    );
  }

  const schemaId = payload.credentialSchema?.id;
  if (expected.schemaId && schemaId !== expected.schemaId) {
    throw new VerificationError(
      `credentialSchema.id must be ${expected.schemaId}, got ${String(schemaId)}`,
    );
  }
  if (payload.credentialSchema && payload.credentialSchema.type !== "JsonSchema") {
    throw new VerificationError(
      `credentialSchema.type must be JsonSchema, got ${String(payload.credentialSchema.type)}`,
    );
  }

  if (
    !payload.credentialSubject
    || typeof payload.credentialSubject !== "object"
    || Array.isArray(payload.credentialSubject)
  ) {
    throw new VerificationError("credentialSubject must be a JSON object");
  }
  if (
    typeof payload.credentialSubject.id === "string"
    && payload.credentialSubject.id !== payload.sub
  ) {
    throw new VerificationError("credentialSubject.id must match JWT sub when present");
  }

  for (const [field, value] of [
    ["validFrom", payload.validFrom],
    ["validUntil", payload.validUntil],
  ]) {
    if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
      throw new VerificationError(`payload ${field} must be an RFC3339 timestamp string`);
    }
  }
  if (Date.parse(payload.validUntil) <= Date.parse(payload.validFrom)) {
    throw new VerificationError("payload validUntil must be later than validFrom");
  }
}

function jsonType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (Number.isInteger(value)) return "integer";
  if (typeof value === "number") return "number";
  return typeof value;
}

function schemaPath(path, segment) {
  if (/^\d+$/.test(String(segment))) return `${path}/${segment}`;
  return `${path}/${String(segment).replaceAll("~", "~0").replaceAll("/", "~1")}`;
}

function failSchema(path, message, errors) {
  errors.push(`${path || "/"}: ${message}`);
}

function assertSupportedSchema(schema, path = "") {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return;
  for (const key of Object.keys(schema)) {
    if (!SUPPORTED_SCHEMA_KEYWORDS.has(key)) {
      throw new VerificationError(`unsupported JSON Schema keyword at ${path || "/"}: ${key}`);
    }
  }
  if (schema.properties && typeof schema.properties === "object") {
    for (const [name, child] of Object.entries(schema.properties)) {
      assertSupportedSchema(child, schemaPath(path, `properties/${name}`));
    }
  }
  if (schema.items && typeof schema.items === "object") {
    assertSupportedSchema(schema.items, schemaPath(path, "items"));
  }
  if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
    assertSupportedSchema(schema.additionalProperties, schemaPath(path, "additionalProperties"));
  }
  if (Array.isArray(schema.oneOf)) {
    schema.oneOf.forEach((child, index) => assertSupportedSchema(child, schemaPath(path, `oneOf/${index}`)));
  }
}

function typeMatches(value, expectedType) {
  const actual = jsonType(value);
  if (expectedType === "number") return actual === "number" || actual === "integer";
  return actual === expectedType;
}

function validateFormat(value, format) {
  if (typeof value !== "string") return true;
  if (format === "date-time") {
    return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)
      && !Number.isNaN(Date.parse(value));
  }
  if (format === "uri") {
    try {
      new URL(value);
      return true;
    } catch {
      return false;
    }
  }
  return true;
}

function validateSchema(value, schema, path, errors) {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return;

  if (Object.hasOwn(schema, "const") && JSON.stringify(value) !== JSON.stringify(schema.const)) {
    failSchema(path, `expected const ${JSON.stringify(schema.const)}`, errors);
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((entry) => JSON.stringify(entry) === JSON.stringify(value))) {
    failSchema(path, `value ${JSON.stringify(value)} is not in enum`, errors);
  }

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((type) => typeMatches(value, type))) {
      failSchema(path, `expected type ${types.join("|")}, got ${jsonType(value)}`, errors);
      return;
    }
  }

  if (typeof value === "string") {
    if (Number.isInteger(schema.minLength) && value.length < schema.minLength) {
      failSchema(path, `string length is below minLength ${schema.minLength}`, errors);
    }
    if (Number.isInteger(schema.maxLength) && value.length > schema.maxLength) {
      failSchema(path, `string length is above maxLength ${schema.maxLength}`, errors);
    }
    if (schema.format && !validateFormat(value, schema.format)) {
      failSchema(path, `string does not match format ${schema.format}`, errors);
    }
  }

  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      failSchema(path, `number is below minimum ${schema.minimum}`, errors);
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      failSchema(path, `number is above maximum ${schema.maximum}`, errors);
    }
  }

  if (Array.isArray(value)) {
    if (Number.isInteger(schema.minItems) && value.length < schema.minItems) {
      failSchema(path, `array length is below minItems ${schema.minItems}`, errors);
    }
    if (schema.items && typeof schema.items === "object") {
      value.forEach((entry, index) => validateSchema(entry, schema.items, schemaPath(path, index), errors));
    }
  }

  if (value && typeof value === "object" && !Array.isArray(value)) {
    const properties = schema.properties && typeof schema.properties === "object" ? schema.properties : {};
    if (Array.isArray(schema.required)) {
      for (const name of schema.required) {
        if (!Object.hasOwn(value, name)) {
          failSchema(schemaPath(path, name), "required property is missing", errors);
        }
      }
    }
    for (const [name, childSchema] of Object.entries(properties)) {
      if (Object.hasOwn(value, name)) {
        validateSchema(value[name], childSchema, schemaPath(path, name), errors);
      }
    }
    if (schema.additionalProperties === false) {
      for (const name of Object.keys(value)) {
        if (!Object.hasOwn(properties, name)) {
          failSchema(schemaPath(path, name), "additional property is not allowed", errors);
        }
      }
    } else if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
      for (const name of Object.keys(value)) {
        if (!Object.hasOwn(properties, name)) {
          validateSchema(value[name], schema.additionalProperties, schemaPath(path, name), errors);
        }
      }
    }
  }

  if (Array.isArray(schema.oneOf)) {
    let matches = 0;
    for (const option of schema.oneOf) {
      const optionErrors = [];
      validateSchema(value, option, path, optionErrors);
      if (optionErrors.length === 0) matches += 1;
    }
    if (matches !== 1) {
      failSchema(path, `oneOf matched ${matches} schemas, expected exactly 1`, errors);
    }
  }
}

async function run(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return 0;
  }

  const compactJws = args.jwt ?? (await readText(args.jwtFile, "application/vc+jwt")).trim();
  const [headerB64, payloadB64, signatureB64] = splitCompactJws(compactJws);
  const header = decodeBase64UrlJson(headerB64, "JOSE header");
  checkJoseHeader(header);

  const didDocument = await loadDidDocument(args.didDocument, header.kid);
  assertDidBinding(didDocument, header.kid);
  const publicJwk = findPublicJwk(didDocument, header.kid);
  verifyJwsSignature(
    header.alg,
    `${headerB64}.${payloadB64}`,
    Buffer.from(signatureB64, "base64url"),
    publicJwk,
  );

  const payload = decodeBase64UrlJson(payloadB64, "VC-JWT payload");
  const now = parseNow(args.now);
  checkClaims(payload, didDocument, {
    claimType: args.claimType,
    issuer: args.issuer,
    now,
    schemaId: args.schemaId,
  });

  if (args.schema) {
    const schema = parseJson(await readText(args.schema, "application/schema+json, application/json"), args.schema);
    assertSupportedSchema(schema);
    const errors = [];
    validateSchema(payload.credentialSubject, schema, "", errors);
    if (errors.length > 0) {
      throw new VerificationError(`credentialSubject does not conform to schema:\n${errors.join("\n")}`);
    }
  }

  if (!args.quiet) {
    const claimType = Array.isArray(payload.type) ? payload.type[1] : undefined;
    console.log(
      `VC-JWT verification passed: kid=${header.kid} iss=${payload.iss} claimType=${claimType} schemaId=${payload.credentialSchema?.id}`,
    );
  }
  return 0;
}

run(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    const message = error instanceof VerificationError ? error.message : error.stack || error.message;
    console.error(`VC-JWT verification failed: ${message}`);
    process.exitCode = 1;
  });
