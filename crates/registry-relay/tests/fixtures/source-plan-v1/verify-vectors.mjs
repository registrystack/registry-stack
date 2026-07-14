#!/usr/bin/env node

import { createHash, createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";

const fixtureDirectory = dirname(fileURLToPath(import.meta.url));
const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function fail(message) {
  throw new Error(`source-plan vector verification failed: ${message}`);
}

function decodeStrictUtf8(bytes, file) {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    fail(`${file}: invalid UTF-8`);
  }
}

class StrictJsonParser {
  constructor(text, file) {
    this.text = text;
    this.file = file;
    this.index = 0;
  }

  parse() {
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.index !== this.text.length) {
      this.error("trailing content");
    }
    return value;
  }

  parseValue() {
    this.skipWhitespace();
    const character = this.text[this.index];
    if (character === "{") return this.parseObject();
    if (character === "[") return this.parseArray();
    if (character === '"') return this.parseString();
    if (character === "t") return this.parseKeyword("true", true);
    if (character === "f") return this.parseKeyword("false", false);
    if (character === "n") return this.parseKeyword("null", null);
    if (character === "-" || (character >= "0" && character <= "9")) {
      return this.parseNumber();
    }
    this.error("expected a JSON value");
  }

  parseObject() {
    this.index += 1;
    const value = Object.create(null);
    const keys = new Set();
    this.skipWhitespace();
    if (this.consume("}")) return value;
    while (true) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') this.error("expected an object key");
      const key = this.parseString();
      if (keys.has(key)) this.error(`duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) this.error("expected ':' after an object key");
      value[key] = this.parseValue();
      this.skipWhitespace();
      if (this.consume("}")) return value;
      if (!this.consume(",")) this.error("expected ',' or '}' in an object");
    }
  }

  parseArray() {
    this.index += 1;
    const value = [];
    this.skipWhitespace();
    if (this.consume("]")) return value;
    while (true) {
      value.push(this.parseValue());
      this.skipWhitespace();
      if (this.consume("]")) return value;
      if (!this.consume(",")) this.error("expected ',' or ']' in an array");
    }
  }

  parseString() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        let value;
        try {
          value = JSON.parse(this.text.slice(start, this.index));
        } catch {
          this.error("invalid JSON string escape");
        }
        for (let offset = 0; offset < value.length; offset += 1) {
          const unit = value.charCodeAt(offset);
          if (unit >= 0xd800 && unit <= 0xdbff) {
            const low = value.charCodeAt(offset + 1);
            if (!(low >= 0xdc00 && low <= 0xdfff)) this.error("unpaired high surrogate");
            offset += 1;
          } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            this.error("unpaired low surrogate");
          }
        }
        return value;
      }
      if (code < 0x20) this.error("unescaped control character in string");
      if (code === 0x5c) {
        this.index += 1;
        const escape = this.text[this.index];
        if ('"\\/bfnrt'.includes(escape)) {
          this.index += 1;
          continue;
        }
        if (escape === "u" && /^[0-9a-fA-F]{4}$/.test(this.text.slice(this.index + 1, this.index + 5))) {
          this.index += 5;
          continue;
        }
        this.error("invalid JSON string escape");
      }
      this.index += 1;
    }
    this.error("unterminated JSON string");
  }

  parseNumber() {
    const match = /^-?(?:0|[1-9][0-9]*)/.exec(this.text.slice(this.index));
    if (!match) this.error("invalid JSON number");
    this.index += match[0].length;
    const delimiter = this.text[this.index];
    if (delimiter === "." || delimiter === "e" || delimiter === "E") {
      this.error("only lexical JSON integers are supported by these vectors");
    }
    if (delimiter !== undefined && !/[\s,}\]]/.test(delimiter)) {
      this.error("invalid character after JSON number");
    }
    const value = Number(match[0]);
    if (!Number.isFinite(value)) this.error("non-finite number is unsupported");
    if (!Number.isSafeInteger(value)) {
      this.error("only finite safe integers are supported by these vectors");
    }
    if (Object.is(value, -0)) this.error("negative zero is unsupported by these vectors");
    return value;
  }

  parseKeyword(keyword, value) {
    if (this.text.slice(this.index, this.index + keyword.length) !== keyword) {
      this.error(`invalid token, expected ${keyword}`);
    }
    this.index += keyword.length;
    return value;
  }

  skipWhitespace() {
    while (/[\t\n\r ]/.test(this.text[this.index] ?? "")) this.index += 1;
  }

  consume(character) {
    if (this.text[this.index] !== character) return false;
    this.index += 1;
    return true;
  }

  error(message) {
    fail(`${this.file}:${this.index + 1}: ${message}`);
  }
}

function parseStrictJson(text, file) {
  return new StrictJsonParser(text, file).parse();
}

function assertParserRejects(text, label) {
  try {
    parseStrictJson(text, `self-test:${label}`);
  } catch {
    return;
  }
  fail(`strict-parser self-test accepted ${label}`);
}

function assertDecoderRejectsBeforeJsonParsing(bytes, label) {
  let jsonParserCalled = false;
  try {
    const text = decodeStrictUtf8(bytes, `self-test:${label}`);
    jsonParserCalled = true;
    parseStrictJson(text, `self-test:${label}`);
  } catch {
    if (!jsonParserCalled) return;
  }
  fail(`strict UTF-8 decoder self-test reached JSON parsing for ${label}`);
}

assertDecoderRejectsBeforeJsonParsing(Buffer.from([0xc3, 0x28]), "malformed UTF-8");

const bomText = decodeStrictUtf8(
  Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("{}")]),
  "self-test:UTF-8 BOM",
);
if (bomText.codePointAt(0) !== 0xfeff) fail("strict UTF-8 decoder self-test stripped the BOM");
assertParserRejects(bomText, "UTF-8 BOM");

for (const [label, text] of [
  ["duplicate member", '{"x":1,"x":2}'],
  ["fraction", '{"x":1.5}'],
  ["rounded fraction", '{"x":1.0000000000000001}'],
  ["exponent form", '{"x":1e0}'],
  ["positive unsafe integer", '{"x":9007199254740992}'],
  ["negative unsafe integer", '{"x":-9007199254740992}'],
  ["negative zero", '{"x":-0}'],
  ["huge exponent", '{"x":1e400}'],
  ["unpaired surrogate", String.raw`{"x":"\ud800"}`],
]) {
  assertParserRejects(text, label);
}

function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      fail("canonicalizer received a number outside the declared vector domain");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail(`unsupported canonicalization value type ${typeof value}`);
}

function assertExactKeys(value, expected, context) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${context} has unexpected fields: ${actual.join(", ")}`);
  }
}

function resolvePointer(value, pointer) {
  if (!pointer.startsWith("/")) fail(`invalid manifest pointer ${pointer}`);
  return pointer
    .slice(1)
    .split("/")
    .map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((current, token) => {
      if (current === null || typeof current !== "object" || !(token in current)) {
        fail(`pointer ${pointer} does not resolve`);
      }
      return current[token];
    }, value);
}

const manifestBytes = await readFile(join(fixtureDirectory, "manifest.json"));
const manifestText = decodeStrictUtf8(manifestBytes, "manifest.json");
const manifest = parseStrictJson(manifestText, "manifest.json");
assertExactKeys(
  manifest,
  ["schema", "canonicalization", "numeric_domain", "domain_separator", "vectors", "cross_references"],
  "manifest",
);
if (manifest.schema !== "registry.relay.source-plan-hash-vectors.v1") fail("unsupported manifest schema");
if (manifest.canonicalization !== "RFC8785") fail("canonicalization must be RFC8785");
if (manifest.numeric_domain !== "finite-safe-integers-only") fail("unexpected numeric domain");
assertExactKeys(manifest.domain_separator, ["encoding", "terminal_nul_bytes"], "domain_separator");
if (manifest.domain_separator.encoding !== "UTF-8" || manifest.domain_separator.terminal_nul_bytes !== 1) {
  fail("domain separator must be UTF-8 followed by exactly one terminal NUL byte");
}

const vectors = new Map();
for (const vector of manifest.vectors) {
  assertExactKeys(vector, ["name", "file", "domain_label", "expected_hash"], `vector ${vector.name}`);
  if (vectors.has(vector.name)) fail(`duplicate vector name ${vector.name}`);
  if (vector.domain_label.includes("\0")) fail(`${vector.name} domain label already contains NUL`);
  if (!/^sha256:[0-9a-f]{64}$/.test(vector.expected_hash)) fail(`${vector.name} has an invalid hash label`);
  const bytes = await readFile(join(fixtureDirectory, vector.file));
  const text = decodeStrictUtf8(bytes, vector.file);
  const value = parseStrictJson(text, vector.file);
  const canonical = canonicalize(value);
  const digest = createHash("sha256")
    .update(Buffer.from(vector.domain_label, "utf8"))
    .update(Buffer.from([0]))
    .update(Buffer.from(canonical, "utf8"))
    .digest("hex");
  const actualHash = `sha256:${digest}`;
  if (actualHash !== vector.expected_hash) {
    fail(`${vector.name} hash mismatch: expected ${vector.expected_hash}, got ${actualHash}`);
  }
  vectors.set(vector.name, { ...vector, value, actualHash });
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

for (const [contractName, policyName] of [
  ["public_contract", "consultation_policy"],
  ["public_contract_utf8_ordering", "consultation_policy_utf8_ordering"],
]) {
  const publicContract = vectors.get(contractName)?.value;
  const policyVector = vectors.get(policyName)?.value;
  if (!publicContract || !policyVector) fail(`missing ${contractName} or ${policyName} vector`);
  const contractAuthorization = publicContract.spec.authorization;
  const contractPolicy = contractAuthorization.policy;
  const generatedPolicy = {
    schema: "registry.relay.consultation-policy.v1",
    enforcement_profile: "registry.relay.consultation-pdp/v1",
    rule_set: "registry.relay.consultation-policy-rules.v1",
    id: contractPolicy.id,
    action: "consultation_execute",
    target: {
      profile: { id: publicContract.id, version: publicContract.version },
      integration: publicContract.spec.integration,
    },
    authorization: {
      workload: contractAuthorization.workload,
      required_scope: contractAuthorization.required_scope,
      purposes: [...contractAuthorization.purposes].sort(compareUtf8),
      legal_basis: contractAuthorization.legal_basis,
      consent: contractAuthorization.consent,
      mandatory_obligations: contractAuthorization.mandatory_obligations,
    },
    decision: {
      permit: "unqualified",
      decision_cache: contractPolicy.decision_cache,
      max_decision_age_ms: contractPolicy.max_decision_age_ms,
      unavailable: contractPolicy.unavailable,
    },
  };
  if (canonicalize(generatedPolicy) !== canonicalize(policyVector)) {
    fail(`${policyName} is not the exact compiler-generated ${contractName} preimage`);
  }
}

const orderingPurposes = vectors
  .get("consultation_policy_utf8_ordering")
  ?.value.authorization.purposes;
const utf8Order = ["\ue000", "\ud800\udc00"].sort(compareUtf8);
const utf16Order = ["\ue000", "\ud800\udc00"].sort();
if (utf8Order[0] === utf16Order[0]) fail("Unicode ordering vector does not discriminate UTF-8 from UTF-16");
if (canonicalize(orderingPurposes) !== canonicalize(utf8Order)) {
  fail("consultation_policy_utf8_ordering purposes are not in UTF-8 byte order");
}

for (const reference of manifest.cross_references) {
  assertExactKeys(reference, ["source", "pointer", "target", "kind"], "cross_reference");
  const source = vectors.get(reference.source);
  const target = vectors.get(reference.target);
  if (!source || !target) fail("cross-reference names an unknown vector");
  const actual = resolvePointer(source.value, reference.pointer);
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) {
    fail(`${reference.source}${reference.pointer} is not an identity object`);
  }
  const expected = { id: target.value.id, version: target.value.version };
  if (reference.kind === "artifact_identity") {
    expected.hash = target.actualHash;
  } else if (reference.kind === "integration_identity") {
    delete expected.version;
    expected.revision = Number(target.value.version);
  } else if (reference.kind === "derived_policy_identity") {
    delete expected.version;
    expected.hash = target.actualHash;
    expected.decision_cache = target.value.decision.decision_cache;
    expected.max_decision_age_ms = target.value.decision.max_decision_age_ms;
    expected.unavailable = target.value.decision.unavailable;
  } else if (reference.kind !== "profile_identity") {
    fail(`unsupported cross-reference kind ${reference.kind}`);
  }
  assertExactKeys(actual, Object.keys(expected), `${reference.source}${reference.pointer}`);
  for (const [key, value] of Object.entries(expected)) {
    if (actual[key] !== value) fail(`${reference.source}${reference.pointer}/${key} does not match ${reference.target}`);
  }
}

const runtimeVectorFile = "runtime-chain-vectors.json";
const runtimeVectorBytes = await readFile(join(fixtureDirectory, runtimeVectorFile));
const runtimeVector = parseStrictJson(
  decodeStrictUtf8(runtimeVectorBytes, runtimeVectorFile),
  runtimeVectorFile,
);
assertExactKeys(
  runtimeVector,
  [
    "schema",
    "canonicalization",
    "numeric_domain",
    "synthetic_fixture",
    "commitment_key",
    "framing",
    "cases",
  ],
  "runtime vector",
);
if (runtimeVector.schema !== "registry.relay.consultation-runtime-chain-v1") {
  fail("unsupported runtime-chain vector schema");
}
if (runtimeVector.canonicalization !== "RFC8785") fail("runtime-chain canonicalization must be RFC8785");
if (runtimeVector.numeric_domain !== "finite-safe-integers-only") {
  fail("unexpected runtime-chain numeric domain");
}
if (runtimeVector.synthetic_fixture !== true) fail("runtime-chain fixture must be explicitly synthetic");

assertExactKeys(runtimeVector.commitment_key, ["id", "master_key", "derivation"], "commitment_key");
assertExactKeys(runtimeVector.commitment_key.master_key, ["encoding", "value"], "master_key");
if (
  runtimeVector.commitment_key.master_key.encoding !== "hex" ||
  !/^[0-9a-f]{64}$/.test(runtimeVector.commitment_key.master_key.value)
) {
  fail("runtime-chain master key must be an exact synthetic 32-byte lowercase hex value");
}
if (runtimeVector.commitment_key.master_key.value !== "42".repeat(32)) {
  fail("runtime-chain master key is not the reviewed synthetic 0x42 vector");
}
assertExactKeys(
  runtimeVector.commitment_key.derivation,
  ["algorithm", "info_utf8", "output_bytes"],
  "commitment_key.derivation",
);
const derivation = runtimeVector.commitment_key.derivation;
if (
  derivation.algorithm !== "HKDF-Expand-only-HMAC-SHA256" ||
  derivation.info_utf8 !== "registry-platform-audit/audit-pseudonym-key/v1" ||
  derivation.output_bytes !== 32
) {
  fail("runtime-chain key derivation contract drifted");
}
assertExactKeys(runtimeVector.framing, ["encoding", "separator_hex", "shape"], "runtime framing");
if (
  runtimeVector.framing.encoding !== "UTF-8" ||
  runtimeVector.framing.separator_hex !== "00" ||
  runtimeVector.framing.shape !== "domain_label || 0x00 || RFC8785(value)"
) {
  fail("runtime-chain framing contract drifted");
}

const masterKey = Buffer.from(runtimeVector.commitment_key.master_key.value, "hex");
const commitmentKey = createHmac("sha256", masterKey)
  .update(Buffer.from(derivation.info_utf8, "utf8"))
  .update(Buffer.from([1]))
  .digest();

function verifyCanonicalMember(member, context) {
  assertExactKeys(member, ["domain_label", "value", "canonical_json", "expected"], context);
  if (member.domain_label.includes("\0")) fail(`${context} domain label already contains NUL`);
  const canonicalJson = canonicalize(member.value);
  if (member.canonical_json !== canonicalJson) fail(`${context} canonical JSON drifted`);
  return Buffer.concat([
    Buffer.from(member.domain_label, "utf8"),
    Buffer.from([0]),
    Buffer.from(canonicalJson, "utf8"),
  ]);
}

function verifyHmacMember(member, context) {
  const preimage = verifyCanonicalMember(member, context);
  if (!/^hmac-sha256:[0-9a-f]{64}$/.test(member.expected)) {
    fail(`${context} has an invalid HMAC label`);
  }
  const actual = `hmac-sha256:${createHmac("sha256", commitmentKey).update(preimage).digest("hex")}`;
  if (actual !== member.expected) fail(`${context} HMAC mismatch: expected ${member.expected}, got ${actual}`);
}

function verifyDigestMember(member, context) {
  const preimage = verifyCanonicalMember(member, context);
  if (!/^sha256:[0-9a-f]{64}$/.test(member.expected)) fail(`${context} has an invalid digest label`);
  const actual = `sha256:${createHash("sha256").update(preimage).digest("hex")}`;
  if (actual !== member.expected) fail(`${context} digest mismatch: expected ${member.expected}, got ${actual}`);
}

const expectedRuntimeCases = new Map([
  ["bounded_http_no_consent", { planKind: "bounded_http", consent: false }],
  ["script_no_consent", { planKind: "script", consent: false }],
  ["bounded_http_required_consent", { planKind: "bounded_http", consent: true }],
]);
if (!Array.isArray(runtimeVector.cases) || runtimeVector.cases.length !== expectedRuntimeCases.size) {
  fail("runtime-chain fixture must contain the exact reviewed case set");
}
const seenRuntimeCases = new Set();
for (const runtimeCase of runtimeVector.cases) {
  assertExactKeys(
    runtimeCase,
    ["name", "hmac_commitments", "ordinary_digests", "completion_seed"],
    `runtime case ${runtimeCase.name}`,
  );
  const expectedCase = expectedRuntimeCases.get(runtimeCase.name);
  if (!expectedCase || seenRuntimeCases.has(runtimeCase.name)) {
    fail(`unknown or duplicate runtime-chain case ${runtimeCase.name}`);
  }
  seenRuntimeCases.add(runtimeCase.name);
  const context = `runtime case ${runtimeCase.name}`;
  const commitments = runtimeCase.hmac_commitments;
  assertExactKeys(commitments, ["subject", "input", "predicate", "consent"], `${context} commitments`);
  for (const name of ["subject", "input", "predicate"]) {
    verifyHmacMember(commitments[name], `${context} ${name}`);
  }
  if (expectedCase.consent) {
    if (commitments.consent === null) fail(`${context} omits required consent commitment`);
    verifyHmacMember(commitments.consent, `${context} consent`);
    if (commitments.consent.value.raw_consent_reference !== "SYNTHETIC-CONSENT-0001") {
      fail(`${context} consent reference is not the reviewed synthetic value`);
    }
  } else if (commitments.consent !== null) {
    fail(`${context} unexpectedly includes consent`);
  }
  if (
    commitments.subject.value.canonical_selector?.components?.subject_id?.value !==
    "SYNTHETIC-SUBJECT-0001"
  ) {
    fail(`${context} subject is not the reviewed synthetic value`);
  }

  const digests = runtimeCase.ordinary_digests;
  assertExactKeys(
    digests,
    ["authorization_context", "execution_plan", "authorized_request"],
    `${context} ordinary digests`,
  );
  for (const name of ["authorization_context", "execution_plan", "authorized_request"]) {
    verifyDigestMember(digests[name], `${context} ${name}`);
  }
  if (digests.execution_plan.value.backend_kind !== expectedCase.planKind) {
    fail(`${context} execution plan kind drifted`);
  }
  if (digests.execution_plan.value.predicate_commitment !== commitments.predicate.expected) {
    fail(`${context} execution plan is not bound to its predicate commitment`);
  }
  if (
    digests.authorized_request.value.commitment_key_id !== runtimeVector.commitment_key.id ||
    digests.authorized_request.value.input_commitment !== commitments.input.expected ||
    digests.authorized_request.value.subject_handle !== commitments.subject.expected ||
    digests.authorized_request.value.authorization_context_digest !== digests.authorization_context.expected ||
    digests.authorized_request.value.execution_plan_digest !== digests.execution_plan.expected
  ) {
    fail(`${context} authorized request breaks its commitment chain`);
  }
  const consentDecision = digests.authorization_context.value.verified_consent_decision;
  if (
    expectedCase.consent !== consentDecision.required ||
    (expectedCase.consent && consentDecision.evidence_commitment !== commitments.consent.expected)
  ) {
    fail(`${context} authorization context breaks its consent chain`);
  }

  const seed = runtimeCase.completion_seed;
  assertExactKeys(seed, ["value", "canonical_json", "canonical_bytes", "expected_digest"], `${context} seed`);
  const canonicalSeed = canonicalize(seed.value);
  if (seed.canonical_json !== canonicalSeed) fail(`${context} seed canonical JSON drifted`);
  if (seed.canonical_bytes !== Buffer.byteLength(canonicalSeed, "utf8")) {
    fail(`${context} seed canonical byte count drifted`);
  }
  const seedDigest = `sha256:${createHash("sha256").update(Buffer.from(canonicalSeed, "utf8")).digest("hex")}`;
  if (seed.expected_digest !== seedDigest) fail(`${context} seed digest mismatch`);
  assertExactKeys(
    seed.value,
    [
      "schema",
      "correlation",
      "profile",
      "integration_pack",
      "private_binding_hash",
      "workload",
      "purpose",
      "policy",
      "acquisition",
      "destinations",
      "credential",
      "dispatch",
      "bounds",
      "request_digest",
      "authorization_context_digest",
      "execution_plan_digest",
    ],
    `${context} seed value`,
  );
  if (
    seed.value.dispatch.plan_kind !== expectedCase.planKind ||
    seed.value.request_digest !== digests.authorized_request.expected ||
    seed.value.authorization_context_digest !== digests.authorization_context.expected ||
    seed.value.execution_plan_digest !== digests.execution_plan.expected
  ) {
    fail(`${context} completion seed breaks its digest chain`);
  }
  if (
    seed.value.bounds.timeout_ms !== digests.execution_plan.value.timeout_ms ||
    seed.value.bounds.timeout_ms !== digests.execution_plan.value.dispatch_budget_ms ||
    seed.value.bounds.timeout_ms < 1 ||
    seed.value.bounds.timeout_ms > 10000
  ) {
    fail(`${context} timeout and dispatch budget are not exactly bound`);
  }
  if (seed.value.policy.consent.required !== expectedCase.consent) {
    fail(`${context} completion seed consent contract drifted`);
  }

  if (expectedCase.planKind === "script") {
    const dataPermits = seed.value.dispatch.permit_bindings.filter(({ kind }) => kind === "data");
    if (
      canonicalize(dataPermits.map(({ ordinal }) => ordinal)) !== canonicalize([0, 1])
    ) {
      fail(`${context} Rhai permits do not preserve the reviewed durable call ordinals`);
    }
  }
}

process.stdout.write(
  `verified ${vectors.size} RFC8785 source-plan vectors, ${manifest.cross_references.length} cross-references, and ${runtimeVector.cases.length} runtime chain cases\n`,
);
