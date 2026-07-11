#!/usr/bin/env node

import { createHash } from "node:crypto";
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
  if (reference.kind === "artifact_identity") expected.hash = target.actualHash;
  else if (reference.kind !== "profile_identity") fail(`unsupported cross-reference kind ${reference.kind}`);
  assertExactKeys(actual, Object.keys(expected), `${reference.source}${reference.pointer}`);
  for (const [key, value] of Object.entries(expected)) {
    if (actual[key] !== value) fail(`${reference.source}${reference.pointer}/${key} does not match ${reference.target}`);
  }
}

process.stdout.write(`verified ${vectors.size} RFC8785 source-plan vectors and ${manifest.cross_references.length} cross-references\n`);
