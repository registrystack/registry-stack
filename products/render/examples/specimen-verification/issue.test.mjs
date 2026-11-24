// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { issueSpecimen } from "./issue.mjs";
import { verificationOrigin, verificationUrl } from "./origin.mjs";
import { createReference, normalizeReference } from "./reference.mjs";

const run = promisify(execFile);

test("each document gets a separate, human-readable lookup reference", () => {
  const first = createReference();
  assert.match(first, /^TEST(?:-[0-9A-F]{4}){5}$/);
  assert.notEqual(createReference(), first);
  assert.equal(normalizeReference(first.toLowerCase().replaceAll("-", " ")), first);
  assert.equal(normalizeReference(first.replaceAll("-", "")), first);
  for (const value of ["NB-P-0001", "../" + first, first + "0", "", null]) {
    assert.equal(normalizeReference(value), null);
  }
});

test("the printed URL uses a web origin with no credentials, query or path", () => {
  assert.equal(verificationOrigin("http://127.0.0.1:4371/"), "http://127.0.0.1:4371");
  assert.equal(verificationOrigin("http://192.168.1.45:4371"), "http://192.168.1.45:4371");
  assert.equal(verificationOrigin("https://verify.example.org"), "https://verify.example.org");
  for (const input of ["file:///tmp", "http://example.org", "https://name@example.org",
    "https://example.org/other", "https://example.org/?ref=old", "https://example.org/#page"]) {
    assert.throws(() => verificationOrigin(input));
  }
});

test("a complete verification page preserves its path prefix", () => {
  const reference = "TEST-1234-5678-9ABC-DEF0-1234";
  assert.equal(verificationUrl({ reference }), "http://127.0.0.1:4371/verify?ref=" + reference);
  assert.equal(verificationUrl({ reference, origin: "http://127.0.0.1:4371" }),
    "http://127.0.0.1:4371/verify?ref=" + reference);
  assert.equal(verificationUrl({
    reference,
    verificationPage: "https://docs.registrystack.org/dev/examples/population-extract/verify/",
  }), "https://docs.registrystack.org/dev/examples/population-extract/verify/?ref=" + reference);
  assert.equal(verificationUrl({
    reference,
    verificationPage: "http://192.168.1.45:4371/dev/examples/population-extract/verify/",
  }), "http://192.168.1.45:4371/dev/examples/population-extract/verify/?ref=" + reference);
});

test("a complete verification page rejects ambiguous or unsafe destinations", () => {
  const reference = "TEST-1234-5678-9ABC-DEF0-1234";
  assert.throws(() => verificationUrl({
    reference,
    origin: "http://127.0.0.1:4371",
    verificationPage: "https://docs.registrystack.org/dev/examples/population-extract/verify/",
  }), /either origin or verification page/i);
  for (const verificationPage of [
    "not a URL",
    "file:///tmp/verify/",
    "http://docs.registrystack.org/dev/examples/population-extract/verify/",
    "https://name@example.org/verify/",
    "https://example.org/verify/?old=value",
    "https://example.org/verify/#section",
    "https://example.org/not-the-verification-page/",
  ]) {
    assert.throws(() => verificationUrl({ reference, verificationPage }));
  }
});

test("the CLI refuses origin and verification page together before issuing", async (t) => {
  const registry = await mkdtemp(join(tmpdir(), "render-ambiguous-issue-"));
  t.after(() => rm(registry, { recursive: true, force: true }));
  await assert.rejects(run(process.execPath, [
    new URL("issue.mjs", import.meta.url).pathname,
    "--registry", registry,
    "--origin", "http://127.0.0.1:4371",
    "--verification-page", "https://docs.registrystack.org/dev/examples/population-extract/verify/",
  ]), (error) => {
    assert.match(error.stderr, /either origin or verification page/i);
    return true;
  });
  assert.deepEqual(await readdir(registry), []);
});

test("a failed signing command leaves no issuance record", async (t) => {
  const registry = await mkdtemp(join(tmpdir(), "render-failed-issue-"));
  t.after(() => rm(registry, { recursive: true, force: true }));
  await assert.rejects(issueSpecimen({
    registry, origin: "http://127.0.0.1:4371", render: join(registry, "missing-render"),
  }), /missing-render/);
  assert.deepEqual(await readdir(registry), []);
});

test("real issuance registers the exact signed PDF, without personal data in the receipt", async (t) => {
  const registry = await mkdtemp(join(tmpdir(), "render-test-issue-"));
  t.after(() => rm(registry, { recursive: true, force: true }));
  const result = await issueSpecimen({
    registry,
    verificationPage: "https://docs.registrystack.org/dev/examples/population-extract/verify/",
    render: process.env.REGISTRY_RENDER_BIN ?? "registry-render",
  });
  assert.deepEqual(await readdir(registry), [result.reference]);
  const dir = join(registry, result.reference);
  assert.deepEqual((await readdir(dir)).sort(), ["document.pdf", "receipt.json", "test-root.pem"]);
  const receipt = JSON.parse(await readFile(join(dir, "receipt.json"), "utf8"));
  assert.deepEqual(Object.keys(receipt).sort(), ["issuedAt", "reference", "signedFileDigest"]);
  assert.equal(receipt.reference, result.reference);
  assert.equal(result.url,
    "https://docs.registrystack.org/dev/examples/population-extract/verify/?ref=" + receipt.reference);
  assert.ok(Number.isFinite(Date.parse(receipt.issuedAt)));
  const pdf = await readFile(join(dir, "document.pdf"));
  assert.ok(pdf.includes(Buffer.from("/ETSI.CAdES.detached")));
  assert.equal(receipt.signedFileDigest, "sha256:" + createHash("sha256").update(pdf).digest("hex"));
});
