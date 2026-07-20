import assert from "node:assert/strict";
import test from "node:test";

import {
  NotaryError,
  NotaryProblemError,
  NotaryTransportError,
  RegistryNotaryClient,
} from "../src/index.js";

test("evaluate converts camelCase request fields and response fields", async () => {
  const calls = [];
  const controller = new AbortController();
  const request = {
    target: {
      type: "Person",
      identifiers: [{ scheme: "NATIONAL_ID", value: "subj-0000001" }],
    },
    claims: [{ id: "date-of-birth", version: "2026-05-29" }],
    signal: controller.signal,
  };
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    bearerToken: "test-token",
    defaultPurpose: "benefits_eligibility",
    fetch: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({
        evaluation_id: "eval-1",
        results: [{ claim_id: "date-of-birth", issued_at: "2026-05-29T00:00:00Z" }],
      });
    },
  });

  const result = await client.evaluate(request);

  assert.deepEqual(result, {
    evaluationId: "eval-1",
    results: [{ claimId: "date-of-birth", issuedAt: "2026-05-29T00:00:00Z" }],
  });
  assert.equal(calls.length, 1);
  assert.equal(String(calls[0].url), "https://notary.example/v1/evaluations");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.signal, controller.signal);
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    target: {
      type: "Person",
      identifiers: [{ scheme: "NATIONAL_ID", value: "subj-0000001" }],
    },
    claims: [{ id: "date-of-birth", version: "2026-05-29" }],
  });
  assert.equal(calls[0].init.headers.get("accept"), "application/vnd.registry-notary.claim-result+json");
  assert.equal(calls[0].init.headers.get("authorization"), "Bearer test-token");
  assert.equal(calls[0].init.headers.get("data-purpose"), "benefits_eligibility");
  assert.equal(request.target.identifiers[0].scheme, "NATIONAL_ID");
});

test("evaluateRequest preserves snake_case request and response shapes", async () => {
  const calls = [];
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    apiKey: "key-1",
    fetch: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({
        evaluation_id: "eval-raw",
        results: [{ claim_id: "date-of-birth" }],
      });
    },
  });

  const result = await client.evaluateRequest(
    {
      target: {
        type: "Person",
        identifiers: [{ scheme: "NATIONAL_ID", value: "subj-0000001" }],
      },
      claims: ["date-of-birth"],
      purpose: "benefits_eligibility",
    },
    { purpose: "benefits_eligibility", requestId: "req-1" },
  );

  assert.deepEqual(result, {
    evaluation_id: "eval-raw",
    results: [{ claim_id: "date-of-birth" }],
  });
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    target: {
      type: "Person",
      identifiers: [{ scheme: "NATIONAL_ID", value: "subj-0000001" }],
    },
    claims: ["date-of-birth"],
    purpose: "benefits_eligibility",
  });
  assert.equal(calls[0].init.headers.get("x-api-key"), "key-1");
  assert.equal(calls[0].init.headers.get("x-request-id"), "req-1");
});

test("evaluateRequest rejects idempotency keys on non-idempotent evaluate route", async () => {
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async () => jsonResponse({ results: [] }),
  });

  await assert.rejects(
    client.evaluateRequest(
      { target: { type: "Person", id: "subj-0000001" }, claims: ["date-of-birth"] },
      { idempotencyKey: "ignored-by-server" },
    ),
    (error) => error instanceof NotaryError && error.code === "unsupported_idempotency_key",
  );
});

test("batchEvaluateRequest sends Idempotency-Key when supplied", async () => {
  const calls = [];
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({ batch_id: "batch-1", status: "completed" });
    },
  });

  const result = await client.batchEvaluateRequest(
    {
      items: [
        {
          target: {
            type: "Person",
            identifiers: [{ scheme: "NATIONAL_ID", value: "subj-1" }],
          },
        },
      ],
      claims: ["age"],
    },
    { idempotencyKey: "batch-key" },
  );

  assert.equal(result.batch_id, "batch-1");
  assert.equal(String(calls[0].url), "https://notary.example/v1/batch-evaluations");
  assert.equal(calls[0].init.headers.get("Idempotency-Key"), "batch-key");
});

test("batchEvaluate converts camelCase request and response fields", async () => {
  const calls = [];
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({ batch_id: "batch-1", summary: { succeeded: 1, failed: 0 } });
    },
  });

  const result = await client.batchEvaluate({
    items: [
      {
        target: {
          type: "Person",
          identifiers: [{ scheme: "NATIONAL_ID", value: "subj-1" }],
        },
      },
    ],
    claims: ["age"],
  });

  assert.deepEqual(JSON.parse(calls[0].init.body).items, [
    {
      target: {
        type: "Person",
        identifiers: [{ scheme: "NATIONAL_ID", value: "subj-1" }],
      },
    },
  ]);
  assert.deepEqual(result, { batchId: "batch-1", summary: { succeeded: 1, failed: 0 } });
});

test("core helper methods cover claims, render, issue, and credential status", async () => {
  const calls = [];
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (String(url).endsWith("/v1/claims")) return jsonResponse({ data: [{ id: "age" }] });
      if (String(url).endsWith("/v1/claims/claim%20one")) return jsonResponse({ id: "claim one" });
      if (String(url).endsWith("/v1/evaluations/eval-1/render")) return jsonResponse({ document: { ok: true } });
      if (String(url).endsWith("/v1/credentials")) return jsonResponse({ credential_id: "cred-1" });
      return jsonResponse({ credential_id: "cred-1", status: "valid" });
    },
  });

  assert.deepEqual(await client.listClaims(), { data: [{ id: "age" }] });
  assert.deepEqual(await client.getClaim("claim one"), { id: "claim one" });
  assert.deepEqual(await client.renderRequest({ evaluation_id: "eval-1", format: "json" }), {
    document: { ok: true },
  });
  assert.deepEqual(await client.issueCredentialRequest({ evaluation_id: "eval-1" }), {
    credential_id: "cred-1",
  });
  assert.deepEqual(await client.credentialStatus("cred-1"), {
    credential_id: "cred-1",
    status: "valid",
  });
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[2].init.method, "POST");
  assert.equal(String(calls[4].url), "https://notary.example/v1/credentials/cred-1/status");
  assert.deepEqual(JSON.parse(calls[2].init.body), { format: "json" });
});

test("renderRequest rejects missing request object", async () => {
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async () => jsonResponse({}),
  });

  await assert.rejects(
    client.renderRequest(null),
    (error) => error instanceof NotaryError && error.code === "request.invalid_type",
  );
});

test("constructor rejects unsafe base configuration", () => {
  assert.throws(
    () => new RegistryNotaryClient({ baseUrl: "http://notary.example" }),
    (error) => error instanceof NotaryError && error.code === "insecure_base_url",
  );
  assert.throws(
    () => new RegistryNotaryClient({ baseUrl: "https://notary.example", bearerToken: "token", apiKey: "key" }),
    (error) => error instanceof NotaryError && error.code === "multiple_auth_modes",
  );
});

test("AbortSignal is passed to fetch and abort maps to NotaryTransportError", async () => {
  const controller = new AbortController();
  controller.abort();
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async (_url, init) => {
      assert.equal(init.signal, controller.signal);
      throw new DOMException("The operation was aborted", "AbortError");
    },
  });

  await assert.rejects(
    client.evaluate({
      target: { type: "Person", id: "subj-0000001" },
      claims: ["date-of-birth"],
      signal: controller.signal,
    }),
    (error) =>
      error instanceof NotaryTransportError &&
      error.kind === "abort" &&
      error.code === "aborted" &&
      error.retryable === false,
  );
});

test("Problem Details errors are mapped and detail is redacted by default", async () => {
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async () =>
      jsonResponse(
        {
          type: "https://id.registrystack.org/problems/registry-notary/target/not-found",
          title: "Target not found",
          status: 404,
          detail: "secret target subj-0000001 was not found",
          code: "target.not_found",
        },
        {
          status: 404,
          statusText: "Not Found",
          headers: { "content-type": "application/problem+json", "x-request-id": "req-123" },
        },
      ),
  });

  await assert.rejects(
    client.evaluateRequest({ target: { type: "Person", id: "subj-0000001" }, claims: ["date-of-birth"] }),
    (error) => {
      assert.ok(error instanceof NotaryProblemError);
      assert.equal(error.status, 404);
      assert.equal(error.code, "target.not_found");
      assert.equal(error.title, "Target not found");
      assert.equal(error.requestId, "req-123");
      assert.equal(error.problemType, "https://id.registrystack.org/problems/registry-notary/target/not-found");
      assert.equal(error.detail, undefined);
      assert.equal(error.message.includes("secret target"), false);
      assert.deepEqual(error.toJSON(), {
        kind: "problem",
        status: 404,
        code: "target.not_found",
        title: "Target not found",
        retryable: false,
        request_id: "req-123",
      });
      return true;
    },
  );
});

test("decode and oversized response errors are redacted", async () => {
  const decodeClient = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async () =>
      new Response("not-json-with-subj-secret", {
        status: 200,
        headers: { "x-request-id": "req-decode" },
      }),
  });

  await assert.rejects(decodeClient.listClaims(), (error) => {
    assert.ok(error instanceof NotaryProblemError);
    assert.equal(error.kind, "decode");
    assert.equal(error.requestId, "req-decode");
    assert.equal(error.message.includes("subj-secret"), false);
    return true;
  });

  const oversizedClient = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async () =>
      new Response("x".repeat(8 * 1024 * 1024 + 1), {
        status: 200,
        headers: { "x-request-id": "req-large" },
      }),
  });

  await assert.rejects(oversizedClient.listClaims(), (error) => {
    assert.ok(error instanceof NotaryProblemError);
    assert.equal(error.kind, "body_too_large");
    assert.equal(error.code, "body.too_large");
    assert.equal(error.requestId, "req-large");
    return true;
  });

  let textRead = false;
  const fallbackOversizedClient = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async () => ({
      ok: true,
      status: 200,
      headers: new Headers({
        "content-length": String(8 * 1024 * 1024 + 1),
        "x-request-id": "req-large-header",
      }),
      body: null,
      text: async () => {
        textRead = true;
        return "{}";
      },
    }),
  });

  await assert.rejects(fallbackOversizedClient.listClaims(), (error) => {
    assert.ok(error instanceof NotaryProblemError);
    assert.equal(error.kind, "body_too_large");
    assert.equal(error.requestId, "req-large-header");
    return true;
  });
  assert.equal(textRead, false);
});

test("purpose conflicts fail before sending", async () => {
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    defaultPurpose: "benefits_eligibility",
    fetch: async () => {
      throw new Error("fetch should not be called");
    },
  });

  await assert.rejects(
    client.evaluateRequest({
      target: { type: "Person", id: "subj-0000001" },
      claims: ["date-of-birth"],
      purpose: "another_purpose",
    }),
    (error) => error instanceof NotaryError && error.code === "purpose_conflict",
  );
});

test("retry policy retries GET and idempotent batch only", async () => {
  const listCalls = [];
  const listClient = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    retryPolicy: {
      maxAttempts: 2,
      baseDelayMs: 0,
      maxDelayMs: 0,
      retryUnavailable: true,
    },
    fetch: async (url, init) => {
      listCalls.push({ url, init });
      if (listCalls.length === 1) {
        return jsonResponse({ code: "busy", title: "Busy" }, { status: 503, headers: { "retry-after": "0" } });
      }
      return jsonResponse({ data: [{ id: "age" }] });
    },
  });

  assert.deepEqual(await listClient.listClaims(), { data: [{ id: "age" }] });
  assert.equal(listCalls.length, 2);

  const batchCalls = [];
  const batchClient = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    retryPolicy: {
      maxAttempts: 2,
      baseDelayMs: 0,
      maxDelayMs: 0,
      retryUnavailable: true,
    },
    fetch: async (url, init) => {
      batchCalls.push({ url, init });
      if (batchCalls.length === 1) {
        return jsonResponse({ code: "busy", title: "Busy" }, { status: 503 });
      }
      return jsonResponse({ batch_id: "batch-1" });
    },
  });

  assert.deepEqual(
    await batchClient.batchEvaluateRequest(
      { items: [{ target: { type: "Person", id: "subj-1" } }], claims: ["age"] },
      { idempotencyKey: "batch-key" },
    ),
    { batch_id: "batch-1" },
  );
  assert.equal(batchCalls.length, 2);
  assert.equal(batchCalls[0].init.headers.get("Idempotency-Key"), "batch-key");

  const evaluateCalls = [];
  const evaluateClient = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    retryPolicy: {
      maxAttempts: 2,
      baseDelayMs: 0,
      maxDelayMs: 0,
      retryUnavailable: true,
    },
    fetch: async () => {
      evaluateCalls.push({});
      return jsonResponse({ code: "busy", title: "Busy" }, { status: 503 });
    },
  });

  await assert.rejects(
    evaluateClient.evaluateRequest({ target: { type: "Person", id: "subj-1" }, claims: ["age"] }),
    (error) => error instanceof NotaryProblemError && error.status === 503,
  );
  assert.equal(evaluateCalls.length, 1);
});

test("HTTP-date Retry-After uses server Date header", async () => {
  const originalNow = Date.now;
  Date.now = () => Date.parse("Wed, 31 Dec 2098 00:00:00 GMT");
  try {
    const calls = [];
    const client = new RegistryNotaryClient({
      baseUrl: "https://notary.example",
      retryPolicy: {
        maxAttempts: 2,
        baseDelayMs: 1000,
        maxDelayMs: 1000,
        retryUnavailable: true,
      },
      fetch: async () => {
        calls.push({});
        if (calls.length === 1) {
          return jsonResponse(
            { code: "busy", title: "Busy" },
            {
              status: 503,
              headers: {
                date: "Wed, 31 Dec 2099 00:00:00 GMT",
                "retry-after": "Wed, 31 Dec 2099 00:00:00 GMT",
              },
            },
          );
        }
        return jsonResponse({ data: [{ id: "age" }] });
      },
    });

    const started = performance.now();
    assert.deepEqual(await client.listClaims(), { data: [{ id: "age" }] });

    assert.equal(calls.length, 2);
    assert.equal(performance.now() - started < 100, true);
  } finally {
    Date.now = originalNow;
  }
});

test("retry sleep removes abort listener after timeout", async () => {
  const calls = [];
  let addedListener;
  let removedListener;
  const signal = {
    aborted: false,
    addEventListener: (_event, listener) => {
      addedListener = listener;
    },
    removeEventListener: (_event, listener) => {
      removedListener = listener;
    },
  };
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    retryPolicy: {
      maxAttempts: 2,
      baseDelayMs: 50,
      maxDelayMs: 1,
      retryUnavailable: true,
    },
    fetch: async () => {
      calls.push({});
      if (calls.length === 1) {
        return jsonResponse({ code: "busy", title: "Busy" }, { status: 503, headers: { "retry-after": "1" } });
      }
      return jsonResponse({ data: [{ id: "age" }] });
    },
  });

  assert.deepEqual(await client.listClaims({ signal }), { data: [{ id: "age" }] });
  assert.equal(calls.length, 2);
  assert.equal(typeof addedListener, "function");
  assert.equal(removedListener, addedListener);
});

test("JWKS helpers cache, refresh, and force refresh on unknown kid", async () => {
  const calls = [];
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (calls.length === 1) return jsonResponse({ keys: [{ kid: "key-1", kty: "EC" }] });
      if (calls.length === 2) return jsonResponse({ keys: [{ kid: "key-2", kty: "EC" }] });
      return jsonResponse({ keys: [{ kid: "key-3", kty: "EC" }] });
    },
  });

  assert.deepEqual(await client.issuerJwks(), { keys: [{ kid: "key-1", kty: "EC" }] });
  assert.deepEqual(await client.issuerJwks(), { keys: [{ kid: "key-1", kty: "EC" }] });
  assert.equal(calls.length, 1);
  assert.deepEqual(await client.getJwk("key-2"), { kid: "key-2", kty: "EC" });
  assert.equal(calls.length, 2);
  assert.deepEqual(await client.refreshJwks(), { keys: [{ kid: "key-3", kty: "EC" }] });
  assert.equal(String(calls[0].url), "https://notary.example/.well-known/evidence/jwks.json");
});

test("OID4VCI and federation helpers use route-specific wire shapes", async () => {
  const calls = [];
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (String(url).endsWith("/.well-known/openid-credential-issuer")) {
        return jsonResponse({ credential_issuer: "https://issuer.example" });
      }
      if (String(url).endsWith("/oid4vci/credential")) {
        return jsonResponse({ format: "dc+sd-jwt", credential: "credential-secret" });
      }
      return new Response("response.jws.compact", {
        status: 200,
        headers: { "content-type": "application/jwt" },
      });
    },
  });

  assert.deepEqual(await client.oid4vciIssuerMetadata(), { credential_issuer: "https://issuer.example" });
  assert.deepEqual(await client.oid4vciCredential({ proof: { jwt: "holder-proof-secret" } }), {
    format: "dc+sd-jwt",
    credential: "credential-secret",
  });
  assert.equal(await client.federationEvaluateJws("request.jws.compact"), "response.jws.compact");

  assert.equal(String(calls[1].url), "https://notary.example/oid4vci/credential");
  assert.deepEqual(JSON.parse(calls[1].init.body), { proof: { jwt: "holder-proof-secret" } });
  assert.equal(calls[2].init.body, "request.jws.compact");
  assert.equal(calls[2].init.headers.get("content-type"), "application/jwt");
  assert.equal(calls[2].init.headers.get("accept"), "application/jwt");
});

test("OID4VCI errors redact descriptions and credential material", async () => {
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async () =>
      jsonResponse(
        {
          error: "invalid_proof",
          error_description: "holder proof includes c_nonce nonce-secret",
        },
        {
          status: 400,
          headers: { "content-type": "application/json", "x-request-id": "req-oid" },
        },
      ),
  });

  await assert.rejects(client.oid4vciCredential({ proof: { jwt: "holder-proof-secret" } }), (error) => {
    assert.ok(error instanceof NotaryProblemError);
    assert.equal(error.kind, "oid4vci");
    assert.equal(error.code, "invalid_proof");
    assert.equal(error.requestId, "req-oid");
    assert.equal(error.message.includes("nonce-secret"), false);
    assert.equal(JSON.stringify(error).includes("holder-proof-secret"), false);
    return true;
  });
});

test("cross-origin redirects strip SDK auth headers", async () => {
  const calls = [];
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    apiKey: "secret-api-key",
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (calls.length === 1) {
        return new Response("", {
          status: 302,
          headers: { location: "https://redirect.example/v1/claims" },
        });
      }
      return jsonResponse({ data: [] });
    },
  });

  await client.listClaims();

  assert.equal(String(calls[0].url), "https://notary.example/v1/claims");
  assert.equal(String(calls[1].url), "https://redirect.example/v1/claims");
  assert.equal(calls[0].init.redirect, "manual");
  assert.equal(calls[0].init.headers.get("x-api-key"), "secret-api-key");
  assert.equal(calls[1].init.headers.get("x-api-key"), null);
  assert.equal(calls[1].init.headers.get("authorization"), null);
});

test("same-origin redirects preserve SDK auth headers", async () => {
  const calls = [];
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    bearerToken: "secret-bearer",
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (calls.length === 1) {
        return new Response("", {
          status: 302,
          headers: { location: "/v1/claims?redirected=true" },
        });
      }
      return jsonResponse({ data: [] });
    },
  });

  await client.listClaims();

  assert.equal(String(calls[1].url), "https://notary.example/v1/claims?redirected=true");
  assert.equal(calls[0].init.headers.get("authorization"), "Bearer secret-bearer");
  assert.equal(calls[1].init.headers.get("authorization"), "Bearer secret-bearer");
});

test("POST redirects converted to GET drop body headers", async () => {
  const calls = [];
  const client = new RegistryNotaryClient({
    baseUrl: "https://notary.example",
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (calls.length === 1) {
        init.headers.set("content-length", "64");
        return new Response("", {
          status: 303,
          headers: { location: "/v1/claims" },
        });
      }
      return jsonResponse({ data: [] });
    },
  });

  await client.evaluateRequest({ target: { type: "Person", id: "subj-0000001" }, claims: ["age"] });

  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[1].init.method, "GET");
  assert.equal(calls[1].init.body, undefined);
  assert.equal(calls[1].init.headers.get("content-type"), null);
  assert.equal(calls[1].init.headers.get("content-length"), null);
});

function jsonResponse(body, init = {}) {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    statusText: init.statusText ?? "OK",
    headers: {
      "content-type": "application/json",
      ...init.headers,
    },
  });
}
