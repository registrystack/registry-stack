import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import compile from "@openfn/compiler";
import run from "@openfn/runtime";
import {
  NotaryCallerError,
  assertAllClaimsSatisfied,
  assertClaimSatisfied,
  buildEvaluationRequest,
  callNotaryEvaluation,
  handleEvaluationProblem,
  handleEvaluationSuccess,
  redactNotaryResponse,
  selectClaimResult,
  shouldSkipEvaluation,
} from "../src/index.js";

const baseState = Object.freeze({
  data: {
    request_id: "wf-req-1",
    national_id: "person-123",
  },
  configuration: {
    notary_base_url: "https://notary.example",
    notary_token: "secret-token",
    notary_target_fingerprint_key: "test-key",
  },
});
const packageRoot = fileURLToPath(new URL("..", import.meta.url));

test("buildEvaluationRequest sends auth, purpose, request id, and current Notary body shape", () => {
  const state = buildEvaluationRequest(baseState, {
    claimId: "benefits-person-exists",
    purpose: "benefits_eligibility",
    target: {
      type: "Person",
      identifiers: [{ scheme: "national_id", valueFrom: "national_id", issuer: "civil_registry" }],
    },
    relationship: { type: "self" },
    disclosure: "predicate",
  });

  assert.equal(state.data.notary_request.url, "https://notary.example/v1/evaluations");
  assert.equal(state.data.notary_request.headers.Authorization, "Bearer secret-token");
  assert.equal(state.data.notary_request.headers["Data-Purpose"], "benefits_eligibility");
  assert.equal(state.data.notary_request.headers["X-Request-Id"], "wf-req-1");
  assert.deepEqual(state.data.notary_request.body, {
    target: {
      type: "Person",
      identifiers: [{ scheme: "national_id", value: "person-123", issuer: "civil_registry" }],
    },
    relationship: { type: "self" },
    claims: ["benefits-person-exists"],
    disclosure: "predicate",
    purpose: "benefits_eligibility",
  });
});

test("buildEvaluationRequest normalizes relationship aliases to the wire shape", () => {
  const state = buildEvaluationRequest(baseState, {
    claimId: "benefits-person-exists",
    purpose: "benefits_eligibility",
    target: {
      type: "Person",
      identifiers: [{ scheme: "national_id", valueFrom: "national_id", issuer: "civil_registry" }],
    },
    relationship: {
      relationship_type: "case_worker",
      attributes: { case_id: "case-123" },
    },
  });

  assert.deepEqual(state.data.notary_request.body.relationship, {
    type: "case_worker",
    attributes: { case_id: "case-123" },
  });
});

test("buildEvaluationRequest rejects mismatched body and header purpose", () => {
  assert.throws(
    () =>
      buildEvaluationRequest(baseState, {
        claimId: "claim-a",
        purpose: "benefits_eligibility",
        bodyPurpose: "fraud_review",
        target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
      }),
    (error) => error instanceof NotaryCallerError && error.code === "purpose.mismatch",
  );
});

test("buildEvaluationRequest generates a request id when upstream lacks one", () => {
  const state = buildEvaluationRequest(
    {
      data: { national_id: "person-123" },
      configuration: baseState.configuration,
    },
    {
      claimId: "claim-a",
      purpose: "benefits_eligibility",
      target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
      requestIdFactory: () => "generated-req",
    },
  );

  assert.equal(state.data.notary_request.headers["X-Request-Id"], "generated-req");
});

test("buildEvaluationRequest propagates traceparent for audit correlation", () => {
  const state = buildEvaluationRequest(
    {
      data: {
        request_id: "wf-req-1",
        national_id: "person-123",
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
      },
      configuration: baseState.configuration,
    },
    {
      claimId: "claim-a",
      purpose: "benefits_eligibility",
      target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
    },
  );

  assert.equal(
    state.data.notary_request.headers.traceparent,
    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
  );
});

test("handleEvaluationSuccess reads results as an array and stores per-result evaluation id", () => {
  const prepared = buildEvaluationRequest(baseState, {
    claimId: "benefits-person-exists",
    purpose: "benefits_eligibility",
    target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
  });

  const state = handleEvaluationSuccess(
    {
      ...prepared,
      response: {
        headers: { "x-request-id": "notary-req-1" },
        body: {
          results: [
            { claim_id: "other", evaluation_id: "eval-other", satisfied: false },
            { claim_id: "benefits-person-exists", evaluation_id: "eval-1", satisfied: true },
          ],
        },
      },
    },
    { claimId: "benefits-person-exists" },
  );

  assert.deepEqual(state.data.notary, {
    branch: "satisfied",
    claim: "benefits-person-exists",
    evaluation_id: "eval-1",
    purpose: "benefits_eligibility",
    request_id: "notary-req-1",
    satisfied: true,
    target_fingerprint: state.data.notary.target_fingerprint,
  });
  assert.equal("national_id" in state.data, false);
  assert.equal("notary_request" in state.data, false);
});

test("handleEvaluationSuccess supports not_satisfied and all-claims policy", () => {
  const prepared = buildEvaluationRequest(baseState, {
    claimIds: ["claim-a", "claim-b"],
    purpose: "benefits_eligibility",
    target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
    multiClaimPolicy: "all_must_be_satisfied",
  });

  const state = handleEvaluationSuccess(
    {
      ...prepared,
      response: {
        body: {
          results: [
            { claim_id: "claim-a", evaluation_id: "eval-1", satisfied: true },
            { claim_id: "claim-b", evaluation_id: "eval-1", satisfied: false },
          ],
        },
      },
    },
    { claimIds: ["claim-a", "claim-b"], multiClaimPolicy: "all_must_be_satisfied" },
  );

  assert.equal(state.data.notary.branch, "not_satisfied");
  assert.deepEqual(state.data.notary.claims.map((claim) => [claim.claim, claim.satisfied]), [
    ["claim-a", true],
    ["claim-b", false],
  ]);
});

test("handleEvaluationSuccess supports per-claim routing", () => {
  const prepared = buildEvaluationRequest(baseState, {
    claimIds: ["claim-a", "claim-b"],
    purpose: "benefits_eligibility",
    target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
    multiClaimPolicy: "per_claim_routing",
  });

  const state = handleEvaluationSuccess(
    {
      ...prepared,
      response: {
        body: {
          results: [
            { claim_id: "claim-a", evaluation_id: "eval-1", satisfied: true },
            { claim_id: "claim-b", evaluation_id: "eval-2", satisfied: false },
          ],
        },
      },
    },
    { claimIds: ["claim-a", "claim-b"], multiClaimPolicy: "per_claim_routing" },
  );

  assert.equal(state.data.notary.branch, "per_claim_routing");
  assert.deepEqual(state.data.notary.claims.map((claim) => claim.branch), ["satisfied", "not_satisfied"]);
});

test("shouldSkipEvaluation skips whole-job replay when safe notary state exists", () => {
  const prepared = buildEvaluationRequest(baseState, {
    claimId: "benefits-person-exists",
    purpose: "benefits_eligibility",
    target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
  });
  const completed = handleEvaluationSuccess(
    {
      ...prepared,
      response: {
        body: {
          results: [{ claim_id: "benefits-person-exists", evaluation_id: "eval-1", satisfied: true }],
        },
      },
    },
    { claimId: "benefits-person-exists" },
  );

  assert.equal(
    shouldSkipEvaluation(
      {
        ...completed,
        configuration: baseState.configuration,
        data: { ...completed.data, national_id: "person-123" },
      },
      {
        claimId: "benefits-person-exists",
        purpose: "benefits_eligibility",
        target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
      },
    ),
    true,
  );
});

test("handleEvaluationProblem maps expected problem branches without leaking detail", () => {
  const cases = [
    ["target.not_found", "not_found"],
    ["target.match_ambiguous", "ambiguous"],
    ["evidence.not_available", "evidence_not_available"],
    ["purpose.not_allowed", "policy_denied"],
    ["source.unavailable", "source_unavailable"],
    ["idempotency.conflict", "idempotency_conflict"],
    ["request.invalid", "invalid_request"],
  ];

  for (const [code, branch] of cases) {
    const state = handleEvaluationProblem(
      {
        ...baseState,
        response: {
          statusCode: code === "source.unavailable" ? 503 : 400,
          headers: { "x-request-id": `req-${code}` },
          body: {
            type: `https://docs.example/problems/${code}`,
            title: "Problem",
            status: code === "source.unavailable" ? 503 : 400,
            detail: "secret subject person-123",
            code,
            request_id: `req-${code}`,
          },
        },
      },
      { claimId: "benefits-person-exists", purpose: "benefits_eligibility" },
    );

    assert.equal(state.data.notary.branch, branch);
    assert.equal(state.data.notary.problem.code, code);
    assert.equal("detail" in state.data.notary.problem, false);
    assert.equal(JSON.stringify(state).includes("secret subject"), false);
  }
});

test("handleEvaluationProblem preserves Problem Details request id when response header is absent", () => {
  const state = handleEvaluationProblem(
    {
      ...baseState,
      response: {
        statusCode: 409,
        headers: {},
        body: {
          title: "Evidence not available",
          status: 409,
          code: "evidence.not_available",
          request_id: "problem-req-1",
        },
      },
    },
    { claimId: "benefits-person-exists", purpose: "benefits_eligibility" },
  );

  assert.equal(state.data.notary.request_id, "problem-req-1");
});

test("handleEvaluationProblem maps 429 and retryable 503 to retryable infrastructure", () => {
  for (const status of [429, 503]) {
    const state = handleEvaluationProblem(
      {
        ...baseState,
        response: {
          statusCode: status,
          headers: { "retry-after": "3" },
          body: { title: "Retry later", status, code: "rate_limited" },
        },
      },
      { claimId: "claim-a", purpose: "benefits_eligibility" },
    );

    assert.equal(state.data.notary.branch, "retryable_infrastructure");
    assert.equal(state.data.notary.retry_after_seconds, 3);
  }
});

test("handleEvaluationProblem accepts HTTP-date Retry-After values", () => {
  const state = handleEvaluationProblem(
    {
      ...baseState,
      response: {
        statusCode: 429,
        headers: {
          date: "Tue, 01 Jan 2030 00:00:00 GMT",
          "retry-after": "Tue, 01 Jan 2030 00:00:10 GMT",
        },
        body: { title: "Retry later", status: 429, code: "rate_limited" },
      },
    },
    { claimId: "claim-a", purpose: "benefits_eligibility" },
  );

  assert.equal(state.data.notary.branch, "retryable_infrastructure");
  assert.equal(state.data.notary.retry_after_seconds, 10);
});

test("redacted final state contains no forbidden values", () => {
  const prepared = buildEvaluationRequest(baseState, {
    claimId: "benefits-person-exists",
    purpose: "benefits_eligibility",
    target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
  });
  const state = handleEvaluationSuccess(
    {
      ...prepared,
      response: {
        body: {
          results: [{ claim_id: "benefits-person-exists", evaluation_id: "eval-1", satisfied: true }],
        },
      },
    },
    { claimId: "benefits-person-exists" },
  );
  const serialized = JSON.stringify(state);

  assert.equal(serialized.includes("secret-token"), false);
  assert.equal(serialized.includes("person-123"), false);
  assert.equal(serialized.includes("Authorization"), false);
  assert.equal(serialized.includes("notary_request"), false);
});

test("callNotaryEvaluation sends one POST with Notary headers and body", async () => {
  const calls = [];
  const state = await callNotaryEvaluation(baseState, {
    claimId: "benefits-person-exists",
    purpose: "benefits_eligibility",
    target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
    fetch: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({
        results: [{ claim_id: "benefits-person-exists", evaluation_id: "eval-1", satisfied: true }],
      });
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://notary.example/v1/evaluations");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers.Authorization, "Bearer secret-token");
  assert.equal(calls[0].init.headers["Content-Type"], "application/json");
  assert.equal(calls[0].init.headers["Data-Purpose"], "benefits_eligibility");
  assert.equal(calls[0].init.headers["X-Request-Id"], "wf-req-1");
  assert.deepEqual(JSON.parse(calls[0].init.body).claims, ["benefits-person-exists"]);
  assert.equal(state.data.notary.branch, "satisfied");
});

test("callNotaryEvaluation propagates traceparent on the Notary POST", async () => {
  const calls = [];
  await callNotaryEvaluation(
    {
      data: {
        request_id: "wf-req-1",
        national_id: "person-123",
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
      },
      configuration: baseState.configuration,
    },
    {
      claimId: "benefits-person-exists",
      purpose: "benefits_eligibility",
      target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
      fetch: async (url, init) => {
        calls.push({ url, init });
        return jsonResponse({
          results: [{ claim_id: "benefits-person-exists", evaluation_id: "eval-1", satisfied: true }],
        });
      },
    },
  );

  assert.equal(calls[0].init.headers.traceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00");
});

test("callNotaryEvaluation rejects malformed JSON without leaking response text", async () => {
  await assert.rejects(
    () =>
      callNotaryEvaluation(baseState, {
        claimId: "benefits-person-exists",
        purpose: "benefits_eligibility",
        target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
        fetch: async () =>
          new Response("secret subject person-123", {
            status: 502,
            headers: { "content-type": "application/json" },
          }),
      }),
    (error) => error instanceof NotaryCallerError && error.code === "response.invalid_json",
  );
});

test("callNotaryEvaluation maps Problem Details without logging detail", async () => {
  const errors = [];
  const originalError = console.error;
  console.error = (...args) => errors.push(args.join(" "));
  try {
    const state = await callNotaryEvaluation(baseState, {
      claimId: "benefits-person-exists",
      purpose: "benefits_eligibility",
      target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
      fetch: async () =>
        jsonResponse(
          {
            title: "Evidence not available",
            status: 409,
            detail: "secret subject person-123",
            code: "evidence.not_available",
            request_id: "req-evidence",
          },
          { status: 409, headers: { "x-request-id": "req-evidence" } },
        ),
    });

    assert.equal(state.data.notary.branch, "evidence_not_available");
    assert.equal(JSON.stringify(state).includes("secret subject"), false);
    assert.equal(errors.join("\n").includes("secret subject"), false);
  } finally {
    console.error = originalError;
  }
});

test("callNotaryEvaluation maps transport errors without leaking error detail", async () => {
  const state = await callNotaryEvaluation(baseState, {
    claimId: "benefits-person-exists",
    purpose: "benefits_eligibility",
    target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
    fetch: async () => {
      throw new Error("socket failed for secret subject person-123");
    },
  });

  assert.equal(state.data.notary.branch, "retryable_infrastructure");
  assert.equal(state.data.notary.problem.code, "transport.error");
  assert.equal(state.data.notary.problem.retryable, true);
  assert.equal("notary_request" in state.data, false);
  assert.equal(JSON.stringify(state).includes("secret subject"), false);
});

test("callNotaryEvaluation accepts plain object response headers in tests", async () => {
  const state = await callNotaryEvaluation(baseState, {
    claimId: "benefits-person-exists",
    purpose: "benefits_eligibility",
    target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
    fetch: async () => ({
      status: 200,
      headers: { "x-request-id": "plain-header-req" },
      text: async () =>
        JSON.stringify({
          results: [{ claim_id: "benefits-person-exists", evaluation_id: "eval-plain", satisfied: true }],
        }),
    }),
  });

  assert.equal(state.data.notary.request_id, "plain-header-req");
  assert.equal(state.data.notary.evaluation_id, "eval-plain");
});

test("callNotaryEvaluation skips replay without a second POST", async () => {
  const calls = [];
  const first = await callNotaryEvaluation(baseState, {
    claimId: "benefits-person-exists",
    purpose: "benefits_eligibility",
    target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
    fetch: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({
        results: [{ claim_id: "benefits-person-exists", evaluation_id: "eval-1", satisfied: true }],
      });
    },
  });
  const replay = await callNotaryEvaluation(
    {
      ...first,
      configuration: baseState.configuration,
      data: { ...first.data, national_id: "person-123" },
    },
    {
      claimId: "benefits-person-exists",
      purpose: "benefits_eligibility",
      target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "national_id" }] },
      fetch: async (url, init) => {
        calls.push({ url, init });
        throw new Error("fetch should not run on replay");
      },
    },
  );

  assert.equal(calls.length, 1);
  assert.equal(replay.data.notary.evaluation_id, "eval-1");
});

test("redaction removes nested data paths used as source identifiers", () => {
  const prepared = buildEvaluationRequest(
    {
      data: {
        person: { national_id: "person-123", name: "Ada" },
        source_row: { secret: "raw-row" },
      },
      configuration: baseState.configuration,
    },
    {
      claimId: "benefits-person-exists",
      purpose: "benefits_eligibility",
      target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "person.national_id" }] },
      redactDataPaths: ["person", "source_row"],
    },
  );
  const state = handleEvaluationSuccess(
    {
      ...prepared,
      response: {
        body: {
          results: [{ claim_id: "benefits-person-exists", evaluation_id: "eval-1", satisfied: true }],
        },
      },
    },
    {
      claimId: "benefits-person-exists",
      redactDataPaths: ["person", "source_row"],
    },
  );

  const serialized = JSON.stringify(state);
  assert.equal(serialized.includes("person-123"), false);
  assert.equal(serialized.includes("raw-row"), false);
});

test("path helpers reject prototype traversal", () => {
  const state = handleEvaluationSuccess(
    {
      data: {
        safe: { id: "person-123" },
        notary_context: {
          claim_ids: ["claim-a"],
          purpose: "benefits_eligibility",
          redact_data_paths: ["__proto__.polluted", "constructor.prototype.polluted", "safe.id"],
        },
      },
      response: {
        body: {
          results: [{ claim_id: "claim-a", evaluation_id: "eval-1", satisfied: true }],
        },
      },
    },
    { claimId: "claim-a" },
  );

  assert.equal({}.polluted, undefined);
  assert.equal(state.data.safe.id, undefined);
  assert.throws(
    () =>
      buildEvaluationRequest(baseState, {
        claimId: "claim-a",
        purpose: "benefits_eligibility",
        target: { type: "Person", identifiers: [{ scheme: "national_id", valueFrom: "__proto__.national_id" }] },
      }),
    (error) => error instanceof NotaryCallerError && error.code === "target.value_required",
  );
});

test("exported helper functions select, assert, and redact safely", () => {
  const response = {
    body: {
      results: [
        { claim_id: "claim-a", evaluation_id: "eval-a", satisfied: true },
        { claim_id: "claim-b", evaluation_id: "eval-b", satisfied: false },
      ],
    },
  };
  const state = {
    data: {
      notary: {
        branch: "per_claim_routing",
        claims: [
          { claim: "claim-a", satisfied: true },
          { claim: "claim-b", satisfied: true },
        ],
      },
    },
  };

  assert.equal(selectClaimResult(response, "claim-b").evaluation_id, "eval-b");
  assert.equal(assertClaimSatisfied(state, "claim-a"), state);
  assert.equal(assertAllClaimsSatisfied(state, ["claim-a", "claim-b"]), state);
  assert.throws(
    () => selectClaimResult({ body: { results: {} } }, "claim-a"),
    (error) => error instanceof NotaryCallerError && error.code === "response.invalid_results",
  );
  assert.throws(
    () => assertClaimSatisfied({ data: { notary: { claim: "claim-a", satisfied: false } } }, "claim-a"),
    (error) => error instanceof NotaryCallerError && error.code === "claim.not_satisfied",
  );
  assert.deepEqual(redactNotaryResponse({
    body: {
      title: "Problem",
      status: 409,
      code: "evidence.not_available",
      detail: "secret subject person-123",
      request_id: "req-1",
    },
  }), {
    title: "Problem",
    status: 409,
    code: "evidence.not_available",
    request_id: "req-1",
  });
});

test("template uses safe helper operation and does not configure automatic retries", () => {
  const template = readFileSync(new URL("../jobs/evaluate-claim-http.js", import.meta.url), "utf8");

  assert.match(template, /callNotaryEvaluation/);
  assert.match(template, /import\s+\{\s*execute,\s*fn\s*\}\s+from\s+["']@openfn\/language-common["']/);
  assert.doesNotMatch(template, /from\s+["']@openfn\/language-http["']/);
  assert.doesNotMatch(template, /post\(/);
  assert.doesNotMatch(template, /retry/i);
  assert.doesNotMatch(template, /Idempotency-Key/i);
});

test("compiled OpenFn template runs through the OpenFn runtime and calls Notary once", async () => {
  const template = readFileSync(new URL("../jobs/evaluate-claim-http.js", import.meta.url), "utf8");
  const { code } = compile(template);
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return jsonResponse(
      {
        results: [{ claim_id: "benefits-person-exists", evaluation_id: "eval-runtime", satisfied: true }],
      },
      { headers: { "x-request-id": "notary-runtime-req" } },
    );
  };

  try {
    const result = await run(
      {
        workflow: {
          steps: [{ id: "evaluate-claim", expression: code }],
          start: "evaluate-claim",
        },
        options: { start: "evaluate-claim" },
      },
      baseState,
      {
        linker: {
          modules: {
            "@openfn/language-common": { path: resolve(packageRoot, "node_modules/@openfn/language-common") },
            "../src/index.js": { path: packageRoot },
          },
          cacheKey: `openfn-caller-test-${process.pid}-${Date.now()}`,
        },
        statePropsToRemove: [],
      },
    );

    assert.equal(result.errors, undefined);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://notary.example/v1/evaluations");
    assert.equal(JSON.parse(calls[0].init.body).purpose, "benefits_eligibility");
    assert.equal(result.data.notary.branch, "satisfied");
    assert.equal(result.data.notary.evaluation_id, "eval-runtime");
    assert.equal(result.data.notary.request_id, "notary-runtime-req");
    assert.equal("national_id" in result.data, false);
    assert.equal("configuration" in result, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function jsonResponse(body, options = {}) {
  const status = options.status ?? 200;
  const headers = new Headers(options.headers ?? {});
  if (!headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  return new Response(JSON.stringify(body), { status, headers });
}
