import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  authorizeCedar,
  cedarVersion,
  validateCedarArtifacts,
} from "../src/cedar.mjs";
import {
  authorizeClosedYaml,
  loadClosedPolicy,
} from "../src/closed-yaml.mjs";
import { scenarios, trustedFacts } from "../src/scenarios.mjs";

const engines = [
  ["cedar", authorizeCedar],
  ["closed-yaml", authorizeClosedYaml],
];

for (const [engine, authorize] of engines) {
  for (const scenario of scenarios) {
    test(`${engine}: ${scenario.id}`, async () => {
      const result = await authorize(scenario.policy, scenario.input);
      assert.equal(result.allowed, scenario.allowed);
      assert.equal(result.reason, scenario.reason);
      assert.equal(result.engine, engine);
    });
  }
}

test("both candidates have exact decision parity", async () => {
  for (const scenario of scenarios) {
    const cedar = await authorizeCedar(scenario.policy, scenario.input);
    const closed = await authorizeClosedYaml(scenario.policy, scenario.input);
    assert.deepEqual(
      { allowed: cedar.allowed, reason: cedar.reason },
      { allowed: closed.allowed, reason: closed.reason },
      scenario.id,
    );
  }
});

test("the spike executes the pinned Cedar engine", () => {
  assert.equal(cedarVersion(), "4.14.0");
});

test("Cedar schema and policies validate without warnings or errors", async () => {
  const diagnostics = await validateCedarArtifacts();
  assert.deepEqual(diagnostics, {
    schema: { errors: [], warnings: [] },
    subtree: { errors: [], warnings: [] },
    owner: { errors: [], warnings: [] },
  });
});

test("Cedar wrapper denies on invalid policy diagnostics", async () => {
  const result = await authorizeCedar("subtree", scenarios[0].input, {
    policyText: "permit(principal, action, resource) when { principal.noSuchAttribute };",
  });
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "evaluation-error");
  assert.ok(result.diagnostics.length > 0);
});

test("Cedar wrapper denies on invalid schema diagnostics", async () => {
  const result = await authorizeCedar("subtree", scenarios[0].input, {
    schemaText: "namespace Adapter { entity Broken = { missing: }; }",
  });
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "evaluation-error");
  assert.ok(result.diagnostics.length > 0);
});

test("Cedar forbid overrides an otherwise matching permit", async () => {
  const policy = await readFile(
    new URL("../policies/owner.cedar", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(policy, /!context\.explicitDeny/);
  const matchingPermit = scenarios.find(({ id }) => id === "owner").input;
  const permit = await authorizeCedar("owner", matchingPermit);
  const forbidden = await authorizeCedar("owner", {
    ...matchingPermit,
    trustedContext: { ...matchingPermit.trustedContext, explicitDeny: true },
  });
  assert.equal(permit.allowed, true);
  assert.equal(forbidden.allowed, false);
  assert.equal(forbidden.reason, "explicit-deny");
});

test("closed YAML parser rejects unknown, missing, and mistyped members", async () => {
  const valid = await readFile(
    new URL("../policies/closed-subtree.yaml", import.meta.url),
    "utf8",
  );
  const cases = [
    valid.replace("requiredService:", "unexpected: true\n  requiredService:"),
    valid.replace(/\n  relationship:.*\n/, "\n"),
    valid.replace("effect: permit", "effect: 7"),
    valid.replace("denyWhenExplicit: true", "denyWhenExplicit: false"),
    valid.replace("policy:\n", "policy:\n  role: admin\n"),
  ];

  for (const source of cases) {
    assert.throws(() => loadClosedPolicy(source), /closed policy refused/);
  }
});

test("closed YAML parser rejects tagged scalars reported as warnings", async () => {
  const valid = await readFile(
    new URL("../policies/closed-subtree.yaml", import.meta.url),
    "utf8",
  );
  const tagged = valid.replace("effect: permit", "effect: !reviewed permit");
  assert.throws(() => loadClosedPolicy(tagged), /closed policy refused/);
});

test("caller-owned role and relationship claims cannot create authority", async () => {
  const input = {
    ...scenarios.find(({ id }) => id === "otherunit").input,
    request: {
      ...scenarios.find(({ id }) => id === "otherunit").input.request,
      claims: {
        roles: ["admin"],
        verifiedPerson: true,
        service: "registry-reader",
        organisationUnit: "ou-root",
        ownerPrincipalId: "person-alice",
      },
    },
  };

  for (const [, authorize] of engines) {
    const result = await authorize("subtree", input);
    assert.equal(result.allowed, false);
    assert.equal(result.reason, "no-matching-permit");
  }
});

test("invalid trusted facts are refused before policy evaluation", async () => {
  const invalid = structuredClone(trustedFacts);
  invalid.principals[0].verifiedPerson = "yes";
  const input = {
    ...scenarios[0].input,
    trustedFacts: invalid,
  };

  for (const [, authorize] of engines) {
    const result = await authorize("subtree", input);
    assert.equal(result.allowed, false);
    assert.equal(result.reason, "invalid-trusted-facts");
  }
});

test("malformed trusted-fact list entries fail closed without throwing", async () => {
  const mutations = [
    (facts) => {
      facts.principals[0] = null;
    },
    (facts) => {
      facts.records[0] = 7;
    },
    (facts) => {
      facts.organisationUnits[0] = "ou-root";
    },
    (facts) => {
      facts.principals = null;
    },
  ];
  for (const mutate of mutations) {
    const facts = structuredClone(trustedFacts);
    mutate(facts);
    const input = { ...scenarios[0].input, trustedFacts: facts };
    for (const [, authorize] of engines) {
      const result = await authorize("subtree", input);
      assert.equal(result.allowed, false);
      assert.equal(result.reason, "invalid-trusted-facts");
    }
  }
});
