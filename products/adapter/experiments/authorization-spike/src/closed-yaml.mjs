import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";

import { isDescendantOrSelf, prepareTrustedInput } from "./trusted-input.mjs";

const policyUrls = {
  subtree: new URL("../policies/closed-subtree.yaml", import.meta.url),
  owner: new URL("../policies/closed-owner.yaml", import.meta.url),
};

function refuse(message) {
  throw new Error(`closed policy refused: ${message}`);
}

function object(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    refuse(`${label} must be a mapping`);
  }
}

function exactKeys(value, expected, label) {
  object(value, label);
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    refuse(`${label} has missing or unknown members`);
  }
}

function exactString(value, expected, label) {
  if (typeof value !== "string" || value !== expected) {
    refuse(`${label} must be ${expected}`);
  }
}

export function loadClosedPolicy(source) {
  const document = parseDocument(source, {
    merge: false,
    schema: "core",
    uniqueKeys: true,
    version: "1.2",
  });
  if (document.errors.length > 0) refuse("YAML syntax is invalid");
  if (document.warnings.length > 0) refuse("YAML warnings are not accepted");
  let value;
  try {
    value = document.toJS({ maxAliasCount: 0 });
  } catch {
    refuse("aliases are not accepted");
  }
  exactKeys(value, ["apiVersion", "kind", "policy"], "document");
  exactString(value.apiVersion, "authorization-spike/v1", "apiVersion");
  exactString(value.kind, "ClosedAuthorizationPolicy", "kind");
  exactKeys(
    value.policy,
    [
      "denyWhenExplicit",
      "effect",
      "id",
      "operation",
      "relationship",
      "requiredService",
      "requireVerifiedPerson",
    ],
    "policy",
  );
  if (typeof value.policy.id !== "string" || value.policy.id.length === 0) {
    refuse("policy.id must be a non-empty string");
  }
  exactString(value.policy.effect, "permit", "policy.effect");
  exactString(value.policy.operation, "records-get", "policy.operation");
  if (
    value.policy.relationship !== "organisation-unit-subtree" &&
    value.policy.relationship !== "source-record-owner"
  ) {
    refuse("policy.relationship is not supported");
  }
  exactString(value.policy.requiredService, "registry-reader", "policy.requiredService");
  if (value.policy.requireVerifiedPerson !== true) {
    refuse("policy.requireVerifiedPerson must be true");
  }
  if (value.policy.denyWhenExplicit !== true) {
    refuse("policy.denyWhenExplicit must be true");
  }
  return Object.freeze(value.policy);
}

function readPolicy(name) {
  const url = policyUrls[name];
  if (!url) throw new Error(`unknown policy: ${name}`);
  const policy = loadClosedPolicy(readFileSync(url, "utf8"));
  const expected = name === "subtree" ? "organisation-unit-subtree" : "source-record-owner";
  if (policy.relationship !== expected) refuse("selected policy has the wrong relationship");
  return policy;
}

export async function authorizeClosedYaml(name, input) {
  const prepared = prepareTrustedInput(input);
  if (!prepared.ok) return { engine: "closed-yaml", ...prepared };

  let policy;
  try {
    policy = readPolicy(name);
  } catch (error) {
    return {
      engine: "closed-yaml",
      allowed: false,
      reason: "evaluation-error",
      diagnostics: [error.message],
    };
  }

  if (prepared.trustedContext.explicitDeny) {
    return { engine: "closed-yaml", allowed: false, reason: "explicit-deny", diagnostics: [] };
  }
  const commonPermit =
    prepared.request.operation === policy.operation &&
    prepared.principal.verifiedPerson === policy.requireVerifiedPerson &&
    prepared.trustedContext.actingService === policy.requiredService;
  const relationshipPermit =
    policy.relationship === "source-record-owner"
      ? prepared.resource.ownerPrincipalId === prepared.principal.id
      : isDescendantOrSelf(
          prepared.resource.organisationUnit,
          prepared.principal.organisationUnit,
          prepared.hierarchy.parents,
        );
  const allowed = commonPermit && relationshipPermit;
  return {
    engine: "closed-yaml",
    allowed,
    reason: allowed ? "permit" : "no-matching-permit",
    diagnostics: [],
  };
}
