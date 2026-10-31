import cedar from "@cedar-policy/cedar-wasm/nodejs";
import { readFileSync } from "node:fs";

import { prepareTrustedInput } from "./trusted-input.mjs";

const policyUrls = {
  subtree: new URL("../policies/subtree.cedar", import.meta.url),
  owner: new URL("../policies/owner.cedar", import.meta.url),
};
const schema = readFileSync(new URL("../policies/schema.cedarschema", import.meta.url), "utf8");

function uid(type, id) {
  return { type: `Adapter::${type}`, id };
}

function diagnostics(answer) {
  if (answer.type === "failure") return [...answer.errors, ...(answer.warnings ?? [])];
  return [
    ...(answer.validationErrors ?? []).map(({ error }) => error),
    ...(answer.validationWarnings ?? []).map(({ error }) => error),
    ...(answer.otherWarnings ?? []),
  ];
}

function policyText(name) {
  const url = policyUrls[name];
  if (!url) throw new Error(`unknown policy: ${name}`);
  return readFileSync(url, "utf8");
}

function validatePolicy(text, schemaText) {
  const parsedSchema = cedar.checkParseSchema(schemaText);
  if (parsedSchema.type === "failure") {
    return { errors: parsedSchema.errors, warnings: parsedSchema.warnings ?? [] };
  }
  const parsed = cedar.checkParsePolicySet({ staticPolicies: text });
  if (parsed.type === "failure") {
    return { errors: parsed.errors, warnings: parsed.warnings ?? [] };
  }
  const validated = cedar.validate({
    schema: schemaText,
    policies: { staticPolicies: text },
    validationSettings: { mode: "strict" },
  });
  if (validated.type === "failure") {
    return { errors: validated.errors, warnings: validated.warnings };
  }
  return {
    errors: validated.validationErrors.map(({ error }) => error),
    warnings: [
      ...validated.validationWarnings.map(({ error }) => error),
      ...validated.otherWarnings,
    ],
  };
}

function cedarEntities(facts) {
  return [
    ...facts.organisationUnits.map((unit) => ({
      uid: uid("OrganisationUnit", unit.id),
      attrs: {},
      parents: unit.parent ? [uid("OrganisationUnit", unit.parent)] : [],
    })),
    ...facts.principals.map((principal) => ({
      uid: uid("Principal", principal.id),
      attrs: {
        verifiedPerson: principal.verifiedPerson,
        organisationUnit: uid("OrganisationUnit", principal.organisationUnit),
      },
      parents: [],
    })),
    ...facts.records.map((record) => ({
      uid: uid("Record", record.id),
      attrs: {
        ownerPrincipal: uid("Principal", record.ownerPrincipalId),
        organisationUnit: uid("OrganisationUnit", record.organisationUnit),
      },
      parents: [],
    })),
  ];
}

export function cedarVersion() {
  return cedar.getCedarVersion();
}

export async function validateCedarArtifacts() {
  const parsedSchema = cedar.checkParseSchema(schema);
  const schemaErrors = parsedSchema.type === "failure" ? parsedSchema.errors : [];
  const result = { schema: { errors: schemaErrors, warnings: [] } };
  for (const name of Object.keys(policyUrls)) {
    const validated = cedar.validate({
      schema,
      policies: { staticPolicies: policyText(name) },
      validationSettings: { mode: "strict" },
    });
    if (validated.type === "failure") {
      result[name] = { errors: validated.errors, warnings: validated.warnings };
    } else {
      result[name] = {
        errors: validated.validationErrors,
        warnings: [...validated.validationWarnings, ...validated.otherWarnings],
      };
    }
  }
  return result;
}

export async function authorizeCedar(name, input, options = {}) {
  const prepared = prepareTrustedInput(input);
  if (!prepared.ok) return { engine: "cedar", ...prepared };

  try {
    const text = options.policyText ?? policyText(name);
    const schemaText = options.schemaText ?? schema;
    const policyDiagnostics = validatePolicy(text, schemaText);
    if (policyDiagnostics.errors.length > 0) {
      return {
        engine: "cedar",
        allowed: false,
        reason: "evaluation-error",
        diagnostics: [...policyDiagnostics.errors, ...policyDiagnostics.warnings],
      };
    }

    const answer = cedar.isAuthorized({
      principal: uid("Principal", prepared.trustedContext.authenticatedPrincipalId),
      action: uid("Action", prepared.request.operation),
      resource: uid("Record", prepared.request.resourceId),
      context: {
        actingService: prepared.trustedContext.actingService,
        explicitDeny: prepared.trustedContext.explicitDeny,
      },
      schema: schemaText,
      validateRequest: true,
      policies: { staticPolicies: text },
      entities: cedarEntities(prepared.facts),
    });

    if (answer.type === "failure" || answer.response.diagnostics.errors.length > 0) {
      return {
        engine: "cedar",
        allowed: false,
        reason: "evaluation-error",
        diagnostics:
          answer.type === "failure" ? diagnostics(answer) : answer.response.diagnostics.errors,
      };
    }

    const allowed = answer.response.decision === "allow";
    return {
      engine: "cedar",
      allowed,
      reason: allowed
        ? "permit"
        : prepared.trustedContext.explicitDeny
          ? "explicit-deny"
          : "no-matching-permit",
      diagnostics: [...policyDiagnostics.warnings, ...answer.warnings],
    };
  } catch {
    return {
      engine: "cedar",
      allowed: false,
      reason: "evaluation-error",
      diagnostics: [{ message: "Cedar invocation failed before returning diagnostics." }],
    };
  }
}
