class TrustedInputError extends Error {}

function object(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TrustedInputError(`${label} must be an object`);
  }
}

function exactKeys(value, keys, label) {
  object(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TrustedInputError(`${label} has missing or unknown members`);
  }
}

function nonemptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TrustedInputError(`${label} must be a non-empty string`);
  }
}

function uniqueById(values, label) {
  if (!Array.isArray(values)) {
    throw new TrustedInputError(`${label} must be a list`);
  }
  const ids = new Set();
  for (const value of values) {
    object(value, `${label} item`);
    nonemptyString(value.id, `${label}.id`);
    if (ids.has(value.id)) {
      throw new TrustedInputError(`${label} contains a duplicate id`);
    }
    ids.add(value.id);
  }
  return ids;
}

function validateOrganisationUnits(units) {
  const ids = uniqueById(units, "organisationUnits");
  const parents = new Map();
  for (const unit of units) {
    const keys = unit.parent === undefined ? ["id"] : ["id", "parent"];
    exactKeys(unit, keys, "organisationUnit");
    if (unit.parent !== undefined) {
      nonemptyString(unit.parent, "organisationUnit.parent");
      if (!ids.has(unit.parent) || unit.parent === unit.id) {
        throw new TrustedInputError("organisationUnit parent is unknown or self-referential");
      }
      parents.set(unit.id, unit.parent);
    }
  }
  for (const id of ids) {
    const seen = new Set([id]);
    let current = id;
    while (parents.has(current)) {
      current = parents.get(current);
      if (seen.has(current)) {
        throw new TrustedInputError("organisationUnit hierarchy contains a cycle");
      }
      seen.add(current);
    }
  }
  return { ids, parents };
}

export function prepareTrustedInput(input) {
  try {
    exactKeys(input, ["request", "trustedContext", "trustedFacts"], "input");
    exactKeys(
      input.request,
      ["principalId", "operation", "resourceId", "claims"],
      "request",
    );
    nonemptyString(input.request.principalId, "request.principalId");
    nonemptyString(input.request.operation, "request.operation");
    nonemptyString(input.request.resourceId, "request.resourceId");
    object(input.request.claims, "request.claims");
    exactKeys(
      input.trustedContext,
      ["actingService", "authenticatedPrincipalId", "explicitDeny"],
      "trustedContext",
    );
    nonemptyString(input.trustedContext.actingService, "trustedContext.actingService");
    nonemptyString(
      input.trustedContext.authenticatedPrincipalId,
      "trustedContext.authenticatedPrincipalId",
    );
    if (typeof input.trustedContext.explicitDeny !== "boolean") {
      throw new TrustedInputError("trustedContext.explicitDeny must be a boolean");
    }

    const facts = input.trustedFacts;
    exactKeys(facts, ["organisationUnits", "principals", "records"], "trustedFacts");
    const hierarchy = validateOrganisationUnits(facts.organisationUnits);
    const principalIds = uniqueById(facts.principals, "principals");
    const recordIds = uniqueById(facts.records, "records");

    for (const principal of facts.principals) {
      exactKeys(
        principal,
        ["id", "organisationUnit", "verifiedPerson"],
        "principal",
      );
      if (typeof principal.verifiedPerson !== "boolean") {
        throw new TrustedInputError("principal.verifiedPerson must be a boolean");
      }
      nonemptyString(principal.organisationUnit, "principal.organisationUnit");
      if (!hierarchy.ids.has(principal.organisationUnit)) {
        throw new TrustedInputError("principal organisationUnit is unknown");
      }
    }

    for (const record of facts.records) {
      exactKeys(
        record,
        ["id", "organisationUnit", "ownerPrincipalId"],
        "record",
      );
      nonemptyString(record.ownerPrincipalId, "record.ownerPrincipalId");
      nonemptyString(record.organisationUnit, "record.organisationUnit");
      if (!principalIds.has(record.ownerPrincipalId)) {
        throw new TrustedInputError("record ownerPrincipalId is unknown");
      }
      if (!hierarchy.ids.has(record.organisationUnit)) {
        throw new TrustedInputError("record organisationUnit is unknown");
      }
    }

    if (input.request.principalId !== input.trustedContext.authenticatedPrincipalId) {
      return { ok: false, allowed: false, reason: "principal-mismatch", diagnostics: [] };
    }

    const principal = facts.principals.find(
      ({ id }) => id === input.trustedContext.authenticatedPrincipalId,
    );
    const resource = facts.records.find(({ id }) => id === input.request.resourceId);
    if (!principal || !resource) {
      return { ok: false, allowed: false, reason: "unknown-entity", diagnostics: [] };
    }

    return {
      ok: true,
      request: input.request,
      trustedContext: input.trustedContext,
      facts,
      principal,
      resource,
      hierarchy,
      principalIds,
      recordIds,
    };
  } catch (error) {
    if (!(error instanceof TrustedInputError)) {
      throw error;
    }
    return {
      ok: false,
      allowed: false,
      reason: "invalid-trusted-facts",
      diagnostics: [error.message],
    };
  }
}

export function isDescendantOrSelf(descendant, ancestor, parents) {
  let current = descendant;
  while (current !== undefined) {
    if (current === ancestor) return true;
    current = parents.get(current);
  }
  return false;
}
