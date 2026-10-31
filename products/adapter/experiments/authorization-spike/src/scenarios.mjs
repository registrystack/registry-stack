export const trustedFacts = Object.freeze({
  principals: [
    {
      id: "person-alice",
      verifiedPerson: true,
      organisationUnit: "ou-root",
    },
    {
      id: "person-bob",
      verifiedPerson: true,
      organisationUnit: "ou-other",
    },
    {
      id: "person-carol",
      verifiedPerson: false,
      organisationUnit: "ou-root",
    },
  ],
  records: [
    {
      id: "record-child",
      ownerPrincipalId: "person-alice",
      organisationUnit: "ou-child",
    },
    {
      id: "record-root",
      ownerPrincipalId: "person-bob",
      organisationUnit: "ou-root",
    },
    {
      id: "record-other",
      ownerPrincipalId: "person-bob",
      organisationUnit: "ou-other",
    },
    {
      id: "record-grandchild",
      ownerPrincipalId: "person-bob",
      organisationUnit: "ou-grandchild",
    },
  ],
  organisationUnits: [
    { id: "ou-root" },
    { id: "ou-child", parent: "ou-root" },
    { id: "ou-grandchild", parent: "ou-child" },
    { id: "ou-other" },
  ],
});

function input(principalId, resourceId, options = {}) {
  return {
    request: {
      principalId,
      operation: options.operation ?? "records-get",
      resourceId,
      claims: options.claims ?? {},
    },
    trustedContext: {
      actingService: options.actingService ?? "registry-reader",
      authenticatedPrincipalId: options.authenticatedPrincipalId ?? principalId,
      explicitDeny: options.explicitDeny ?? false,
    },
    trustedFacts: options.trustedFacts ?? trustedFacts,
  };
}

const missingVerified = structuredClone(trustedFacts);
delete missingVerified.principals[0].verifiedPerson;

const cyclicHierarchy = structuredClone(trustedFacts);
cyclicHierarchy.organisationUnits[0].parent = "ou-child";

const unknownParent = structuredClone(trustedFacts);
unknownParent.organisationUnits[1].parent = "ou-missing";

export const scenarios = Object.freeze([
  {
    id: "descendant",
    policy: "subtree",
    input: input("person-alice", "record-child"),
    allowed: true,
    reason: "permit",
  },
  {
    id: "sameunit",
    policy: "subtree",
    input: input("person-alice", "record-root"),
    allowed: true,
    reason: "permit",
  },
  {
    id: "deeper-descendant",
    policy: "subtree",
    input: input("person-alice", "record-grandchild"),
    allowed: true,
    reason: "permit",
  },
  {
    id: "otherunit",
    policy: "subtree",
    input: input("person-alice", "record-other"),
    allowed: false,
    reason: "no-matching-permit",
  },
  {
    id: "owner",
    policy: "owner",
    input: input("person-alice", "record-child"),
    allowed: true,
    reason: "permit",
  },
  {
    id: "nonowner",
    policy: "owner",
    input: input("person-bob", "record-child"),
    allowed: false,
    reason: "no-matching-permit",
  },
  {
    id: "denydefault",
    policy: "owner",
    input: input("person-bob", "record-child"),
    allowed: false,
    reason: "no-matching-permit",
  },
  {
    id: "explicit-deny",
    policy: "owner",
    input: input("person-alice", "record-child", { explicitDeny: true }),
    allowed: false,
    reason: "explicit-deny",
  },
  {
    id: "wrongoperation",
    policy: "owner",
    input: input("person-alice", "record-child", { operation: "records-update" }),
    allowed: false,
    reason: "no-matching-permit",
  },
  {
    id: "false-verified-person",
    policy: "subtree",
    input: input("person-carol", "record-root"),
    allowed: false,
    reason: "no-matching-permit",
  },
  {
    id: "wrong-acting-service",
    policy: "subtree",
    input: input("person-alice", "record-child", { actingService: "other-service" }),
    allowed: false,
    reason: "no-matching-permit",
  },
  {
    id: "caller-selects-another-known-principal",
    policy: "owner",
    input: input("person-bob", "record-other", {
      authenticatedPrincipalId: "person-alice",
    }),
    allowed: false,
    reason: "principal-mismatch",
  },
  {
    id: "missing-trusted-attribute",
    policy: "subtree",
    input: input("person-alice", "record-child", { trustedFacts: missingVerified }),
    allowed: false,
    reason: "invalid-trusted-facts",
  },
  {
    id: "unknown-principal",
    policy: "owner",
    input: input("person-unknown", "record-child"),
    allowed: false,
    reason: "unknown-entity",
  },
  {
    id: "unknown-resource",
    policy: "owner",
    input: input("person-alice", "record-unknown"),
    allowed: false,
    reason: "unknown-entity",
  },
  {
    id: "cyclic-organisation-hierarchy",
    policy: "subtree",
    input: input("person-alice", "record-child", { trustedFacts: cyclicHierarchy }),
    allowed: false,
    reason: "invalid-trusted-facts",
  },
  {
    id: "unknown-organisation-parent",
    policy: "subtree",
    input: input("person-alice", "record-child", { trustedFacts: unknownParent }),
    allowed: false,
    reason: "invalid-trusted-facts",
  },
]);
