permit(
  principal is Adapter::Principal,
  action == Adapter::Action::"records-get",
  resource is Adapter::Record
)
when {
  principal.verifiedPerson &&
  context.actingService == "registry-reader" &&
  resource.organisationUnit in principal.organisationUnit
};

forbid(principal, action, resource)
when { context.explicitDeny };
