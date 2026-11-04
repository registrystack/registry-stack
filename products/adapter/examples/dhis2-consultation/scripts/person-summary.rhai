// A second public view over the same acquired DHIS2 entity. Source attributes
// are intentionally not copied.
fn project_person_summary(source) {
    #{
        organisationUnit: source.orgUnit,
        lastChangedAt: source.updatedAt
    }
}
