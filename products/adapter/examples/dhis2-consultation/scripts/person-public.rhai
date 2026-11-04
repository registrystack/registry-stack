// The public person view. Source attributes are intentionally not copied.
fn project_person_public(source) {
    #{
        source: #{
            id: source.trackedEntity,
            type: source.trackedEntityType
        },
        registration: #{
            organisationUnit: source.orgUnit,
            createdAt: source.createdAt,
            updatedAt: source.updatedAt
        }
    }
}
