// SPDX-License-Identifier: Apache-2.0
//! Edges declared by BReg, Casework, Scheduling, and Messaging authoring contracts.

use super::spec::{DocumentRules, FileRule, NameRule as N, ProductKind, ProductSpec, Scope};

const BREG_DECLARATIONS: &[N] = &[
    N::global("registry/id", "BReg registry"),
    N::global("entities/*/id", "BReg entity"),
    N::scoped("entities/*/fields/*/id", "BReg field", 1, "id"),
    N::scoped("entities/*/attachments/*/id", "BReg attachment", 1, "id"),
    N::scoped("entities/*/attachments/*/id", "BReg field", 1, "id"),
    N::scoped("entities/*/derived/*/fields/*/id", "BReg field", 3, "id"),
    N::scoped(
        "extendEntities/*/derived/*/fields/*/id",
        "BReg field",
        0,
        "entity",
    ),
    N::scoped(
        "entities/*/selectorProfiles/*/id",
        "BReg selector profile",
        1,
        "id",
    ),
    N::scoped("entities/*/readPaths/*/id", "BReg read path", 1, "id"),
    N::scoped(
        "entities/*/accessProfiles/*/id",
        "BReg entity access profile",
        1,
        "id",
    ),
    N::scoped("entities/*/indexes/*/id", "BReg index", 1, "id"),
    N::scoped("entities/*/derived/*/id", "BReg derivation", 1, "id"),
    N::scoped("extendEntities/*/fields/*/id", "BReg field", 0, "entity"),
    N::scoped(
        "extendEntities/*/selectorProfiles/*/id",
        "BReg selector profile",
        0,
        "entity",
    ),
    N::scoped(
        "extendEntities/*/readPaths/*/id",
        "BReg read path",
        0,
        "entity",
    ),
    N::global("actions/*/id", "BReg action"),
    N::scoped("actions/*/inputs/*/id", "BReg action input", 1, "id"),
    N::scoped("actions/*/effects/*/id", "BReg action effect", 1, "id"),
    N::scoped(
        "actions/*/handler/writes/*/id",
        "BReg action effect",
        3,
        "id",
    ),
    N::global("accessProfiles/*/id", "BReg access profile"),
    N::global("vocabularies/*/id", "BReg vocabulary"),
    N::global("evidenceProviders/*/id", "BReg Evidence provider"),
    N::global(
        "recipients/organizations/*/id",
        "BReg recipient organization",
    ),
    N::global("recipients/groups/*/id", "BReg recipient group"),
    N::global("manifestProjection/datasets/*/id", "BReg dataset"),
    N::global("manifestProjection/dataServices/*/id", "BReg data service"),
];

const BREG_REFERENCES: &[N] = &[
    N::global("modules/*/id", "BReg module"),
    N::global("dependencies/*", "BReg module"),
    N::global("extendEntities/*/entity", "BReg entity"),
    N::global("entities/*/fields/*/target", "BReg entity"),
    N::global("entities/*/fields/*/vocabulary", "BReg vocabulary"),
    N::global("extendEntities/*/fields/*/target", "BReg entity"),
    N::global("extendEntities/*/fields/*/vocabulary", "BReg vocabulary"),
    N {
        reports_unresolved: false,
        ..N::global("entities/*/primaryDataset", "BReg dataset")
    },
    N::scoped(
        "entities/*/selectorProfiles/*/fields/*",
        "BReg field",
        2,
        "id",
    ),
    N::scoped("entities/*/constraints/*/fields/*", "BReg field", 2, "id"),
    N::scoped("entities/*/constraints/*/left", "BReg field", 1, "id"),
    N::scoped("entities/*/constraints/*/right", "BReg field", 1, "id"),
    N::scoped("entities/*/constraints/*/field", "BReg field", 1, "id"),
    N::scoped("entities/*/constraints/*/startField", "BReg field", 1, "id"),
    N::scoped("entities/*/constraints/*/endField", "BReg field", 1, "id"),
    N::scoped(
        "entities/*/constraints/*/scopeFields/*",
        "BReg field",
        2,
        "id",
    ),
    N::scoped(
        "entities/*/constraints/*/when/*/field",
        "BReg field",
        3,
        "id",
    ),
    N::scoped("entities/*/indexes/*/fields/*", "BReg field", 2, "id"),
    N::global("entities/*/readPaths/*/through", "BReg entity"),
    N::global("entities/*/readPaths/*/to", "BReg entity"),
    N::scoped("entities/*/geojson/geometryField", "BReg field", 0, "id"),
    N::scoped("entities/*/temporal/startField", "BReg field", 0, "id"),
    N::scoped("entities/*/temporal/endField", "BReg field", 0, "id"),
    N::scoped("entities/*/temporal/scopeFields/*", "BReg field", 0, "id"),
    N::scoped(
        "entities/*/accessProfiles/*/readableFields/*",
        "BReg field",
        2,
        "id",
    ),
    N::scoped(
        "entities/*/accessProfiles/*/writableFields/*",
        "BReg field",
        2,
        "id",
    ),
    N::scoped(
        "entities/*/accessProfiles/*/filterableFields/*",
        "BReg field",
        2,
        "id",
    ),
    N::scoped(
        "entities/*/accessProfiles/*/sortableFields/*",
        "BReg field",
        2,
        "id",
    ),
    N::scoped(
        "entities/*/accessProfiles/*/rowBoundaries/*/field",
        "BReg field",
        3,
        "id",
    ),
    N::global("accessProfiles/*/permissions/*/entity", "BReg entity"),
    N::global("accessProfiles/*/permissions/*/action", "BReg action"),
    N::global(
        "accessProfiles/*/permissions/*/targets/*/entity",
        "BReg entity",
    ),
    N::scoped(
        "accessProfiles/*/permissions/*/results/*",
        "BReg action effect",
        0,
        "action",
    ),
    N::scoped(
        "accessProfiles/*/permissions/*/readableFields/*",
        "BReg field",
        0,
        "entity",
    ),
    N::scoped(
        "accessProfiles/*/permissions/*/writableFields/*",
        "BReg field",
        0,
        "entity",
    ),
    N::scoped(
        "accessProfiles/*/permissions/*/filterableFields/*",
        "BReg field",
        0,
        "entity",
    ),
    N::scoped(
        "accessProfiles/*/permissions/*/sortableFields/*",
        "BReg field",
        0,
        "entity",
    ),
    N::scoped(
        "accessProfiles/*/permissions/*/rowBoundaries/*/field",
        "BReg field",
        0,
        "entity",
    ),
    N::scoped(
        "accessProfiles/*/permissions/*/targets/*/rowBoundaries/*/field",
        "BReg field",
        0,
        "entity",
    ),
    N::global("actions/*/inputs/*/target", "BReg entity"),
    N::global("actions/*/inputs/*/vocabulary", "BReg vocabulary"),
    N::global("actions/*/effects/*/target/entity", "BReg entity"),
    N::global("actions/*/handler/writes/*/target/entity", "BReg entity"),
    N::scoped(
        "actions/*/handler/writes/*/fields/*",
        "BReg field",
        0,
        "target.entity",
    ),
    N::scoped(
        "actions/*/effects/*/set/$key",
        "BReg field",
        0,
        "target.entity",
    ),
    N::scoped(
        "actions/*/effects/*/set/*/fromField",
        "BReg action input",
        4,
        "id",
    ),
    N::scoped(
        "actions/*/effects/*/set/*/fromEffect",
        "BReg action effect",
        4,
        "id",
    ),
    N::global("manifestProjection/accessProfile", "BReg access profile"),
    N::global(
        "manifestProjection/dataServices/*/servesDatasets/*",
        "BReg dataset",
    ),
    N::global("manifestProjection/distributions/*/dataset", "BReg dataset"),
    N::global(
        "manifestProjection/distributions/*/accessService",
        "BReg data service",
    ),
];

const BREG_FILES: &[FileRule] = &[
    FileRule {
        path: "modules/*/id",
        prefix: "modules/",
        suffix: "/module.yaml",
        relative_to_document: false,
        index_target: true,
    },
    FileRule::root("actions/*/handler/script", false),
    FileRule::root("actions/*/handler/module", false),
    FileRule::root("entities/*/changeRequest/planner/script", false),
    FileRule::root("entities/*/hooks/*/handler/script", false),
    FileRule::root("entities/*/hooks/*/handler/module", false),
    FileRule::root("entities/*/derived/*/sql", false),
    FileRule::root("extendEntities/*/derived/*/sql", false),
];

const BREG_MODULE_FILES: &[FileRule] = &[
    FileRule {
        relative_to_document: true,
        ..FileRule::root("actions/*/handler/script", false)
    },
    FileRule {
        relative_to_document: true,
        ..FileRule::root("actions/*/handler/module", false)
    },
    FileRule {
        relative_to_document: true,
        ..FileRule::root("entities/*/changeRequest/planner/script", false)
    },
    FileRule {
        relative_to_document: true,
        ..FileRule::root("entities/*/hooks/*/handler/script", false)
    },
    FileRule {
        relative_to_document: true,
        ..FileRule::root("entities/*/hooks/*/handler/module", false)
    },
    FileRule {
        relative_to_document: true,
        ..FileRule::root("entities/*/derived/*/sql", false)
    },
    FileRule {
        relative_to_document: true,
        ..FileRule::root("extendEntities/*/derived/*/sql", false)
    },
];

const CASEWORK_DECLARATIONS: &[N] = &[
    N::global("casework/id", "Casework project"),
    N::global("sources/*/id", "Casework source"),
    N::global("queues/*/id", "Casework queue"),
    N::global("accessProfiles/*/id", "Casework access profile"),
    N::global("reviewKinds/*/id", "Casework review kind"),
    N::scoped(
        "reviewKinds/*/stages/*/id",
        "Casework review stage",
        1,
        "id",
    ),
    N::scoped(
        "reviewKinds/*/outcomes/*/id",
        "Casework review outcome",
        1,
        "id",
    ),
    N::global("reviewProducers/*/id", "Casework review producer"),
    N::global("calendars/*/id", "Casework calendar"),
    N::global("clocks/*/id", "Casework clock"),
    N::global("taskTemplates/*/id", "Casework task template"),
];
const CASEWORK_REFERENCES: &[N] = &[
    N {
        reports_unresolved: false,
        ..N::scoped(
            "sources/*/requests/*/entity",
            "Casework request entity",
            1,
            "id",
        )
    },
    N {
        scope: Scope::Composite(&[(2, "id"), (0, "entity")]),
        reports_unresolved: false,
        ..N::global("sources/*/requests/*/projection/*", "Casework source field")
    },
    N {
        scope: Scope::Composite(&[(2, "id"), (0, "entity")]),
        reports_unresolved: false,
        ..N::global(
            "sources/*/requests/*/contextProjection/*",
            "Casework source field",
        )
    },
    N {
        scope: Scope::Composite(&[(5, "id"), (0, "entity")]),
        reports_unresolved: false,
        ..N::global(
            "sources/*/requests/*/routing/*/when/fields/$key",
            "Casework source field",
        )
    },
    N::global("sources/*/requests/*/queue", "Casework queue"),
    N::global("sources/*/requests/*/clock", "Casework clock"),
    N::global("reviewKinds/*/stages/*/queue", "Casework queue"),
    N::global(
        "reviewKinds/*/stages/*/decidingProfiles/*",
        "Casework access profile",
    ),
    N::global("reviewProducers/*/profile", "Casework access profile"),
    N::global(
        "reviewProducers/*/initiatorProfile",
        "Casework access profile",
    ),
    N::global("reviewProducers/*/kinds/*", "Casework review kind"),
    N {
        reports_unresolved: false,
        ..N::global("reviewProducers/*/sourceNamespaces/*", "Casework source")
    },
    N::global("clocks/*/calendar", "Casework calendar"),
    N::global("clocks/*/steps/*/action/reassign/queue", "Casework queue"),
    N::global("sources/*/requests/*/routing/*/queue", "Casework queue"),
    N::global(
        "taskTemplates/*/eligibleProfiles/*",
        "Casework access profile",
    ),
    N::global("taskTemplates/*/source", "Casework source"),
    N::global("taskTemplates/*/reviewKinds/*", "Casework review kind"),
    N::global("sources/$key", "Casework source"),
];

const SCHEDULING_DECLARATIONS: &[N] = &[
    N::global("scheduling/id", "Scheduling project"),
    N::global("services/*/id", "Scheduling service"),
    N::global("offerings/*/id", "Scheduling offering"),
    N::global("openings/*/id", "Scheduling opening"),
    N::global("holidaySets/*/id", "Scheduling holiday set"),
];
const SCHEDULING_REFERENCES: &[N] = &[
    N::global("offerings/*/service", "Scheduling service"),
    N::global("openings/*/holidaySet", "Scheduling holiday set"),
    // These names are runtime records. They remain navigable to records.yaml when available,
    // but a policy's compiler cannot require local development records to exist.
    N {
        reports_unresolved: false,
        ..N::global("offerings/*/location", "Scheduling location")
    },
    N {
        reports_unresolved: false,
        ..N::global("offerings/*/exactTime/pool", "Scheduling resource pool")
    },
    N {
        reports_unresolved: false,
        ..N::global("offerings/*/arrival/window", "Scheduling arrival window")
    },
    N {
        reports_unresolved: false,
        ..N::global("openings/*/location", "Scheduling location")
    },
];

const BREG_DOCUMENTS: &[DocumentRules] = &[
    DocumentRules {
        pattern: "@document",
        declarations: BREG_DECLARATIONS,
        references: BREG_REFERENCES,
        files: BREG_FILES,
    },
    DocumentRules {
        pattern: "modules/*/module.yaml",
        declarations: &[N::global("id", "BReg module")],
        references: &[],
        files: &[],
    },
    DocumentRules {
        pattern: "modules/*/module.yaml",
        declarations: BREG_DECLARATIONS,
        references: BREG_REFERENCES,
        files: BREG_MODULE_FILES,
    },
];

const CASEWORK_DOCUMENTS: &[DocumentRules] = &[
    DocumentRules {
        pattern: "@document",
        declarations: CASEWORK_DECLARATIONS,
        references: CASEWORK_REFERENCES,
        files: &[FileRule::root("sources/*/description", true)],
    },
    DocumentRules {
        pattern: "runtime.yaml",
        declarations: &[],
        references: &[N::global("sources/$key", "Casework source")],
        files: &[],
    },
    DocumentRules {
        pattern: "@source-description",
        declarations: &[
            N::scoped(
                "requests/*/requestEntity",
                "Casework request entity",
                0,
                "sourceId",
            ),
            N {
                scope: Scope::Composite(&[(0, "sourceId"), (0, "requestEntity")]),
                ..N::global("requests/*/fields/*/field", "Casework source field")
            },
            N::scoped(
                "request/requestEntity",
                "Casework request entity",
                0,
                "sourceId",
            ),
            N {
                scope: Scope::Composite(&[(0, "sourceId"), (0, "requestEntity")]),
                ..N::global("request/fields/*/field", "Casework source field")
            },
        ],
        references: &[
            N::global("sourceId", "Casework source"),
            N::global("request/review/policyId", "Casework review kind"),
            N::global("requests/*/review/policyId", "Casework review kind"),
        ],
        files: &[],
    },
    DocumentRules {
        pattern: "dev-clients.yaml",
        declarations: &[N::global("clients/*/id", "Casework development client")],
        references: &[
            N::global("clients/*/accessProfile", "Casework access profile"),
            N::global("directory/*/queue", "Casework queue"),
            N::global("directory/*/staff/*", "Casework development client"),
            N::global("directory/*/supervisors/*", "Casework development client"),
        ],
        files: &[],
    },
    DocumentRules {
        pattern: "fixtures/*.yaml",
        declarations: &[N::global("name", "Casework fixture")],
        references: &[
            N::global("review/kind", "Casework review kind"),
            N::global("source/id", "Casework source"),
            N {
                reports_unresolved: false,
                ..N::scoped("source/requestEntity", "Casework request entity", 0, "id")
            },
            N::global("expect/queue", "Casework queue"),
            N::scoped(
                "expect/outcomes/*",
                "Casework review outcome",
                0,
                "review.kind",
            ),
        ],
        files: &[],
    },
];

const SCHEDULING_DOCUMENTS: &[DocumentRules] = &[
    DocumentRules {
        pattern: "@document",
        declarations: SCHEDULING_DECLARATIONS,
        references: SCHEDULING_REFERENCES,
        files: &[],
    },
    DocumentRules {
        pattern: "records.yaml",
        declarations: &[
            N::global("locations/*/id", "Scheduling location"),
            N::global("pools/*/id", "Scheduling resource pool"),
            N::global("windows/*/id", "Scheduling arrival window"),
            N::scoped("exceptions/*/id", "Scheduling exception", 0, "location"),
        ],
        references: &[
            N::global("windows/*/location", "Scheduling location"),
            N::global("exceptions/*/location", "Scheduling location"),
            N::scoped(
                "exceptions/*/reopens",
                "Scheduling exception",
                0,
                "location",
            ),
        ],
        files: &[],
    },
    DocumentRules {
        pattern: "fixtures/*.yaml",
        declarations: &[N::global("name", "Scheduling fixture")],
        references: &[N::global("cases/*/request/offering", "Scheduling offering")],
        files: &[],
    },
];

const MESSAGING_DOCUMENTS: &[DocumentRules] = &[
    DocumentRules {
        pattern: "@document",
        declarations: &[
            N::global("providers/*/id", "Messaging provider"),
            N::global("senderProfiles/*/id", "Messaging sender profile"),
            N::global("templates/*/id", "Messaging template"),
            N::global("accessProfiles/*/id", "Messaging access profile"),
        ],
        references: &[
            N::global("senderProfiles/*/provider", "Messaging provider"),
            N::global(
                "accessProfiles/*/senderProfiles/*",
                "Messaging sender profile",
            ),
            N::global("accessProfiles/*/templates/*", "Messaging template"),
        ],
        files: &[FileRule {
            path: "templates/*/id",
            prefix: "templates/",
            suffix: "/{version}/template.yaml",
            relative_to_document: false,
            index_target: true,
        }],
    },
    DocumentRules {
        pattern: "runtime.yaml",
        declarations: &[],
        references: &[N::global("providers/$key", "Messaging provider")],
        files: &[],
    },
    DocumentRules {
        pattern: "templates/*/*/template.yaml",
        declarations: &[
            N {
                scope: super::spec::Scope::Document,
                ..N::global("locales/*", "Messaging locale")
            },
            N {
                scope: super::spec::Scope::Document,
                ..N::global("parts/*", "Messaging part")
            },
        ],
        references: &[],
        files: &[],
    },
    DocumentRules {
        pattern: "providers/*/provider.yaml",
        declarations: &[],
        references: &[],
        files: &[
            FileRule {
                relative_to_document: true,
                ..FileRule::root("prepareScript", false)
            },
            FileRule {
                relative_to_document: true,
                ..FileRule::root("interpretScript", false)
            },
            FileRule {
                relative_to_document: true,
                ..FileRule::root("receiptScript", false)
            },
        ],
    },
];

pub(super) fn spec(product: ProductKind) -> Option<ProductSpec> {
    let (marker, version_prefix, kind, documents) = match product {
        ProductKind::Breg => (
            "registry.yaml",
            "registry.registrystack.org/v1alpha1",
            "RegistryProject",
            BREG_DOCUMENTS,
        ),
        ProductKind::Casework => (
            "casework.yaml",
            "registry.registrystack.org/casework/",
            "CaseworkProject",
            CASEWORK_DOCUMENTS,
        ),
        ProductKind::Scheduling => (
            "scheduling.yaml",
            "id.registrystack.org/formats/scheduling/project/",
            "SchedulingProject",
            SCHEDULING_DOCUMENTS,
        ),
        ProductKind::Messaging => (
            "messaging.yaml",
            "id.registrystack.org/formats/messaging/project/",
            "MessagingProject",
            MESSAGING_DOCUMENTS,
        ),
        _ => return None,
    };
    Some(ProductSpec {
        product,
        marker,
        discriminator: "apiVersion",
        version_prefix,
        kind,
        documents,
    })
}
