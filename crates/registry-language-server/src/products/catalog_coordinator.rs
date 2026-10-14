// SPDX-License-Identifier: Apache-2.0
//! Local Coordinator authoring edges from the current compiled project contract.

use super::spec::{DocumentRules, FileRule, NameRule as N};

const DECLARATIONS: &[N] = &[
    N::global("project/id", "Coordinator workflow"),
    N::global("types/$key", "Coordinator type"),
    N::global("functions/$key", "Coordinator Function"),
    N::global("contracts/$key", "Coordinator contract import"),
    N::global("operations/$key", "Coordinator Operation"),
    N::global("workflow/steps/$key", "Coordinator Step"),
    N::global("workflow/outcomes/$key", "Coordinator outcome"),
    N::global("workflow/eventTriggers/$key", "Coordinator event trigger"),
];

const REFERENCES: &[N] = &[
    N::global("workflow/start", "Coordinator Step"),
    N::global("workflow/steps/*/next", "Coordinator Step"),
    N::global("workflow/steps/*/onDeclaredRefusal", "Coordinator Step"),
    N::global("workflow/steps/*/onTimeout", "Coordinator Step"),
    N::global("workflow/steps/*/onCancel", "Coordinator Step"),
    N::global("workflow/steps/*/cases/*", "Coordinator Step"),
    N::global("workflow/steps/*/completion/step", "Coordinator Step"),
    N::global("workflow/steps/*/operation", "Coordinator Operation"),
    N::global("workflow/steps/*/outcome", "Coordinator outcome"),
    N::global("workflow/review/outcomes/$key", "Coordinator outcome"),
    N::global(
        "operations/*/action/contract",
        "Coordinator contract import",
    ),
    N::global(
        "operations/*/completions/*/interpret",
        "Coordinator Function",
    ),
    // Mapping inputs and fields hold References, so literal JSON payloads are never walked.
    N {
        only_when: Some(("type", "function")),
        ..N::global("workflow/steps/*/input/function", "Coordinator Function")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/input/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/input/inputs/*/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/input/fields/*/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "function")),
        ..N::global("workflow/steps/*/choose/function", "Coordinator Function")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/choose/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/choose/inputs/*/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/choose/fields/*/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "function")),
        ..N::global(
            "workflow/steps/*/waitUntil/function",
            "Coordinator Function",
        )
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/waitUntil/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global(
            "workflow/steps/*/waitUntil/inputs/*/step",
            "Coordinator Step",
        )
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global(
            "workflow/steps/*/waitUntil/fields/*/step",
            "Coordinator Step",
        )
    },
    N {
        only_when: Some(("type", "function")),
        ..N::global("workflow/steps/*/output/function", "Coordinator Function")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/output/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/output/inputs/*/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/steps/*/output/fields/*/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "function")),
        ..N::global(
            "workflow/eventTriggers/*/input/function",
            "Coordinator Function",
        )
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global("workflow/eventTriggers/*/input/step", "Coordinator Step")
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global(
            "workflow/eventTriggers/*/input/inputs/*/step",
            "Coordinator Step",
        )
    },
    N {
        only_when: Some(("type", "step")),
        ..N::global(
            "workflow/eventTriggers/*/input/fields/*/step",
            "Coordinator Step",
        )
    },
    // Whole-schema reference positions only. Nested JSON Schema is left to its own tools.
    N::global("types/*/typeRef", "Coordinator type"),
    N::global("types/*/operationInput", "Coordinator Operation"),
    N::global("types/*/operationOutput", "Coordinator Operation"),
    N::global("types/*/operationRefusal", "Coordinator Operation"),
    N::global(
        "types/*/completionOutput/operation",
        "Coordinator Operation",
    ),
    N::global("functions/*/inputs/*/typeRef", "Coordinator type"),
    N::global(
        "functions/*/inputs/*/operationInput",
        "Coordinator Operation",
    ),
    N::global(
        "functions/*/inputs/*/operationOutput",
        "Coordinator Operation",
    ),
    N::global(
        "functions/*/inputs/*/operationRefusal",
        "Coordinator Operation",
    ),
    N::global(
        "functions/*/inputs/*/completionOutput/operation",
        "Coordinator Operation",
    ),
    N::global("functions/*/output/typeRef", "Coordinator type"),
    N::global("functions/*/output/operationInput", "Coordinator Operation"),
    N::global(
        "functions/*/output/operationOutput",
        "Coordinator Operation",
    ),
    N::global(
        "functions/*/output/operationRefusal",
        "Coordinator Operation",
    ),
    N::global(
        "functions/*/output/completionOutput/operation",
        "Coordinator Operation",
    ),
    N::global("operations/*/responseSchema/typeRef", "Coordinator type"),
    N::global(
        "operations/*/responseSchema/operationInput",
        "Coordinator Operation",
    ),
    N::global(
        "operations/*/responseSchema/operationOutput",
        "Coordinator Operation",
    ),
    N::global(
        "operations/*/responseSchema/operationRefusal",
        "Coordinator Operation",
    ),
    N::global(
        "operations/*/responseSchema/completionOutput/operation",
        "Coordinator Operation",
    ),
    N::global("workflow/input/typeRef", "Coordinator type"),
    N::global("workflow/input/operationInput", "Coordinator Operation"),
    N::global("workflow/input/operationOutput", "Coordinator Operation"),
    N::global("workflow/input/operationRefusal", "Coordinator Operation"),
    N::global(
        "workflow/input/completionOutput/operation",
        "Coordinator Operation",
    ),
    N::global("workflow/outcomes/*/typeRef", "Coordinator type"),
    N::global(
        "workflow/outcomes/*/operationInput",
        "Coordinator Operation",
    ),
    N::global(
        "workflow/outcomes/*/operationOutput",
        "Coordinator Operation",
    ),
    N::global(
        "workflow/outcomes/*/operationRefusal",
        "Coordinator Operation",
    ),
    N::global(
        "workflow/outcomes/*/completionOutput/operation",
        "Coordinator Operation",
    ),
    N::global("workflow/eventTriggers/*/event/typeRef", "Coordinator type"),
    N::global(
        "workflow/eventTriggers/*/event/operationInput",
        "Coordinator Operation",
    ),
    N::global(
        "workflow/eventTriggers/*/event/operationOutput",
        "Coordinator Operation",
    ),
    N::global(
        "workflow/eventTriggers/*/event/operationRefusal",
        "Coordinator Operation",
    ),
    N::global(
        "workflow/eventTriggers/*/event/completionOutput/operation",
        "Coordinator Operation",
    ),
];

pub(super) const DOCUMENTS: &[DocumentRules] = &[DocumentRules {
    pattern: "workflow.yaml",
    declarations: DECLARATIONS,
    references: REFERENCES,
    // Assets remain navigation targets; no Rhai or generated contract bytes are indexed.
    files: &[
        FileRule::root("functions/*/source", false),
        FileRule::root("contracts/*/source", false),
    ],
}];
