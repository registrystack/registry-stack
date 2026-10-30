// SPDX-License-Identifier: Apache-2.0

//! The unchanged BReg tool catalog and its caller-filtered schemas.

use rmcp::model::{Tool, ToolAnnotations};

use crate::{
    contract::Contract,
    tools::{
        application_input_schema, empty_input_schema, list_input_schema, start_input_schema,
        update_input_schema, DESCRIBE_SERVICE, GET_APPLICATION_STATUS, GET_MY_DETAILS,
        LIST_APPLICATIONS, PREPARE_REVIEW, START_APPLICATION, UPDATE_APPLICATION,
    },
};

/// The tool definitions, with the start and update schemas taken from
/// the contract the registry publishes for this caller.
pub(crate) fn tool_definitions(service_name: &str, contract: &Contract) -> Vec<Tool> {
    vec![
        Tool::new(
            DESCRIBE_SERVICE,
            format!(
                "Describe the {service_name} service and what the chat host will see. \
                 Returns no personal data."
            ),
            empty_input_schema(),
        )
        .with_title("Describe the service")
        .with_annotations(read_only()),
        Tool::new(
            GET_MY_DETAILS,
            "Read the signed-in citizen's own record, as labelled registry data.",
            empty_input_schema(),
        )
        .with_title("Read my details")
        .with_annotations(read_only()),
        Tool::new(
            START_APPLICATION,
            "Start a draft application for the signed-in citizen's own record. Generate a new \
             startAttemptId UUID for each new application and reuse it for retries. A retry may \
             return the initial state without Get authority; get_application_status reads the \
             authorized current state. The draft is not submitted; the citizen reviews and \
             submits it on the service's own page.",
            start_input_schema(contract),
        )
        .with_title("Start an application")
        .with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        ),
        Tool::new(
            UPDATE_APPLICATION,
            "Change fields of one of the citizen's own draft applications. Name the \
             revision the edits were made against.",
            update_input_schema(contract),
        )
        .with_title("Update an application")
        .with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(true)
                .idempotent(true)
                .open_world(false),
        ),
        Tool::new(
            PREPARE_REVIEW,
            "Return the link where the citizen reviews and submits one of their own \
             applications. Nothing is submitted by this tool.",
            application_input_schema(),
        )
        .with_title("Prepare the review")
        .with_annotations(read_only()),
        Tool::new(
            LIST_APPLICATIONS,
            "Resume the signed-in citizen's own applications.",
            list_input_schema(),
        )
        .with_title("List my applications")
        .with_annotations(read_only()),
        Tool::new(
            GET_APPLICATION_STATUS,
            "Report the status of one of the citizen's own applications, as the registry \
             records it.",
            application_input_schema(),
        )
        .with_title("Get an application's status")
        .with_annotations(read_only()),
    ]
}

fn read_only() -> ToolAnnotations {
    ToolAnnotations::new()
        .read_only(true)
        .destructive(false)
        .idempotent(true)
        .open_world(false)
}
