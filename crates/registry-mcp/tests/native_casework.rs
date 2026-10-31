// SPDX-License-Identifier: Apache-2.0

//! Native process-boundary proof for delegated staff reads through Casework.
//!
//! This test links neither the Casework nor BReg runtime. `BREG_BIN`,
//! `BREGCTL_BIN`, `CASEWORK_BIN`, and `CASEWORKCTL_BIN` name separately built
//! executables. `REGISTRY_STACK_FIXTURES_ROOT` names the matching source tree,
//! and `CASEWORK_MCP_TEST_DATABASE_URL` names an explicitly disposable
//! PostgreSQL server. The issuer, jurisdiction, people, proposals, and records
//! are synthetic.

#[path = "support/native_casework/mod.rs"]
mod native_casework;

use native_casework::{error_code, structured, NativeCaseworkStack, CONTEXT_TOOL, LIST_TOOL};
use serde_json::json;
use std::collections::BTreeSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires matching native BReg and Casework binaries, maintained fixtures and owned PostgreSQL"]
async fn native_staff_gateway_preserves_delegated_read_authority() {
    let stack = NativeCaseworkStack::start().await;
    let alice = stack.client_for_alice().await;
    let bob = stack.client_for_bob().await;

    let tools = alice
        .list_all_tools()
        .await
        .expect("list the two configured delegated read tools");
    let names = tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect::<BTreeSet<_>>();
    assert_eq!(names, BTreeSet::from([LIST_TOOL, CONTEXT_TOOL]));
    assert!(tools.iter().all(|tool| {
        tool.annotations.as_ref().is_some_and(|annotations| {
            annotations.read_only_hint == Some(true) && annotations.destructive_hint == Some(false)
        })
    }));

    let alice_page = stack.list(&alice).await;
    assert_eq!(alice_page.is_error, Some(false), "{alice_page:?}");
    let alice_page = structured(&alice_page);
    let alice_tasks = stack.task_ids(&alice_page);
    assert_eq!(
        alice_tasks,
        [stack.alice_zone_a_task(), stack.bob_zone_a_task()]
            .into_iter()
            .collect()
    );
    let bob_page = stack.list(&bob).await;
    assert_eq!(bob_page.is_error, Some(false), "{bob_page:?}");
    let bob_page = structured(&bob_page);
    assert!(stack.task_ids(&bob_page).is_empty());

    let before_context_audit = stack.casework_audit_entry_count();
    let context = stack.context(&alice, stack.alice_zone_a_task()).await;
    assert_eq!(context.is_error, Some(false), "{context:?}");
    stack.assert_one_context_success_since(before_context_audit);
    let context = structured(&context);
    assert_eq!(
        context.pointer("/caseworkData/value/taskId"),
        Some(&json!(stack.alice_zone_a_task()))
    );
    assert_eq!(
        context.pointer("/caseworkData/value/context/projection/display/currentAddressLine"),
        Some(&json!("1 Synthetic Road"))
    );
    assert!(context.pointer("/caseworkData/value/policy").is_some());
    assert!(context
        .pointer("/caseworkData/value/policyClosure")
        .is_none());

    let before_cross_subject = stack.exchange_count();
    let concealed = stack.context(&bob, stack.alice_zone_a_task()).await;
    assert_eq!(error_code(&concealed), "casework-task-not-found");
    let concealed = structured(&concealed);
    let trace = concealed
        .pointer("/error/traceId")
        .and_then(serde_json::Value::as_str)
        .expect("concealed Casework trace is preserved");
    assert_eq!(trace.len(), 32);
    assert!(trace.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        error_code(&stack.context(&bob, stack.bob_zone_a_task()).await),
        "casework-task-not-found"
    );
    assert_eq!(
        stack.exchange_count(),
        before_cross_subject + 2,
        "each refused backend read obtains fresh downstream authority"
    );

    assert_eq!(
        error_code(&stack.context(&alice, stack.alice_zone_b_task()).await),
        "casework-task-not-found",
        "the BReg row boundary must conceal a currently assigned foreign-jurisdiction proposal"
    );

    stack.transfer_zone_a_to_bob().await;
    assert_eq!(
        error_code(&stack.context(&alice, stack.bob_zone_a_task()).await),
        "casework-task-not-found",
        "the previous holder loses access immediately after assignment transfer"
    );
    let transferred = stack.context(&bob, stack.bob_zone_a_task()).await;
    assert_eq!(transferred.is_error, Some(false), "{transferred:?}");
    let transferred = structured(&transferred);
    assert_eq!(
        transferred.pointer("/caseworkData/value/taskId"),
        Some(&json!(stack.bob_zone_a_task()))
    );
    let alice_page = stack.list(&alice).await;
    assert_eq!(alice_page.is_error, Some(false), "{alice_page:?}");
    let alice_page = structured(&alice_page);
    assert_eq!(
        stack.task_ids(&alice_page),
        [stack.alice_zone_a_task()].into_iter().collect()
    );
    let bob_page = stack.list(&bob).await;
    assert_eq!(bob_page.is_error, Some(false), "{bob_page:?}");
    let bob_page = structured(&bob_page);
    assert_eq!(
        stack.task_ids(&bob_page),
        [stack.bob_zone_a_task()].into_iter().collect()
    );

    let before_unconfigured = stack.exchange_count();
    stack
        .assert_unknown_tool(
            &alice,
            "claim_review_task",
            json!({"taskId": stack.bob_zone_a_task()}),
        )
        .await;
    assert_eq!(stack.exchange_count(), before_unconfigured);

    stack.revoke_alice_membership().await;
    let revoked_page = stack.list(&alice).await;
    if revoked_page.is_error == Some(true) {
        assert_eq!(error_code(&revoked_page), "casework-access-refused");
    } else {
        assert!(
            stack.task_ids(&structured(&revoked_page)).is_empty(),
            "revoked membership must reveal no protected review rows"
        );
    }
    assert_eq!(
        error_code(&stack.context(&alice, stack.alice_zone_a_task()).await),
        "casework-task-not-found"
    );

    stack.assert_exchange_chain();
    stack.assert_minimized_audit();
    stack.finish().await;
}
