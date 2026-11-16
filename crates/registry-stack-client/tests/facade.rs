use registry_stack_client::{
    auth, breg, casework, discovery, evidence, messaging, record, scheduling,
};

#[test]
fn facade_keeps_every_product_under_its_own_module() {
    fn names<T>() -> &'static str {
        std::any::type_name::<T>()
    }

    assert!(names::<breg::BaseRegistryClient>().contains("registry_breg_client"));
    assert!(names::<breg::BRegMetadataOperation>().contains("registry_breg_client"));
    assert_eq!(breg::Uuid::nil(), casework::Uuid::nil());
    assert!(names::<casework::CaseworkClient>().contains("registry_casework_client"));
    assert!(names::<messaging::MessagingClient>().contains("registry_messaging_client"));
    assert!(names::<messaging::ProblemCode>().contains("registry_messaging_core"));
    assert!(names::<scheduling::SchedulingClient>().contains("registry_scheduling_client"));
    assert!(names::<scheduling::ProblemCode>().contains("registry_scheduling_core"));
    assert!(names::<discovery::DiscoveryClient>().contains("registry_discovery_client"));
    assert!(names::<evidence::EvidenceClient>().contains("registry_evidence_client"));
    assert!(names::<record::RegistryRecord>().contains("registry_record"));
    assert!(names::<auth::BearerToken>().contains("registry_platform_httputil"));
}

#[test]
fn facade_names_the_shared_review_progress_code() {
    let code = breg::ReviewProgressCode::parse("initial-verification").unwrap();
    let code: casework::ReviewProgressCode = code;
    assert_eq!(code.as_str(), "initial-verification");
}

// Compile-only client calls: consumers must name observed outcomes using this
// facade alone, while the original Complete outcomes remain unchanged.
async fn observed_breg_reads(
    client: &breg::BaseRegistryClient,
    options: &breg::BRegRecordOptions,
    query: &breg::BRegListRequest,
) -> Result<(), breg::BaseRegistryClientError> {
    let single: breg::BRegObservedRead<breg::BRegComplete<record::RegistryRecordSingleResponse>> =
        client
            .get_record_with_response_status("records", "id", options)
            .await?;
    let _: u16 = single.response_status();
    let _: breg::BRegComplete<record::RegistryRecordSingleResponse> = single.into_outcome();
    let page: breg::BRegObservedRead<
        breg::BRegComplete<breg::BRegPage<record::RegistryRecordCollectionResponse>>,
    > = client
        .list_records_with_response_status("records", query)
        .await?;
    let _: u16 = page.response_status();
    Ok(())
}

async fn observed_casework_reads(
    client: &casework::CaseworkClient,
    token: &casework::BearerToken,
    profile: &str,
    query: &casework::ReviewStaffingQuery,
    id: casework::Uuid,
) -> Result<(), casework::CaseworkClientError> {
    let auth = || casework::CaseworkAuth::new(token, profile);
    let single: casework::CaseworkObservedRead<casework::CaseworkComplete<casework::ReviewTask>> =
        client.review_task_with_response_status(auth(), id).await?;
    let _: u16 = single.response_status();
    let page: casework::CaseworkObservedRead<casework::CaseworkComplete<casework::ReviewTaskPage>> =
        client
            .review_tasks_with_response_status(auth(), query)
            .await?;
    let _: casework::CaseworkComplete<casework::ReviewTaskPage> = page.into_outcome();
    Ok(())
}

#[test]
fn facade_names_observed_read_outcomes_without_changing_complete_types() {
    let _ = observed_breg_reads;
    let _ = observed_casework_reads;
}
