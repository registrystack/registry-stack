use registry_stack_client::{auth, breg, discovery, evidence, record, relay};

#[test]
fn facade_keeps_every_product_under_its_own_module() {
    fn names<T>() -> &'static str {
        std::any::type_name::<T>()
    }

    assert!(names::<breg::BaseRegistryClient>().contains("registry_breg_client"));
    assert!(names::<relay::RelayClient>().contains("registry_relay_client"));
    assert!(names::<discovery::DiscoveryClient>().contains("registry_discovery_client"));
    assert!(names::<evidence::EvidenceClient>().contains("registry_evidence_client"));
    assert!(names::<record::RegistryRecord>().contains("registry_record"));
    assert!(names::<auth::BearerToken>().contains("registry_platform_httputil"));
}
