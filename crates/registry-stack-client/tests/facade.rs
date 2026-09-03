use registry_stack_client::{auth, discovery, evidence, record, registry_server, relay};

#[test]
fn facade_keeps_every_product_under_its_own_module() {
    fn names<T>() -> &'static str {
        std::any::type_name::<T>()
    }

    assert!(names::<registry_server::RegistryServerClient>().contains("registry_server_client"));
    assert!(names::<relay::RelayClient>().contains("registry_relay_client"));
    assert!(names::<discovery::DiscoveryClient>().contains("registry_discovery_client"));
    assert!(names::<evidence::EvidenceClient>().contains("registry_evidence_client"));
    assert!(names::<record::RegistryRecord>().contains("registry_record"));
    assert!(names::<auth::BearerToken>().contains("registry_platform_httputil"));
}
