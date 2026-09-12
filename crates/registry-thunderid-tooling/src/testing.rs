//! Test-only support: the complete synthetic fixture.
//!
//! [`synthetic_description`] is the closed, product-neutral description the
//! integration tests render and load on the pinned upstream container. It
//! names no product, institution, person, or purpose — the neutral
//! vocabulary of the description type is the whole of what it exercises. A
//! stored copy of the fully rendered fixture lives under
//! `products/identity/thunderid/fixtures/` and must be regenerable from this
//! description alone.

use std::collections::BTreeMap;

use crate::description::{
    ClientSecretMethod, CompatibilityClient, IssuerDescription, MachineClient, OrganizationUnit,
    Resource, ResourceServer, Role, SessionIdentity,
};

/// The ES256 public half of a deterministic test-only client key. It
/// authenticates nothing; it exists so the rendered fixture carries a
/// realistic one-key JWKS of the client's own.
pub const SYNTHETIC_CLIENT_PUBLIC_JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"synthetic-client-key-1","x":"TH-XDvwYtzdc43QDOiBjfdQZTCx1k9Rz5ELDu_2NS8JW","y":"eLx0gh3VmCC2DeubmC0CdDgno7aEBYEkz5Legyg-2Go0"}]}"#;

pub fn synthetic_description() -> IssuerDescription {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "synthetic_tag".to_owned(),
        serde_json::Value::String("fixture-agency".to_owned()),
    );
    IssuerDescription {
        session: SessionIdentity {
            label: "identity-integration".to_owned(),
            id: "a1b2c3d4e5f60718".to_owned(),
        },
        port: 18_491,
        state_root: std::env::temp_dir().join("registry-thunderid-tooling-fixture"),
        organization_unit: OrganizationUnit {
            id: "01900000-0000-7000-8000-000000000001".to_owned(),
            handle: "default".to_owned(),
            name: "Default".to_owned(),
            description: "Default organization unit".to_owned(),
        },
        resource_servers: vec![ResourceServer {
            id: "0197aaaa-0000-7000-8000-0000000000b1".to_owned(),
            name: "Synthetic Evidence".to_owned(),
            identifier: "urn:registry:tooling-test:evidence".to_owned(),
            description: "Synthetic resource server for the integration fixture".to_owned(),
            resources: vec![Resource {
                name: "Evidence".to_owned(),
                handle: "evidence".to_owned(),
                parent: None,
                description: "Synthetic evidence operations".to_owned(),
                actions: vec![crate::description::Action {
                    name: "Invoke".to_owned(),
                    handle: "invoke".to_owned(),
                    description: "Invoke an evidence request".to_owned(),
                }],
            }],
        }],
        roles: vec![Role {
            id: "0197aaaa-0000-7000-8000-0000000000c1".to_owned(),
            name: "Synthetic Invoker".to_owned(),
            description: "May invoke the synthetic resource".to_owned(),
            permissions: vec![(
                "0197aaaa-0000-7000-8000-0000000000b1".to_owned(),
                vec!["evidence:invoke".to_owned()],
            )],
            assigned_agents: vec!["0197aaaa-0000-7000-8000-0000000000a1".to_owned()],
        }],
        machine_clients: vec![MachineClient {
            agent_id: "0197aaaa-0000-7000-8000-0000000000a1".to_owned(),
            name: "Synthetic Machine Client".to_owned(),
            description: "Fixture private_key_jwt client".to_owned(),
            client_id: "synthetic-machine-client".to_owned(),
            public_jwks: SYNTHETIC_CLIENT_PUBLIC_JWKS.to_owned(),
            attributes,
            token_attributes: vec!["synthetic_tag".to_owned()],
            access_token_lifetime_seconds: 300,
            token_exchange: None,
        }],
        compatibility_clients: vec![CompatibilityClient {
            agent_id: "0197aaaa-0000-7000-8000-0000000000a2".to_owned(),
            name: "Synthetic Compatibility Client".to_owned(),
            description: "Fixture client_secret_post client".to_owned(),
            client_id: "synthetic-compatibility-client".to_owned(),
            method: ClientSecretMethod::Post,
            secret_file: "secrets/compatibility-client-secret".into(),
        }],
        exchange_issuers: vec![],
        schema_attributes: vec!["synthetic_tag".to_owned()],
    }
}
