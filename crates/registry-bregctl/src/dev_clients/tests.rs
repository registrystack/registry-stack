// SPDX-License-Identifier: Apache-2.0

use super::*;
use registry_platform_yaml::{Expect, Reader};

const CLIENTS_HEADER: &str =
    "apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1\nkind: BRegDevClients\n";

fn fixture() -> Clients {
    serde_json::from_value(json!({
        "clients": [
            {
                "id": "operator",
                "accessProfiles": ["operator"],
                "scopes": ["registry:generic:operate"],
                "claims": {"registry_principal": "synthetic-operator", "registry_purpose": "record-change"}
            },
            {
                "id": "source",
                "accessProfiles": ["evidence-source"],
                "scopes": ["registry:generic:lookup"],
                "claims": {"registry_principal": "synthetic-source", "registry_purpose": "record-read"}
            }
        ]
    })).unwrap()
}

fn enable_file_provider(clients: &mut Clients) {
    clients.secret_providers = Some(
        serde_json::from_value(json!({
            "file": {"root": "/synthetic-secret-provider"}
        }))
        .unwrap(),
    );
}

fn check_clients(label: &str, bytes: &[u8]) -> Result<(), Report> {
    let document = Reader::new(label).read(bytes, &Expect::one(&DEV_CLIENTS_FORMAT))?;
    let diagnostics = check(&document)?;
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(Report::new(diagnostics))
    }
}

fn clients_refusal(bytes: &[u8]) -> Report {
    check_clients("dev-clients.yaml", bytes).unwrap_err()
}

fn codes(report: &Report) -> Vec<&str> {
    report
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

fn machine_grant_inventory(mut clients: Clients) -> Clients {
    clients.clients.push(
        serde_json::from_value(json!({
            "id":"task-agent","accessProfiles":[],"scopes":["casework:grants:assert"],"claims":{},
            "grants":[{"audience":"urn:scheduling:dev:machine","scopes":["scheduling:read"]}]
        }))
        .unwrap(),
    );
    clients.issuer.resources.extend([
        IssuerResource {
            audience: "urn:casework:dev:machine".into(),
            scopes: vec!["casework:grants:assert".into(), "casework:read".into()],
        },
        IssuerResource {
            audience: "urn:scheduling:dev:machine".into(),
            scopes: vec!["scheduling:read".into()],
        },
    ]);
    clients
        .issuer
        .client_resources
        .insert("task-agent".into(), "urn:casework:dev:machine".into());
    clients.issuer.exchange_clients.push("task-agent".into());
    clients.issuer.exchange_issuers.push(IssuerConnection {
        id: "casework".into(),
        issuer: "https://casework.example.test".into(),
        jwks_endpoint: "https://casework.example.test/oauth2/jwks".into(),
        mapping: IssuerConnectionMapping::InstitutionalGrant,
        clients: vec!["task-agent".into()],
        token_attributes: BTreeMap::new(),
    });
    clients
}

#[test]
fn clients_require_explicit_unique_profile_bindings_and_closed_fields() {
    let clients = fixture();
    let mut value = serde_json::to_value(&clients).unwrap();
    check_clients("dev-clients.yaml", &serde_json::to_vec(&value).unwrap()).unwrap();
    value["clients"][1]["accessProfiles"] = json!(["operator"]);
    assert!(check_clients("dev-clients.yaml", &serde_json::to_vec(&value).unwrap()).is_err());
    value["clients"][1]["accessProfiles"] = json!(["evidence-source"]);
    value["clients"][1]["secret"] = json!("must-not-be-accepted");
    assert!(check_clients("dev-clients.yaml", &serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn every_removed_clients_member_is_refused_at_its_position_naming_its_replacement() {
    let document = format!(
        "{CLIENTS_HEADER}version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims: {{registry_principal: generic-registry-operator, registry_purpose: registry-operations}}
    clientIdFile: /private/published-client-id
    assertionKeyFile: /private/published-assertion-key
    assertionKeyInputFile: /private/imported-assertion-key
destinations:
  hooks:
    receiver:
      origin: http://127.0.0.1:18888
      path: /inbox
      hmacKeyFile: /private/hmac-key
evidenceProviders:
  qualification:
    baseUrl: http://127.0.0.1:18093
    trustBindingId: exact-local-trust-v1
    tokenFile: /private/provider-token
    trustedJwksFile: /private/provider-jwks
    caBundleFile: /private/provider-ca
    privateKeyJwt:
      tokenEndpoint: http://127.0.0.1:18091/oauth2/token
      clientId: guard-reader
      privateKeyFile: /private/provider-key
      assertionAudience: http://127.0.0.1:18091
      resource: urn:example:evidence
      scopes: [evidence:invoke]
reviewAuthorities:
  casework-a:
    endpoint: http://127.0.0.1:18096/
    profile: integration-requester
    producerId: registry-producer
    recoveryDays: 7
    client: operator
    completionTokenFile: /private/completion-token
issuer:
  interactiveApplications:
    - id: portal
      clientSecretFile: /private/portal-secret
      origin: http://127.0.0.1:3000
      redirectUris: [http://127.0.0.1:3000/callback]
      grants: [{{scopes: [registry:generic:operate]}}]
      tokenAttributes: []
  syntheticUsers:
    - username: staff
      email: staff@example.test
      passwordFile: /private/staff-password
      attributes: {{}}
      grants: [{{scopes: [registry:generic:operate]}}]
"
    );
    let report = clients_refusal(document.as_bytes());
    let rendered = report.render_human();
    let removed = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "config.removed-key")
        .map(|diagnostic| {
            let source = diagnostic
                .source
                .as_ref()
                .expect("a removed key has a position");
            assert!(source.line.is_some(), "{rendered}");
            (
                diagnostic.path.as_str(),
                diagnostic.suggested_action.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (path, replacement) in [
        ("/version", "apiVersion"),
        ("/clients/0/clientIdFile", "rstack development plan"),
        ("/clients/0/assertionKeyFile", "rstack development plan"),
        ("/clients/0/assertionKeyInputFile", "assertionKeyRef"),
        (
            "/destinations/hooks/receiver/hmacKeyFile",
            "hmacSha256KeyRef",
        ),
        ("/evidenceProviders/qualification/tokenFile", "tokenRef"),
        (
            "/evidenceProviders/qualification/trustedJwksFile",
            "trustedJwksRef",
        ),
        (
            "/evidenceProviders/qualification/caBundleFile",
            "caBundleRef",
        ),
        (
            "/evidenceProviders/qualification/privateKeyJwt/privateKeyFile",
            "privateKeyRef",
        ),
        (
            "/reviewAuthorities/casework-a/completionTokenFile",
            "completion.hmacSha256KeyRef",
        ),
        (
            "/issuer/interactiveApplications/0/clientSecretFile",
            "clientSecretRef",
        ),
        ("/issuer/syntheticUsers/0/passwordFile", "passwordRef"),
    ] {
        let fix = removed
            .get(path)
            .unwrap_or_else(|| panic!("{path} is not reported as removed: {rendered}"));
        assert!(fix.contains(replacement), "{path}: {fix}");
    }
    assert_eq!(removed.len(), 12, "{rendered}");
    assert!(
        !codes(&report).contains(&"config.unknown-key"),
        "a removed member is not also unknown: {rendered}"
    );
    assert!(
        !rendered.contains("/private/"),
        "no authored path is repeated: {rendered}"
    );
}

#[test]
fn every_unknown_clients_member_is_reported_with_its_position() {
    let document = format!(
        "{CLIENTS_HEADER}clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims: {{registry_principal: generic-registry-operator, registry_purpose: registry-operations}}
    assertionKey: secret:file/operator-key
seed: []
secretProvider: {{environment: {{}}}}
"
    );
    let report = clients_refusal(document.as_bytes());
    let rendered = report.render_human();
    let unknown = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "config.unknown-key")
        .map(|diagnostic| {
            let source = diagnostic
                .source
                .as_ref()
                .expect("an unknown key has a position");
            (diagnostic.path.as_str(), source.line)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        unknown,
        [
            ("/clients/0/assertionKey", Some(8)),
            ("/secretProvider", Some(10))
        ],
        "{rendered}"
    );
    assert!(
        rendered.contains("secretProviders"),
        "the closest key is named: {rendered}"
    );
}

#[test]
fn machine_resource_grants_refuse_undeclared_broader_duplicate_and_unbounded_permissions() {
    let base = fixture();
    let base = machine_grant_inventory(base);
    check_clients("dev-clients.yaml", &serde_json::to_vec(&base).unwrap()).unwrap();
    let read = json!({"audience":"urn:scheduling:dev:machine","scopes":["scheduling:read"]});
    for grants in [
        json!([{"audience":"urn:undeclared:machine","scopes":["scheduling:read"]}]),
        json!([{"audience":"not a resource URI","scopes":["scheduling:read"]}]),
        json!([{"audience":"urn:scheduling:dev:machine","scopes":["scheduling:commit"]}]),
        json!([{"audience":"urn:scheduling:dev:machine","scopes":["scheduling:*"]}]),
        json!([{"audience":"urn:scheduling:dev:machine","scopes":[]}]),
        json!([{"audience":"urn:scheduling:dev:machine","scopes":["scheduling:read","scheduling:read"]}]),
        json!([read.clone(), read.clone()]),
        json!(vec![read.clone(); 8]),
        json!([{"audience":"urn:scheduling:dev:machine","scopes":vec!["scheduling:read";33]}]),
    ] {
        let mut clients = base.clone();
        clients.clients.last_mut().unwrap().grants = serde_json::from_value(grants).unwrap();
        let error = check_clients(
            "dev-clients.yaml",
            serde_norway::to_string(&clients).unwrap().as_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("machine client grants"), "{error}");
    }
    let mut wider_bootstrap = base;
    wider_bootstrap
        .clients
        .last_mut()
        .unwrap()
        .scopes
        .push("casework:read".into());
    assert!(check_clients(
        "dev-clients.yaml",
        serde_norway::to_string(&wider_bootstrap)
            .unwrap()
            .as_bytes()
    )
    .unwrap_err()
    .to_string()
    .contains("one exact bootstrap scope"));
}

#[test]
fn local_task_grant_status_refuses_wider_authority_duplicate_sources_and_unsafe_endpoints() {
    let mut clients = fixture();
    let client = clients
        .clients
        .iter_mut()
        .find(|client| client.id == "source")
        .unwrap();
    client.access_profiles.clear();
    client.scopes = vec!["casework:grants:status".into()];
    clients.task_grant_status.insert(
        "casework".into(),
        LocalTaskGrantStatus {
            source_issuer: registry_platform_yaml::ExternalId::new(
                "https://casework.local.example",
            )
            .unwrap(),
            base_url: "http://127.0.0.1:18096/".into(),
            client: "source".into(),
        },
    );
    let valid = serde_json::to_value(&clients).unwrap();
    check_clients("dev-clients.yaml", &serde_json::to_vec(&valid).unwrap()).unwrap();
    for base in [
        "https://casework.example/",
        "http://localhost:18096/",
        "http://127.0.0.1/",
        "http://127.0.0.1:0/",
        "http://secret@127.0.0.1:18096/",
        "http://127.0.0.1:18096/?authority=other",
    ] {
        let mut invalid = valid.clone();
        invalid["taskGrantStatus"]["casework"]["baseUrl"] = json!(base);
        assert!(check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&invalid).unwrap().into_bytes()
        )
        .is_err());
    }
    for (field, value) in [
        (
            "scopes",
            json!(["casework:grants:status", "casework:grants:assert"]),
        ),
        ("scopes", json!(["casework:grants:assert"])),
        ("accessProfiles", json!(["operator"])),
        ("allowBregAccess", json!(true)),
        ("claims", json!({"registry_actor_kind":"human"})),
    ] {
        let mut invalid = valid.clone();
        invalid["clients"][1][field] = value;
        assert!(check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&invalid).unwrap().into_bytes()
        )
        .is_err());
    }
    for (field, value) in [
        ("client", json!("missing")),
        ("sourceIssuer", json!("invalid issuer")),
        ("scopes", json!(["casework:grants:status"])),
    ] {
        let mut invalid = valid.clone();
        invalid["taskGrantStatus"]["casework"][field] = value;
        assert!(check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&invalid).unwrap().into_bytes()
        )
        .is_err());
    }
    let mut duplicate = valid.clone();
    duplicate["taskGrantStatus"]["other"] = duplicate["taskGrantStatus"]["casework"].clone();
    assert!(check_clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&duplicate).unwrap().into_bytes()
    )
    .is_err());
    let mut oversized = valid.clone();
    for index in 1..9 {
        let mut binding = valid["taskGrantStatus"]["casework"].clone();
        binding["sourceIssuer"] = json!(format!("https://casework-{index}.example"));
        oversized["taskGrantStatus"][format!("casework-{index}")] = binding;
    }
    assert!(check_clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&oversized).unwrap().into_bytes()
    )
    .is_err());
}

#[test]
fn local_review_authorities_are_closed_and_bounded() {
    let mut clients = fixture();
    let binding = LocalReviewAuthority {
        endpoint: "http://127.0.0.1:18096/".into(),
        profile: "integration-requester".into(),
        producer_id: "registry-producer".into(),
        recovery_days: 7,
        client: "operator".into(),
        completion: None,
    };
    clients
        .review_authorities
        .insert("casework-a".into(), binding.clone());
    check_clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();

    for endpoint in [
        "https://casework.example/",
        "http://127.0.0.1/",
        "http://127.0.0.1:0/",
        "http://secret@127.0.0.1:18096/",
        "http://127.0.0.1:18096/?authority=other",
    ] {
        clients
            .review_authorities
            .get_mut("casework-a")
            .unwrap()
            .endpoint = endpoint.into();
        assert!(check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes()
        )
        .is_err());
    }
    clients
        .review_authorities
        .get_mut("casework-a")
        .unwrap()
        .endpoint = "http://127.0.0.1:18096/".into();
    for invalid in [String::new(), "x".repeat(129), "bad profile".to_owned()] {
        clients
            .review_authorities
            .get_mut("casework-a")
            .unwrap()
            .profile = invalid;
        assert!(check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes()
        )
        .is_err());
    }
    clients
        .review_authorities
        .get_mut("casework-a")
        .unwrap()
        .profile = "integration-requester".into();
    clients
        .review_authorities
        .get_mut("casework-a")
        .unwrap()
        .client = "undeclared-producer".into();
    assert!(check_clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes()
    )
    .is_err());

    clients.review_authorities.clear();
    for index in 0..9 {
        clients
            .review_authorities
            .insert(format!("casework-{index}"), binding.clone());
    }
    assert!(check_clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes()
    )
    .is_err());

    clients.review_authorities.clear();
    clients
        .review_authorities
        .insert("casework-a".into(), binding);
    for (key, replacement) in [
        ("completionTokenRef", "completion.hmacSha256KeyRef"),
        ("completionRecipient", "completion.recipientBinding"),
    ] {
        let mut raw = serde_json::to_value(&clients).unwrap();
        raw["reviewAuthorities"]["casework-a"][key] = json!("canary-old-value");
        let refusal = check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&raw).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains(replacement), "{refusal}");
        assert!(
            !refusal.contains("canary-old-value"),
            "the refusal for {key} repeats the old reference value"
        );
    }
}

#[test]
fn multi_purpose_claim_union_is_refused_above_the_issuer_attribute_limit() {
    // Every multi-purpose client shares one generated first-party connection,
    // which projects the union of their claim names plus the reserved
    // registry_purpose and scope. The issuer bounds that union, so each client
    // being within its own 32-claim bound is not enough.
    let base = fixture();
    let mut clients = base.clone();
    for client in &mut clients.clients {
        client.claims.insert(
            "registry_purpose".into(),
            json!(["record-change", "record-read"]),
        );
    }
    let (operator, source) = clients.clients.split_at_mut(1);
    for index in 0..7 {
        operator[0]
            .claims
            .insert(format!("operator_claim_{index}"), json!("value"));
    }
    for index in 0..5 {
        source[0]
            .claims
            .insert(format!("source_claim_{index}"), json!("value"));
    }
    // registry_actor_kind, registry_principal, registry_purpose, scope, and
    // twelve distinct authored claims: exactly the limit.
    check_clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    clients.clients[1]
        .claims
        .insert("source_claim_5".into(), json!("value"));
    let refusal = check_clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap_err()
    .to_string();
    assert!(refusal.contains("at most 16"), "{refusal}");
    assert!(refusal.contains("multi-purpose"), "{refusal}");
}

#[test]
fn local_evidence_provider_ids_follow_the_governed_evidence_grammar() {
    // The map key names a provider the registry project declares, and the
    // governed Evidence identifier grammar admits an underscore. A key this
    // file refuses is a declared provider a dev session can never bind.
    let mut clients = fixture();
    enable_file_provider(&mut clients);
    let token = SecretReference::parse("secret:file/provider-token").unwrap();
    let jwks = SecretReference::parse("secret:file/provider-jwks").unwrap();
    let provider = LocalEvidenceProvider {
        base_url: "http://127.0.0.1:18093".into(),
        trust_binding_id: "exact-local-trust-v1".into(),
        token_ref: Some(token),
        private_key_jwt: None,
        trusted_jwks_ref: jwks,
        revoked_key_ids: vec![],
        ca_bundle_ref: None,
    };
    for id in ["qualification", "trusted_provider", "provider-2"] {
        clients.evidence_providers.clear();
        clients
            .evidence_providers
            .insert(id.into(), provider.clone());
        check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_or_else(|error| panic!("{id}: {error}"));
    }
    // The grammar is closed in the other direction too: it is anchored on a
    // lowercase letter and admits no other byte.
    for id in ["2provider", "_provider", "Provider", "provider.two", ""] {
        clients.evidence_providers.clear();
        clients
            .evidence_providers
            .insert(id.into(), provider.clone());
        let refusal = check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("local identifier"), "{id}: {refusal}");
    }
}

#[test]
fn a_secret_reference_needs_a_declared_provider() {
    let mut clients = fixture();
    enable_file_provider(&mut clients);
    let completion = SecretReference::parse("secret:file/review-completion-key").unwrap();
    clients.review_authorities.insert(
        "casework-a".into(),
        LocalReviewAuthority {
            endpoint: "http://127.0.0.1:18096/".into(),
            profile: "integration-requester".into(),
            producer_id: "registry-producer".into(),
            recovery_days: 7,
            client: "operator".into(),
            completion: Some(LocalReviewCompletion {
                recipient_binding: "registry-breg".into(),
                hmac_sha256_key_ref: completion.clone(),
                previous_hmac_sha256_key_ref: None,
            }),
        },
    );
    check_clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .expect("an enabled file provider makes the offline reference valid");

    let mut undeclared = clients.clone();
    undeclared.secret_providers = None;
    let refusal = format!(
        "{:#}",
        check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&undeclared).unwrap().into_bytes()
        )
        .unwrap_err()
    );
    assert!(
        refusal.contains("reviewAuthorities.casework-a.completion.hmacSha256KeyRef names a secret")
            && refusal.contains("declares no secretProviders"),
        "{refusal}"
    );
    assert!(!refusal.contains(completion.as_str()), "{refusal}");

    // A reference to a provider the file does not enable is refused, naming
    // the member and the block that enables it.
    let mut disabled = clients.clone();
    disabled
        .review_authorities
        .get_mut("casework-a")
        .unwrap()
        .completion
        .as_mut()
        .unwrap()
        .hmac_sha256_key_ref =
        SecretReference::parse("secret:env/BREGCTL_DEV_UNSET_SECRET").unwrap();
    let refusal = format!(
        "{:#}",
        check_clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&disabled).unwrap().into_bytes()
        )
        .unwrap_err()
    );
    assert!(
        refusal.contains("completion.hmacSha256KeyRef") && refusal.contains("secretProviders"),
        "{refusal}"
    );
    assert!(!refusal.contains("BREGCTL_DEV_UNSET_SECRET"), "{refusal}");
}

#[test]
fn offline_validation_does_not_open_secret_files() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = tempfile::tempdir().unwrap();
    let secret = scratch.path().join("staff-password");
    std::fs::write(&secret, vec![b'x'; 1025]).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut clients = serde_json::to_value(fixture()).unwrap();
    clients["secretProviders"] = json!({"file": {"root": scratch.path()}});
    clients["issuer"]["syntheticUsers"] = json!([{
        "username": "staff", "email": "staff@example.test",
        "passwordRef": "secret:file/staff-password", "attributes": {},
        "grants": [{"scopes": ["registry:generic:operate"]}]
    }]);
    check_clients("dev-clients.yaml", &serde_json::to_vec(&clients).unwrap()).unwrap();
}
