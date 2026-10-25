// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;

use clap::Parser as _;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use registry_messaging::config::RuntimeConfig;
use serde_json::Value;

use super::*;
use crate::{starter, Cli, Command};

/// A starter project with a generated session beside it, as a start leaves
/// it before PostgreSQL answers.
fn session() -> (tempfile::TempDir, PathBuf, PathBuf, LoadedPackage) {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let project = fs::canonicalize(temporary.path()).unwrap().join("project");
    starter::write(&project).unwrap();
    load_project(&project).unwrap();
    let docker = docker::Docker::new(PathBuf::from("/nonexistent/docker"));
    let (lock, root) = fresh_session(&project, &docker).unwrap();
    drop(lock);
    let loaded = install_project(&project, &root).unwrap();
    let passwords = config::generate(&root, true).unwrap();
    config::database_urls(&root, 55432, &passwords).unwrap();
    (temporary, project, root, loaded)
}

#[test]
fn the_generated_configuration_is_one_the_runtime_accepts() {
    let (_temporary, _project, root, loaded) = session();
    let endpoints = config::Endpoints {
        api_port: 18107,
        metrics_port: 19107,
        smtp_port: 11025,
        gateway_port: 18200,
    };
    let document =
        config::runtime_document(&root.join("package"), &root, &loaded, &endpoints).unwrap();
    // CFG-SCHEMA-7 and CFG-ENV-5: the modeline, then the envelope.
    let mut lines = document.lines();
    assert_eq!(
        lines.next(),
        Some(
            "# yaml-language-server: $schema=https://id.registrystack.org/schemas/messaging/runtime/runtime.v1alpha1.schema.json"
        )
    );
    assert_eq!(
        lines.next(),
        Some("apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1")
    );
    assert_eq!(lines.next(), Some("kind: MessagingRuntimeConfig"));
    let path = root.join("runtime.yaml");
    private::create(&path, document.as_bytes()).unwrap();

    let checked = RuntimeConfig::load(&path).unwrap();
    assert_eq!(
        checked.load_package().unwrap().package.digest(),
        loaded.package.digest()
    );
    let secrets = checked.secret_resolver().unwrap();
    for reference in [
        "secret:file/runtime-database-url",
        "secret:file/migration-database-url",
        "secret:file/messaging-audit-key",
        "secret:file/gateway-token",
        "secret:file/gateway-callback-key",
        "secret:file/jwks.json",
        "secret:file/postgres-ca.pem",
    ] {
        secrets.resolve(reference).unwrap();
    }
    // The session's secrets never appear in the configuration itself.
    for name in [
        "gateway-token",
        "gateway-callback-key",
        "messaging-audit-key",
    ] {
        let secret = fs::read_to_string(root.join("secrets").join(name)).unwrap();
        assert!(
            !document.contains(secret.trim()),
            "{name} leaked into runtime.yaml"
        );
    }
    assert!(document.contains("hmac-sha256-body"));
    assert!(document.contains("development-loopback"));
}

/// An egress allowlist is written from the dev help, so the help names the
/// exact references the session pulls.
#[test]
fn dev_help_names_the_image_references_it_pulls() {
    assert_eq!(
        docker::POSTGRES_IMAGE,
        "docker.io/library/postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675"
    );
    let cli = <Cli as clap::CommandFactory>::command();
    let help = cli
        .get_subcommands()
        .find(|command| command.get_name() == "dev")
        .and_then(|command| command.get_long_about())
        .expect("messagingctl dev describes its session")
        .to_string();
    for image in [docker::POSTGRES_IMAGE, docker::MAILPIT_IMAGE] {
        assert!(help.contains(image), "messagingctl dev help omits {image}");
    }
}

#[test]
fn every_session_file_is_owner_only() {
    let (_temporary, project, root, _loaded) = session();
    for directory in ["secrets", "database", "issuer"] {
        for entry in fs::read_dir(root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            private::check(&path, false).unwrap();
        }
    }
    assert_eq!(
        fs::read_to_string(project.join(STATE_DIRECTORY).join(".gitignore")).unwrap(),
        "*\n"
    );
}

#[test]
fn a_token_verifies_under_the_session_key_set_with_the_profile_claims() {
    let (_temporary, _project, root, loaded) = session();
    let signed = config::token(&root, &loaded, "case-system").unwrap();
    let jwks: JwkSet =
        serde_json::from_slice(&fs::read(root.join("secrets/jwks.json")).unwrap()).unwrap();
    let header = jsonwebtoken::decode_header(signed.as_str()).unwrap();
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    let key = jwks.find(header.kid.as_deref().unwrap()).unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[config::ISSUER]);
    validation.set_audience(&[config::AUDIENCE]);
    let claims = jsonwebtoken::decode::<Value>(
        signed.as_str(),
        &DecodingKey::from_jwk(key).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(claims["azp"], "case-system");
    assert_eq!(claims["sub"], "dev-case-system");
    assert_eq!(claims["scope"], "messaging:send");
    assert_eq!(claims["registry_actor_kind"], "service");

    let operator = config::token(&root, &loaded, "operations-console").unwrap();
    let claims = jsonwebtoken::decode::<Value>(
        operator.as_str(),
        &DecodingKey::from_jwk(key).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(claims["scope"], "messaging:operate");
    assert!(claims.get("registry_actor_kind").is_none());
}

#[test]
fn a_header_file_is_owner_only_and_carries_the_bearer_token() {
    let (_temporary, _project, root, loaded) = session();
    let signed = config::token(&root, &loaded, "case-system").unwrap();
    let path = config::header_file(&root, "case-system", &signed).unwrap();
    private::check(&path, false).unwrap();
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        format!("Authorization: Bearer {}\n", signed.as_str())
    );
}

#[test]
fn a_client_no_profile_names_is_refused_with_the_package_clients() {
    let (_temporary, _project, root, loaded) = session();
    let Err(failure) = config::token(&root, &loaded, "stranger") else {
        panic!("an unknown client is refused");
    };
    assert_eq!(failure.exit, DOMAIN_REFUSAL_EXIT);
    assert!(
        failure.message.contains("case-system, operations-console"),
        "{}",
        failure.message
    );
}

#[test]
fn api_origin_requires_the_ready_session_endpoint() {
    let (_temporary, _project, root, _loaded) = session();
    let session = Session {
        root: root.clone(),
        owner: uuid::Uuid::new_v4().to_string(),
        containers: vec![],
        borrowed: None,
    };
    session
        .write("ready", &json!({"api": "http://127.0.0.1:18107"}))
        .unwrap();
    let record = read_session(&root).unwrap();
    assert_eq!(api_origin(&record).unwrap(), "http://127.0.0.1:18107");

    session.write("stopped", &json!({})).unwrap();
    let record = read_session(&root).unwrap();
    assert!(api_origin(&record)
        .unwrap_err()
        .message
        .contains("not ready"));
}

#[test]
fn a_token_without_a_session_is_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("project");
    starter::write(&project).unwrap();
    let Err(failure) = token(&TokenArgs {
        client: "case-system".to_owned(),
        project,
    }) else {
        panic!("a project without a session has no key to sign with");
    };
    assert_eq!(failure.exit, DOMAIN_REFUSAL_EXIT);
    assert!(
        failure.message.contains("messagingctl dev"),
        "{}",
        failure.message
    );
}

#[test]
fn a_second_start_in_the_same_project_is_refused_while_the_first_runs() {
    let (_temporary, project, _root, _loaded) = session();
    let docker = docker::Docker::new(PathBuf::from("/nonexistent/docker"));
    let held = private::lock(&project.join(STATE_DIRECTORY).join("dev.lock"))
        .unwrap()
        .unwrap();
    let Err(failure) = fresh_session(&project, &docker) else {
        panic!("the lock is held");
    };
    assert_eq!(failure.exit, DOMAIN_REFUSAL_EXIT);
    drop(held);
}

#[test]
fn a_project_path_that_reads_as_an_expression_is_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("${HOME}");
    fs::create_dir(&project).unwrap();
    let Err(failure) = project_directory(&project) else {
        panic!("the runtime configuration would expand the path");
    };
    assert_eq!(failure.exit, DOMAIN_REFUSAL_EXIT);
}

#[test]
fn dev_parses_a_start_and_a_token_request() {
    let Cli {
        command: Command::Dev(args),
        ..
    } = Cli::try_parse_from(["messagingctl", "dev", "project", "--port", "18107"]).unwrap()
    else {
        panic!("dev parses");
    };
    assert!(args.action.is_none());
    assert_eq!(args.start.port, 18107);
    assert_eq!(args.start.mock_latency_ms, 200);

    let Cli {
        command: Command::Dev(args),
        ..
    } = Cli::try_parse_from(["messagingctl", "dev", "token", "case-system", "project"]).unwrap()
    else {
        panic!("dev token parses");
    };
    let Some(DevAction::Token(token)) = args.action else {
        panic!("the token action is selected");
    };
    assert_eq!(token.client, "case-system");
    assert_eq!(token.project, PathBuf::from("project"));
}

fn borrowed_binding() -> borrowed::Binding {
    serde_json::from_value(json!({
        "project": "/owner", "bregctl": "/bin/bregctl",
        "issuer": "http://127.0.0.1:8095",
        "tokenEndpoint": "http://127.0.0.1:8095/oauth2/token",
        "resource": "urn:registrystack:messaging:notices",
        "clients": {"case-system": {
            "principal": "case-system", "profile": "case-notices", "actorKind": "service"
        }}
    }))
    .unwrap()
}

fn borrowed_claims(binding: &borrowed::Binding) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": binding.issuer, "aud": binding.resource,
        "sub": "case-system", "azp": "case-system",
        "scope": "messaging:send", "registry_actor_kind": "service",
        "iat": now, "nbf": now, "exp": now + 3600,
        "jti": uuid::Uuid::new_v4().to_string()
    })
}

fn sign_borrowed(root: &Path, loaded: &LoadedPackage, claims: &Value) -> Zeroizing<String> {
    let own = config::token(root, loaded, "case-system").unwrap();
    let header = jsonwebtoken::decode_header(&own).unwrap();
    let key = Zeroizing::new(private::read(&root.join("issuer/signing-key.der"), 4096).unwrap());
    Zeroizing::new(
        jsonwebtoken::encode(
            &header,
            claims,
            &jsonwebtoken::EncodingKey::from_ec_der(&key),
        )
        .unwrap(),
    )
}

#[test]
fn paired_issuer_options_require_an_explicit_resource() {
    for arguments in [
        vec![
            "messagingctl",
            "dev",
            "project",
            "--issuer-project",
            "owner",
        ],
        vec![
            "messagingctl",
            "dev",
            "project",
            "--resource",
            "urn:messaging",
        ],
    ] {
        assert!(Cli::try_parse_from(arguments).is_err());
    }
    let cli = Cli::try_parse_from([
        "messagingctl",
        "dev",
        "project",
        "--issuer-project",
        "owner",
        "--resource",
        "urn:messaging",
    ])
    .unwrap();
    let Command::Dev(args) = cli.command else {
        panic!("dev command");
    };
    assert_eq!(args.start.resource.as_deref(), Some("urn:messaging"));
}

#[test]
fn borrowed_configuration_uses_scope_and_static_issuer_keys() {
    let (_temporary, _project, root, loaded) = session();
    let binding = borrowed_binding();
    let document = config::runtime_document_with_issuer(
        &root.join("package"),
        &root,
        &loaded,
        &config::Endpoints {
            api_port: 18107,
            metrics_port: 19107,
            smtp_port: 11025,
            gateway_port: 18200,
        },
        Some(&binding),
    )
    .unwrap();
    let path = root.join("runtime.yaml");
    private::create(&path, document.as_bytes()).unwrap();
    let checked = RuntimeConfig::load(&path).unwrap();
    assert_eq!(checked.authentication.oidc.scope_claim, "scope");
    assert!(document.contains(&binding.issuer));
    assert!(document.contains(&binding.resource));
    assert!(document.contains("secret:file/jwks.json"));
    assert!(!document.contains("assertion-key"));
    assert!(!document.contains("assertionIssuers"));
}

#[tokio::test]
async fn borrowed_client_tokens_preserve_messaging_authorization() {
    let (_temporary, _project, root, loaded) = session();
    let binding = borrowed_binding();
    let claims = borrowed_claims(&binding);
    let signed = sign_borrowed(&root, &loaded, &claims);
    let (expires, caller) = borrowed::verify(&root, &loaded, &binding, "case-system", &signed)
        .await
        .unwrap();
    assert!(expires > 0 && expires <= 3600);
    assert_eq!(
        serde_json::to_value(&caller).unwrap()["principal"],
        "case-system"
    );
    for (claim, value) in [
        ("scope", json!("messaging:operate")),
        ("aud", json!("urn:another-resource")),
        ("iss", json!("http://127.0.0.1:8096")),
        ("registry_actor_kind", json!("human")),
        ("azp", json!("operations-console")),
    ] {
        let mut changed = claims.clone();
        changed[claim] = value;
        let signed = sign_borrowed(&root, &loaded, &changed);
        assert!(
            borrowed::verify(&root, &loaded, &binding, "case-system", &signed)
                .await
                .is_err(),
            "accepted changed {claim}"
        );
    }
    let (_other, _project, other_root, other_loaded) = session();
    let signed = sign_borrowed(&other_root, &other_loaded, &claims);
    assert!(
        borrowed::verify(&root, &loaded, &binding, "case-system", &signed)
            .await
            .is_err()
    );
}

#[test]
fn borrowed_token_refuses_changed_client_credentials() {
    let (_temporary, _project, root, _loaded) = session();
    private::directory(&root.join("credentials")).unwrap();
    let retained = root.join("credentials/case-system");
    private::directory(&retained).unwrap();
    let scratch = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&root)
        .unwrap();
    for file in ["client-id", "assertion-key.jwk"] {
        private::create(&retained.join(file), b"original").unwrap();
        private::create(&scratch.path().join(file), b"original").unwrap();
    }
    borrowed::same_export(&root, scratch.path(), "case-system").unwrap();
    for file in ["client-id", "assertion-key.jwk"] {
        private::replace(&scratch.path().join(file), b"changed").unwrap();
        assert!(borrowed::same_export(&root, scratch.path(), "case-system").is_err());
        private::replace(&scratch.path().join(file), b"original").unwrap();
    }
}

#[test]
fn borrowed_token_refuses_changed_principal() {
    let binding = borrowed_binding();
    let expected = &binding.clients["case-system"];
    borrowed::same_caller(expected, expected).unwrap();
    for (member, value) in [
        ("principal", json!("another")),
        ("profile", json!("operations")),
        ("actorKind", json!("human")),
    ] {
        let mut changed = serde_json::to_value(expected).unwrap();
        changed[member] = value;
        let changed = serde_json::from_value(changed).unwrap();
        assert!(borrowed::same_caller(expected, &changed).is_err());
    }
}

#[test]
fn borrowed_token_requires_ready_session() {
    let (_temporary, project, root, _loaded) = session();
    let session = Session {
        root: root.clone(),
        owner: uuid::Uuid::new_v4().to_string(),
        containers: vec![],
        borrowed: Some(borrowed_binding()),
    };
    for state in ["starting", "stopped", "stop-failed"] {
        session.write(state, &json!({})).unwrap();
        let Err(error) = token(&TokenArgs {
            client: "case-system".to_owned(),
            project: project.clone(),
        }) else {
            panic!("a stopped session cannot issue a token");
        };
        assert!(error.message.contains("not ready"));
        assert!(!root.join("tokens/case-system.header").exists());
    }
}

#[test]
fn a_session_record_that_cannot_be_serialized_fails_and_keeps_the_previous_record() {
    use std::os::unix::ffi::OsStringExt as _;

    let (_temporary, _project, root, _loaded) = session();
    let mut session = Session {
        root: root.clone(),
        owner: uuid::Uuid::new_v4().to_string(),
        containers: vec![],
        borrowed: Some(borrowed_binding()),
    };
    session.write("starting", &json!({})).unwrap();
    let before = fs::read(root.join("session.json")).unwrap();

    // The record is JSON, which spells a path only as UTF-8.
    session.borrowed.as_mut().unwrap().project =
        PathBuf::from(std::ffi::OsString::from_vec(vec![0x2f, 0xff]));
    let failure = session.write("ready", &json!({})).unwrap_err();
    assert_eq!(failure.exit, OPERATIONAL_FAILURE_EXIT);
    assert_eq!(failure.code, "dev.failed");
    assert!(
        failure
            .message
            .starts_with("the session record could not be written"),
        "{}",
        failure.message
    );
    assert!(!failure.message.contains('\u{fffd}'), "{}", failure.message);
    assert_eq!(fs::read(root.join("session.json")).unwrap(), before);
}

#[test]
fn borrowed_state_round_trips_a_profile_without_actor_kind() {
    let (_temporary, _project, root, _loaded) = session();
    let mut binding = borrowed_binding();
    binding.clients.insert(
        "operations-console".to_owned(),
        serde_json::from_value(json!({
            "principal": "operations-console", "profile": "operations"
        }))
        .unwrap(),
    );
    Session {
        root: root.clone(),
        owner: uuid::Uuid::new_v4().to_string(),
        containers: vec![],
        borrowed: Some(binding),
    }
    .write("ready", &json!({}))
    .unwrap();
    let record = read_session(&root).unwrap();
    assert_eq!(record.borrowed_issuer.unwrap().clients.len(), 2);
}

#[test]
fn dev_state_checks_offline_and_refuses_wrong_envelopes() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/messaging/examples/formats/dev-session/.messaging/dev/session.json");
    check_session_file(&example).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.json");
    let original: Value = serde_json::from_slice(&fs::read(&example).unwrap()).unwrap();
    for (member, value) in [
        ("kind", json!("OtherState")),
        ("apiVersion", json!("future")),
        ("state", json!("unknown")),
    ] {
        let mut changed = original.clone();
        changed[member] = value;
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(check_session_file(&path).is_err());
    }
    assert!(Cli::try_parse_from([
        "messagingctl",
        "check",
        "--dev-state",
        "state.json",
        "--project",
        "project"
    ])
    .is_err());
}

#[test]
fn a_standalone_session_keeps_its_local_token_behavior() {
    let (_temporary, project, root, _loaded) = session();
    Session {
        root,
        owner: uuid::Uuid::new_v4().to_string(),
        containers: vec![],
        borrowed: None,
    }
    .write("stopped", &json!({}))
    .unwrap();
    assert!(token(&TokenArgs {
        client: "case-system".to_owned(),
        project
    })
    .is_ok());
}

#[test]
fn a_borrowed_session_does_not_generate_a_signing_key() {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let project = temporary.path().join("project");
    starter::write(&project).unwrap();
    let docker = docker::Docker::new(PathBuf::from("/nonexistent/docker"));
    let (_lock, root) = fresh_session(&project, &docker).unwrap();
    private::create(&root.join("secrets/jwks.json"), b"retained public snapshot").unwrap();
    config::generate(&root, false).unwrap();
    assert!(!root.join("issuer/signing-key.der").exists());
    assert_eq!(
        fs::read(root.join("secrets/jwks.json")).unwrap(),
        b"retained public snapshot"
    );
}
