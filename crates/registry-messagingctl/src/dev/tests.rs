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
    let loaded = load_package(&project).unwrap();
    let docker = docker::Docker::new(PathBuf::from("/nonexistent/docker"));
    let (lock, root) = fresh_session(&project, &docker).unwrap();
    drop(lock);
    let passwords = config::generate(&root).unwrap();
    config::database_urls(&root, 55432, &passwords).unwrap();
    (temporary, project, root, loaded)
}

#[test]
fn the_generated_configuration_is_one_the_runtime_accepts() {
    let (_temporary, project, root, loaded) = session();
    let endpoints = config::Endpoints {
        api_port: 18107,
        metrics_port: 19107,
        smtp_port: 11025,
        gateway_port: 18200,
    };
    let document = serde_norway::to_string(&config::runtime_config(
        &project, &root, &loaded, &endpoints,
    ))
    .unwrap();
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
    assert_eq!(claims["registry_scopes"], "messaging:send");
    assert_eq!(claims["registry_actor_kind"], "service");

    let operator = config::token(&root, &loaded, "operations-console").unwrap();
    let claims = jsonwebtoken::decode::<Value>(
        operator.as_str(),
        &DecodingKey::from_jwk(key).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(claims["registry_scopes"], "messaging:operate");
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
    assert_eq!(failure.exit, REFUSAL_EXIT);
    assert!(
        failure.message.contains("case-system, operations-console"),
        "{}",
        failure.message
    );
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
    assert_eq!(failure.exit, REFUSAL_EXIT);
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
    assert_eq!(failure.exit, REFUSAL_EXIT);
    drop(held);
}

#[test]
fn a_project_path_that_reads_as_an_expression_is_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("${HOME}");
    fs::create_dir(&project).unwrap();
    let Err(failure) = project_directory(&project) else {
        panic!("the runtime configuration would substitute the path");
    };
    assert_eq!(failure.exit, REFUSAL_EXIT);
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
