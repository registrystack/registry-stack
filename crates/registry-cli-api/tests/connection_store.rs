use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
};

use registry_cli_api::{
    run_api, run_api_with_profile_headers, run_connection, AddConnectionArgs, ApiArgs,
    CheckConnectionArgs, ConnectionCommand, ListConnectionArgs, ShowConnectionArgs,
    UseConnectionArgs,
};
use tempfile::TempDir;

const CLIENT_JWK: &str = r#"{"kty":"EC","crv":"P-384","d":"Cp2oq8BnIF6oQ2KWV-1yiR7Mf0rFOuDZ5nvS9E_9HGEODI76izZiDEFQ5kfSwCAg","x":"TH-XDvwYtzdc43QDOiBjfdQZTCx1k9Rz5ELDu_2NS8JWcCv8HlfK0T9rYijDIcAY","y":"eLx0gh3VmCC2DeubmC0CdDgno7aEBYEkz5Legyg-2GoLlFohSIop3zKCGSjhg7Ta","alg":"ES384","kid":"client-key-es384-2026-01"}"#;

fn write_secret(path: &Path, value: &str) {
    fs::write(path, value).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn api_args(path: &str, output: PathBuf) -> ApiArgs {
    ApiArgs {
        path: path.to_owned(),
        project: None,
        client: None,
        connection: None,
        url: None,
        token_file: None,
        ca_file: None,
        method: None,
        input: None,
        header: Vec::new(),
        accept: None,
        output: Some(output),
        include: false,
        idempotency_key: None,
        if_match: None,
    }
}

fn add_args(name: &str, url: String) -> AddConnectionArgs {
    AddConnectionArgs {
        name: name.to_owned(),
        url: Some(url),
        ca_file: None,
        access_profile: None,
        anonymous: false,
        token_file: None,
        token_env: None,
        private_key_jwt: false,
        token_endpoint: None,
        client_id: None,
        private_key_file: None,
        scope: Vec::new(),
        resource: None,
        assertion_audience: None,
    }
}

fn request_server(count: usize, status: &str, body: &str) -> (String, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = mpsc::channel();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    thread::spawn(move || {
        for _ in 0..count {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = socket.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                    continue;
                };
                let end = end + 4;
                let text = String::from_utf8_lossy(&request[..end]);
                let length = text
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if request.len() >= end + length {
                    break;
                }
            }
            sent.send(request).unwrap();
            socket.write_all(response.as_bytes()).unwrap();
        }
    });
    (format!("http://{address}/prefix"), received)
}

#[test]
fn saved_connections_add_show_use_reread_credentials_and_acquire_private_key_jwt() {
    let temporary = TempDir::new().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", temporary.path().join("config"));

    let production_secrets = temporary.path().join("production-secrets");
    let staging_secrets = temporary.path().join("staging-secrets");
    let jwt_secrets = temporary.path().join("jwt-secrets");
    fs::create_dir_all(&production_secrets).unwrap();
    fs::create_dir_all(&staging_secrets).unwrap();
    fs::create_dir_all(&jwt_secrets).unwrap();
    let production_token = production_secrets.join("token");
    let staging_token = staging_secrets.join("token");
    let private_key = jwt_secrets.join("client-key");
    write_secret(&production_token, "first-token\n");
    write_secret(&staging_token, "staging-token\n");
    write_secret(&private_key, CLIENT_JWK);

    let lax_token = temporary.path().join("lax-token");
    fs::write(&lax_token, "must-not-be-read-later\n").unwrap();
    fs::set_permissions(&lax_token, fs::Permissions::from_mode(0o644)).unwrap();
    let mut lax = add_args("lax", "https://registry.example.test/api".to_owned());
    lax.token_file = Some(lax_token);
    let error = run_connection("breg", ConnectionCommand::Add(Box::new(lax)))
        .expect_err("connection add must preflight owner-only credential permissions");
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("0400 or 0600"));
    assert!(!error.to_string().contains("must-not-be-read-later"));

    let invalid_key = jwt_secrets.join("invalid-client-key");
    write_secret(&invalid_key, "invalid-private-key-canary");
    let mut invalid_renewable = add_args(
        "invalid-renewable",
        "https://registry.example.test/api".to_owned(),
    );
    invalid_renewable.private_key_jwt = true;
    invalid_renewable.token_endpoint = Some("https://issuer.example.test/token".to_owned());
    invalid_renewable.client_id = Some("registry-cli-test".to_owned());
    invalid_renewable.private_key_file = Some(invalid_key);
    let error = run_connection("breg", ConnectionCommand::Add(Box::new(invalid_renewable)))
        .expect_err("connection add must preflight the private key file");
    assert_eq!(error.exit_code(), 3);
    assert!(!error.to_string().contains("invalid-private-key-canary"));

    let (base_url, requests) = request_server(2, "200 OK", "{} ");
    let mut production = add_args("production", base_url);
    production.token_file = Some(production_token.clone());
    run_connection("breg", ConnectionCommand::Add(Box::new(production))).unwrap();

    let mut unsupported_profile = add_args(
        "unsupported-profile",
        "https://registry.example.test/api".to_owned(),
    );
    unsupported_profile.anonymous = true;
    unsupported_profile.access_profile = Some("staff".to_owned());
    let error = run_connection(
        "breg",
        ConnectionCommand::Add(Box::new(unsupported_profile)),
    )
    .expect_err("non-Casework adapters must refuse saved access profiles");
    assert_eq!(error.exit_code(), 2);

    let mut staging = add_args("staging", "https://staging.example.test/api".to_owned());
    staging.token_file = Some(staging_token);
    run_connection("breg", ConnectionCommand::Add(Box::new(staging))).unwrap();
    fs::set_permissions(
        staging_secrets.join("token"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let mut unusable = api_args("v1/status", temporary.path().join("unusable.out"));
    unusable.connection = Some("staging".to_owned());
    let error = run_api("breg", unusable, |_, _| unreachable!("saved connection"))
        .expect_err("runtime credential errors must give value-free recovery guidance");
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("0400 or 0600"));
    assert!(!error.to_string().contains("staging-token"));
    run_connection(
        "breg",
        ConnectionCommand::List(ListConnectionArgs::default()),
    )
    .unwrap();
    run_connection(
        "breg",
        ConnectionCommand::Show(ShowConnectionArgs {
            name: "production".to_owned(),
        }),
    )
    .unwrap();

    let mut first = api_args("v1/status", temporary.path().join("first.out"));
    first.connection = Some("production".to_owned());
    run_api("breg", first, |_, _| {
        unreachable!("saved remote connection")
    })
    .unwrap();
    let first_request = String::from_utf8(requests.recv().unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(first_request.contains("authorization: bearer first-token\r\n"));

    let project = temporary.path().join("project");
    let nested = project.join("modules/contacts");
    fs::create_dir_all(&nested).unwrap();
    fs::write(project.join("registry.yaml"), "marker").unwrap();
    run_connection(
        "breg",
        ConnectionCommand::Use(UseConnectionArgs {
            name: "production".to_owned(),
            project: Some(nested.clone()),
        }),
    )
    .unwrap();
    write_secret(&production_token, "replacement-token\n");
    let mut second = api_args("v1/status", temporary.path().join("second.out"));
    second.project = Some(nested);
    run_api("breg", second, |_, _| {
        unreachable!("selected remote connection")
    })
    .unwrap();
    let second_request = String::from_utf8(requests.recv().unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(second_request.contains("authorization: bearer replacement-token\r\n"));

    let (casework_url, casework_requests) = request_server(1, "200 OK", "{} ");
    let mut casework = add_args("production", casework_url);
    casework.token_file = Some(production_token.clone());
    casework.access_profile = Some("staff".to_owned());
    run_connection("casework", ConnectionCommand::Add(Box::new(casework))).unwrap();
    let mut profiled = api_args("v1/status", temporary.path().join("profiled.out"));
    profiled.connection = Some("production".to_owned());
    let missing_headers = run_api("casework", profiled.clone(), |_, _| {
        unreachable!("saved remote connection")
    })
    .expect_err("a saved profile requires adapter-owned header names");
    assert_eq!(missing_headers.exit_code(), 3);
    run_api_with_profile_headers(
        "casework",
        profiled,
        |_, _| unreachable!("saved remote connection"),
        &["Registry-Casework-Profile", "Registry-Review-Profile"],
    )
    .unwrap();
    let casework_request = String::from_utf8(casework_requests.recv().unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(casework_request.contains("authorization: bearer replacement-token\r\n"));
    assert!(casework_request.contains("registry-casework-profile: staff\r\n"));
    assert!(casework_request.contains("registry-review-profile: staff\r\n"));

    let saved = fs::read_to_string(
        temporary
            .path()
            .join("config/registrystack/connections.yaml"),
    )
    .unwrap();
    assert!(!saved.contains("first-token"));
    assert!(!saved.contains("replacement-token"));
    assert!(saved.contains(&production_secrets.display().to_string()));
    assert!(saved.contains(&staging_secrets.display().to_string()));
    assert!(saved.contains("accessProfile: staff"));

    let check_only = temporary.path().join("check-only.yaml");
    fs::write(
        &check_only,
        "apiVersion: id.registrystack.org/formats/platform/cli-connections/v1alpha1\nkind: PlatformCliConnections\nconnections:\n  - product: breg\n    name: offline\n    baseUrl: https://registry.example.test/api\n    secretProviders:\n      environment: {}\n    auth:\n      type: bearer\n      tokenRef: secret:env/REGISTRY_STACK_CHECK_ONLY_TOKEN\n",
    )
    .unwrap();
    std::env::remove_var("REGISTRY_STACK_CHECK_ONLY_TOKEN");
    run_connection(
        "breg",
        ConnectionCommand::Check(CheckConnectionArgs {
            file: check_only,
            deny_warnings: false,
        }),
    )
    .expect("offline check must not resolve the referenced credential");

    let unsupported_profile_file = temporary.path().join("unsupported-profile.yaml");
    fs::write(
        &unsupported_profile_file,
        "apiVersion: id.registrystack.org/formats/platform/cli-connections/v1alpha1\nkind: PlatformCliConnections\nconnections:\n  - product: breg\n    name: invalid\n    baseUrl: https://registry.example.test/api\n    accessProfile: staff\n    auth:\n      type: anonymous\n",
    )
    .unwrap();
    let error = run_connection(
        "breg",
        ConnectionCommand::Check(CheckConnectionArgs {
            deny_warnings: false,
            file: unsupported_profile_file,
        }),
    )
    .expect_err("manually authored non-Casework access profiles must be refused");
    assert_eq!(error.exit_code(), 3);

    let ca = temporary.path().join("institution-ca.pem");
    fs::write(&ca, "not a PEM certificate\n").unwrap();
    let mut private_ca = add_args("private-ca", "https://registry.example.test/api".to_owned());
    private_ca.anonymous = true;
    private_ca.ca_file = Some(ca.canonicalize().unwrap());
    run_connection("breg", ConnectionCommand::Add(Box::new(private_ca))).unwrap();
    let saved = fs::read_to_string(
        temporary
            .path()
            .join("config/registrystack/connections.yaml"),
    )
    .unwrap();
    assert!(saved.contains("trustedRootCertificatesFile:"));
    let mut private_ca_call = api_args("v1/status", temporary.path().join("ca.out"));
    private_ca_call.connection = Some("private-ca".to_owned());
    let error = run_api("breg", private_ca_call, |_, _| {
        unreachable!("saved connection")
    })
    .expect_err("invalid saved trust material must be refused locally");
    assert_eq!(error.exit_code(), 3);

    let token_body = r#"{"access_token":"renewed-token","token_type":"Bearer","expires_in":300}"#;
    let (token_endpoint, token_requests) = request_server(1, "200 OK", token_body);
    let (api_url, api_requests) = request_server(1, "503 Service Unavailable", "failure");
    let mut renewable = add_args("renewable", api_url);
    renewable.private_key_jwt = true;
    renewable.token_endpoint = Some(format!("{token_endpoint}/token"));
    renewable.client_id = Some("registry-cli-test".to_owned());
    renewable.private_key_file = Some(private_key);
    run_connection("breg", ConnectionCommand::Add(Box::new(renewable))).unwrap();

    let mut call = api_args("v1/status", temporary.path().join("failure.out"));
    call.connection = Some("renewable".to_owned());
    let error = run_api("breg", call, |_, _| unreachable!("saved remote connection"))
        .expect_err("the API status remains a visible refusal");
    assert_eq!(error.exit_code(), 1);
    let token_request = String::from_utf8(token_requests.recv().unwrap()).unwrap();
    assert!(token_request.starts_with("POST /prefix/token HTTP/1.1\r\n"));
    assert!(token_request.contains("grant_type=client_credentials"));
    assert!(token_request.contains("client_assertion="));
    let api_request = String::from_utf8(api_requests.recv().unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(api_request.contains("authorization: bearer renewed-token\r\n"));
    assert_eq!(
        fs::read(temporary.path().join("failure.out")).unwrap(),
        b"failure"
    );
}
