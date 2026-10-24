use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{mpsc, Mutex},
    thread,
    time::{Duration, Instant},
};

use fs2::FileExt as _;
use registry_cli_api::{
    run_api, run_api_with_profile_headers, run_connection, AddConnectionArgs, ApiArgs,
    CheckConnectionArgs, ConnectionCommand, ListConnectionArgs, ShowConnectionArgs,
    UseConnectionArgs,
};
use tempfile::TempDir;

const CLIENT_JWK: &str = r#"{"kty":"EC","crv":"P-384","d":"Cp2oq8BnIF6oQ2KWV-1yiR7Mf0rFOuDZ5nvS9E_9HGEODI76izZiDEFQ5kfSwCAg","x":"TH-XDvwYtzdc43QDOiBjfdQZTCx1k9Rz5ELDu_2NS8JWcCv8HlfK0T9rYijDIcAY","y":"eLx0gh3VmCC2DeubmC0CdDgno7aEBYEkz5Legyg-2GoLlFohSIop3zKCGSjhg7Ta","alg":"ES384","kid":"client-key-es384-2026-01"}"#;
const MUTATION_WORKER: &str = "REGISTRY_CLI_API_MUTATION_WORKER";
const MUTATION_WORKER_READY: &str = "REGISTRY_CLI_API_MUTATION_WORKER_READY";
const MUTATION_WORKER_PROJECT: &str = "REGISTRY_CLI_API_MUTATION_WORKER_PROJECT";
static ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

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

fn mutation_worker(mode: &str, config_root: &Path, ready: &Path, project: &Path) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "connection_mutation_process_worker",
            "--nocapture",
        ])
        .env(MUTATION_WORKER, mode)
        .env(MUTATION_WORKER_READY, ready)
        .env(MUTATION_WORKER_PROJECT, project)
        .env("XDG_CONFIG_HOME", config_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_for_worker_ready(paths: &[&Path], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if paths.iter().all(|path| path.is_file()) {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

fn wait_for_worker(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "connection mutation worker timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn connection_mutation_process_worker() {
    let Some(mode) = std::env::var_os(MUTATION_WORKER) else {
        return;
    };
    let ready = PathBuf::from(std::env::var_os(MUTATION_WORKER_READY).unwrap());
    fs::write(ready, b"ready").unwrap();
    match mode.to_str().unwrap() {
        "add" => {
            let mut args = add_args("review", "https://casework.example.test/api".to_owned());
            args.anonymous = true;
            run_connection("casework", ConnectionCommand::Add(Box::new(args))).unwrap();
        }
        "use" => {
            let project = PathBuf::from(std::env::var_os(MUTATION_WORKER_PROJECT).unwrap());
            run_connection(
                "breg",
                ConnectionCommand::Use(UseConnectionArgs {
                    name: "production".to_owned(),
                    project: Some(project),
                }),
            )
            .unwrap();
        }
        _ => panic!("unknown connection mutation worker mode"),
    }
}

#[test]
fn cross_process_add_and_use_preserve_disjoint_store_changes() {
    let _environment = ENVIRONMENT_LOCK.lock().unwrap();
    let temporary = TempDir::new().unwrap();
    let config_root = temporary.path().join("config");
    std::env::set_var("XDG_CONFIG_HOME", &config_root);
    let store_path = config_root.join("registrystack/connections.yaml");
    let lock_path = config_root.join("registrystack/connections.yaml.lock");
    let project = temporary.path().join("breg-project");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("registry.yaml"), "marker").unwrap();

    let mut production = add_args("production", "https://registry.example.test/api".to_owned());
    production.anonymous = true;
    run_connection("breg", ConnectionCommand::Add(Box::new(production.clone()))).unwrap();
    let before_refusal = fs::read(&store_path).unwrap();
    let refusal = run_connection("breg", ConnectionCommand::Add(Box::new(production)))
        .expect_err("a duplicate add is refused inside the locked transaction");
    assert_eq!(refusal.exit_code(), 2);
    assert_eq!(fs::read(&store_path).unwrap(), before_refusal);

    let mut after_refusal = add_args(
        "recovery",
        "https://registry-recovery.example.test/api".to_owned(),
    );
    after_refusal.anonymous = true;
    run_connection("breg", ConnectionCommand::Add(Box::new(after_refusal)))
        .expect("the mutation after a refusal acquires the released lock");

    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    lock.lock_exclusive().unwrap();
    let add_ready = temporary.path().join("add.ready");
    let use_ready = temporary.path().join("use.ready");
    let mut add = mutation_worker("add", &config_root, &add_ready, &project);
    let mut select = mutation_worker("use", &config_root, &use_ready, &project);
    let ready = wait_for_worker_ready(
        &[add_ready.as_path(), use_ready.as_path()],
        Duration::from_secs(5),
    );
    if !ready {
        fs2::FileExt::unlock(&lock).unwrap();
        let _ = add.kill();
        let _ = select.kill();
        let add = add.wait_with_output().unwrap();
        let select = select.wait_with_output().unwrap();
        panic!(
            "connection mutation workers did not become ready\nadd stdout:\n{}\nadd stderr:\n{}\nuse stdout:\n{}\nuse stderr:\n{}",
            String::from_utf8_lossy(&add.stdout),
            String::from_utf8_lossy(&add.stderr),
            String::from_utf8_lossy(&select.stdout),
            String::from_utf8_lossy(&select.stderr)
        );
    }
    thread::sleep(Duration::from_millis(200));
    let add_finished_while_locked = add.try_wait().unwrap().is_some();
    let use_finished_while_locked = select.try_wait().unwrap().is_some();
    fs2::FileExt::unlock(&lock).unwrap();

    let add = wait_for_worker(add, Duration::from_secs(5));
    let select = wait_for_worker(select, Duration::from_secs(5));
    assert!(
        !add_finished_while_locked,
        "add bypassed the held store lock\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr)
    );
    assert!(
        !use_finished_while_locked,
        "use bypassed the held store lock\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&select.stdout),
        String::from_utf8_lossy(&select.stderr)
    );
    assert!(
        add.status.success(),
        "add failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr)
    );
    assert!(
        select.status.success(),
        "use failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&select.stdout),
        String::from_utf8_lossy(&select.stderr)
    );
    assert!(add.stderr.is_empty());
    assert!(select.stderr.is_empty());

    run_connection(
        "breg",
        ConnectionCommand::Check(CheckConnectionArgs {
            file: store_path.clone(),
            deny_warnings: false,
        }),
    )
    .expect("the combined saved store remains valid");
    let bytes = fs::read(&store_path).unwrap();
    let saved = registry_platform_yaml::Reader::new(store_path.display().to_string())
        .scan(&bytes)
        .unwrap()
        .expect("saved store is not empty")
        .to_json_value();
    assert!(saved["connections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| { entry["product"] == "casework" && entry["name"] == "review" }));
    assert!(saved["selections"].as_array().unwrap().iter().any(|entry| {
        entry["product"] == "breg"
            && entry["connection"] == "production"
            && entry["project"] == project.display().to_string()
    }));
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
    let _environment = ENVIRONMENT_LOCK.lock().unwrap();
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
