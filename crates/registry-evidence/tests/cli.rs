#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    net::{TcpListener, TcpStream},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use serde_json::{json, Value};

/// A value planted in every mutated artifact so a diagnostic that leaks a
/// document value fails loudly instead of quietly.
const CANARY: &str = "s3cr3t-canary-value";

/// A bounded local JWKS endpoint for exercising the actual CLI process.
///
/// The acceptance bundle is switched to its explicit local-assurance HTTP
/// issuer profile, so this server proves the same fetch path the deployed
/// authenticator uses without depending on a network outside the test.
struct JwksServer {
    origin: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl JwksServer {
    fn start() -> Self {
        Self::start_with(None)
    }

    /// The same endpoint served over HTTPS, under a certificate a private
    /// certificate authority signed. Returns the authority's PEM certificate,
    /// which no platform root store holds.
    fn start_under_private_ca() -> (Self, String) {
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let mut authority =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("private CA parameters");
        authority.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let authority_key = rcgen::KeyPair::generate().expect("private CA key");
        let authority_certificate = authority
            .self_signed(&authority_key)
            .expect("private CA certificate");
        let server_key = rcgen::KeyPair::generate().expect("server key");
        let server = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("server parameters")
            .signed_by(
                &server_key,
                &rcgen::Issuer::from_params(&authority, &authority_key),
            )
            .expect("the private CA signs the server certificate");
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![server.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("TLS server configuration");
        let server = Self::start_with(Some(Arc::new(config)));
        (server, pem_certificate(authority_certificate.der()))
    }

    fn start_with(tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("JWKS server binds");
        listener
            .set_nonblocking(true)
            .expect("JWKS listener becomes nonblocking");
        let address = listener.local_addr().expect("JWKS server has an address");
        let key = registry_platform_crypto::PrivateJwk::parse(VERIFY_PRIVATE_JWK)
            .expect("fixture key parses");
        let body =
            serde_json::to_vec(&json!({"keys": [key.public()]})).expect("JWKS response serializes");
        let response = Arc::new(
            [
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes(),
                body,
            ]
            .concat(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let tls_scheme = tls.is_some();
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // A BSD socket inherits the listener's nonblocking
                        // mode, which would read an empty request whenever
                        // the client's bytes had not yet arrived.
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        match &tls {
                            None => answer_jwks_request(stream, &response),
                            Some(config) => {
                                let Ok(connection) =
                                    tokio_rustls::rustls::ServerConnection::new(Arc::clone(config))
                                else {
                                    continue;
                                };
                                answer_jwks_request(
                                    tokio_rustls::rustls::StreamOwned::new(connection, stream),
                                    &response,
                                );
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });
        let scheme = if tls_scheme { "https" } else { "http" };
        Self {
            origin: format!("{scheme}://{address}"),
            stop,
            worker: Some(worker),
        }
    }

    fn origin(&self) -> &str {
        &self.origin
    }
}

/// Read one request and answer it with the key set, or with 404 for any other
/// request line.
fn answer_jwks_request(mut stream: impl std::io::Read + std::io::Write, response: &[u8]) {
    let mut request = Vec::with_capacity(1_024);
    while request.len() < 8_192 && !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0_u8; 512];
        let Ok(read) = stream.read(&mut chunk) else {
            break;
        };
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    let valid_request = request.starts_with(b"GET /.well-known/jwks.json HTTP/1.1\r\n");
    let rejected = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let _ = stream.write_all(if valid_request { response } else { rejected });
    let _ = stream.flush();
}

/// One DER certificate as a PEM block, the form a `caBundleFile` holds.
fn pem_certificate(der: &[u8]) -> String {
    use base64::Engine as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}

impl Drop for JwksServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("JWKS server stops");
        }
    }
}

/// One shipped reference deployment project, staged for the real binary.
///
/// Its fixtures take the reference evaluation path rather than the acceptance
/// path, and they are the fixtures an adopter's own project resembles, so
/// behavior that differs between the two paths is proven on both.
struct ReferenceProject {
    root: tempfile::TempDir,
}

impl ReferenceProject {
    fn stage() -> Self {
        let root = tempfile::tempdir().expect("temporary deployment");
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence",
        );
        copy_tree(&project.join("bundle"), &root.path().join("bundle"));
        let bundle_configuration = root.path().join("bundle/evidence.yaml");
        let bundle_document =
            fs::read_to_string(&bundle_configuration).expect("read bundle document");
        fs::write(
            &bundle_configuration,
            bundle_document.replacen(
                "assuranceProfile: evidence-grade",
                "assuranceProfile: local",
                1,
            ),
        )
        .expect("select local assurance for the isolated CLI test");
        let secret_root = root.path().join("secrets");
        fs::create_dir(&secret_root).expect("create private secret root");
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("set private secret-root mode");

        stage_reference_secrets(&secret_root);

        let runtime =
            fs::read_to_string(project.join("runtime.yaml")).expect("read runtime template");
        let bundle_path = root.path().join("bundle");
        let bundle_directory = bundle_path.to_str().expect("temporary path is UTF-8");
        let audit_path = root.path().join("audit.jsonl");
        let runtime = runtime
            .replacen("/etc/registry-evidence/bundle", bundle_directory, 1)
            .replacen(
                "/run/secrets/registry-evidence",
                secret_root.to_str().expect("temporary path is UTF-8"),
                1,
            )
            .replacen(
                "/var/lib/registry-evidence/audit/evidence.jsonl",
                audit_path.to_str().expect("temporary path is UTF-8"),
                1,
            )
            .replacen(
                "signer:\n  kind: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  timeoutMilliseconds: 2000",
                "signer:\n  kind: local-jwk\n  privateKeyRef: secret:file/evidence-signing",
                1,
            );
        fs::write(root.path().join("runtime.yaml"), runtime).expect("stage runtime");
        Self { root }
    }

    /// Rewrite the first occurrence of one passage in a staged project file.
    fn replace(&self, relative: &str, from: &str, to: &str) {
        let path = self.root.path().join(relative);
        let text = fs::read_to_string(&path).expect("read staged project file");
        assert!(text.contains(from), "{relative} does not contain {from:?}");
        fs::write(&path, text.replacen(from, to, 1)).expect("write staged project file");
    }

    /// Run against the project with the immutable modes the runtime demands.
    ///
    /// The modes are restored before the caller asserts anything, so a failed
    /// assertion still leaves a tree the temporary directory can remove.
    fn sealed<T>(&self, run: impl FnOnce(&Path) -> T) -> T {
        let bundle = self.root.path().join("bundle");
        let runtime = self.root.path().join("runtime.yaml");
        refresh_package_envelope(&bundle);
        set_tree_mode(&bundle, 0o555, 0o444);
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o444))
            .expect("set immutable runtime mode");
        let outcome = run(&runtime);
        set_tree_mode(&bundle, 0o755, 0o644);
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o644))
            .expect("restore runtime mode");
        outcome
    }
}

#[test]
fn actual_binary_checks_and_evaluates_an_immutable_project() {
    let project = ReferenceProject::stage();
    let (check, evaluate) = project.sealed(|runtime| {
        (
            invoke(runtime, &["check"]),
            invoke(
                runtime,
                &["evaluate", "--fixture", "fixtures/adult-status-cases.yaml"],
            ),
        )
    });

    assert_success(
        &check,
        "Evidence package ",
        " passed check (3 requirements)\n",
    );
    assert_success(
        &evaluate,
        "Evidence fixture passed (",
        " evaluated cases)\n",
    );
}

/// Set the staged bundle's `burstPerPrincipal`, whatever it held before.
fn set_burst(project: &ReferenceProject, burst: u32) {
    let path = project.root.path().join("bundle/evidence.yaml");
    let text = fs::read_to_string(&path).expect("read staged bundle");
    assert!(
        text.contains("burstPerPrincipal:"),
        "the staged bundle declares a burst"
    );
    let rewritten = text
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("burstPerPrincipal:") {
                format!("  burstPerPrincipal: {burst}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&path, rewritten).expect("write staged bundle");
}

/// A burst below the largest request cost the bundle admits makes some
/// requests permanently unadmittable. `check` says so, naming the ceiling and
/// the key to change, and still passes: a smaller burst is a legitimate way to
/// cap batch size, so it is a warning rather than a refusal, and
/// `--deny-warnings` turns it into one.
#[test]
fn check_warns_when_the_burst_cannot_hold_the_largest_request_cost() {
    let project = ReferenceProject::stage();
    set_burst(&project, 10);
    let below = project.sealed(|runtime| invoke(runtime, &["check"]));
    assert!(below.status.success(), "a low burst is not a refusal");
    let stdout = std::str::from_utf8(&below.stdout).expect("stdout is UTF-8");
    assert!(stdout.ends_with(" passed check (3 requirements)\n"));
    let stderr = std::str::from_utf8(&below.stderr).expect("stderr is UTF-8");
    let lines = stderr.lines().collect::<Vec<_>>();
    let bundle = project.root.path().join("bundle/evidence.yaml");
    assert_eq!(lines.len(), 4, "one warning and the summary: {stderr}");
    assert!(
        lines[0].starts_with(&format!(
            "warning[evidence.bundle.burst-below-largest-request] {}:",
            bundle.display()
        )) && lines[0].ends_with(" /rateLimits/burstPerPrincipal"),
        "the warning names the key's position and path: {stderr}"
    );
    assert_eq!(
        lines[1],
        "  the burst is below 16, the request batch item ceiling, the largest request cost this \
         bundle admits: a request batch or holder-bound release that costs more than the burst \
         is always refused as evidence.invalid_request"
    );
    assert_eq!(
        lines[2],
        "  next: Raise rateLimits.burstPerPrincipal to at least 16, the request batch item \
         ceiling, unless capping those requests is intended."
    );
    assert!(lines[3].starts_with("0 errors, 1 warning in "), "{stderr}");

    let denied = project.sealed(|runtime| invoke(runtime, &["check", "--deny-warnings"]));
    assert_eq!(
        denied.status.code(),
        Some(1),
        "--deny-warnings refuses a warning"
    );
    assert!(denied.stdout.is_empty(), "a refused check wrote output");

    set_burst(&project, 16);
    let covered = project.sealed(|runtime| invoke(runtime, &["check"]));
    assert_success(
        &covered,
        "Evidence package ",
        " passed check (3 requirements)\n",
    );
}

/// The offline check reads no secret material and asks nothing of the file
/// modes: a project checks before its secrets are mounted and before its
/// package is sealed, on any machine.
#[test]
fn check_passes_offline_without_secrets_or_immutable_modes() {
    let deployment = Deployment::stage("all-definitions");
    refresh_package_envelope(&deployment.path("bundle"));

    assert_success(
        &invoke(&deployment.path("runtime.yaml"), &["check"]),
        "Evidence package ",
        " passed check (4 requirements)\n",
    );
}

/// Every problem the reader finds is reported in one run, each with the line
/// and column of the member it is about.
#[test]
fn check_reports_every_runtime_finding_with_its_position_in_one_run() {
    let deployment = Deployment::stage("all-definitions");
    let runtime = deployment.path("runtime.yaml");
    deployment.replace(
        "runtime.yaml",
        "  bind: 127.0.0.1:8080\n",
        "  bind: 127.0.0.1:8080\n  port: 8080\n",
    );
    deployment.append("runtime.yaml", "unknownField: true\n");

    let output = invoke(&runtime, &["check"]);
    let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(1), "check exit code: {stderr}");
    assert!(output.stdout.is_empty(), "a refused check wrote output");
    let lines = stderr.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 7, "two errors and the summary: {stderr}");
    assert_eq!(
        lines[0],
        format!(
            "error[config.removed-key] {}:7:3 /listener/port",
            runtime.display()
        )
    );
    assert_eq!(lines[1], "  `port` is no longer accepted");
    assert_eq!(
        lines[2],
        "  next: Declare listener.bind as host:port, such as 127.0.0.1:8080."
    );
    assert_eq!(
        lines[3],
        format!(
            "error[config.unknown-key] {}:25:1 /unknownField",
            runtime.display()
        )
    );
    assert_eq!(lines[4], "  `unknownField` is not a member of this mapping");
    assert!(lines[5].starts_with("  next: "), "{stderr}");
    assert_eq!(lines[6], "2 errors, 0 warnings in 1 file");
}

/// `--format json` writes one ctl report on stdout and nothing on stderr, in
/// both outcomes, and the diagnostics are the CFG-DIAG-1 objects.
#[test]
fn check_as_json_reports_the_envelope_on_success_and_refusal() {
    let deployment = Deployment::stage("all-definitions");
    refresh_package_envelope(&deployment.path("bundle"));
    let runtime = deployment.path("runtime.yaml");

    let passed = invoke(&runtime, &["check", "--format", "json"]);
    assert!(passed.status.success(), "the check passed");
    assert!(passed.stderr.is_empty(), "the JSON form wrote to stderr");
    let report: Value = serde_json::from_slice(&passed.stdout).expect("one JSON document");
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "check");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["requirements"], 4);
    assert!(
        report["packageDigest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:")),
        "the report names the package digest: {report}"
    );
    assert!(
        report["filesChecked"]
            .as_u64()
            .is_some_and(|files| files > 1),
        "the runtime file and the package were checked: {report}"
    );
    assert_eq!(report["diagnostics"], json!([]));

    deployment.append("runtime.yaml", "unknownField: true\n");
    let refused = invoke(&runtime, &["check", "--format", "json"]);
    assert_eq!(refused.status.code(), Some(1), "the check refused");
    assert!(refused.stderr.is_empty(), "the JSON form wrote to stderr");
    let report: Value = serde_json::from_slice(&refused.stdout).expect("one JSON document");
    assert_eq!(report["ok"], false);
    assert_eq!(report["status"], "domain-refusal");
    assert!(report.get("packageDigest").is_none(), "{report}");
    assert!(report.get("requirements").is_none(), "{report}");
    let diagnostics = report["diagnostics"]
        .as_array()
        .expect("a diagnostics list");
    assert_eq!(diagnostics.len(), 1, "{report}");
    let diagnostic = &diagnostics[0];
    assert_eq!(diagnostic["severity"], "error");
    assert_eq!(diagnostic["code"], "config.unknown-key");
    assert_eq!(diagnostic["path"], "/unknownField");
    assert_eq!(
        diagnostic["source"],
        json!({"file": runtime.display().to_string(), "line": 24, "column": 1})
    );
    assert!(diagnostic["suggestedAction"].is_string(), "{report}");
}

/// A runtime file the check cannot read was not refused: the command depends
/// on it, so the check exits 3.
#[test]
fn check_reports_a_runtime_file_it_cannot_read_as_unavailable() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = invoke(&root.path().join("runtime.yaml"), &["check"]);
    assert_one_check_error(
        &output,
        3,
        "evidence.runtime.unavailable",
        "the runtime file could not be read",
    );

    let json = invoke(
        &root.path().join("runtime.yaml"),
        &["check", "--format", "json"],
    );
    assert_eq!(json.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&json.stdout).expect("one JSON document");
    assert_eq!(report["ok"], false);
    assert_eq!(report["status"], "operational-failure");
}

/// Without `--environment` an expression is checked by its syntax and
/// position only: no variable is read, a value check that needs the text is
/// skipped, and a package root filled by substitution is reported as not
/// checked. With it, the check substitutes as startup does.
#[test]
fn check_skips_value_checks_on_substituted_members_unless_asked_for_the_environment() {
    let deployment = Deployment::stage("all-definitions");
    refresh_package_envelope(&deployment.path("bundle"));
    let runtime = deployment.path("runtime.yaml");
    let bundle = deployment.path("bundle");
    deployment.replace(
        "runtime.yaml",
        &format!("  root: {}\n", bundle.display()),
        "  root: ${EVIDENCE_PACKAGE_ROOT}\n",
    );
    let audit = deployment.path("audit.jsonl");
    deployment.replace(
        "runtime.yaml",
        &format!("  path: {}\n", audit.display()),
        "  path: ${EVIDENCE_AUDIT_PATH}\n",
    );
    let check = |arguments: &[&str], variables: &[(&str, &Path)]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .args(arguments)
            .arg("--runtime-config")
            .arg(&runtime)
            .env_remove("REGISTRY_EVIDENCE_RUNTIME")
            .env_remove("EVIDENCE_PACKAGE_ROOT")
            .env_remove("EVIDENCE_AUDIT_PATH")
            .env_remove("EVIDENCE_BIND");
        for (name, value) in variables {
            command.env(name, value);
        }
        command.output().expect("evidence binary starts")
    };

    // The audit path `${EVIDENCE_AUDIT_PATH}` stands for itself and is not an
    // absolute path, a finding that needs the substituted text: skipped.
    let offline = check(&["check"], &[]);
    let stderr = std::str::from_utf8(&offline.stderr).expect("stderr is UTF-8");
    assert_eq!(
        offline.status.code(),
        Some(0),
        "nothing was refused: {stderr}"
    );
    assert!(
        offline.stdout.is_empty(),
        "an unchecked package is not reported as passing"
    );
    let lines = stderr.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "one warning and the summary: {stderr}");
    assert_eq!(
        lines[0],
        format!(
            "warning[evidence.package.not-checked] {}:4:9 /package/root",
            runtime.display()
        )
    );
    assert_eq!(
        lines[1],
        "  package.root is filled by substitution, so the package was not checked"
    );
    assert_eq!(lines[3], "0 errors, 1 warning in 1 file");

    let with_environment = check(
        &["check", "--environment"],
        &[
            ("EVIDENCE_PACKAGE_ROOT", &bundle),
            ("EVIDENCE_AUDIT_PATH", &audit),
        ],
    );
    assert_success(
        &with_environment,
        "Evidence package ",
        " passed check (4 requirements)\n",
    );

    let unset = check(
        &["check", "--environment"],
        &[("EVIDENCE_AUDIT_PATH", &audit)],
    );
    let stderr = std::str::from_utf8(&unset.stderr).expect("stderr is UTF-8");
    assert_eq!(
        unset.status.code(),
        Some(1),
        "an unset variable is refused: {stderr}"
    );
    assert!(
        stderr.contains("EVIDENCE_PACKAGE_ROOT"),
        "the refusal names the variable: {stderr}"
    );

    // A value the decoder parses, such as the listener address, cannot be
    // read from an expression that stands for itself. Its check is skipped,
    // and so is the rest of the file, and a warning says so.
    deployment.replace(
        "runtime.yaml",
        "  bind: 127.0.0.1:8080\n",
        "  bind: ${EVIDENCE_BIND:-127.0.0.1:8080}\n",
    );
    let parsed = check(&["check"], &[]);
    let stderr = std::str::from_utf8(&parsed.stderr).expect("stderr is UTF-8");
    assert_eq!(
        parsed.status.code(),
        Some(0),
        "nothing was refused: {stderr}"
    );
    assert!(
        parsed.stdout.is_empty(),
        "an unchecked package is not reported as passing"
    );
    let lines = stderr.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "one warning and the summary: {stderr}");
    assert_eq!(
        lines[0],
        format!(
            "warning[evidence.runtime.not-checked] {}:6:9 /listener/bind",
            runtime.display()
        )
    );
    let denied = check(&["check", "--deny-warnings"], &[]);
    assert_eq!(
        denied.status.code(),
        Some(1),
        "--deny-warnings refuses an unchecked file"
    );
}

#[test]
fn dependency_check_proves_the_real_runtime_boundaries() {
    let key_server = JwksServer::start();
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());

    assert_success(
        &deployment.check_with_runtime_dependencies(),
        "Evidence package ",
        " passed check (4 requirements)\n",
    );
}

#[test]
fn dependency_check_accepts_an_audit_sink_inside_the_required_root() {
    let key_server = JwksServer::start();
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());

    assert_success(
        &deployment.check_with_audit_under(deployment.root.path()),
        "Evidence package ",
        " passed check (4 requirements)\n",
    );
}

#[test]
fn dependency_check_refuses_an_audit_sink_outside_the_required_root() {
    let key_server = JwksServer::start();
    let ephemeral = tempfile::tempdir().expect("temporary ephemeral root");
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());

    let output = deployment.check_with_audit_under(ephemeral.path());

    assert_one_check_error(
        &output,
        1,
        "evidence.deployment.audit-outside-root",
        "audit destination check failed: the configured audit destination resolves outside the \
         declared audit root",
    );
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert!(!stderr.contains(&deployment.path("audit.jsonl").display().to_string()));
}

#[test]
fn dependency_check_refuses_an_audit_sink_symlinked_out_of_the_required_root() {
    let key_server = JwksServer::start();
    let ephemeral = tempfile::tempdir().expect("temporary ephemeral root");
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());
    let escape = ephemeral.path().join("audit.jsonl");
    fs::write(&escape, "").expect("stage ephemeral audit file");
    std::os::unix::fs::symlink(&escape, deployment.path("audit.jsonl"))
        .expect("stage escaping audit file");

    let output = deployment.check_with_audit_under(deployment.root.path());

    assert_one_check_error(
        &output,
        1,
        "evidence.deployment.audit-outside-root",
        "audit destination check failed: the configured audit destination resolves outside the \
         declared audit root",
    );
}

/// A `stdout` destination is a complete deployment: the dependency proof opens
/// it like any other destination.
#[test]
fn dependency_check_accepts_a_stdout_audit_destination() {
    let key_server = JwksServer::start();
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());
    deployment.write_audit_to_stdout();

    assert_success(
        &deployment.check_with_runtime_dependencies(),
        "Evidence package ",
        " passed check (4 requirements)\n",
    );
    assert!(!deployment.path("audit.jsonl").exists());
}

/// Containment is a statement about a file. A `stdout` destination has none,
/// so the flag is refused rather than silently satisfied.
#[test]
fn dependency_check_refuses_a_required_audit_root_for_a_stdout_destination() {
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.write_audit_to_stdout();

    let output = deployment.check_with_audit_under(deployment.root.path());

    assert_one_check_error(
        &output,
        1,
        "evidence.deployment.audit-not-a-file",
        "--require-audit-under needs a file audit destination; this runtime writes audit to stdout",
    );
}

#[test]
fn dependency_check_refuses_a_required_audit_root_that_is_not_an_absolute_directory() {
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();

    let output = deployment.check_with_audit_under(Path::new("var/lib/registry-evidence"));

    assert_one_check_error(
        &output,
        1,
        "evidence.deployment.audit-outside-root",
        "audit destination check failed: the declared audit root is not an existing absolute \
         directory",
    );
}

#[test]
fn dependency_check_fails_closed_when_the_jwks_endpoint_is_unavailable() {
    let unavailable = TcpListener::bind("127.0.0.1:0").expect("ephemeral port binds");
    let origin = format!(
        "http://{}",
        unavailable.local_addr().expect("listener has an address")
    );
    drop(unavailable);

    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(&origin);
    let output = deployment.check_with_runtime_dependencies();

    assert_one_check_error(
        &output,
        3,
        "evidence.deployment.dependency-unavailable",
        "a required runtime dependency is unavailable",
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&origin));
}

/// An issuer whose key set is served under a private certificate authority is
/// reachable only through the trust profile the bundle names for it: the
/// system roots alone refuse its certificate, and naming the profile adds that
/// one authority for that one connection.
#[test]
fn dependency_check_trusts_a_private_ca_issuer_only_through_its_named_profile() {
    let (key_server, authority) = JwksServer::start_under_private_ca();
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());

    let refused = deployment.check_with_runtime_dependencies();
    assert_one_check_error(
        &refused,
        3,
        "evidence.deployment.dependency-unavailable",
        "a required runtime dependency is unavailable",
    );

    deployment.trust_issuer_through("issuer-pki", &authority);
    let output = deployment.check_with_runtime_dependencies();

    assert_success(
        &output,
        "Evidence package ",
        " passed check (4 requirements)\n",
    );
}

/// A trust profile trusts the authority it names and nothing else: an issuer
/// whose certificate another private authority signed is still refused.
#[test]
fn dependency_check_refuses_an_issuer_the_named_profile_does_not_vouch_for() {
    let (key_server, _authority) = JwksServer::start_under_private_ca();
    let (_other_server, other_authority) = JwksServer::start_under_private_ca();
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());
    deployment.trust_issuer_through("issuer-pki", &other_authority);

    let output = deployment.check_with_runtime_dependencies();

    assert_one_check_error(
        &output,
        3,
        "evidence.deployment.dependency-unavailable",
        "a required runtime dependency is unavailable",
    );
}

/// A profile bound to a file that holds no certificate refuses when the
/// runtime file loads, rather than leaving the issuer on the system roots
/// alone.
#[test]
fn dependency_check_refuses_an_issuer_profile_that_is_not_a_certificate_bundle() {
    let (key_server, _authority) = JwksServer::start_under_private_ca();
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());
    deployment.trust_issuer_through("issuer-pki", "not a certificate\n");

    let output = deployment.check_with_runtime_dependencies();

    assert_one_check_error(
        &output,
        1,
        "evidence.runtime.invalid-ca-bundle",
        "TLS CA bundle contains non-certificate PEM data",
    );
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert!(
        stderr.contains(" /outboundTls/trustProfiles/issuer-pki/caBundleFile\n"),
        "the refusal names the member that binds the file: {stderr}"
    );
}

#[tokio::test]
async fn dependency_check_fails_when_an_audit_writer_already_holds_the_destination() {
    use registry_evidence::audit::EvidenceAuditLog;
    use registry_platform_audit::{AuditDestination, FileDestination};

    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    let destination = FileDestination::new(deployment.path("audit.jsonl"))
        .expect("the audit destination is valid");
    let writer = EvidenceAuditLog::initialize(
        AuditDestination::File(destination),
        b"audit-hash-secret-32-bytes-minimum-value".to_vec(),
        1,
    )
    .await
    .expect("first audit writer initializes");

    let output = deployment.check_with_runtime_dependencies();

    assert_one_check_error(
        &output,
        3,
        "evidence.deployment.audit-unavailable",
        "runtime audit initialization failed: another process holds the single-writer lock \
         beside the audit file; stop it before starting this one",
    );
    drop(writer);
}

/// A candidate staged beside the instance it will replace shares that
/// instance's audit path, so the writer lock is held by design. The lock-free
/// form proves everything else the candidate's start needs and leaves the
/// running writer untouched.
#[tokio::test]
async fn dependency_check_without_the_audit_lock_passes_beside_a_running_writer() {
    use registry_evidence::audit::EvidenceAuditLog;
    use registry_platform_audit::{AuditDestination, FileDestination};

    let key_server = JwksServer::start();
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());
    let writer = EvidenceAuditLog::initialize(
        AuditDestination::File(
            FileDestination::new(deployment.path("audit.jsonl"))
                .expect("the audit destination is valid"),
        ),
        b"audit-hash-secret-32-bytes-minimum-value".to_vec(),
        1,
    )
    .await
    .expect("first audit writer initializes");

    let output = deployment.check_without_audit_lock();

    assert_success(
        &output,
        "Evidence package ",
        " passed check (4 requirements)\n",
    );
    assert!(
        writer.ready().await,
        "the lock-free check disturbed the running writer"
    );
    drop(writer);
}

/// One audit boundary the lock-free check must still refuse, with the exact
/// operator text, and whether a writer holds the destination while it runs.
struct LockFreeAuditCase {
    label: &'static str,
    running_writer: bool,
    break_audit: fn(&Deployment),
    expected: &'static str,
}

const TORN_LINE_SIDE_FILE_OCCUPIED: &str =
    "evidence: runtime audit initialization failed: the audit file could not be opened: audit \
     file has an incomplete final entry and its torn-line side file `<audit.path>.torn` \
     already holds other bytes; archive the side file and restart\n";

/// Leaving the lock to the running writer does not leave the rest of the audit
/// boundary unchecked: a mode, a file the candidate could not write, and an
/// active file ending in a torn line whose side file already holds another
/// each refuse as they would at `serve`.
#[tokio::test]
async fn dependency_check_without_the_audit_lock_still_refuses_an_unusable_audit_boundary() {
    use registry_evidence::audit::EvidenceAuditLog;
    use registry_platform_audit::{AuditDestination, FileDestination};

    const OWNER_ONLY: &str = "evidence: runtime audit initialization failed: the audit file could \
                              not be opened: audit files must be owner-only, singly linked \
                              regular files; chmod them 0600 and remove any extra hard link\n";
    let cases = [
        LockFreeAuditCase {
            label: "an audit file readable beyond its owner",
            running_writer: false,
            break_audit: |deployment| {
                deployment.stage_audit_file("");
                set_mode(&deployment.path("audit.jsonl"), 0o644);
            },
            expected: OWNER_ONLY,
        },
        LockFreeAuditCase {
            label: "an audit file the service owner cannot write",
            running_writer: false,
            break_audit: |deployment| {
                deployment.stage_audit_file("");
                set_mode(&deployment.path("audit.jsonl"), 0o400);
            },
            expected: "evidence: runtime audit initialization failed: the audit file could not \
                       be opened: audit file is not readable and writable\n",
        },
        LockFreeAuditCase {
            label: "a running writer's audit file made readable beyond its owner",
            running_writer: true,
            break_audit: |deployment| set_mode(&deployment.path("audit.jsonl"), 0o644),
            expected: OWNER_ONLY,
        },
        LockFreeAuditCase {
            label: "a torn final line whose side file already holds another",
            running_writer: false,
            break_audit: |deployment| {
                deployment.stage_audit_file("{\"written\":\"before the interruption\"");
                deployment.stage_torn_line_side_file("an earlier torn line");
            },
            expected: TORN_LINE_SIDE_FILE_OCCUPIED,
        },
    ];

    for case in cases {
        let key_server = JwksServer::start();
        let deployment = Deployment::stage("all-definitions");
        deployment.stage_acceptance_secrets();
        deployment.point_authentication_to(key_server.origin());
        let writer = if case.running_writer {
            Some(
                EvidenceAuditLog::initialize(
                    AuditDestination::File(
                        FileDestination::new(deployment.path("audit.jsonl"))
                            .expect("the audit destination is valid"),
                    ),
                    b"audit-hash-secret-32-bytes-minimum-value".to_vec(),
                    1,
                )
                .await
                .expect("first audit writer initializes"),
            )
        } else {
            None
        };
        (case.break_audit)(&deployment);
        let output = deployment.check_without_audit_lock();
        drop(writer);

        assert!(
            !output.status.success(),
            "{}: the lock-free check accepted an unusable audit boundary",
            case.label
        );
        // `check` reports the sentence `serve` prints, as a diagnostic.
        let message = case
            .expected
            .strip_prefix("evidence: ")
            .and_then(|message| message.strip_suffix('\n'))
            .expect("the expected text is the serve-form sentence");
        assert_one_check_error(&output, 3, "evidence.deployment.audit-unavailable", message);
    }
}

#[test]
fn dependency_check_refuses_an_audit_directory_the_candidate_could_not_write() {
    let key_server = JwksServer::start();
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());
    set_mode(deployment.root.path(), 0o500);
    let output = deployment.check_without_audit_lock();
    set_mode(deployment.root.path(), 0o700);

    assert_one_check_error(
        &output,
        3,
        "evidence.deployment.audit-unavailable",
        "runtime audit initialization failed: the audit file could not be opened: audit \
         directory is not readable, writable, and searchable",
    );
}

#[test]
fn check_accepts_the_lock_free_form_only_with_the_dependency_check() {
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.seal();
    let output = invoke(
        &deployment.path("runtime.yaml"),
        &["check", "--without-audit-lock"],
    );
    deployment.unseal();

    assert!(
        !output.status.success(),
        "the lock-free form ran without the dependency check it qualifies"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("--require-runtime-dependencies"));
}

#[test]
fn check_refuses_an_already_stale_bound_extract_with_only_the_governed_source() {
    let root = tempfile::tempdir().expect("temporary deployment");
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence",
    );
    let bundle = root.path().join("bundle");
    copy_tree(&project.join("bundle"), &bundle);
    let bundle_configuration = bundle.join("evidence.yaml");
    let bundle_document = fs::read_to_string(&bundle_configuration).expect("read bundle document");
    fs::write(
        &bundle_configuration,
        bundle_document.replacen(
            "assuranceProfile: evidence-grade",
            "assuranceProfile: local",
            1,
        ),
    )
    .expect("select local assurance");

    let secret_root = root.path().join("secrets");
    fs::create_dir(&secret_root).expect("create private secret root");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("set private secret-root mode");
    stage_reference_secrets(&secret_root);

    let fixture: serde_json::Value = serde_norway::from_slice(
        &fs::read(bundle.join("fixtures/professional-licence-cases.yaml"))
            .expect("read statement fixture"),
    )
    .expect("parse statement fixture");
    let seed = fixture
        .pointer("/common/extract")
        .and_then(serde_json::Value::as_str)
        .expect("fixture carries extract seed")
        .replacen("2026-08-01T00:00:00Z", "2000-01-01T00:00:00Z", 1);
    let extract_path = root.path().join("licence-register.sqlite");
    rusqlite::Connection::open(&extract_path)
        .expect("create extract")
        .execute_batch(&seed)
        .expect("materialize extract");
    fs::set_permissions(&extract_path, fs::Permissions::from_mode(0o444)).expect("seal extract");

    let runtime = fs::read_to_string(project.join("runtime.yaml")).expect("read runtime template");
    let runtime = runtime
        .replacen(
            "/etc/registry-evidence/bundle",
            bundle.to_str().expect("bundle path is UTF-8"),
            1,
        )
        .replacen(
            "/run/secrets/registry-evidence",
            secret_root.to_str().expect("secret path is UTF-8"),
            1,
        )
        .replacen(
            "/var/lib/registry-evidence/audit/evidence.jsonl",
            root.path()
                .join("audit.jsonl")
                .to_str()
                .expect("audit path is UTF-8"),
            1,
        )
        .replacen(
            "/var/lib/registry-evidence/extracts/licence-register-2026-08-01.sqlite",
            extract_path.to_str().expect("extract path is UTF-8"),
            1,
        )
        .replacen(
            "signer:\n  kind: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  timeoutMilliseconds: 2000",
            "signer:\n  kind: local-jwk\n  privateKeyRef: secret:file/evidence-signing",
            1,
        );
    let runtime_path = root.path().join("runtime.yaml");
    fs::write(&runtime_path, runtime).expect("stage runtime");
    refresh_package_envelope(&bundle);
    set_tree_mode(&bundle, 0o555, 0o444);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444)).expect("seal runtime");

    let output = invoke(&runtime_path, &["check", "--require-runtime-dependencies"]);

    set_tree_mode(&bundle, 0o755, 0o644);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o644)).expect("unseal runtime");
    fs::set_permissions(&extract_path, fs::Permissions::from_mode(0o644)).expect("unseal extract");
    assert_one_check_error(
        &output,
        3,
        "evidence.deployment.stale-extract",
        "bound extract is stale for source licence-register",
    );
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(!diagnostic.contains("2000-01-01"));
    assert!(!diagnostic.contains("2026-08-01-licence-register"));
    assert!(!diagnostic.contains(extract_path.to_string_lossy().as_ref()));
}

/// The reference path has to explain itself as well as the acceptance path does.
///
/// A reference case that records only the form it was written in says a case
/// was read, never how far it got, which is the whole of what the trace is for.
#[test]
fn explaining_a_reference_project_fixture_traces_how_far_each_case_reached() {
    let project = ReferenceProject::stage();
    let output = project.sealed(|runtime| {
        invoke(
            runtime,
            &[
                "evaluate",
                "--fixture",
                "fixtures/adult-status-cases.yaml",
                "--explain",
                "--explain-format",
                "json",
            ],
        )
    });

    assert!(
        output.status.success(),
        "explained evaluation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    assert_eq!(report["passed"], json!(true));

    let cases = report["cases"].as_array().expect("cases is an array");
    assert!(!cases.is_empty(), "the document carried no case");
    for case in cases {
        let reached = stage_names(case);
        assert!(
            reached.len() > 1,
            "case {} recorded only {reached:?}, so the trace never says how far it got",
            case["id"]
        );
    }

    // The cases that run the pipeline record the pipeline, so a reader is
    // promised no stage the reference path declines to report.
    let resolved = cases
        .iter()
        .find(|case| case["id"] == json!("positive"))
        .expect("the fixture states a resolving case");
    for stage in [
        "prepare", "acquire", "extract", "derive", "validate", "sign",
    ] {
        assert!(
            stage_names(resolved).contains(&stage),
            "a resolving reference case never recorded {stage}: {:?}",
            stage_names(resolved)
        );
    }

    // An unresolved case reports the unresolved outcome on the stage that
    // reached it, exactly as the acceptance path does.
    let unresolved = cases
        .iter()
        .find(|case| case["id"] == json!("no-match"))
        .expect("the fixture states an unresolved case");
    let extract = unresolved["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("extract"))
        .expect("an unresolved case records its extraction");
    assert_eq!(extract["status"], json!("no-match"));
}

/// A reference case that fails at its source says so on the acquisition.
///
/// A response the source contract refuses is an acquisition that was reached
/// and failed. Reporting only the preparation before it reads as though the
/// case never got as far as calling its source, which is the opposite of what
/// the reader needs from precisely this failure.
#[test]
fn a_reference_case_whose_response_is_refused_records_a_failed_acquisition() {
    let project = ReferenceProject::stage();
    project.replace(
        "bundle/fixtures/adult-status-cases.yaml",
        "  - id: positive\n    response:\n      total: 1\n",
        "  - id: positive\n    response:\n      errors: [source-refused]\n      total: 1\n",
    );
    let output = project.sealed(|runtime| {
        invoke(
            runtime,
            &[
                "evaluate",
                "--fixture",
                "fixtures/adult-status-cases.yaml",
                "--explain",
                "--explain-format",
                "json",
            ],
        )
    });

    assert!(
        !output.status.success(),
        "the refused response was accepted"
    );
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        concat!(
            "case positive: reference fixture source projection failed\n",
            "evidence: reference fixture source projection failed\n",
        )
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    let refused = report["cases"]
        .as_array()
        .expect("cases is an array")
        .iter()
        .find(|case| case["id"] == json!("positive"))
        .expect("the refused case is traced");
    let acquire = refused["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("acquire"))
        .expect("a case refused at its source records its acquisition");
    assert_eq!(acquire["status"], json!("failed"));
}

/// A reference case whose scalar expectation misses by class says so, and the
/// run names the case in both output forms without ever naming the value.
///
/// The fixed message on its own says only that a scalar did not match; the
/// structured line beside it carries the case identifier and the two value
/// classes, which is what a reader needs to find the case and see the shape of
/// the mistake. The mistyped expectation itself reaches neither form.
#[test]
fn a_reference_scalar_mismatch_names_the_case_and_the_value_classes() {
    let project = ReferenceProject::stage();
    project.replace(
        "bundle/fixtures/adult-status-cases.yaml",
        "      value: true\n",
        "      value: definitely-not-a-boolean\n",
    );
    let unexplained = project.sealed(|runtime| {
        invoke(
            runtime,
            &["evaluate", "--fixture", "fixtures/adult-status-cases.yaml"],
        )
    });
    let explained = project.sealed(|runtime| {
        invoke(
            runtime,
            &[
                "evaluate",
                "--fixture",
                "fixtures/adult-status-cases.yaml",
                "--explain",
                "--explain-format",
                "json",
            ],
        )
    });

    for output in [&unexplained, &explained] {
        assert!(!output.status.success(), "the mistyped expectation passed");
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert_eq!(
            stderr,
            concat!(
                "case positive: reference scalar value did not match ",
                "(expected class string, observed class boolean-true)\n",
                "evidence: reference scalar value did not match\n",
            ),
            "the failure must name the case and the classes, never the value"
        );
    }

    let stdout = std::str::from_utf8(&explained.stdout).expect("stdout is UTF-8");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    assert_eq!(report["passed"], json!(false));
    assert_eq!(
        report["failingCase"],
        json!({
            "id": "positive",
            "cause": "reference scalar value did not match",
            "expectedClass": "string",
            "observedClass": "boolean-true",
        }),
        "the document must carry the same named case the line printed"
    );
    for surface in [
        stdout,
        std::str::from_utf8(&explained.stderr).expect("stderr is UTF-8"),
        std::str::from_utf8(&unexplained.stderr).expect("stderr is UTF-8"),
    ] {
        assert!(
            !surface.contains("definitely-not-a-boolean"),
            "a diagnostic reprinted the authored expectation: {surface}"
        );
    }
}

/// A derivation that returns a structured key its reviewed schema never
/// declared fails the fixture evaluation, and the diagnostic names the key.
///
/// The output gate closes the declared property set itself, so the refusal
/// says which key was undeclared instead of only that a shape was wrong. The
/// value the derivation put under that key reaches no diagnostic.
#[test]
fn a_structured_value_naming_an_undeclared_key_fails_the_fixture_and_names_the_key() {
    let deployment = Deployment::stage("adult-status");
    deployment.replace(
        "bundle/evidence.yaml",
        "concepts: [{handle: is_adult, id: urn:example:fixture:concept:adult-status, form: boolean, required: true, constraints: {}}]",
        concat!(
            "concepts: [",
            "{handle: is_adult, id: urn:example:fixture:concept:adult-status, form: boolean, required: true, constraints: {}}, ",
            "{handle: record_note, id: urn:example:fixture:concept:record-note, form: reviewed-structured-value, required: false, constraints: {schema: urn:example:fixture:schema:record-note:v1, maximumSerializedBytes: 512}}]",
        ),
    );
    deployment.write(
        "bundle/schemas/record-note.schema.yaml",
        concat!(
            "$schema: https://json-schema.org/draft/2020-12/schema\n",
            "$id: urn:example:fixture:schema:record-note:v1\n",
            "type: object\n",
            "additionalProperties: false\n",
            "required: [note]\n",
            "properties:\n",
            "  note: {type: string, maxLength: 64}\n",
        ),
    );
    deployment.replace(
        "bundle/derivations/adult-status.rhai",
        "        value: compare_dates(evaluation_context.legal_local_date, threshold) >= 0\n    }]",
        concat!(
            "        value: compare_dates(evaluation_context.legal_local_date, threshold) >= 0\n",
            "    }, #{\n",
            "        concept_id: \"urn:example:fixture:concept:record-note\",\n",
            "        value: #{\n",
            "            form: \"reviewed-structured-value\",\n",
            "            schema: \"urn:example:fixture:schema:record-note:v1\",\n",
            "            fields: #{\n",
            "                note: \"computed\",\n",
            "                undeclared_key: \"CANARY\"\n",
            "            }\n",
            "        }\n",
            "    }]",
        )
        .replace("CANARY", CANARY)
        .as_str(),
    );
    let output = deployment.evaluate(&["--explain", "--explain-format", "json"]);

    assert!(
        !output.status.success(),
        "an undeclared structured key passed the output gate"
    );
    let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert_eq!(
        stderr,
        concat!(
            "case positive: fixture evaluation failed unexpectedly ",
            "(expected class boolean-true, observed absent)\n",
            "evidence: fixture evaluation failed unexpectedly\n",
        )
    );
    assert!(!stderr.contains(CANARY), "the diagnostic reprinted a value");

    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(!stdout.contains(CANARY), "the trace reprinted a value");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    assert_eq!(report["failingCase"]["id"], json!("positive"));
    let failed = report["cases"]
        .as_array()
        .expect("cases is an array")
        .iter()
        .find(|case| case.get("failure").is_some())
        .expect("the document names the case that failed");
    let validate = failed["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("validate"))
        .expect("the failed case records its output gate");
    assert_eq!(validate["status"], json!("failed"));
    assert_eq!(
        validate["note"],
        json!("the output gate rejected an undeclared structured key \"undeclared_key\"")
    );
}

/// A chained acquisition is traced stage by stage, not as one acquisition.
///
/// The whole reason this acquisition kind exists is that it makes several calls
/// in a fixed order, each reading only what an earlier one produced. A trace
/// that reported the chain as a single step would drop exactly the fact a
/// reader needs from it: which call the case got to, and which one stopped it.
#[test]
fn explaining_a_chained_acquisition_traces_every_planned_stage() {
    let deployment = Deployment::stage("surviving-spouse-status");
    // The operator half of the acquisition gate. The bundle names the kind it
    // needs; without this the deployment is refused before any case runs.
    deployment.append(
        "runtime.yaml",
        "acquisitionCapabilities: [search-then-fetch-set]\n",
    );
    let output = deployment.evaluate(&["--explain", "--explain-format", "json"]);

    assert!(
        output.status.success(),
        "explained evaluation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    let cases = report["cases"].as_array().expect("cases is an array");

    // The search and both members, each acquired and each extracted, before the
    // one derivation that sees them together.
    let resolved = cases
        .iter()
        .find(|case| case["id"] == json!("positive"))
        .expect("the fixture states a resolving case");
    assert_eq!(
        stage_names(resolved),
        vec![
            "prepare", "acquire", "extract", "acquire", "extract", "acquire", "extract", "derive",
            "validate", "expect", "sign",
        ],
        "a resolving chained case did not record every planned stage"
    );

    // A member whose response the declared projection refuses stops the chain at
    // its acquisition, so the trace names the call that was refused and never
    // reports the stages after it as reached.
    let refused = cases
        .iter()
        .find(|case| case["id"] == json!("negative-union-register-unresolved"))
        .expect("the fixture states a case whose first member answers nothing");
    assert_eq!(
        stage_outcomes(refused),
        vec![
            ("prepare", "ok"),
            ("acquire", "ok"),
            ("extract", "ok"),
            ("acquire", "failed"),
            ("expect", "ok"),
        ],
        "the chain did not stop on the member whose response was refused"
    );

    // A member that answers, but resolves no unique record for the reference the
    // search produced, stops the chain one stage later: the response is acquired
    // and the extraction is what fails.
    let stopped = cases
        .iter()
        .find(|case| case["id"] == json!("negative-death-register-unresolved"))
        .expect("the fixture states a case whose second member does not resolve");
    assert_eq!(
        stage_outcomes(stopped),
        vec![
            ("prepare", "ok"),
            ("acquire", "ok"),
            ("extract", "ok"),
            ("acquire", "ok"),
            ("extract", "ok"),
            ("acquire", "ok"),
            ("extract", "failed"),
            ("expect", "ok"),
        ],
        "the chain did not stop on the member that resolved nothing"
    );

    // An unresolved search is a settled outcome rather than an inconsistency,
    // and it is reported as one on the stage that reached it.
    let unresolved = cases
        .iter()
        .find(|case| case["id"] == json!("ambiguous"))
        .expect("the fixture states an unresolved search");
    let extract = unresolved["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("extract"))
        .expect("an unresolved search records its extraction");
    assert_eq!(extract["status"], json!("ambiguous"));
}

/// The stages one traced case recorded, each with the status it reached.
fn stage_outcomes(case: &Value) -> Vec<(&str, &str)> {
    case["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .map(|stage| {
            (
                stage["stage"].as_str().expect("a stage is named"),
                stage["status"].as_str().expect("a stage has a status"),
            )
        })
        .collect()
}

/// The stages one traced case recorded, in the order it recorded them.
fn stage_names(case: &Value) -> Vec<&str> {
    case["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .map(|stage| stage["stage"].as_str().expect("a stage is named"))
        .collect()
}

/// The exact unexplained success output of the acceptance fixture.
///
/// It is pinned as one literal rather than a prefix and a suffix, because the
/// property under test is that asking for no trace produces this and nothing
/// else. A shape assertion would pass with a trace printed in the middle.
const UNEXPLAINED_SUCCESS: &str = "Evidence fixture passed (13 evaluated cases)\n";

/// The message the mutated acceptance fixture fails with, trace or no trace.
///
/// The structured line beside it names the case the fixed message belongs to.
/// This mutation fails at the expectation comparison before any value class was
/// reached on either side, so the line carries the case and the cause alone.
const MUTATED_FIXTURE_FAILURE: &str = concat!(
    "case no-match: fixture kernel failure did not match its public problem\n",
    "evidence: fixture kernel failure did not match its public problem\n",
);

/// Turn one acceptance case into a case whose stated outcome cannot happen.
///
/// The record is absent, so the lookup can only be unresolved, while the case
/// now claims a unique match. This is the ordinary authoring mistake `--explain`
/// exists for: the fixed message names the contract that broke, and only the
/// trace can say the extraction never found a record to begin with.
fn state_an_impossible_lookup(deployment: &Deployment) {
    deployment.replace(
        "bundle/fixtures/cases.yaml",
        "{id: no-match, source: {total: 0}, expected_lookup: no_match,",
        "{id: no-match, source: {total: 0}, expected_lookup: match,",
    );
}

#[test]
fn an_unexplained_fixture_run_prints_the_summary_line_and_nothing_else() {
    let deployment = Deployment::stage("adult-status");
    let output = deployment.evaluate(&[]);
    assert!(output.status.success(), "fixture evaluation failed");
    assert!(output.stderr.is_empty(), "fixture evaluation wrote stderr");
    assert_eq!(
        std::str::from_utf8(&output.stdout).expect("stdout is UTF-8"),
        UNEXPLAINED_SUCCESS
    );
}

#[test]
fn explaining_a_passing_fixture_keeps_its_exit_code_and_keeps_its_summary_line() {
    let deployment = Deployment::stage("adult-status");
    let output = deployment.evaluate(&["--explain"]);
    assert!(output.status.success(), "explained evaluation failed");
    assert!(
        output.stderr.is_empty(),
        "explained evaluation wrote stderr"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.ends_with(UNEXPLAINED_SUCCESS),
        "the summary line changed: {stdout}"
    );
    assert!(stdout.contains("case: positive\n"), "{stdout}");
    assert!(stdout.contains("-> case passed\n"), "{stdout}");
    for stage in [
        "prepare", "acquire", "extract", "derive", "validate", "expect", "sign",
    ] {
        assert!(stdout.contains(stage), "the trace never named {stage}");
    }
}

/// The trace names shapes, never values.
///
/// The acceptance fixture states the selector values its diagnostics may never
/// disclose. They are synthetic, but a trace that reprints them is a trace that
/// would reprint a real one from a bundle authored the same way.
#[test]
fn an_explained_fixture_run_discloses_no_protected_selector_value() {
    let deployment = Deployment::stage("adult-status");
    let passing = deployment.evaluate(&["--explain"]);
    let passing_json = deployment.evaluate(&["--explain", "--explain-format", "json"]);
    state_an_impossible_lookup(&deployment);
    let failing = deployment.evaluate(&["--explain"]);
    let failing_json = deployment.evaluate(&["--explain", "--explain-format", "json"]);
    for output in [&passing, &passing_json, &failing, &failing_json] {
        let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
        for protected in ["Amina", "Diallo", "2000-01-01", "fixture-source-canary"] {
            assert!(
                !stdout.contains(protected),
                "the trace disclosed protected input {protected:?}"
            );
        }
    }
}

#[test]
fn explaining_a_failing_fixture_shows_where_the_case_stopped_and_keeps_its_message() {
    let deployment = Deployment::stage("adult-status");
    state_an_impossible_lookup(&deployment);
    let output = deployment.evaluate(&["--explain"]);

    assert!(!output.status.success(), "the mutated fixture passed");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        MUTATED_FIXTURE_FAILURE
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("Evidence fixture passed"),
        "a failed run announced success: {stdout}"
    );
    assert!(stdout.contains("case: no-match\n"), "{stdout}");
    assert!(stdout.contains("extract    no-match"), "{stdout}");
    assert!(
        stdout.contains("response keys available [\"total\"]"),
        "the trace never named the response shape the script saw: {stdout}"
    );
    // The expectation comparison is what rejected this case, so its own stage
    // reports the rejection. A satisfied expectation printed immediately above
    // `case failed` would point a reader away from the stage that failed.
    assert!(
        stdout.contains("expect     failed"),
        "the stage that rejected the case reported success: {stdout}"
    );
    assert!(
        stdout
            .contains("-> case failed: fixture kernel failure did not match its public problem\n"),
        "{stdout}"
    );
    // The cases before the mutated one are reported as reached and passed, so
    // the trace says how far the run got and not only where it stopped.
    assert!(stdout.contains("case: positive\n"), "{stdout}");
}

/// A fixture cannot forge trace lines through its own case identifiers.
///
/// The identifier is interpolated into the rendered text trace, so a control
/// character in one would let a fixture write lines that read as stages the run
/// never reached. It is refused where the identifier is validated rather than
/// escaped where it is rendered: the readable form stays readable, and the
/// forgery has nowhere to start.
#[test]
fn a_case_identifier_carrying_a_control_character_is_refused() {
    let deployment = Deployment::stage("adult-status");
    // Appended rather than substituted: the bundle's category coverage reads
    // the identifiers, so a case renamed outright is refused before evaluation
    // and the identifier check is never reached.
    deployment.replace(
        "bundle/fixtures/cases.yaml",
        "{id: negative-false-is-success,",
        "{id: \"negative-false-is-success\\n  sign       ok         forged\",",
    );
    let output = deployment.evaluate(&["--explain"]);

    assert!(
        !output.status.success(),
        "the forged identifier was accepted"
    );
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        concat!(
            "case (fixture): fixture case identifier is invalid\n",
            "evidence: fixture case identifier is invalid\n",
        ),
        "a failure no case was running for is attributed to the fixture scope"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("forged"),
        "the forged stage line reached the trace: {stdout}"
    );
}

/// A run that fails is checked against its own canaries before it is read.
///
/// The failing run is the one whose trace an operator reads, so it is the one
/// the canaries most need to cover. Checking only a run that settled every case
/// would leave the diagnostic nobody guards being exactly the diagnostic
/// everybody reads.
#[test]
fn a_failing_run_is_refused_when_its_trace_holds_a_declared_canary() {
    let deployment = Deployment::stage("adult-status");
    state_an_impossible_lookup(&deployment);
    // The unresolved lookup names the response members the extraction script
    // saw, and the fixture now declares one of those names protected.
    deployment.replace(
        "bundle/fixtures/cases.yaml",
        "diagnostics_exclude: [Amina, Diallo, '2000-01-01', fixture-source-canary]",
        "diagnostics_exclude: [Amina, Diallo, '2000-01-01', fixture-source-canary, total]",
    );
    let output = deployment.evaluate(&["--explain"]);

    assert!(!output.status.success(), "the leaking run passed");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        "evidence: fixture prohibited diagnostic is present\n"
    );
    // The refusal has to come before the render. A trace reported as prohibited
    // and printed anyway would disclose the value the canary named.
    assert!(
        output.stdout.is_empty(),
        "a prohibited trace was printed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn a_failing_fixture_run_is_unchanged_when_no_trace_is_asked_for() {
    let deployment = Deployment::stage("adult-status");
    state_an_impossible_lookup(&deployment);
    let output = deployment.evaluate(&[]);

    assert!(!output.status.success(), "the mutated fixture passed");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        MUTATED_FIXTURE_FAILURE
    );
    assert!(
        output.stdout.is_empty(),
        "an unexplained failure wrote stdout"
    );
}

/// The trace is an offline fixture diagnostic and reaches nothing else.
///
/// `serve` is the case that matters: a running service must have no way to be
/// asked for a per-case breakdown of an evaluation.
#[test]
fn the_fixture_trace_is_offline_only_and_no_other_subcommand_accepts_it() {
    let deployment = Deployment::stage("adult-status");
    for command in ["serve", "check", "local-audit-last-operation"] {
        let output = invoke(&deployment.path("runtime.yaml"), &[command, "--explain"]);
        assert!(
            !output.status.success(),
            "{command} accepted the fixture trace flag"
        );
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert!(
            stderr.contains("unexpected argument '--explain'"),
            "{command} did not reject the flag during parsing: {stderr}"
        );
    }
}

/// The JSON form is the whole of standard output, so a reader can pipe it.
///
/// The summary line is what would otherwise trail the document, so its absence
/// is asserted rather than assumed, and the count it carries is asserted in the
/// place it moved to.
#[test]
fn explaining_a_passing_fixture_as_json_prints_one_document_and_no_summary_line() {
    let deployment = Deployment::stage("adult-status");
    let output = deployment.evaluate(&["--explain", "--explain-format", "json"]);
    assert!(output.status.success(), "explained evaluation failed");
    assert!(
        output.stderr.is_empty(),
        "explained evaluation wrote stderr"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("Evidence fixture passed"),
        "the JSON document trails the human summary line: {stdout}"
    );

    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    assert_eq!(report["passed"], json!(true));
    assert_eq!(report["evaluatedCases"], json!(13));
    assert_eq!(report["cases"][0]["id"], json!("positive"));
    assert_eq!(report["cases"][0]["stages"][0]["stage"], json!("prepare"));
    assert_eq!(report["cases"][0]["stages"][0]["status"], json!("ok"));
    let cases = report["cases"].as_array().expect("cases is an array");
    assert_eq!(cases.len(), 13, "the document dropped cases");
    assert!(
        cases.iter().all(|case| case.get("failure").is_none()),
        "a passing run reported a failed case"
    );
}

/// The JSON form changes what stdout carries and nothing else.
#[test]
fn explaining_a_failing_fixture_as_json_keeps_its_exit_code_and_keeps_its_message() {
    let deployment = Deployment::stage("adult-status");
    state_an_impossible_lookup(&deployment);
    let output = deployment.evaluate(&["--explain", "--explain-format", "json"]);

    assert!(!output.status.success(), "the mutated fixture passed");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        MUTATED_FIXTURE_FAILURE
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    assert_eq!(report["passed"], json!(false));
    // `no-match` is the ninth case in the fixture's `cases.yaml`, so the run
    // reaches nine cases before the mutation stops it. A reader counts what the
    // run got through, whether or not it got through all of them.
    assert_eq!(
        report["evaluatedCases"],
        json!(9),
        "a failed run lost its evaluated-case count"
    );

    let cases = report["cases"].as_array().expect("cases is an array");
    assert_eq!(
        report["evaluatedCases"],
        json!(cases.len()),
        "the count and the traced cases disagree"
    );
    let failed = cases
        .iter()
        .find(|case| case.get("failure").is_some())
        .expect("the document names the case that failed");
    assert_eq!(failed["id"], json!("no-match"));
    assert_eq!(
        failed["failure"],
        json!("fixture kernel failure did not match its public problem")
    );
    // The document names the failing case beside the trace, with the fixed
    // cause and whatever classes its comparison reached. This mutation stopped
    // at the expectation, so neither side reached a value class.
    assert_eq!(
        report["failingCase"],
        json!({
            "id": "no-match",
            "cause": "fixture kernel failure did not match its public problem"
        }),
        "a failed document must name its failing case value-free"
    );
    let extract = failed["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("extract"))
        .expect("the document carries the stage the case stopped at");
    assert_eq!(extract["status"], json!("no-match"));
    assert_eq!(
        extract["details"],
        json!(["response keys available [\"total\"]"])
    );
    let expect = failed["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("expect"))
        .expect("the document carries the expectation comparison");
    assert_eq!(
        expect["status"],
        json!("failed"),
        "the stage that rejected the case reported success"
    );

    // A case the comparison accepted still reports a satisfied expectation, so
    // the failed status above distinguishes cases rather than marking them all.
    let passed = report["cases"]
        .as_array()
        .expect("cases is an array")
        .iter()
        .find(|case| case["id"] == json!("positive"))
        .expect("the document carries the cases that passed");
    let satisfied = passed["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("expect"))
        .expect("a passing case carries its expectation comparison");
    assert_eq!(satisfied["status"], json!("ok"));
}

/// Asking for a format without asking for the trace is a mistake, not a no-op.
#[test]
fn the_json_trace_format_is_rejected_without_the_trace_it_formats() {
    let deployment = Deployment::stage("adult-status");
    let output = deployment.evaluate(&["--explain-format", "json"]);
    assert!(
        !output.status.success(),
        "a format without a trace was accepted"
    );
    assert!(
        output.stdout.is_empty(),
        "a rejected invocation wrote stdout"
    );
    let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.contains("--explain"),
        "the rejection never named the flag it needs: {stderr}"
    );
}

#[test]
fn local_relying_procedure_is_bearer_free_closed_and_selector_private() {
    let deployment = Deployment::stage("adult-status");
    deployment.stage_acceptance_secrets();
    deployment.seal();
    let input_path = deployment.path("relying-procedure-input.json");
    let draft = json!({
        "schema": "registry.evidence.local-relying-procedure-input/v1",
        "responseFormat": "signed-jws",
        "requirement": "urn:example:fixture:requirement:adult-status:v1",
        "purpose": "fixture-eligibility",
        "audience": "urn:example:local-client:age-checker",
        "subjects": [{
            "role": "subject",
            "selector": {
                "profile": "person-demographics-v1",
                "values": {
                    "given_name": "Amina",
                    "family_name": "Diallo",
                    "birth_date": "2000-01-01"
                }
            }
        }]
    });
    write_private_json(&input_path, &draft);

    // Non-token stdin is deliberately present. Success proves this seam does
    // not authenticate, parse, or otherwise depend on bearer input.
    let output = invoke_local_relying_procedure(
        &deployment.path("runtime.yaml"),
        &input_path,
        b"this-is-not-a-bearer-token\n",
    );
    assert!(
        output.status.success(),
        "procedure preparation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let procedure: Value =
        serde_json::from_slice(&output.stdout).expect("procedure output is one JSON document");
    assert_eq!(
        procedure["schema"],
        json!("registry.evidence.local-relying-procedure/v1")
    );
    assert_eq!(procedure["responseFormat"], json!("signed-jws"));
    assert_eq!(procedure["expectedAssuranceProfile"], json!("local"));
    assert_eq!(
        procedure["requirement"],
        json!("urn:example:fixture:requirement:adult-status:v1")
    );
    assert_eq!(procedure["purpose"], json!("fixture-eligibility"));
    assert_eq!(
        procedure["audience"],
        json!("urn:example:local-client:age-checker")
    );
    assert!(procedure["configurationRevision"]
        .as_str()
        .is_some_and(|revision| revision.starts_with("sha256:") && revision.len() == 71));
    assert!(procedure["trustedJwks"]["keys"]
        .as_array()
        .is_some_and(|keys| keys.len() == 1));
    assert!(procedure["expectedSubjects"][0]["binding"]
        .as_str()
        .is_some_and(|binding| binding.starts_with("urn:evidence:subject:v1_")));
    assert_eq!(
        procedure["expectedOutputs"],
        json!([{
            "handle": "is_adult",
            "concept": "urn:example:fixture:concept:adult-status",
            "required": true,
            "form": "boolean"
        }])
    );
    assert_eq!(procedure["maximumAssertionLifetimeSeconds"], json!(300));
    assert_eq!(procedure["clockSkewSeconds"], json!(30));
    assert!(procedure.get("requestNonce").is_none());
    let serialized = std::str::from_utf8(&output.stdout).expect("procedure output is UTF-8");
    for protected in [
        "Amina",
        "Diallo",
        "2000-01-01",
        "person-demographics-v1",
        "subject-binding-secret-32-bytes-minimum-value",
        "fixture-agency",
    ] {
        assert!(
            !serialized.contains(protected),
            "procedure output disclosed protected input {protected:?}"
        );
    }
    assert!(
        !deployment.path("audit.jsonl").exists(),
        "procedure preparation never opens audit storage"
    );

    let mut wrong_purpose = draft.clone();
    wrong_purpose["purpose"] = json!("not-configured");
    let mut wrong_profile = draft.clone();
    wrong_profile["subjects"][0]["selector"]["profile"] = json!("not-configured-v1");
    let mut missing_value = draft.clone();
    missing_value["subjects"][0]["selector"]["values"]
        .as_object_mut()
        .expect("selector values are an object")
        .remove("birth_date");
    let mut absent_values = draft.clone();
    absent_values["subjects"][0]["selector"]
        .as_object_mut()
        .expect("selector is an object")
        .remove("values");
    let mut unsupported_format = draft.clone();
    unsupported_format["responseFormat"] = json!("sd-jwt-vc");
    for (label, invalid) in [
        ("purpose", wrong_purpose),
        ("profile", wrong_profile),
        ("missing selector value", missing_value),
        ("absent selector values", absent_values),
        ("response format", unsupported_format),
    ] {
        write_private_json(&input_path, &invalid);
        let refused = invoke_local_relying_procedure(
            &deployment.path("runtime.yaml"),
            &input_path,
            b"ignored-stdin\n",
        );
        assert!(!refused.status.success(), "an invalid {label} was accepted");
        assert!(refused.stdout.is_empty(), "an invalid {label} wrote output");
        assert_eq!(
            std::str::from_utf8(&refused.stderr).expect("diagnostic is UTF-8"),
            "evidence: local relying procedure preparation failed\n"
        );
    }

    write_private_json(&input_path, &draft);
    fs::set_permissions(&input_path, fs::Permissions::from_mode(0o644)).expect("widen draft mode");
    let public_input = invoke_local_relying_procedure(
        &deployment.path("runtime.yaml"),
        &input_path,
        b"ignored-stdin\n",
    );
    assert!(
        !public_input.status.success(),
        "a non-private selector draft was accepted"
    );
    assert_eq!(
        std::str::from_utf8(&public_input.stderr).expect("diagnostic is UTF-8"),
        "evidence: local relying procedure preparation failed\n"
    );

    deployment.unseal();
}

/// Stage the platform secrets the reference project's bundle names, with a
/// signing key matching the bundle's governed active public JWK.
/// Source credentials stay absent: `check` must not resolve them.
fn stage_reference_secrets(secret_root: &Path) {
    let write = |name: &str, value: &str| {
        let path = secret_root.join(name);
        fs::write(&path, value).expect("write reference secret");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set owner-only secret mode");
    };
    write("audit-hmac-key", "audit-hash-secret-32-bytes-minimum-value");
    write(
        "subject-binding-hmac-key",
        "subject-binding-secret-32-bytes-minimum-value",
    );
    write("evidence-signing", VERIFY_PRIVATE_JWK);
}

/// One deployment failure class, with the exact operator text it must produce.
///
/// The expected text is split into a prefix and a suffix so a case that
/// reports a text location can pin the cause and the location shape without
/// pinning a line number that ordinary fixture edits would move. The acceptance
/// bundle is named per case because a failure class can be reachable only from
/// the bundle that declares the configuration it is about.
///
/// `needs_runtime` marks a case whose break only exists in `runtime.yaml` or
/// whose bundle is refused only once a runtime document is in scope. `check`
/// carries every case; `bundle-check` has no runtime document at all, so it
/// runs only the bundle-only subset.
struct FailureCase {
    label: &'static str,
    bundle: &'static str,
    break_deployment: fn(&Deployment),
    prefix: &'static str,
    suffix: &'static str,
    needs_runtime: bool,
    /// The code and the message `check` reports for the case, as one
    /// CFG-DIAG-2 diagnostic.
    check: (&'static str, &'static str),
}

/// The shared failure-class table `check` and `bundle-check` both iterate.
///
/// `main.rs` routes `Command::Check` and `Command::BundleCheck` through the
/// same `deployment_load_error` and `kernel_compile_error`, so a bundle-only
/// case produces the identical fixed prefix and suffix under either command;
/// only the third pass (source plan compilation) differs between them.
fn failure_cases() -> Vec<FailureCase> {
    vec![
        FailureCase {
            label: "malformed bundle YAML",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.append("bundle/evidence.yaml", &format!("trailing: [{CANARY}\n"));
            },
            prefix: "evidence: the configuration reader refused the configuration\nerror[yaml.unexpected-end] ",
            suffix: ", which needs a closing `]`\n  next: Complete or remove the unfinished item.\n1 error, 0 warnings in 1 file\n",
            needs_runtime: false,
            check: (
                "yaml.unexpected-end",
                "the document ends inside the list or mapping opened with `[` on line 323, which needs a closing `]`",
            ),
        },
        FailureCase {
            label: "unknown bundle field",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "    principalClaim: sub\n",
                    &format!("    principalClaim: sub\n    unknownField: {CANARY}\n"),
                );
            },
            prefix: "evidence: the configuration reader refused the configuration\nerror[config.unknown-key] ",
            suffix: " /authentication/oidc/unknownField\n  `unknownField` is not a member of this mapping\n  next: Remove `unknownField`; the accepted keys are `issuer`, `audience`, `jwksSource`, `tokenTypes`, `algorithms`, `principalClaim`, `requesterTagsClaim`, `evidenceAudienceClaim`, `claims`, `maximumTokenLifetimeSeconds`, `revokedKeyIds`, `allowedClients`, `assertionIssuers`, `requiredScopes`, `actorClaim`, `tlsTrustProfile`.\n1 error, 0 warnings in 1 file\n",
            needs_runtime: false,
            check: (
                "config.unknown-key",
                "`unknownField` is not a member of this mapping",
            ),
        },
        FailureCase {
            label: "wrong bundle field type",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "version: 1\n",
                    &format!("version: \"{CANARY}\"\n"),
                );
            },
            prefix: "evidence: the configuration reader refused the configuration\nerror[config.expected-integer] ",
            suffix: " /version\n  expected a whole number from 1 to 1, not quoted text\n  next: Write a whole number from 1 to 1.\n1 error, 0 warnings in 1 file\n",
            needs_runtime: false,
            check: (
                "config.expected-integer",
                "expected a whole number from 1 to 1, not quoted text",
            ),
        },
        FailureCase {
            label: "unaccepted bundle field variant",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "  format: flattened-jws-json\n",
                    &format!("  format: {CANARY}\n"),
                );
            },
            prefix: "evidence: the configuration reader refused the configuration\nerror[config.unknown-variant] ",
            suffix: " /signing/format\n  expected one of `flattened-jws-json`\n  next: Use one of `flattened-jws-json`.\n1 error, 0 warnings in 1 file\n",
            needs_runtime: false,
            check: (
                "config.unknown-variant",
                "expected one of `flattened-jws-json`",
            ),
        },
        FailureCase {
            label: "configuration cross-reference",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "      source: source-a\n",
                    &format!("      source: {CANARY}\n"),
                );
            },
            prefix: "evidence: the configuration reader refused the configuration\nerror[evidence.bundle.invalid-requirement] ",
            suffix: " /requirements/0/acquisition\n  requirement acquisition references an unknown source\n  next: Change this member so it meets the rule the message states.\n1 error, 0 warnings in 1 file\n",
            needs_runtime: false,
            check: (
                "evidence.bundle.invalid-requirement",
                "requirement acquisition references an unknown source",
            ),
        },
        FailureCase {
            label: "artifact closure references a missing file",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.remove("bundle/derivations/adult-status.rhai");
            },
            prefix: "evidence: deployment artifact closure is invalid: artifact derivations/adult-status.rhai: the configuration references an artifact the bundle does not contain\n",
            suffix: "",
            needs_runtime: false,
            check: (
                "evidence.bundle.unknown-file",
                "the configuration references an artifact the bundle does not contain",
            ),
        },
        FailureCase {
            label: "artifact closure carries an unreferenced file",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write("bundle/schemas/orphan.schema.yaml", &format!("x: {CANARY}\n"));
            },
            prefix: "evidence: deployment artifact closure is invalid: artifact schemas/orphan.schema.yaml: the bundle contains an artifact the configuration does not reference\n",
            suffix: "",
            needs_runtime: false,
            check: (
                "evidence.bundle.unknown-file",
                "the bundle contains an artifact the configuration does not reference",
            ),
        },
        FailureCase {
            label: "unsafe artifact name is never echoed",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write(
                    &format!("bundle/fixtures/orphan {CANARY}.yaml"),
                    "synthetic_only: true\n",
                );
            },
            prefix: "evidence: deployment artifact closure is invalid: the bundle contains an artifact the configuration does not reference\n",
            suffix: "",
            needs_runtime: false,
            check: (
                "evidence.bundle.unknown-file",
                "the bundle contains an artifact the configuration does not reference",
            ),
        },
        FailureCase {
            label: "script",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.append(
                    "bundle/derivations/adult-status.rhai",
                    &format!("\nthis is not rhai {CANARY}(((\n"),
                );
            },
            prefix: "evidence: deployment script is invalid: artifact derivations/adult-status.rhai: script does not compile\n",
            suffix: "",
            needs_runtime: false,
            check: (
                "evidence.bundle.invalid-script",
                "script does not compile",
            ),
        },
        // The bundle loader compiles a script on a permissive engine that only
        // proves an entrypoint. The kernel is the pass that applies the
        // hardened grammar, so a script using a construct the runtime disables
        // is refused there and has to name its artifact there too.
        FailureCase {
            label: "script the hardened kernel grammar refuses",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.append(
                    "bundle/derivations/adult-status.rhai",
                    &format!("\nfn unreviewed() {{\n    let value = \"{CANARY}\";\n    while false {{ }}\n    value\n}}\n"),
                );
            },
            prefix: "evidence: bundle compilation failed: artifact derivations/adult-status.rhai: script does not compile\n",
            suffix: "",
            needs_runtime: false,
            check: (
                "evidence.bundle.compile-refused",
                "script does not compile",
            ),
        },
        FailureCase {
            label: "fact schema",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write(
                    "bundle/schemas/adult-status-facts.schema.yaml",
                    &format!("type: [{CANARY}]\n"),
                );
            },
            prefix: "evidence: deployment artifact is invalid: artifact schemas/adult-status-facts.schema.yaml: fact schema must close the root object\n",
            suffix: "",
            needs_runtime: false,
            check: (
                "evidence.bundle.invalid-artifact",
                "fact schema must close the root object",
            ),
        },
        FailureCase {
            label: "codelist",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write(
                    "bundle/codelists/residence-region-map.yaml",
                    &format!("id: broken\nversion: \"1\"\nentries: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment artifact is invalid: artifact codelists/residence-region-map.yaml: codelist YAML is invalid\n",
            suffix: "",
            needs_runtime: false,
            check: (
                "evidence.bundle.invalid-artifact",
                "codelist YAML is invalid",
            ),
        },
        FailureCase {
            label: "fixture",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write(
                    "bundle/fixtures/adult-status-cases.yaml",
                    &format!("synthetic_only: true\ncases: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment artifact is invalid: artifact fixtures/adult-status-cases.yaml: fixture cases are missing\n",
            suffix: "",
            needs_runtime: false,
            check: (
                "evidence.bundle.invalid-artifact",
                "fixture cases are missing",
            ),
        },
        FailureCase {
            label: "unknown runtime field",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.append("runtime.yaml", &format!("unknownField: {CANARY}\n"));
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: unknown field at unknownField\n",
            suffix: "",
            needs_runtime: true,
            check: (
                "config.unknown-key",
                "`unknownField` is not a member of this mapping",
            ),
        },
        FailureCase {
            label: "wrong runtime field type",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "runtime.yaml",
                    "  maximumRequestBytes: 65536\n",
                    &format!("  maximumRequestBytes: \"{CANARY}\"\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: field has the wrong type at listener.maximumRequestBytes\n",
            suffix: "",
            needs_runtime: true,
            check: (
                "config.expected-integer",
                "expected a whole number of bytes from 1024 to 1048576, not quoted text",
            ),
        },
        FailureCase {
            label: "runtime operator path",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace_line(
                    "runtime.yaml",
                    "  root: ",
                    &format!("  root: relative/{CANARY}\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: package root must be an absolute path (package.root)\n",
            suffix: "",
            needs_runtime: true,
            check: (
                "evidence.runtime.invalid-package",
                "package root must be an absolute path",
            ),
        },
        // A key an earlier runtime grammar accepted is refused with the key
        // that replaced it, and the value it carried is never echoed.
        FailureCase {
            label: "removed runtime key",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.append("runtime.yaml", &format!("bundleDirectory: /{CANARY}\n"));
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: key is no longer accepted at bundleDirectory; Declare package.root as the absolute path of the package directory.\n",
            suffix: "",
            needs_runtime: true,
            check: (
                "config.removed-key",
                "`bundleDirectory` is no longer accepted",
            ),
        },
        FailureCase {
            label: "removed bundle key",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "    principalClaim: sub\n",
                    &format!("    principalClaim: sub\n    audiences: [{CANARY}]\n"),
                );
            },
            prefix: "evidence: the configuration reader refused the configuration\nerror[config.removed-key] ",
            suffix: " /authentication/oidc/audiences\n  `audiences` is no longer accepted\n  next: Declare the one accepted audience as authentication.oidc.audience.\n1 error, 0 warnings in 1 file\n",
            needs_runtime: false,
            check: (
                "config.removed-key",
                "`audiences` is no longer accepted",
            ),
        },
        // Nothing is broken here: an operator runtime file that says nothing
        // about acquisition capabilities enables nothing beyond the frozen
        // Version 1 acquisition forms, so a bundle that requires a gated kind
        // is refused before the deployment serves anything.
        FailureCase {
            label: "gated acquisition kind the operator did not enable",
            bundle: "surviving-spouse-status",
            break_deployment: |_| {},
            prefix: "evidence: deployment artifact is invalid: the runtime configuration does not enable an acquisition capability the bundle requires\n",
            suffix: "",
            needs_runtime: true,
            check: (
                "evidence.runtime.acquisition-capability-missing",
                "the runtime configuration does not enable an acquisition capability the bundle requires",
            ),
        },
    ]
}

#[test]
fn check_names_a_safe_artifact_and_a_value_free_cause_for_every_failure_class() {
    let mut mismatches = Vec::new();
    for case in failure_cases() {
        let deployment = Deployment::stage(case.bundle);
        (case.break_deployment)(&deployment);
        let output = deployment.check();

        let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert!(
            !stdout.contains(CANARY) && !stderr.contains(CANARY),
            "{}: diagnostic disclosed a document value",
            case.label
        );
        let (code, message) = case.check;
        let lines = stderr.lines().collect::<Vec<_>>();
        let reported = output.status.code() == Some(1)
            && stdout.is_empty()
            && lines.len() == 4
            && lines[0].starts_with(&format!("error[{code}] "))
            && lines[1] == format!("  {message}")
            && lines[2].starts_with("  next: ")
            && lines[3].starts_with("1 error, 0 warnings in ");
        if !reported {
            mismatches.push(format!(
                "{}: exit {:?}, stdout {stdout:?}, stderr {stderr:?}",
                case.label,
                output.status.code()
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "check reported an unexpected diagnostic:\n{}",
        mismatches.join("\n")
    );
}

/// The bundle-only half of the same pin, from the seam Evidencectl uses.
///
/// `bundle-check` shares `Bundle::load` and `OfflineKernel::compile` with
/// `check`, by way of the same `deployment_load_error` and
/// `kernel_compile_error`, so every case here that does not touch
/// `runtime.yaml` must produce the identical value-free diagnostic under
/// either command. The four cases that break or depend on `runtime.yaml`
/// (unknown runtime field, wrong runtime field type, runtime operator path,
/// gated acquisition kind the operator did not enable) are skipped: a bundle
/// alone has no runtime document for them to break, and Evidencectl's build
/// never has one to check either.
#[test]
fn bundle_check_names_a_safe_artifact_and_a_value_free_cause_for_every_failure_class() {
    for case in failure_cases()
        .into_iter()
        .filter(|case| !case.needs_runtime)
    {
        let deployment = Deployment::stage(case.bundle);
        (case.break_deployment)(&deployment);
        let output = deployment.bundle_check();

        assert!(
            !output.status.success(),
            "{}: bundle-check accepted a broken bundle",
            case.label
        );
        let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert!(
            stdout.is_empty(),
            "{}: bundle-check wrote output",
            case.label
        );
        assert!(
            stderr.starts_with(case.prefix) && stderr.ends_with(case.suffix),
            "{}: unexpected diagnostic {stderr:?}",
            case.label
        );
        assert!(
            !stdout.contains(CANARY) && !stderr.contains(CANARY),
            "{}: diagnostic disclosed a document value",
            case.label
        );
    }
}

/// The source-plan pass is the one place `bundle-check` and `check` differ:
/// `compile_bundle_source_plans` checks a statement offline, with no extract
/// mounted, where `compile_source_plans` may open a bound one. None of the
/// acceptance fixtures declare a `sqlite-extract` source, so this reaches that
/// pass through the reference project that does, staging only its `bundle/`
/// directory since `bundle-check` needs nothing else.
#[test]
fn bundle_check_names_a_safe_artifact_and_a_value_free_cause_for_a_broken_statement() {
    let root = tempfile::tempdir().expect("temporary bundle");
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence",
    );
    let bundle = root.path().join("bundle");
    copy_tree(&project.join("bundle"), &bundle);
    let bundle_configuration = bundle.join("evidence.yaml");
    let bundle_document = fs::read_to_string(&bundle_configuration).expect("read bundle document");
    fs::write(
        &bundle_configuration,
        bundle_document.replacen(
            "assuranceProfile: evidence-grade",
            "assuranceProfile: local",
            1,
        ),
    )
    .expect("select local assurance");
    // A first statement with no table reference (so the offline check's
    // deliberate no-op pass on an unresolved name never reaches it) followed by
    // a second statement, which SQLite refuses before either statement runs.
    // The canary sits in the statement that is never reached, so a diagnostic
    // that echoed the artifact's SQL instead of naming its cause would surface it.
    fs::write(
        bundle.join("queries/professional-licence-lookup.sql"),
        format!("SELECT 1;\nSELECT '{CANARY}';\n"),
    )
    .expect("write broken statement");

    refresh_package_envelope(&bundle);
    set_tree_mode(&bundle, 0o555, 0o444);
    let output = invoke_bundle_check(&bundle);
    set_tree_mode(&bundle, 0o755, 0o644);

    assert!(
        !output.status.success(),
        "a broken statement passed bundle-check"
    );
    assert!(output.stdout.is_empty(), "bundle-check wrote output");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("diagnostic is UTF-8"),
        "evidence: source plan compilation failed: artifact queries/professional-licence-lookup.sql: the artifact holds more than one statement\n"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
}

/// The operator half of the acquisition gate, from the other side.
///
/// The bundle author declares which acquisition kinds the bundle needs; the
/// operator who deploys it decides, in a file the bundle author does not write,
/// which of them this deployment may serve. The same bundle the failure classes
/// above refuse passes check once the runtime file names the capability, which
/// is what makes the refusal a deployment decision rather than a spelling
/// accident.
#[test]
fn check_accepts_a_gated_acquisition_kind_the_operator_enabled() {
    let deployment = Deployment::stage("surviving-spouse-status");
    deployment.append(
        "runtime.yaml",
        "acquisitionCapabilities: [search-then-fetch-set]\n",
    );
    deployment.write_secret("audit-hash-key", "audit-hash-secret-32-bytes-minimum-value");
    deployment.write_secret(
        "subject-binding-key",
        "subject-binding-secret-32-bytes-minimum-value",
    );
    deployment.write_secret("signing-key", VERIFY_PRIVATE_JWK);
    deployment.write_secret("civil-record-search-token", "synthetic-source-token");
    deployment.write_secret("union-register-token", "synthetic-source-token");
    deployment.write_secret("death-register-token", "synthetic-source-token");

    assert_success(
        &deployment.check(),
        "Evidence package ",
        " passed check (1 requirements)\n",
    );
}

/// Secret material the server would refuse at startup must already fail
/// `check`, with the same fixed operator message startup produces. Each case
/// stages the complete acceptance secret set and then breaks exactly one
/// piece of it.
/// The target-host proof validates deployment secret material exactly as
/// `serve` does. A key that is served but is not the governed one is refused
/// input (exit 1); a key or provider this host could not reach is an
/// unavailable dependency (exit 3).
#[test]
fn check_rejects_secret_material_the_server_would_refuse_at_startup() {
    struct SecretFailureCase {
        label: &'static str,
        break_secrets: fn(&Deployment),
        exit: i32,
        code: &'static str,
        expected: &'static str,
    }
    let cases = [
        SecretFailureCase {
            label: "signing key differs from the governed active public JWK",
            break_secrets: |deployment| deployment.write_mismatched_signing_key(),
            exit: 1,
            code: "evidence.deployment.signing-refused",
            expected: "runtime signing initialization failed: the signing key is not the \
                       bundle's governed active public JWK",
        },
        SecretFailureCase {
            label: "Transit signer socket is missing",
            break_secrets: |deployment| {
                // Transit custody is what the evidence-grade profile demands,
                // so the staged bundle returns to the profile it ships with.
                deployment.replace(
                    "bundle/evidence.yaml",
                    "assuranceProfile: local",
                    "assuranceProfile: evidence-grade",
                );
                let socket = deployment.path("transit.sock");
                deployment.replace(
                    "runtime.yaml",
                    "signer:\n  kind: local-jwk\n  privateKeyRef: secret:file/signing-key\n",
                    &format!(
                        "signer:\n  kind: transit\n  unixSocketPath: {}\n  mount: transit\n  \
                         keyName: evidence-signing\n  keyVersion: 7\n  timeoutMilliseconds: 2000\n",
                        socket.display()
                    ),
                );
            },
            exit: 3,
            code: "evidence.deployment.signing-unavailable",
            expected: "runtime signing initialization failed: the Transit provider did not \
                       answer on the configured Unix socket (missing socket, refused connection, \
                       or timeout)",
        },
        SecretFailureCase {
            label: "audit hash key below the minimum length",
            break_secrets: |deployment| deployment.write_secret("audit-hash-key", "short"),
            exit: 3,
            code: "evidence.deployment.audit-unavailable",
            expected: "runtime audit initialization failed: the audit hash key is unusable",
        },
        SecretFailureCase {
            label: "subject binding key missing",
            break_secrets: |deployment| deployment.remove("secrets/subject-binding-key"),
            exit: 3,
            code: "evidence.deployment.secret-unavailable",
            expected: "runtime secret initialization failed",
        },
    ];

    for case in cases {
        let deployment = Deployment::stage("all-definitions");
        deployment.stage_acceptance_secrets();
        (case.break_secrets)(&deployment);
        let offline = deployment.check();
        assert_success(
            &offline,
            "Evidence package ",
            " passed check (4 requirements)\n",
        );
        let output = deployment.check_with_runtime_dependencies();

        assert!(
            !output.status.success(),
            "{}: check accepted secret material the server would refuse",
            case.label
        );
        assert_one_check_error(&output, case.exit, case.code, case.expected);
    }
}

/// One audit initialization failure class, with the exact operator text it
/// must produce and any handle the fault needs held open while `serve` runs.
struct AuditFaultCase {
    label: &'static str,
    break_audit: fn(&Deployment) -> Option<fs::File>,
    expected: &'static str,
}

/// The audit boundary refuses to start for unrelated reasons, and from outside
/// the process they are indistinguishable: a mode an operator fixes with
/// `chmod`, a destination setting outside the platform bounds, and a second
/// writer already holding the destination lock are different questions with
/// different answers. Each names itself, and none of them names the audit
/// path, which the operator already has in the runtime file.
#[test]
fn serve_names_why_the_audit_boundary_refused_to_initialize() {
    let cases = [
        AuditFaultCase {
            label: "an audit file readable beyond its owner",
            break_audit: |deployment| {
                deployment.stage_audit_file("");
                set_mode(&deployment.path("audit.jsonl"), 0o644);
                None
            },
            expected: "evidence: runtime audit initialization failed: the audit file could not \
                       be opened: audit files must be owner-only, singly linked regular files; \
                       chmod them 0600 and remove any extra hard link\n",
        },
        AuditFaultCase {
            label: "a second writer holding the audit destination lock",
            break_audit: |deployment| {
                let path = deployment.path("audit.jsonl.lock");
                fs::write(&path, "").expect("stage audit destination lock");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("set owner-only audit lock mode");
                let held = fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .expect("open audit destination lock");
                held.try_lock().expect("hold the audit destination lock");
                Some(held)
            },
            expected: "evidence: runtime audit initialization failed: another process holds the \
                       single-writer lock beside the audit file; stop it before starting this \
                       one\n",
        },
        AuditFaultCase {
            label: "a torn final line whose side file already holds another",
            break_audit: |deployment| {
                // No trailing newline: the writer moves the torn line to its
                // side file at open, and never overwrites one that holds
                // other bytes.
                deployment.stage_audit_file("{\"written\":\"before the interruption\"");
                deployment.stage_torn_line_side_file("an earlier torn line");
                None
            },
            expected: TORN_LINE_SIDE_FILE_OCCUPIED,
        },
        AuditFaultCase {
            label: "an audit file an earlier writer left in another format",
            break_audit: |deployment| {
                deployment.stage_audit_file("{\"envelope_id\":\"01J000000000000000000000\"}\n");
                None
            },
            expected: "evidence: runtime audit initialization failed: the audit file could not \
                       be opened: audit file's first entry is not in the format this writer \
                       produces; archive it and restart with a fresh path\n",
        },
        AuditFaultCase {
            label: "a malformed rotation sequence file beside the audit file",
            break_audit: |deployment| {
                let path = deployment.path("audit.jsonl.seq");
                fs::write(&path, "not a number\n").expect("stage audit sequence file");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("set owner-only audit sequence mode");
                None
            },
            expected: "evidence: runtime audit initialization failed: the audit file could not \
                       be opened: audit sequence file is malformed; it must hold the next sealed \
                       segment sequence as one decimal number and a newline\n",
        },
    ];

    for case in cases {
        let deployment = Deployment::stage_on_port("all-definitions", free_port());
        deployment.stage_acceptance_secrets();
        deployment.seal();
        let _held = (case.break_audit)(&deployment);
        let output = invoke(&deployment.path("runtime.yaml"), &["serve"]);
        deployment.unseal();

        assert!(
            !output.status.success(),
            "{}: serve started on a refused audit boundary",
            case.label
        );
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert_eq!(
            stderr, case.expected,
            "{}: unexpected diagnostic",
            case.label
        );
    }
}

/// A restart is a SIGTERM stop and a start on the same path, executed against
/// the real binary. The writer reopens the existing active file and appends:
/// it neither verifies nor rewrites what an earlier process wrote, because
/// integrity after the fact belongs to the append-only store audit is shipped
/// to. This also proves the SIGTERM handling that makes the stop possible.
#[test]
fn serve_stops_on_sigterm_and_restarts_on_the_same_audit_file() {
    let port = free_port();
    let deployment = Deployment::stage_on_port("all-definitions", port);
    deployment.stage_acceptance_secrets();
    // A real entry shape: the writer now refuses to open a file whose first
    // entry is not in its current envelope format (eventId/schema/time/
    // correlation/phase), so this stub must satisfy that shape to stand in
    // for content an earlier process wrote.
    let earlier = "{\"eventId\":\"5b1b5b8e-6f2b-4c1a-9b7a-6b1b5b8e6f2b\",\"schema\":\"registry.test.audit/v1\",\"time\":\"2024-01-01T00:00:00Z\",\"correlation\":\"by-an-earlier-process\",\"phase\":\"request\",\"record\":{\"written\":\"by an earlier process\"}}\n";
    deployment.stage_audit_file(earlier);
    deployment.seal();
    let path = deployment.path("audit.jsonl");

    let mut service = deployment.serve();
    wait_until_ready(port);
    stop(&mut service);
    let inode = fs::metadata(&path)
        .expect("the service kept its audit file")
        .ino();

    let mut restarted = deployment.serve();
    wait_until_ready(port);
    stop(&mut restarted);
    deployment.unseal();

    assert_eq!(
        fs::metadata(&path)
            .expect("the restart kept the audit file")
            .ino(),
        inode,
        "a restart reopens the same active file"
    );
    assert!(
        fs::read_to_string(&path)
            .expect("the audit file reads")
            .starts_with(earlier),
        "a restart never rewrites earlier content"
    );
}

/// A `stdout` audit destination carries audit entries alone: the serving
/// process writes its operational records to stderr whatever the destination
/// is, so a collector never meets a log line in the audit stream.
#[test]
fn serve_keeps_operational_records_off_a_stdout_audit_destination() {
    let port = free_port();
    let deployment = Deployment::stage_on_port("all-definitions", port);
    deployment.stage_acceptance_secrets();
    deployment.write_audit_to_stdout();
    deployment.seal();
    let service = deployment.serve_capturing();
    wait_until_ready(port);
    let (stdout, stderr) = service.stop();
    deployment.unseal();

    assert!(
        stderr
            .lines()
            .any(|line| line.contains("evidence service listening")),
        "the operational records reach stderr: {stderr}"
    );
    for line in stdout.lines() {
        let entry: serde_json::Value =
            serde_json::from_str(line).expect("every stdout line is JSON");
        assert!(
            entry.get("schema").is_some(),
            "stdout carried a line that is not an audit entry: {line}"
        );
    }
}

/// A torn final line left by an interrupted write no longer blocks a restart:
/// `serve` moves it to the owner-only side file, truncates the active file to
/// its last complete line, and says so on stderr with the side file's path
/// and byte count, never the torn bytes.
#[test]
fn serve_moves_a_torn_final_line_aside_and_starts() {
    let port = free_port();
    let deployment = Deployment::stage_on_port("all-definitions", port);
    deployment.stage_acceptance_secrets();
    let earlier = "{\"eventId\":\"5b1b5b8e-6f2b-4c1a-9b7a-6b1b5b8e6f2b\",\"schema\":\"registry.test.audit/v1\",\"time\":\"2024-01-01T00:00:00Z\",\"correlation\":\"by-an-earlier-process\",\"phase\":\"request\",\"record\":{\"written\":\"by an earlier process\"}}\n";
    let torn = "{\"eventId\":\"torn-canary\",\"record\":{\"written\":";
    deployment.stage_audit_file(&format!("{earlier}{torn}"));
    deployment.seal();
    let service = deployment.serve_capturing();
    wait_until_ready(port);
    let (_, stderr) = service.stop();
    deployment.unseal();

    let side = deployment.path("audit.jsonl.torn");
    assert_eq!(fs::read_to_string(&side).expect("side file"), torn);
    assert_eq!(
        fs::metadata(&side).expect("side file").permissions().mode() & 0o777,
        0o600
    );
    assert!(fs::read_to_string(deployment.path("audit.jsonl"))
        .expect("active file")
        .starts_with(earlier));
    let recovery = stderr
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSON record"))
        .find(|record| record["fields"]["side_file"].is_string())
        .unwrap_or_else(|| panic!("the recovery is logged: {stderr}"));
    assert_eq!(recovery["level"], "ERROR");
    assert_eq!(
        recovery["fields"]["side_file"],
        side.display().to_string().as_str()
    );
    assert_eq!(recovery["fields"]["bytes"], torn.len());
    assert!(
        !stderr.contains("torn-canary"),
        "the torn bytes were logged"
    );
}

/// The staged verification key identifier, echoed by the protected header.
const VERIFY_KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";

/// A staged P-256 test key. It signs fixture assertions in this test binary
/// only and is not a deployment key.
const VERIFY_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;

/// A different valid P-256 key used to prove exact public-key matching.
const MISMATCHED_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256","kid":"xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}"#;

/// A staged request nonce, of the exact 43-character request-nonce shape.
const FIXTURE_NONCE: &str = "r1N1mq48U3PpZ5keuZEgmA5KMC2KDrF1hT6640koy6I";

/// A different nonce of the same shape, carrying the canary so a policy
/// diagnostic that echoed the expected value would fail loudly.
const CANARY_NONCE: &str = "s3cr3t-canary-value000000000000000000000000";

#[test]
fn verify_accepts_an_authentic_and_current_stored_response() {
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &fixture_policy());
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_eq!(
        output.status.code(),
        Some(0),
        "verify rejected a good response"
    );
    assert!(output.stderr.is_empty(), "verify wrote diagnostics");
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.starts_with(
            "verified-at: 2026-08-02T12:00:00Z\nauthentic: yes\ncurrently-valid: yes\n"
        ),
        "unexpected verification output {stdout:?}"
    );
    assert!(
        stdout.contains(&format!("\"requestNonce\": \"{FIXTURE_NONCE}\"")),
        "verify did not print the verified Evidence for inspection"
    );
}

#[test]
fn verify_separates_authenticity_from_current_validity() {
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &fixture_policy());
    let output = stored.verify(Some("2026-08-05T00:00:00Z"));

    assert_eq!(
        output.status.code(),
        Some(3),
        "an expired response did not report its own exit status"
    );
    assert!(output.stderr.is_empty(), "verify wrote diagnostics");
    assert_eq!(
        std::str::from_utf8(&output.stdout).expect("stdout is UTF-8"),
        "verified-at: 2026-08-05T00:00:00Z\nauthentic: yes\ncurrently-valid: no\n",
        "an expired response must stay authentic without being current"
    );
}

#[test]
fn verify_rejects_a_tampered_payload_without_naming_a_value() {
    let mut tampered = fixture_evidence();
    tampered["supportedValues"][0]["value"] = serde_json::Value::String(CANARY.to_owned());
    let stored = StoredResponse::stage(&fixture_evidence(), &tampered, &fixture_policy());
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "authentic: no\n",
        "evidence: stored response verification failed (signature)\n",
    );
}

#[test]
fn verify_reports_only_the_generic_policy_class_for_a_wrong_expected_nonce() {
    let policy = fixture_policy().replacen(FIXTURE_NONCE, CANARY_NONCE, 1);
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "authentic: no\n",
        "evidence: stored response verification failed (policy)\n",
    );
}

#[test]
fn verify_rejects_a_policy_document_with_an_unknown_field() {
    let policy = format!("{}unknownField: {CANARY}\n", fixture_policy());
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "",
        "evidence: stored response verification failed (malformed)\n",
    );
}

/// A policy stating a time bound the verification policy contract forbids is an
/// unusable input document, not a verification outcome: honouring it would make
/// the verifier accept assertions a conformant relying party must refuse, and
/// the failure-class vocabulary is frozen, so there is no class to report it
/// under. The command therefore refuses it before verifying anything, exactly as
/// it refuses a policy with an unknown field.
#[test]
fn verify_rejects_a_policy_document_outside_the_contract_time_bounds() {
    for (label, replaced, with) in [
        (
            "a lifetime past the contract ceiling",
            "maximumAssertionLifetimeSeconds: 172800",
            "maximumAssertionLifetimeSeconds: 31536001",
        ),
        (
            "a zero lifetime",
            "maximumAssertionLifetimeSeconds: 172800",
            "maximumAssertionLifetimeSeconds: 0",
        ),
        (
            "a skew past the contract ceiling",
            "clockSkewSeconds: 30",
            "clockSkewSeconds: 301",
        ),
    ] {
        let policy = fixture_policy().replacen(replaced, with, 1);
        assert!(policy.contains(with), "{label} did not reach the policy");
        let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
        let output = stored.verify(Some("2026-08-02T12:00:00Z"));

        assert_verification_failure(
            &output,
            "2026-08-02T12:00:00Z",
            "",
            "evidence: stored response verification failed (malformed)\n",
        );
    }
}

#[test]
fn verify_rejects_a_policy_document_outside_the_contract_list_bounds() {
    for (label, minimum_items, maximum_items) in [
        ("a zero minimum", 0, 1),
        ("a minimum past the ceiling", 65, 64),
        ("a zero maximum", 1, 0),
        ("a maximum past the ceiling", 1, 65),
    ] {
        let policy = fixture_policy().replacen(
            "form: boolean",
            &format!(
                "form:\n      list:\n        minimumItems: {minimum_items}\n        maximumItems: {maximum_items}"
            ),
            1,
        );
        let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
        let output = stored.verify(Some("2026-08-02T12:00:00Z"));

        assert_verification_failure(
            &output,
            "2026-08-02T12:00:00Z",
            "",
            "evidence: stored response verification failed (malformed)\n",
        );
        assert_eq!(output.status.code(), Some(1), "{label} was accepted");
    }
}

#[test]
fn verify_rejects_a_verification_instant_that_is_not_strict_utc() {
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &fixture_policy());

    for at in ["2026-08-02T12:00:00+02:00", "2026-08-02", CANARY] {
        let output = stored.verify(Some(at));
        assert_eq!(output.status.code(), Some(1), "verify accepted {at:?}");
        assert!(
            output.stdout.is_empty(),
            "verify printed an unusable instant"
        );
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert_eq!(
            stderr, "evidence: verification instant is not strict RFC 3339 UTC\n",
            "unexpected verification diagnostic"
        );
    }
}

#[test]
fn verify_accepts_an_authentic_and_current_stored_sd_jwt_vc() {
    let stored = StoredCredential::stage(&fixture_policy(), |credential| credential);
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_eq!(
        output.status.code(),
        Some(0),
        "verify rejected a good credential"
    );
    assert!(output.stderr.is_empty(), "verify wrote diagnostics");
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.contains("authentic: yes\n") && stdout.contains("currently-valid: yes\n"),
        "verify did not report the credential as authentic and current"
    );
    assert!(
        stdout.contains("urn:example:concept"),
        "verify did not print the rebuilt Evidence for inspection"
    );
}

#[test]
fn verify_rejects_a_stored_sd_jwt_vc_whose_disclosure_was_replaced() {
    // Substitute a well-formed disclosure of the same claim with the opposite
    // value. Its digest is absent from the signed `_sd`, so the credential
    // fails without the signature itself being touched.
    let stored = StoredCredential::stage(&fixture_policy(), |credential| {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let body = credential
            .strip_suffix('~')
            .expect("the credential ends with the key-binding terminator");
        let (jwt, disclosure) = body.split_once('~').expect("the credential discloses");
        let decoded: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(disclosure)
                .expect("disclosure decodes"),
        )
        .expect("disclosure parses");
        let replaced = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!([decoded[0], decoded[1], true]))
                .expect("disclosure serializes"),
        );
        format!("{jwt}~{replaced}~")
    });
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "authentic: no\n",
        "evidence: stored response verification failed (disclosure)\n",
    );
}

#[test]
fn verify_requires_exactly_one_stored_response_format() {
    let stored = StoredCredential::stage(&fixture_policy(), |credential| credential);
    for arguments in [
        vec![],
        vec![
            "--jws".to_owned(),
            stored.path("response.sd-jwt").display().to_string(),
            "--sd-jwt-vc".to_owned(),
            stored.path("response.sd-jwt").display().to_string(),
        ],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .args(&arguments)
            .arg("--jwks")
            .arg(stored.path("trusted.jwks.json"))
            .arg("--policy")
            .arg(stored.path("policy.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        let output = command.output().expect("evidence binary starts");
        assert_eq!(
            output.status.code(),
            Some(2),
            "verify accepted an ambiguous stored-response selection"
        );
        assert!(
            output.stdout.is_empty(),
            "verify began before selecting a stored response"
        );
    }
}

/// The audience the fixture relying party put in the challenge it issued.
const KEY_BINDING_AUDIENCE: &str = "urn:example:relying-party";

/// The challenge the fixture relying party issued and retained. Comparing it is
/// not consuming it, so every run below may present it again.
const KEY_BINDING_NONCE: &str = "QH-fpo3GJG9ksxAJeee7wQqpaRCkly8q-ltiG5QQmSk";

/// The holder's own key: the second staged test pair, reused here because no
/// deployment ever holds a holder private key and this is a test pair only.
const HOLDER_PRIVATE_JWK: &str = MISMATCHED_PRIVATE_JWK;

/// The public half of [`HOLDER_PRIVATE_JWK`], as a credential's confirmation
/// key. No key identifier is confirmed, so the proof header nominates none.
const HOLDER_PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256"}"#;

/// The instant every holder-bound run below verifies at. The fixture assertion
/// is current at it, and a proof stamped with it is inside the accepted window.
const PRESENTATION_INSTANT: &str = "2026-08-02T12:00:00Z";

#[test]
fn verify_presentation_accepts_an_authentic_and_current_presentation() {
    let stored = StoredPresentation::stage(
        &holder_bound_fixture_policy(),
        valid_key_binding_claims,
        HOLDER_PRIVATE_JWK,
    );
    let output = stored.verify_presentation(Some(PRESENTATION_INSTANT));

    assert_eq!(
        output.status.code(),
        Some(0),
        "verify-presentation rejected a good presentation"
    );
    assert!(
        output.stderr.is_empty(),
        "verify-presentation wrote diagnostics"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.starts_with("verified-at: 2026-08-02T12:00:00Z\nauthentic: yes\npossession: "),
        "unexpected verification output {stdout:?}"
    );
    assert!(
        stdout.contains("currently-valid: yes\n"),
        "verify-presentation did not report the presentation as current"
    );
    assert!(
        stdout.contains("\"subjectBinding\": \"holder-bound\""),
        "verify-presentation did not print the rebuilt Evidence for inspection"
    );
    // The command answers what possession was proven and refuses to imply
    // more: the challenge was compared, and comparing it retired nothing.
    assert!(
        stdout.contains(
            "possession: proven when the key-binding JWT was signed; \
             not proof that the presentation is fresh, single-use, or unreplayed\n"
        ),
        "verify-presentation overstated what a verified proof establishes"
    );
}

/// The documented behavior, asserted deliberately rather than left implied: the
/// expected challenge is compared and never consumed, so the same stored bytes
/// verify again under the same policy. Nothing here is a replay defence, and a
/// relying party that needs one owns it in its own challenge lifecycle.
#[test]
fn verify_presentation_accepts_the_same_stored_bytes_every_time() {
    let stored = StoredPresentation::stage(
        &holder_bound_fixture_policy(),
        valid_key_binding_claims,
        HOLDER_PRIVATE_JWK,
    );

    for attempt in 1..=2 {
        let output = stored.verify_presentation(Some(PRESENTATION_INSTANT));
        assert_eq!(
            output.status.code(),
            Some(0),
            "attempt {attempt} over unchanged bytes was refused"
        );
        assert!(
            output.stderr.is_empty(),
            "attempt {attempt} wrote diagnostics"
        );
        let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
        assert!(
            stdout.contains("authentic: yes\n") && stdout.contains("currently-valid: yes\n"),
            "attempt {attempt} did not report the same answer"
        );
    }
}

#[test]
fn verify_presentation_reports_only_the_key_binding_class_for_a_failed_proof() {
    let policy = holder_bound_fixture_policy();
    let cases = [
        (
            "a challenge answered to another relying party",
            StoredPresentation::stage(
                &policy,
                |issued| {
                    let mut claims = valid_key_binding_claims(issued);
                    claims["aud"] = json!("urn:example:other-relying-party");
                    claims
                },
                HOLDER_PRIVATE_JWK,
            ),
        ),
        (
            "a proof bound to bytes other than the presented ones",
            StoredPresentation::stage(
                &policy,
                |issued| {
                    let mut claims = valid_key_binding_claims(issued);
                    claims["sd_hash"] = json!(disclosure_hash(&format!("{issued}~")));
                    claims
                },
                HOLDER_PRIVATE_JWK,
            ),
        ),
        (
            "a signer other than the confirmed holder key",
            // The service signing key: authentic for the credential, and not
            // the key the issuer confirmed for the holder.
            StoredPresentation::stage(&policy, valid_key_binding_claims, VERIFY_PRIVATE_JWK),
        ),
    ];

    for (label, stored) in &cases {
        let output = stored.verify_presentation(Some(PRESENTATION_INSTANT));
        assert_verification_failure(
            &output,
            PRESENTATION_INSTANT,
            "authentic: no\n",
            "evidence: stored response verification failed (key-binding)\n",
        );
        assert_eq!(output.status.code(), Some(1), "{label} was accepted");
    }
}

/// Neither command reads the other's serialization. A presentation carries no
/// trailing tilde, so `verify` refuses it, and it is refused for its shape
/// rather than its policy: the Version 1 policy staged for this run is one that
/// command does accept.
#[test]
fn verify_refuses_a_holder_bound_presentation() {
    let stored = StoredPresentation::stage(
        &holder_bound_fixture_policy(),
        valid_key_binding_claims,
        HOLDER_PRIVATE_JWK,
    );
    let output = stored.verify_as_stored_response(Some(PRESENTATION_INSTANT));

    assert_verification_failure(
        &output,
        PRESENTATION_INSTANT,
        "authentic: no\n",
        "evidence: stored response verification failed (malformed)\n",
    );
}

/// The other direction: an audience-scoped credential ends in the trailing
/// tilde that marks an absent proof, so it is refused for offering no
/// possession rather than verified without one.
#[test]
fn verify_presentation_refuses_an_audience_scoped_credential() {
    let stored = StoredCredential::stage(&holder_bound_fixture_policy(), |credential| credential);
    let output = stored.verify_presentation(Some(PRESENTATION_INSTANT));

    assert_verification_failure(
        &output,
        PRESENTATION_INSTANT,
        "authentic: no\n",
        "evidence: stored response verification failed (key-binding)\n",
    );
}

/// Assert one closed verification failure: exit 1, the chosen instant, the
/// expected remaining stdout, only the closed class on stderr, and no leaked
/// document value on either stream.
fn assert_verification_failure(
    output: &Output,
    instant: &str,
    remaining_stdout: &str,
    stderr: &str,
) {
    assert_eq!(output.status.code(), Some(1), "verify accepted a bad input");
    let printed_out = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let printed_err = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert_eq!(
        printed_out,
        format!("verified-at: {instant}\n{remaining_stdout}"),
        "unexpected verification output"
    );
    assert_eq!(printed_err, stderr, "unexpected verification diagnostic");
    assert!(
        !printed_out.contains(CANARY) && !printed_err.contains(CANARY),
        "verification disclosed a document value"
    );
}

/// The stored Evidence payload the verify tests sign and re-verify.
fn fixture_evidence() -> serde_json::Value {
    serde_json::json!({
        "schema": "registry.assertion-evidence/v1",
        "assuranceProfile": "evidence-grade",
        "subjectBinding": "audience-scoped",
        "requestNonce": FIXTURE_NONCE,
        "id": "urn:ulid:01K1EXAMPLE0000000000000000",
        "type": "Evidence",
        "supportsRequirement": "urn:example:requirement:v1",
        "isConformantTo": "urn:example:type:v1",
        "issuedBy": "urn:example:issuer",
        "providedBy": "urn:example:provider",
        "issuedAt": "2026-08-02T00:00:00Z",
        "observedAt": "2026-08-02T00:00:00Z",
        "validUntil": "2026-08-03T00:00:00Z",
        "purpose": "casework",
        "audience": "urn:example:audience",
        "configurationRevision": format!("sha256:{}", "0".repeat(64)),
        "subjects": [{"role": "subject", "binding": format!("urn:evidence:subject:v1_{}", "A".repeat(43))}],
        "supportedValues": [{"providesValueFor": "urn:example:concept", "value": false}],
    })
}

/// The relying-procedure policy matching that payload.
///
/// A real relying party builds this from independently retained trusted state.
/// The test simulates that state from the fixture it controls.
fn fixture_policy() -> String {
    format!(
        "expectedAssuranceProfile: evidence-grade
issuedBy: urn:example:issuer
providedBy: urn:example:provider
requirement: urn:example:requirement:v1
evidenceType: urn:example:type:v1
purpose: casework
audience: urn:example:audience
configurationRevision: sha256:{revision}
requestNonce: {FIXTURE_NONCE}
expectedSubjects:
  - role: subject
    binding: urn:evidence:subject:v1_{binding}
expectedOutputs:
  - concept: urn:example:concept
    form: boolean
maximumAssertionLifetimeSeconds: 172800
clockSkewSeconds: 30
revokedKeyIds: []
",
        revision = "0".repeat(64),
        binding = "A".repeat(43),
    )
}

/// The same fixture assertion under the holder-bound mode: no audience and no
/// request nonce, because it names no relying party and correlates to no single
/// request.
fn holder_bound_fixture_evidence() -> serde_json::Value {
    let mut evidence = fixture_evidence();
    evidence["subjectBinding"] = json!("holder-bound");
    let members = evidence.as_object_mut().expect("the fixture is an object");
    members.remove("audience");
    members.remove("requestNonce");
    evidence
}

/// The holder-bound relying-procedure policy matching that payload.
///
/// A real relying party builds this from independently retained trusted state,
/// including the challenge it issued itself. The test simulates that state from
/// the fixture it controls.
fn holder_bound_fixture_policy() -> String {
    format!(
        "subjectBinding: holder-bound
expectedAssuranceProfile: evidence-grade
issuedBy: urn:example:issuer
providedBy: urn:example:provider
requirement: urn:example:requirement:v1
evidenceType: urn:example:type:v1
expectedIssuancePurpose: casework
configurationRevision: sha256:{revision}
expectedSubjects:
  - role: subject
    binding: urn:evidence:subject:v1_{binding}
expectedOutputs:
  - concept: urn:example:concept
    form: boolean
maximumAssertionLifetimeSeconds: 172800
revokedKeyIds: []
keyBindingAudience: {KEY_BINDING_AUDIENCE}
keyBindingNonce: {KEY_BINDING_NONCE}
maximumKeyBindingAgeSeconds: 300
clockSkewSeconds: 30
",
        revision = "0".repeat(64),
        binding = "A".repeat(43),
    )
}

/// The four members RFC 9901 section 4.3 permits, over one presentation prefix.
///
/// `sd_hash_input` is the presentation up to and including its last tilde,
/// which for a complete issued credential is that serialization itself.
fn valid_key_binding_claims(sd_hash_input: &str) -> Value {
    json!({
        "nonce": KEY_BINDING_NONCE,
        "aud": KEY_BINDING_AUDIENCE,
        "iat": presentation_instant(),
        "sd_hash": disclosure_hash(sd_hash_input),
    })
}

/// The verification instant the holder-bound runs share, as a Unix second.
fn presentation_instant() -> i64 {
    chrono::DateTime::parse_from_rfc3339(PRESENTATION_INSTANT)
        .expect("the staged instant parses")
        .timestamp()
}

/// The `sd_hash` a proof carries over one presentation prefix.
fn disclosure_hash(sd_hash_input: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    URL_SAFE_NO_PAD.encode(registry_platform_sdjwt::presentation_disclosure_hash(
        sd_hash_input,
    ))
}

/// Sign one compact JWT over the given header and claims with a staged test
/// key.
fn sign_compact_jwt(header: &Value, claims: &Value, private_jwk: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use registry_platform_crypto::{sign, PrivateJwk};

    let key = PrivateJwk::parse(private_jwk).expect("the staged key parses");
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("header serializes")),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize")),
    );
    let signature =
        URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes(), &key).expect("the staged key signs"));
    format!("{signing_input}.{signature}")
}

/// The three files an operator holds for offline re-verification: one stored
/// signed response, one pinned trusted key set, and one policy document.
struct StoredResponse {
    root: tempfile::TempDir,
}

impl StoredResponse {
    /// Sign `signed`, store `stored` as the response payload, and stage
    /// `policy`. Passing different payloads produces a tampered response whose
    /// signature no longer covers the stored bytes.
    fn stage(signed: &serde_json::Value, stored: &serde_json::Value, policy: &str) -> Self {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use registry_platform_crypto::{sign, PrivateJwk};

        let root = tempfile::tempdir().expect("temporary verification inputs");
        let key = PrivateJwk::parse(VERIFY_PRIVATE_JWK).expect("fixture key parses");
        let protected = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"alg":"ES256","kid":"{VERIFY_KEY_ID}","typ":"evidence+jws","cty":"application/evidence+json"}}"#
        ));
        let signed_payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(signed).expect("Evidence payload serializes"));
        let signature = URL_SAFE_NO_PAD.encode(
            sign(format!("{protected}.{signed_payload}").as_bytes(), &key)
                .expect("fixture payload signs"),
        );
        let stored_payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(stored).expect("Evidence payload serializes"));

        fs::write(
            root.path().join("response.jws.json"),
            format!(
                r#"{{"protected":"{protected}","payload":"{stored_payload}","signature":"{signature}"}}"#
            ),
        )
        .expect("stage the stored response");
        fs::write(
            root.path().join("trusted.jwks.json"),
            serde_json::to_vec(&serde_json::json!({"keys": [key.public()]}))
                .expect("trusted JWKS serializes"),
        )
        .expect("stage the pinned key set");
        fs::write(root.path().join("policy.yaml"), policy).expect("stage the policy");
        Self { root }
    }

    /// Run `verify` with no runtime file staged, so the command proves it needs
    /// no deployment and opens no socket.
    fn verify(&self, at: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .arg("--jws")
            .arg(self.root.path().join("response.jws.json"))
            .arg("--jwks")
            .arg(self.root.path().join("trusted.jwks.json"))
            .arg("--policy")
            .arg(self.root.path().join("policy.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        if let Some(at) = at {
            command.arg("--at").arg(at);
        }
        command.output().expect("evidence binary starts")
    }
}

/// The SD-JWT VC counterpart of `StoredResponse`. The same assertion is
/// serialized through the production issuance path, so the command is proven
/// against the bytes an adopter actually receives rather than a hand-built
/// approximation.
struct StoredCredential {
    root: tempfile::TempDir,
}

impl StoredCredential {
    /// Issue the fixture assertion, apply `mutate` to the serialization, and
    /// stage it beside the pinned key set and the policy.
    fn stage(policy: &str, mutate: impl FnOnce(String) -> String) -> Self {
        use registry_evidence::{
            model::Evidence,
            sdjwt_vc::issuance_input,
            signing::{jwks_document, EvidenceSigner},
        };
        use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
        use std::sync::Arc;

        let root = tempfile::tempdir().expect("temporary verification inputs");
        let evidence: Evidence =
            serde_json::from_value(fixture_evidence()).expect("the fixture is an Evidence payload");
        let private = PrivateJwk::parse(VERIFY_PRIVATE_JWK).expect("fixture key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("fixture signer builds"));

        let (credential, trusted) = tokio::runtime::Runtime::new()
            .expect("issuance runtime starts")
            .block_on(async {
                let signer = EvidenceSigner::initialize(provider, VERIFY_KEY_ID)
                    .await
                    .expect("signer initializes");
                let input =
                    issuance_input(&evidence, None, &BTreeMap::new()).expect("the fixture maps");
                let credential = signer
                    .sign_sd_jwt_vc(input)
                    .await
                    .expect("credential serializes");
                let trusted = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
                (credential, trusted)
            });

        fs::write(root.path().join("response.sd-jwt"), mutate(credential))
            .expect("stage the stored credential");
        fs::write(
            root.path().join("trusted.jwks.json"),
            serde_json::to_vec(&trusted).expect("JWKS serializes"),
        )
        .expect("stage the pinned key set");
        fs::write(root.path().join("policy.yaml"), policy).expect("stage the policy");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn verify(&self, at: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .arg("--sd-jwt-vc")
            .arg(self.path("response.sd-jwt"))
            .arg("--jwks")
            .arg(self.path("trusted.jwks.json"))
            .arg("--policy")
            .arg(self.path("policy.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        if let Some(at) = at {
            command.arg("--at").arg(at);
        }
        command.output().expect("evidence binary starts")
    }

    /// Offer the issued audience-scoped credential to the holder-bound command,
    /// which must refuse bytes that carry no proof of possession.
    fn verify_presentation(&self, at: Option<&str>) -> Output {
        invoke_verify_presentation(
            &self.path("response.sd-jwt"),
            &self.path("trusted.jwks.json"),
            &self.path("policy.yaml"),
            at,
        )
    }
}

/// The three files an operator holds for offline re-verification of a
/// holder-bound presentation: one stored presentation carrying the holder's
/// key-binding JWT after its last tilde, one pinned trusted key set, and one
/// holder-bound policy document.
struct StoredPresentation {
    root: tempfile::TempDir,
}

impl StoredPresentation {
    /// Issue the holder-bound fixture confirming the test holder key, append a
    /// key-binding JWT carrying `claims` and signed by `key_binding_jwk`, and
    /// stage the result beside the pinned key set and the policy.
    ///
    /// `claims` receives the issued serialization, which is exactly the input
    /// RFC 9901 section 4.3.1 hashes into `sd_hash`, so a case can bind a proof
    /// to bytes other than the ones it travels with.
    fn stage(policy: &str, claims: impl FnOnce(&str) -> Value, key_binding_jwk: &str) -> Self {
        use registry_evidence::{
            model::{Evidence, HolderPublicKey},
            sdjwt_vc::issuance_input,
            signing::{jwks_document, EvidenceSigner},
        };
        use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
        use std::sync::Arc;

        let root = tempfile::tempdir().expect("temporary verification inputs");
        let evidence: Evidence = serde_json::from_value(holder_bound_fixture_evidence())
            .expect("the fixture is a holder-bound Evidence payload");
        let holder: HolderPublicKey =
            serde_json::from_str(HOLDER_PUBLIC_JWK).expect("the holder key parses");
        let private = PrivateJwk::parse(VERIFY_PRIVATE_JWK).expect("fixture key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("fixture signer builds"));

        let (issued, trusted) = tokio::runtime::Runtime::new()
            .expect("issuance runtime starts")
            .block_on(async {
                let signer = EvidenceSigner::initialize(provider, VERIFY_KEY_ID)
                    .await
                    .expect("signer initializes");
                let input = issuance_input(&evidence, Some(&holder), &BTreeMap::new())
                    .expect("the fixture maps");
                let issued = signer
                    .sign_sd_jwt_vc(input)
                    .await
                    .expect("credential serializes");
                let trusted = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
                (issued, trusted)
            });
        let key_binding = sign_compact_jwt(
            &json!({"alg": "ES256", "typ": "kb+jwt"}),
            &claims(&issued),
            key_binding_jwk,
        );

        fs::write(
            root.path().join("presentation.sd-jwt"),
            format!("{issued}{key_binding}"),
        )
        .expect("stage the stored presentation");
        fs::write(
            root.path().join("trusted.jwks.json"),
            serde_json::to_vec(&trusted).expect("JWKS serializes"),
        )
        .expect("stage the pinned key set");
        fs::write(root.path().join("policy.yaml"), policy).expect("stage the policy");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn verify_presentation(&self, at: Option<&str>) -> Output {
        invoke_verify_presentation(
            &self.path("presentation.sd-jwt"),
            &self.path("trusted.jwks.json"),
            &self.path("policy.yaml"),
            at,
        )
    }

    /// Offer the same presentation bytes to the Version 1 `verify` command,
    /// against a policy document that command does accept, so its refusal is
    /// about the serialization rather than the policy it was handed.
    fn verify_as_stored_response(&self, at: Option<&str>) -> Output {
        let policy = self.path("audience-scoped-policy.yaml");
        fs::write(&policy, fixture_policy()).expect("stage the Version 1 policy");
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .arg("--sd-jwt-vc")
            .arg(self.path("presentation.sd-jwt"))
            .arg("--jwks")
            .arg(self.path("trusted.jwks.json"))
            .arg("--policy")
            .arg(policy)
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        if let Some(at) = at {
            command.arg("--at").arg(at);
        }
        command.output().expect("evidence binary starts")
    }
}

/// Run `verify-presentation` with no runtime file staged, so the command proves
/// it needs no deployment and opens no socket.
fn invoke_verify_presentation(
    presentation: &Path,
    jwks: &Path,
    policy: &Path,
    at: Option<&str>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
    command
        .arg("verify-presentation")
        .arg("--sd-jwt-vc-presentation")
        .arg(presentation)
        .arg("--jwks")
        .arg(jwks)
        .arg("--policy")
        .arg(policy)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME");
    if let Some(at) = at {
        command.arg("--at").arg(at);
    }
    command.output().expect("evidence binary starts")
}

/// A service whose standard output and error threads collect everything it
/// writes until it exits.
struct CapturedService {
    child: Child,
    stdout: std::thread::JoinHandle<String>,
    stderr: std::thread::JoinHandle<String>,
}

impl CapturedService {
    /// Stop the service with SIGTERM and return what it wrote to stdout and
    /// stderr.
    fn stop(mut self) -> (String, String) {
        stop(&mut self.child);
        (
            self.stdout.join().expect("stdout drains"),
            self.stderr.join().expect("stderr drains"),
        )
    }
}

fn stop(service: &mut Child) {
    let pid = rustix::process::Pid::from_raw(
        i32::try_from(service.id()).expect("child identifier is a pid"),
    )
    .expect("child identifier is a pid");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("send SIGTERM");
    let status = service.wait().expect("service exits");
    assert!(
        status.success(),
        "SIGTERM did not stop the service cleanly: {status}"
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a local port")
        .local_addr()
        .expect("reserved port")
        .port()
}

/// Poll `/ready` until the service reports a healthy audit writer.
///
/// Readiness covers the subject-binding key, the signer, the audit writer's
/// hold on its active file, and every source credential, so a ready service
/// proves the whole startup path completed rather than only that a socket is
/// open.
fn wait_until_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = String::new();
    while Instant::now() < deadline {
        if let Some(status) = probe(port, "/ready") {
            if status == "HTTP/1.1 200 OK" {
                return;
            }
            last = status;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the service never became ready (last status {last:?})");
}

fn probe(port: u16, path: &str) -> Option<String> {
    use std::io::{BufRead as _, BufReader, Write as _};

    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut status = String::new();
    BufReader::new(stream).read_line(&mut status).ok()?;
    Some(status.trim_end().to_owned())
}

/// A staged deployment: one acceptance bundle, one operator runtime file, and
/// one private secret root under a single temporary directory.
struct Deployment {
    root: tempfile::TempDir,
    port: u16,
}

impl Deployment {
    fn stage(case: &str) -> Self {
        Self::stage_on_port(case, 8080)
    }

    fn stage_on_port(case: &str, port: u16) -> Self {
        let deployment = Self {
            root: tempfile::tempdir().expect("temporary deployment"),
            port,
        };
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance")
            .join(case);
        copy_tree(&source, &deployment.path("bundle"));
        deployment.replace(
            "bundle/evidence.yaml",
            "assuranceProfile: evidence-grade",
            "assuranceProfile: local",
        );
        // The acceptance bundles keep the burst of ten the runtime rate-limit
        // tests rewrite. A staged deployment holds a full request batch, as a
        // deployment that heeded the burst warning would, so a clean `check`
        // here still means no diagnostics at all.
        deployment.replace(
            "bundle/evidence.yaml",
            "burstPerPrincipal: 10,",
            "burstPerPrincipal: 16,",
        );
        let secrets = deployment.path("secrets");
        fs::create_dir(&secrets).expect("create private secret root");
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
            .expect("set private secret-root mode");
        fs::write(
            deployment.path("runtime.yaml"),
            deployment.runtime_document(),
        )
        .expect("stage runtime");
        deployment
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn runtime_document(&self) -> String {
        format!(
            "apiVersion: registry.registrystack.org/evidence-runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: {bundle}
listener:
  bind: 127.0.0.1:{port}
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 5000
secretProviders:
  file:
    root: {secrets}
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing-key
audit:
  path: {audit}
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
",
            bundle = self.path("bundle").display(),
            port = self.port,
            secrets = self.path("secrets").display(),
            audit = self.path("audit.jsonl").display(),
        )
    }

    fn write(&self, relative: &str, contents: &str) {
        fs::write(self.path(relative), contents).expect("write staged artifact");
    }

    fn append(&self, relative: &str, contents: &str) {
        let path = self.path(relative);
        let mut text = fs::read_to_string(&path).expect("read staged artifact");
        text.push_str(contents);
        fs::write(path, text).expect("write staged artifact");
    }

    fn remove(&self, relative: &str) {
        fs::remove_file(self.path(relative)).expect("remove staged artifact");
    }

    fn replace(&self, relative: &str, from: &str, to: &str) {
        let path = self.path(relative);
        let text = fs::read_to_string(&path).expect("read staged artifact");
        assert!(text.contains(from), "staged artifact has no {from:?}");
        fs::write(path, text.replacen(from, to, 1)).expect("write staged artifact");
    }

    fn replace_line(&self, relative: &str, prefix: &str, line: &str) {
        let path = self.path(relative);
        let text = fs::read_to_string(&path).expect("read staged artifact");
        let replaced = text
            .lines()
            .map(|current| {
                if current.starts_with(prefix) {
                    line.to_owned()
                } else {
                    format!("{current}\n")
                }
            })
            .collect::<String>();
        assert_ne!(replaced, text, "staged artifact has no {prefix:?} line");
        fs::write(path, replaced).expect("write staged artifact");
    }

    fn write_secret(&self, name: &str, value: &str) {
        let path = self.path("secrets").join(name);
        fs::write(&path, value).expect("write staged secret");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set owner-only secret mode");
    }

    /// Stage every logical secret the acceptance bundle references.
    ///
    /// The signing key matches the governed public fixture key, and the source
    /// credentials are synthetic constants that never reach a network because
    /// the test performs no evidence request.
    fn stage_acceptance_secrets(&self) {
        self.write_secret("audit-hash-key", "audit-hash-secret-32-bytes-minimum-value");
        self.write_secret(
            "subject-binding-key",
            "subject-binding-secret-32-bytes-minimum-value",
        );
        self.write_secret("signing-key", VERIFY_PRIVATE_JWK);
        self.write_secret("source-a-token", "synthetic-source-token");
        self.write_secret("source-b-token", "synthetic-source-token");
        self.write_secret("source-c-username", "synthetic-source-user");
        self.write_secret("source-c-password", "synthetic-source-password");
        self.write_secret("source-d-token", "synthetic-source-token");
    }

    fn point_authentication_to(&self, origin: &str) {
        self.replace(
            "bundle/evidence.yaml",
            "  issuer: https://identity.invalid\n",
            &format!("  issuer: {origin}\n"),
        );
        self.replace(
            "bundle/evidence.yaml",
            "      uri: https://identity.invalid/.well-known/jwks.json\n",
            &format!("      uri: {origin}/.well-known/jwks.json\n"),
        );
    }

    /// Name `profile` as the issuer's TLS trust profile in the bundle and bind
    /// it in the runtime file to a read-only file holding `authority_pem`.
    fn trust_issuer_through(&self, profile: &str, authority_pem: &str) {
        let bundle_path = self.path(&format!("{profile}.pem"));
        fs::write(&bundle_path, authority_pem).expect("stage the issuer CA bundle");
        fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o444))
            .expect("seal the issuer CA bundle");
        let text =
            fs::read_to_string(self.path("bundle/evidence.yaml")).expect("read staged bundle");
        let jwks_line = text
            .lines()
            .find(|line| line.starts_with("      uri: "))
            .expect("the bundle names a JWKS URI")
            .to_owned();
        self.replace(
            "bundle/evidence.yaml",
            &format!("{jwks_line}\n"),
            &format!("{jwks_line}\n    tlsTrustProfile: {profile}\n"),
        );
        self.replace(
            "runtime.yaml",
            "  trustProfiles: {}\n",
            &format!(
                "  trustProfiles:\n    {profile}: {{caBundleFile: {}}}\n",
                bundle_path.display()
            ),
        );
    }

    /// Place an audit file the service will find on start, owner-only as the
    /// writer requires. A case that is about a mode widens it afterwards.
    fn stage_torn_line_side_file(&self, contents: &str) {
        let path = self.path("audit.jsonl.torn");
        fs::write(&path, contents).expect("stage torn-line side file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set owner-only torn-line side file mode");
    }

    fn stage_audit_file(&self, contents: &str) {
        let path = self.path("audit.jsonl");
        fs::write(&path, contents).expect("stage audit file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set owner-only audit file mode");
    }

    /// Point the runtime's audit at `stdout` instead of the staged file.
    fn write_audit_to_stdout(&self) {
        self.replace(
            "runtime.yaml",
            &format!("audit:\n  path: {}\n", self.path("audit.jsonl").display()),
            "audit:\n  destination: stdout\n",
        );
    }

    /// Overwrite the staged signing key with a different valid P-256 key.
    fn write_mismatched_signing_key(&self) {
        self.write_secret("signing-key", MISMATCHED_PRIVATE_JWK);
    }

    /// Start `serve` against the sealed deployment.
    fn serve(&self) -> Child {
        Command::new(env!("CARGO_BIN_EXE_evidence"))
            .arg("serve")
            .arg("--runtime-config")
            .arg(self.path("runtime.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("evidence service starts")
    }

    /// Start `serve` with both output streams drained into memory, so a test
    /// can read what the process wrote to each.
    fn serve_capturing(&self) -> CapturedService {
        let mut child = Command::new(env!("CARGO_BIN_EXE_evidence"))
            .arg("serve")
            .arg("--runtime-config")
            .arg(self.path("runtime.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME")
            .env_remove("EVIDENCE_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("evidence service starts");
        let drain = |mut stream: Box<dyn std::io::Read + Send>| {
            std::thread::spawn(move || {
                let mut text = String::new();
                stream.read_to_string(&mut text).expect("output reads");
                text
            })
        };
        let stdout = drain(Box::new(child.stdout.take().expect("stdout")));
        let stderr = drain(Box::new(child.stderr.take().expect("stderr")));
        CapturedService {
            child,
            stdout,
            stderr,
        }
    }

    /// Run `check` against the sealed deployment, then restore write access so
    /// the temporary directory can be cleaned up.
    fn check(&self) -> Output {
        self.seal();
        let output = invoke(&self.path("runtime.yaml"), &["check"]);
        self.unseal();
        output
    }

    fn check_with_runtime_dependencies(&self) -> Output {
        self.seal();
        let output = invoke(
            &self.path("runtime.yaml"),
            &["check", "--require-runtime-dependencies"],
        );
        self.unseal();
        output
    }

    /// Run `bundle-check` against the sealed bundle directory alone, the same
    /// seam Evidencectl uses to validate a compiled project before it has a
    /// runtime document.
    fn bundle_check(&self) -> Output {
        self.seal();
        let output = invoke_bundle_check(&self.path("bundle"));
        self.unseal();
        output
    }

    /// Run the dependency proof without taking the audit writer lock, the form
    /// that checks a candidate beside the instance holding that lock.
    fn check_without_audit_lock(&self) -> Output {
        self.seal();
        let output = invoke(
            &self.path("runtime.yaml"),
            &[
                "check",
                "--require-runtime-dependencies",
                "--without-audit-lock",
            ],
        );
        self.unseal();
        output
    }

    /// Run the dependency proof and additionally require the configured audit
    /// file to resolve inside `root`, the path an operator declares persistent.
    fn check_with_audit_under(&self, root: &Path) -> Output {
        self.seal();
        let output = invoke(
            &self.path("runtime.yaml"),
            &[
                "check",
                "--require-runtime-dependencies",
                "--require-audit-under",
                &root.display().to_string(),
            ],
        );
        self.unseal();
        output
    }

    /// Evaluate the staged bundle's own fixture, with any extra arguments.
    fn evaluate(&self, arguments: &[&str]) -> Output {
        let mut invocation = vec!["evaluate", "--fixture", "fixtures/cases.yaml"];
        invocation.extend_from_slice(arguments);
        self.seal();
        let output = invoke(&self.path("runtime.yaml"), &invocation);
        self.unseal();
        output
    }

    fn seal(&self) {
        refresh_package_envelope(&self.path("bundle"));
        set_tree_mode(&self.path("bundle"), 0o555, 0o444);
        fs::set_permissions(self.path("runtime.yaml"), fs::Permissions::from_mode(0o444))
            .expect("seal runtime");
    }

    fn unseal(&self) {
        set_tree_mode(&self.path("bundle"), 0o755, 0o644);
        fs::set_permissions(self.path("runtime.yaml"), fs::Permissions::from_mode(0o644))
            .expect("unseal runtime");
    }
}

fn refresh_package_envelope(root: &Path) {
    for reserved in [
        registry_platform_config::SUM_FILE,
        registry_platform_config::REVISION_FILE,
    ] {
        let path = root.join(reserved);
        if path.exists() {
            fs::remove_file(path).expect("prior package envelope is removed");
        }
    }
    registry_platform_config::write_sum_file(
        root,
        None,
        &registry_platform_config::PackageLimits {
            max_files: 1_024,
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_depth: 3,
            max_path_bytes: 128,
        },
        "evidencectl package",
    )
    .expect("package envelope is refreshed");
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if self.path("bundle").is_dir() {
            set_tree_mode(&self.path("bundle"), 0o755, 0o644);
        }
    }
}

fn write_private_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec(value).expect("local relying procedure draft serializes"),
    )
    .expect("write local relying procedure draft");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("make local relying procedure draft owner-only");
}

fn invoke_local_relying_procedure(runtime: &Path, input: &Path, stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_evidence"))
        .arg("prepare-local-relying-procedure")
        .arg("--runtime-config")
        .arg(runtime)
        .arg("--input")
        .arg(input)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("evidence binary starts");
    let mut child_stdin = child.stdin.take().expect("command stdin is piped");
    child_stdin
        .write_all(stdin)
        .expect("write deliberately irrelevant stdin");
    drop(child_stdin);
    child.wait_with_output().expect("evidence command exits")
}

#[test]
fn the_removed_runtime_inputs_are_refused_with_their_replacement_named() {
    let flag = Command::new(env!("CARGO_BIN_EXE_evidence"))
        .args(["check", "--runtime", "/etc/registry-evidence/runtime.yaml"])
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .expect("evidence binary starts");
    assert_eq!(
        flag.status.code(),
        Some(2),
        "the removed flag is a usage error"
    );
    assert_eq!(
        std::str::from_utf8(&flag.stderr).expect("stderr is UTF-8"),
        "evidence: --runtime is no longer accepted; pass --runtime-config FILE\n"
    );
    assert!(flag.stdout.is_empty(), "the refusal wrote to stdout");

    let environment = Command::new(env!("CARGO_BIN_EXE_evidence"))
        .args([
            "check",
            "--runtime-config",
            "/etc/registry-evidence/runtime.yaml",
        ])
        .env(
            "REGISTRY_EVIDENCE_RUNTIME",
            "/etc/registry-evidence/runtime.yaml",
        )
        .output()
        .expect("evidence binary starts");
    assert_eq!(
        environment.status.code(),
        Some(2),
        "the removed environment variable is a usage error"
    );
    assert_eq!(
        std::str::from_utf8(&environment.stderr).expect("stderr is UTF-8"),
        "evidence: REGISTRY_EVIDENCE_RUNTIME is no longer read; unset it and pass --runtime-config FILE\n"
    );
}

/// Run one runtime subcommand, `arguments[0]`, against `runtime`.
fn invoke(runtime: &Path, arguments: &[&str]) -> Output {
    let (command, rest) = arguments.split_first().expect("a subcommand is named");
    Command::new(env!("CARGO_BIN_EXE_evidence"))
        .arg(command)
        .arg("--runtime-config")
        .arg(runtime)
        .args(rest)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .expect("evidence binary starts")
}

/// Run `bundle-check` against a bundle directory, with no runtime document at
/// all: the subcommand takes no runtime configuration.
fn invoke_bundle_check(bundle: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidence"))
        .arg("bundle-check")
        .arg("--bundle")
        .arg(bundle)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .expect("evidence binary starts")
}

fn assert_success(output: &Output, prefix: &str, suffix: &str) {
    assert!(output.status.success(), "evidence command failed");
    let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.is_empty() || is_clean_check_summary(stderr),
        "evidence command wrote diagnostics: {stderr}"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.starts_with(prefix) && stdout.ends_with(suffix),
        "evidence command output shape changed"
    );
}

/// `check` ends its human report with one summary line even when it found
/// nothing to report.
fn is_clean_check_summary(stderr: &str) -> bool {
    stderr
        .strip_prefix("0 errors, 0 warnings in ")
        .and_then(|rest| rest.strip_suffix(" files\n"))
        .is_some_and(|count| count.parse::<usize>().is_ok())
}

/// Assert that a refused `check` exited `exit`, wrote nothing to stdout, and
/// reported exactly one error: `code` on its position line, then `message`, a
/// `next:` action, and the summary line.
fn assert_one_check_error(output: &Output, exit: i32, code: &str, message: &str) {
    let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert_eq!(
        output.status.code(),
        Some(exit),
        "check exit code: {stderr}"
    );
    assert!(output.stdout.is_empty(), "a refused check wrote output");
    let lines = stderr.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "check reported one error: {stderr}");
    assert!(
        lines[0].starts_with(&format!("error[{code}] ")),
        "check reported {code}: {stderr}"
    );
    assert_eq!(lines[1], format!("  {message}"), "check message: {stderr}");
    assert!(lines[2].starts_with("  next: "), "check action: {stderr}");
    assert!(
        lines[3].starts_with("1 error, 0 warnings in "),
        "check summary: {stderr}"
    );
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create staged directory");
    for entry in fs::read_dir(source).expect("read source tree") {
        let entry = entry.expect("source entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("source entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy staged artifact");
        }
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set staged mode");
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    let metadata = fs::symlink_metadata(path).expect("staged path metadata");
    if metadata.is_dir() {
        for entry in fs::read_dir(path).expect("read staged tree") {
            set_tree_mode(
                &entry.expect("staged entry").path(),
                directory_mode,
                file_mode,
            );
        }
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("set staged directory mode");
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
            .expect("set staged file mode");
    }
}
