// SPDX-License-Identifier: Apache-2.0
//! The `breg-review` binary as an operator runs it: `check` reads the runtime
//! configuration offline, resolving no secret and opening no socket, and
//! reports every finding in the shared diagnostic shape; `serve` resolves the
//! secrets the file names before it listens. Also its startup refusals,
//! shutdown on SIGINT and SIGTERM, and a full sign-in and submit whose
//! operational log and audit journal carry no credential, code, state,
//! cookie, or CSRF value.

mod support;

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use axum::http::StatusCode;
use support::{browser, cookie_pair, Environment, Harness, Options, CITIZEN_A, REQUEST_ID};

const BINARY: &str = env!("CARGO_BIN_EXE_breg-review");

struct Running {
    child: Child,
    /// Standard output, where the operational log goes.
    log: std::path::PathBuf,
    /// Standard error, which a serving page leaves empty.
    errors: std::path::PathBuf,
}

impl Running {
    fn stop(mut self) -> String {
        self.child.kill().expect("stop the review page");
        self.child.wait().expect("reap the review page");
        self.read_log()
    }

    fn read_log(&self) -> String {
        std::fs::read_to_string(&self.log).expect("read the operational log")
    }

    fn read_errors(&self) -> String {
        std::fs::read_to_string(&self.errors).expect("read standard error")
    }

    /// Send `signal` and wait for the page to exit on its own.
    async fn signal(mut self, signal: &str) -> (std::process::ExitStatus, Self) {
        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.child.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -{signal} failed");
        for _ in 0..200 {
            if let Some(status) = self.child.try_wait().expect("poll the review page") {
                return (status, self);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.child.kill().expect("stop the review page");
        self.child.wait().expect("reap the review page");
        panic!(
            "breg-review did not exit after SIGTERM or SIGINT: {}",
            self.read_log()
        );
    }
}

async fn free_address() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn spawn(environment: &Environment) -> Running {
    let log = environment.directory.path().join("operational.log");
    let errors = environment.directory.path().join("stderr.log");
    let child = Command::new(BINARY)
        .arg("--runtime-config")
        .arg(&environment.config_path)
        .arg("serve")
        .env("BREG_REVIEW_LOG", "info")
        .stdout(std::fs::File::create(&log).unwrap())
        .stderr(std::fs::File::create(&errors).unwrap())
        .spawn()
        .expect("start breg-review");
    Running { child, log, errors }
}

fn check(environment: &Environment, arguments: &[&str]) -> std::process::Output {
    Command::new(BINARY)
        .arg("--runtime-config")
        .arg(&environment.config_path)
        .arg("check")
        .args(arguments)
        .env_remove("BREG_REVIEW_LOG")
        .stdin(Stdio::null())
        .output()
        .expect("run breg-review")
}

/// The JSON report `check --format json` writes, with its exit status.
fn report(environment: &Environment) -> (Option<i32>, serde_json::Value) {
    let output = check(environment, &["--format", "json"]);
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = serde_json::from_slice(&output.stdout).expect("the report is JSON");
    (output.status.code(), report)
}

fn codes(report: &serde_json::Value) -> Vec<(String, String)> {
    report["diagnostics"]
        .as_array()
        .expect("the report lists its diagnostics")
        .iter()
        .map(|diagnostic| {
            (
                diagnostic["code"].as_str().expect("code").to_owned(),
                diagnostic["path"].as_str().expect("path").to_owned(),
            )
        })
        .collect()
}

/// Run `serve` to a startup failure. Startup fetches discovery from the
/// in-process provider, so the binary runs off the test's runtime thread.
async fn serve_failing(environment: &Environment) -> std::process::Output {
    let config_path = environment.config_path.clone();
    tokio::task::spawn_blocking(move || {
        Command::new(BINARY)
            .arg("--runtime-config")
            .arg(config_path)
            .arg("serve")
            .env_remove("BREG_REVIEW_LOG")
            .stdin(Stdio::null())
            .output()
            .expect("run breg-review")
    })
    .await
    .unwrap()
}

fn replace_client_key_with_inline_canary(environment: &Environment) {
    let document = std::fs::read_to_string(&environment.config_path).unwrap();
    let inline = document.replace(
        "clientKeyRef: secret:file/client-key.jwk",
        "clientKeyRef: '{\"kty\":\"OKP\",\"d\":\"inline-canary-value\"}'",
    );
    assert_ne!(inline, document);
    std::fs::write(&environment.config_path, inline).unwrap();
}

fn assert_json_lines(log: &str) {
    for line in log.lines() {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|_| panic!("a log line is not JSON: {line}"));
    }
}

async fn wait_until_healthy(harness: &Harness) {
    for _ in 0..200 {
        if let Ok(response) = harness.http.get(harness.url("/health")).send().await {
            if response.status() == StatusCode::OK {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("breg-review never became healthy");
}

fn parameter(url: &str, name: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("{name} in {url}"))
}

#[tokio::test]
async fn a_full_journey_leaves_no_credential_in_the_log_or_the_journal() {
    let environment = Environment::prepare(free_address().await, &Options::default()).await;
    let running = spawn(&environment);
    let harness = Harness {
        environment,
        http: browser(),
    };
    wait_until_healthy(&harness).await;

    let start = harness
        .get(&format!("/signin?return=%2Frequests%2F{REQUEST_ID}"), None)
        .await;
    assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.body);
    let state = parameter(start.location(), "state");
    let nonce = parameter(start.location(), "nonce");
    let sign_in_cookie = cookie_pair(&start.set_cookie("breg-review-signin").unwrap());
    let redirected = harness
        .http
        .get(format!("{}&login_hint={CITIZEN_A}", start.location()))
        .send()
        .await
        .unwrap();
    let callback = redirected.headers()["location"]
        .to_str()
        .unwrap()
        .to_owned();
    let code = parameter(&callback, "code");
    let signed_in = support::page(
        harness
            .http
            .get(&callback)
            .header("cookie", &sign_in_cookie)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.body);
    let session = cookie_pair(&signed_in.set_cookie("breg-review-session").unwrap());
    // The same callback presented to a second sign-in carries the wrong
    // state: it is refused and logged, still without its values.
    let second = harness
        .get(&format!("/signin?return=%2Frequests%2F{REQUEST_ID}"), None)
        .await;
    let second_cookie = cookie_pair(&second.set_cookie("breg-review-signin").unwrap());
    let replay = support::page(
        harness
            .http
            .get(&callback)
            .header("cookie", &second_cookie)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);

    let review = harness
        .get(&format!("/requests/{REQUEST_ID}"), Some(&session))
        .await;
    assert_eq!(review.status, StatusCode::OK, "{}", review.body);
    let csrf = review.input("csrf").unwrap();
    let view = review.input("view").unwrap();
    let submitted = harness
        .post(
            &format!("/requests/{REQUEST_ID}/submit"),
            Some(&session),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_eq!(submitted.status, StatusCode::OK, "{}", submitted.body);

    let errors = running.read_errors();
    let log = running.stop();
    assert!(
        errors.is_empty(),
        "the operational log is on stdout: {errors}"
    );
    let journal = harness.environment.audit_text();
    let bearers = harness.environment.registry.bearer_tokens();
    assert!(!bearers.is_empty(), "the registry saw the person's token");
    let session_value = session.split_once('=').unwrap().1;
    let sign_in_value = sign_in_cookie.split_once('=').unwrap().1;
    let mut secrets = vec![
        state.as_str(),
        nonce.as_str(),
        code.as_str(),
        session_value,
        sign_in_value,
        csrf.as_str(),
        view.as_str(),
        CITIZEN_A,
    ];
    secrets.extend(bearers.iter().map(String::as_str));
    for secret in secrets {
        assert!(!log.contains(secret), "the operational log leaked a value");
        assert!(
            !journal.contains(secret),
            "the audit journal leaked a value"
        );
    }
    assert!(log.contains("the review page is listening"), "{log}");
    assert!(log.contains("the wrong state"), "{log}");
    assert_json_lines(&log);
}

#[tokio::test]
async fn an_inline_client_key_stops_startup_without_echoing_it() {
    let environment = Environment::prepare(free_address().await, &Options::default()).await;
    replace_client_key_with_inline_canary(&environment);

    let output = serve_failing(&environment).await;

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("breg-review: the runtime configuration was refused\n"),
        "{stderr}"
    );
    assert!(stderr.contains("/signIn/clientKeyRef"), "{stderr}");
    assert!(!stderr.contains("inline-canary-value"), "{stderr}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.is_empty(), "{stdout}");
}

#[tokio::test]
async fn check_accepts_a_valid_configuration_without_reading_its_secrets() {
    let environment = Environment::prepare(free_address().await, &Options::default()).await;
    // `check` resolves no secret, so it passes with every secret file gone.
    for name in ["client-key.jwk", "audit-key"] {
        std::fs::remove_file(environment.directory.path().join("secrets").join(name)).unwrap();
    }

    let output = check(&environment, &[]);

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert_eq!(stdout, "0 errors, 0 warnings in 1 file\n");
    assert!(stderr.is_empty(), "{stderr}");
    // `check` opens no journal: the audit directory stays empty.
    assert!(
        harness_audit_is_empty(&environment),
        "check wrote to the audit journal"
    );

    let (code, report) = report(&environment);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(
        report["apiVersion"],
        "id.registrystack.org/formats/breg/review-ctl-report/v1alpha1"
    );
    assert_eq!(report["kind"], "BRegReviewCtlReport");
    assert_eq!(report["command"], "check");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["ok"], true);
    assert_eq!(report["filesChecked"], 1);
    assert!(codes(&report).is_empty(), "{report}");
}

#[tokio::test]
async fn check_refuses_an_invalid_configuration_without_echoing_it() {
    let environment = Environment::prepare(free_address().await, &Options::default()).await;
    replace_client_key_with_inline_canary(&environment);

    let output = check(&environment, &[]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.starts_with("breg-review check refused the input.\n"),
        "{stderr}"
    );
    assert!(stderr.contains("/signIn/clientKeyRef"), "{stderr}");
    assert!(!stderr.contains("inline-canary-value"), "{stderr}");

    let (code, report) = report(&environment);
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(
        codes(&report),
        [(
            "config.invalid-value".to_owned(),
            "/signIn/clientKeyRef".to_owned()
        )]
    );
    assert!(
        !report.to_string().contains("inline-canary-value"),
        "{report}"
    );
}

/// Decoding stops at the first refused value; once the file decodes, every
/// semantic finding is reported together.
#[tokio::test]
async fn check_reports_every_semantic_finding_by_code() {
    let environment = Environment::prepare(free_address().await, &Options::default()).await;
    let document = std::fs::read_to_string(&environment.config_path).unwrap();
    let bind = document
        .lines()
        .find(|line| line.trim_start().starts_with("bind: "))
        .expect("the document binds an address")
        .to_owned();
    let refused = document.replace(&bind, "  bind: 0.0.0.0:8115").replacen(
        "scopes: [",
        "scopes: [openid, ",
        1,
    );
    assert_eq!(refused.matches("openid").count(), 1, "{refused}");
    std::fs::write(&environment.config_path, refused).unwrap();

    let (code, report) = report(&environment);

    assert_eq!(code, Some(1), "{report}");
    assert_eq!(
        codes(&report),
        [
            (
                "breg.review-runtime.public-bind".to_owned(),
                "/listener/bind".to_owned()
            ),
            (
                "breg.review-runtime.openid-scope".to_owned(),
                "/signIn/scopes/0".to_owned()
            ),
        ]
    );
}

/// A client key that parses but cannot authenticate the sign-in client, here
/// one without a key identifier, is refused when `serve` starts. `check`
/// reads no secret, so it cannot see the key.
#[tokio::test]
async fn serve_refuses_a_client_key_without_a_key_identifier() {
    let environment = Environment::prepare(free_address().await, &Options::default()).await;
    let key_path = environment.directory.path().join("secrets/client-key.jwk");
    let mut key: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&key_path).unwrap()).unwrap();
    let private = key["d"].as_str().unwrap().to_owned();
    assert!(key.as_object_mut().unwrap().remove("kid").is_some());
    std::fs::write(&key_path, serde_json::to_vec(&key).unwrap()).unwrap();

    assert_eq!(check(&environment, &[]).status.code(), Some(0));
    let served = serve_failing(&environment).await;

    assert_eq!(served.status.code(), Some(1));
    let stdout = String::from_utf8(served.stdout).unwrap();
    let stderr = String::from_utf8(served.stderr).unwrap();
    assert!(
        stderr.contains("the client key must carry a key identifier"),
        "{stderr}"
    );
    assert!(!stderr.contains(&private), "{stderr}");
    assert!(!stdout.contains(&private), "{stdout}");
}

#[tokio::test]
async fn serve_refuses_an_unreadable_secret_by_its_safe_reference() {
    let environment = Environment::prepare(free_address().await, &Options::default()).await;
    std::fs::remove_file(environment.directory.path().join("secrets/audit-key")).unwrap();

    assert_eq!(check(&environment, &[]).status.code(), Some(0));
    let output = serve_failing(&environment).await;

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(
            "the secret reference secret:file/audit-key could not be resolved: no readable secret"
        ),
        "{stderr}"
    );
    assert!(
        !stderr.contains(environment.directory.path().to_str().unwrap()),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_missing_configuration_file_is_an_operational_failure() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("missing-runtime.yaml");
    let output = Command::new(BINARY)
        .arg("--runtime-config")
        .arg(&missing)
        .args(["check", "--format", "json"])
        .stdin(Stdio::null())
        .output()
        .expect("run breg-review");

    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert_eq!(report["status"], "operational-failure");
    assert_eq!(
        codes(&report),
        [(
            "platform.runtime-config.unavailable".to_owned(),
            String::new()
        )]
    );
}

#[tokio::test]
async fn a_missing_subcommand_is_a_usage_error() {
    let environment = Environment::prepare(free_address().await, &Options::default()).await;
    let output = Command::new(BINARY)
        .arg("--runtime-config")
        .arg(&environment.config_path)
        .output()
        .expect("run breg-review");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("check"), "{stderr}");
    assert!(stderr.contains("serve"), "{stderr}");
}

/// `serve` refuses an unknown level with exit status 2 before any work.
/// `check` logs nothing and reads no level.
#[tokio::test]
async fn an_unknown_log_level_stops_startup() {
    let environment = Environment::prepare(free_address().await, &Options::default()).await;
    let run = |subcommand: &str| {
        Command::new(BINARY)
            .arg("--runtime-config")
            .arg(&environment.config_path)
            .arg(subcommand)
            .env("BREG_REVIEW_LOG", "debug")
            .output()
            .expect("run breg-review")
    };
    let served = run("serve");
    assert_eq!(served.status.code(), Some(2));
    let stderr = String::from_utf8(served.stderr).unwrap();
    assert_eq!(
        stderr,
        "breg-review: BREG_REVIEW_LOG must be one of error, warn, or info\n"
    );
    assert!(served.stdout.is_empty());

    let checked = run("check");
    assert_eq!(checked.status.code(), Some(0));
    assert_eq!(checked.stdout, b"0 errors, 0 warnings in 1 file\n");
}

#[tokio::test]
async fn sigterm_and_sigint_stop_the_page_cleanly() {
    for signal in ["TERM", "INT"] {
        let environment = Environment::prepare(free_address().await, &Options::default()).await;
        let running = spawn(&environment);
        let harness = Harness {
            environment,
            http: browser(),
        };
        wait_until_healthy(&harness).await;

        let (status, running) = running.signal(signal).await;

        let log = running.read_log();
        assert!(status.success(), "SIG{signal} exit {status}: {log}");
        assert!(log.contains("the review page is shutting down"), "{log}");
        assert!(log.contains("the review page stopped"), "{log}");
        assert_json_lines(&log);
        assert!(
            running.read_errors().is_empty(),
            "{}",
            running.read_errors()
        );
    }
}

fn harness_audit_is_empty(environment: &Environment) -> bool {
    std::fs::read_dir(environment.audit_path.parent().unwrap())
        .unwrap()
        .next()
        .is_none()
}
