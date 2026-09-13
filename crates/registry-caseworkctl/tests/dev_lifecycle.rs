// SPDX-License-Identifier: Apache-2.0
//! Installed-binary proof that `caseworkctl dev` is the whole local runtime.
//!
//! Opt in after building `casework` and `caseworkctl`; Docker must be
//! available. This creates and removes only its own synthetic database.
//!
//! ```sh
//! cargo build --locked -p registry-casework -p registry-caseworkctl
//! cargo test -p registry-caseworkctl --test dev_lifecycle -- --ignored
//! ```

use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// One project served by one retained local session, with the three ports it
/// was started on. Fixed ports would make two concurrent runs collide, so the
/// kernel names them and the session retains them across every restart.
struct Session {
    project: PathBuf,
    casework_bin: PathBuf,
    ports: [u16; 3],
    _workspace: tempfile::TempDir,
}

impl Session {
    fn ctl(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_caseworkctl"))
            .args(["--format", "json"])
            .args(args)
            // The journal assertion below needs the default service event even
            // when a maintainer's shell sets a quieter global tracing filter.
            .env("RUST_LOG", "info")
            .output()
            .expect("native ctl command launches")
    }

    /// The machine-readable report of one successful command, with the refusal
    /// it printed on failure. A report never carries a key or a token.
    fn report(&self, args: &[&str], output: Output) -> Value {
        assert!(
            output.status.success(),
            "caseworkctl {args:?} refused: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("a JSON report")
    }

    fn success(&self, args: &[&str]) -> Value {
        self.report(args, self.ctl(args))
    }

    /// Start the retained session. Every start names the same three ports, so
    /// a restart proves the session keeps them rather than probing new ones.
    fn start(&self) -> Value {
        let project = self.project.to_str().expect("a UTF-8 project path");
        let [casework_port, issuer_port, database_port] = self.ports.map(|port| port.to_string());
        let report = self.success(&[
            "dev",
            project,
            "--casework-port",
            &casework_port,
            "--issuer-port",
            &issuer_port,
            "--database-port",
            &database_port,
            "--casework-bin",
            self.casework_bin.to_str().expect("a UTF-8 casework path"),
        ]);
        assert_eq!(report["status"], "ready", "{report:#}");
        assert_eq!(
            report["caseworkUrl"],
            format!("http://127.0.0.1:{casework_port}")
        );
        assert_eq!(
            report["tokenEndpoint"],
            format!("http://127.0.0.1:{issuer_port}/oauth2/token")
        );
        report
    }

    fn stop(&self, args: &[&str]) -> Value {
        let project = self.project.to_str().expect("a UTF-8 project path");
        let mut invocation = vec!["dev", "stop", project];
        invocation.extend_from_slice(args);
        self.success(&invocation)
    }

    /// Obtain a fresh token through the maintained local development command.
    /// Read its private header file without printing the bearer.
    fn token(&self, report: &Value, id: &str) -> String {
        let _ = client(report, id);
        let issued = self.success(&[
            "dev",
            "token",
            id,
            self.project.to_str().expect("a UTF-8 project path"),
        ]);
        let header = fs::read_to_string(
            issued["headerFile"]
                .as_str()
                .expect("a private header file"),
        )
        .expect("the reported header is readable");
        let token = header
            .trim()
            .strip_prefix("Authorization: Bearer ")
            .expect("the local command writes a bearer header")
            .to_owned();
        assert_eq!(
            token.split('.').count(),
            3,
            "a compact token has three parts"
        );
        token
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Every exit, including a panicking assertion, reclaims the container
        // and the data volume this test created. A failed reclaim is reported
        // rather than dropped, unless the test is already unwinding.
        let project = self.project.to_str().expect("a UTF-8 project path");
        let output = self.ctl(&["dev", "stop", project, "--remove"]);
        if !output.status.success() && !std::thread::panicking() {
            panic!(
                "dev stop --remove failed during cleanup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

/// One binary this test drives, built from this workspace beside the
/// `caseworkctl` under test.
fn prerequisite(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_BIN_EXE_caseworkctl"))
        .parent()
        .expect("the test binary has a build directory")
        .join(name);
    assert!(
        path.is_file(),
        "build {name} before running the retained lifecycle test: {}",
        path.display()
    );
    path
}

/// Three distinct loopback ports nothing is listening on: bind `127.0.0.1:0`,
/// let the kernel name the port, and release all three together.
fn free_ports() -> [u16; 3] {
    let held: Vec<std::net::TcpListener> = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port is available"))
        .collect();
    let ports: Vec<u16> = held
        .iter()
        .map(|listener| listener.local_addr().expect("the bound port").port())
        .collect();
    drop(held);
    ports.try_into().expect("three ports")
}

fn client<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["clients"]
        .as_array()
        .expect("the report lists every local client")
        .iter()
        .find(|client| client["id"] == id)
        .unwrap_or_else(|| panic!("the report names the {id} client"))
}

fn http(
    method: &str,
    url: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (u16, Value) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a local runtime");
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("an HTTP client");
        let mut request = match method {
            "POST" => client.post(url),
            _ => client.get(url),
        };
        if let Some(body) = body {
            request = request.json(&body);
        }
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await.expect("the local runtime answers");
        let status = response.status().as_u16();
        let bytes = response.bytes().await.expect("a bounded body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    })
}

/// Create one hosted item as the Requester and return its identifier.
fn create_hosted_item(session: &Session, report: &Value, reference: &str) -> String {
    let token = session.token(report, "requester");
    let (status, body) = http(
        "POST",
        &format!(
            "{}/v1/hosted-items",
            report["caseworkUrl"].as_str().expect("a Casework URL")
        ),
        Some(&token),
        &[
            ("registry-casework-profile", "requester"),
            ("idempotency-key", reference),
        ],
        Some(json!({
            "kind": "decision",
            "requesterReference": reference,
            "display": {
                "summary": "Confirm the prepared synthetic batch",
                "reference": reference
            }
        })),
    );
    assert_eq!(status, 201, "{body:#}");
    assert_eq!(body["requesterReference"], reference);
    assert_eq!(body["kind"], "decision");
    body["itemId"].as_str().expect("an item ID").to_owned()
}

/// Every work item the Staff client sees in the seeded team's queue.
fn inbox(session: &Session, report: &Value) -> Vec<Value> {
    let token = session.token(report, "staff");
    let (status, body) = http(
        "GET",
        &format!(
            "{}/v1/work-items?view=my_teams&queue=decisions&limit=25",
            report["caseworkUrl"].as_str().expect("a Casework URL")
        ),
        Some(&token),
        &[("registry-casework-profile", "staff")],
        None,
    );
    assert_eq!(status, 200, "{body:#}");
    assert_eq!(body["servedQueues"], json!(["decisions"]));
    body["items"].as_array().expect("a work item page").clone()
}

#[test]
#[ignore = "requires Docker and a built casework"]
fn dev_serves_a_tutorial_project_and_retains_its_records() {
    let workspace = tempfile::tempdir().expect("a work directory");
    let session = Session {
        project: workspace.path().join("casework"),
        casework_bin: prerequisite("casework"),
        ports: free_ports(),
        _workspace: workspace,
    };
    let project = session.project.to_str().expect("a UTF-8 project path");

    // What the tutorial reader runs first. `init` writes the local clients the
    // first start registers, so nothing else has to be authored.
    let created = session.success(&["init", project, "--template", "standalone-decision"]);
    assert!(
        created["created"]
            .as_array()
            .expect("a created list")
            .contains(&json!("dev-clients.yaml")),
        "{created:#}"
    );

    let first = session.start();
    assert_eq!(first["directory"]["teams"], 1, "{first:#}");
    assert_eq!(
        http(
            "GET",
            &format!("{}/ready", first["caseworkUrl"].as_str().unwrap()),
            None,
            &[],
            None
        )
        .0,
        200
    );

    // The session a first start leaves behind satisfies every operator check,
    // including the seeded directory the reader never had to fill in.
    let doctor = session.success(&[
        "doctor",
        "--runtime-config",
        first["operatorConfig"]
            .as_str()
            .expect("an operator config"),
    ]);
    assert_eq!(doctor["checks"]["directory"], "ready", "{doctor:#}");
    assert_eq!(doctor["checks"]["secretFiles"], "ready", "{doctor:#}");

    let item = create_hosted_item(&session, &first, "synthetic-batch-0042");
    let items = inbox(&session, &first);
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["itemId"], item);
    assert_eq!(items[0]["queueId"], "decisions");
    assert_eq!(
        items[0]["hosted"]["requesterReference"],
        "synthetic-batch-0042"
    );

    // A stopped session keeps its records: the same item is in the same inbox
    // after a restart, on the same retained ports.
    assert_eq!(session.stop(&[])["status"], "stopped");
    let second = session.start();
    let items = inbox(&session, &second);
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["itemId"], item);

    // Removal discards them: the same project starts empty and serves again.
    assert_eq!(session.stop(&["--remove"])["status"], "stopped");
    let third = session.start();
    assert_eq!(third["directory"]["teams"], 1, "{third:#}");
    assert!(inbox(&session, &third).is_empty());
    let replacement = create_hosted_item(&session, &third, "synthetic-batch-0043");
    assert_ne!(replacement, item);
    assert_eq!(inbox(&session, &third).len(), 1);

    // The journal spans the retained session, not one start.
    let journal = session.success(&["dev", "events", project]);
    assert!(
        !journal["events"]
            .as_array()
            .expect("a journal tail")
            .is_empty(),
        "{journal:#}"
    );

    session.stop(&["--remove"]);
}
