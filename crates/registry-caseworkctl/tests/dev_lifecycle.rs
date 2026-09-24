// SPDX-License-Identifier: Apache-2.0
//! Installed-binary proof that `caseworkctl dev` is the whole local runtime and
//! that the candidate unified Casework facades reach it through their native
//! product bindings.
//!
//! Run the maintained product script so the service, CLI, and native bindings
//! are built together. Docker, Node.js, npm, and Python must be available. The
//! test creates and removes only its own synthetic database.
//!
//! ```sh
//! products/casework/scripts/check-review-journeys.sh
//! ```
//!
//! The script supplies only the candidate Casework native artifact to each
//! exact unified Casework facade. Inert sibling namespace stubs stand in for
//! the other four product bindings, whose package assembly has a separate
//! release gate. This is real HTTP/native-facade proof, not installed tarball
//! or wheel proof.

use serde_json::{json, Value};
use std::{
    env, fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const NODE_JOURNEY: &str = r#"
'use strict';

const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const { CaseworkClient } = require(process.env.CASEWORK_NODE_FACADE_CLIENT);
const client = new CaseworkClient({ baseUrl: input.baseUrl });

async function main() {
  if (input.operation === 'list') {
    const outcome = await client.reviewTasks(input.token, input.profile, { limit: 25 });
    process.stdout.write(JSON.stringify(outcome.value));
    return;
  }
  if (input.operation === 'refuseUnauthorizedList') {
    try {
      await client.reviewTasks(input.token, input.profile, { limit: 25 });
    } catch (error) {
      if (error && error.kind === 'problem' && error.status === 403) {
        process.stdout.write(JSON.stringify({ refused: true, status: error.status }));
        return;
      }
      throw error;
    }
    throw new Error('the producer unexpectedly received the reviewer inbox');
  }
  if (input.operation === 'result') {
    const outcome = await client.reviewResult(input.token, input.profile, input.accepted);
    process.stdout.write(JSON.stringify(outcome));
    return;
  }
  throw new Error(`unknown Node journey operation: ${input.operation}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
"#;

const PYTHON_JOURNEY: &str = r#"
import json
import sys

from registry_client import casework

with open(sys.argv[1], encoding="utf-8") as source:
    request = json.load(source)

client = casework.CaseworkClient(request["baseUrl"])
page = client.review_tasks(
    request["token"], request["profile"], {"limit": 25}, None,
)["value"]
items = page["items"]
if len(items) != 1 or items[0]["requestId"] != request["requestId"]:
    raise AssertionError("the retained request was not in the candidate Python client's inbox")
task = items[0]
claimed = client.claim_review_task(
    request["token"], request["profile"], task["taskId"], task["revision"],
    "python-claim-synthetic-batch-0042", None,
)["value"]
client.decide_review_task(
    request["token"], request["profile"], task["taskId"], claimed["revision"],
    "python-answer-synthetic-batch-0042",
    {"decision": {"type": "answer", "outcome": "confirmed"}}, None,
)
sys.stdout.write(json.dumps({"requestId": task["requestId"], "claimedRevision": claimed["revision"]}))
"#;

struct NativeClients {
    root: PathBuf,
    node_script: PathBuf,
    node_modules: PathBuf,
    node_facade_client: PathBuf,
    python_script: PathBuf,
    python_path: PathBuf,
}

impl NativeClients {
    fn prepare(root: &Path) -> Self {
        let native_root = root.join("native-clients");
        fs::create_dir_all(&native_root).expect("the native journey directory is writable");

        let node_facade_root = required_path("CASEWORK_NODE_FACADE_ROOT");
        let node_native = required_path("CASEWORK_NODE_NATIVE");
        let node_manifest: Value = serde_json::from_slice(
            &fs::read(node_facade_root.join("package.json"))
                .expect("the unified Node package manifest is readable"),
        )
        .expect("the unified Node package manifest is JSON");
        let node_version = node_manifest["version"]
            .as_str()
            .expect("the unified Node package has a version");
        let platform_suffix = match (env::consts::OS, env::consts::ARCH) {
            ("macos", "aarch64") => "darwin-arm64",
            ("linux", "x86_64") => "linux-x64-gnu",
            ("linux", "aarch64") => "linux-arm64-gnu",
            pair => panic!("the unified Node client does not support {pair:?}"),
        };
        let node_modules = native_root.join("node_modules");
        let platform_package = node_modules
            .join("@registrystack")
            .join(format!("client-{platform_suffix}"));
        fs::create_dir_all(&platform_package).expect("the Node platform shim is writable");
        fs::write(
            platform_package.join("package.json"),
            serde_json::to_vec(&json!({
                "name": format!("@registrystack/client-{platform_suffix}"),
                "version": node_version,
                "main": "index.js"
            }))
            .expect("the Node platform manifest is representable"),
        )
        .expect("the Node platform manifest is writable");
        fs::write(
            platform_package.join("index.js"),
            format!(
                "'use strict';\nmodule.exports = {{ casework: require({}) }};\n",
                serde_json::to_string(
                    node_native
                        .to_str()
                        .expect("the Node native binding path is UTF-8")
                )
                .expect("the Node native binding path is JSON")
            ),
        )
        .expect("the Node platform shim is writable");
        let node_script = native_root.join("journey.cjs");
        fs::write(&node_script, NODE_JOURNEY).expect("the Node journey is writable");

        let python_facade_root = required_path("CASEWORK_PYTHON_FACADE_ROOT");
        let python_product_root = required_path("CASEWORK_PYTHON_PRODUCT_ROOT");
        let python_native = required_path("CASEWORK_PYTHON_NATIVE");
        let python_path = native_root.join("python");
        let unified_package = python_path.join("registry_client");
        fs::create_dir_all(&unified_package).expect("the Python facade directory is writable");
        fs::copy(
            python_facade_root.join("__init__.py"),
            unified_package.join("__init__.py"),
        )
        .expect("the exact unified Python facade is copied");
        for sibling in ["breg", "discovery", "evidence", "messaging", "relay"] {
            let package = unified_package.join(sibling);
            fs::create_dir_all(&package).expect("the Python sibling stub is writable");
            fs::write(package.join("__init__.py"), "")
                .expect("the Python sibling stub is writable");
        }
        let casework_package = unified_package.join("casework");
        fs::create_dir_all(&casework_package).expect("the Python Casework package is writable");
        fs::copy(
            python_product_root.join("__init__.py"),
            casework_package.join("__init__.py"),
        )
        .expect("the exact Casework Python facade is copied");
        fs::copy(
            python_native,
            casework_package.join("registry_casework_client.so"),
        )
        .expect("the candidate Casework Python binding is copied");
        let python_script = native_root.join("journey.py");
        fs::write(&python_script, PYTHON_JOURNEY).expect("the Python journey is writable");

        Self {
            root: native_root,
            node_script,
            node_modules,
            node_facade_client: node_facade_root.join("casework/client.js"),
            python_script,
            python_path,
        }
    }

    fn node(&self, input: &Value) -> Value {
        self.run(
            Command::new("node")
                .arg(&self.node_script)
                .env("NODE_PATH", &self.node_modules)
                .env("CASEWORK_NODE_FACADE_CLIENT", &self.node_facade_client),
            "node",
            input,
        )
    }

    fn python(&self, input: &Value) -> Value {
        self.run(
            Command::new("python3")
                .arg(&self.python_script)
                .env("PYTHONPATH", &self.python_path),
            "python",
            input,
        )
    }

    fn run(&self, command: &mut Command, name: &str, input: &Value) -> Value {
        let input_path = self.root.join(format!("{name}-input.json"));
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(true).write(true).mode(0o600);
        let mut file = options
            .open(&input_path)
            .expect("the private native-client input is writable");
        serde_json::to_writer(&mut file, input).expect("the native-client input is JSON");
        drop(file);
        let output = command
            .arg(&input_path)
            .output()
            .unwrap_or_else(|error| panic!("the candidate {name} client launches: {error}"));
        assert!(
            output.status.success(),
            "the candidate {name} client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("the candidate {name} client returned JSON: {error}"))
    }
}

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(
        env::var_os(name)
            .unwrap_or_else(|| panic!("{name} is required; run check-review-journeys.sh")),
    );
    assert!(path.exists(), "{name} does not exist: {}", path.display());
    path
}

/// One project served by one retained local session, with the three ports it
/// was started on. Fixed ports would make two concurrent runs collide, so the
/// kernel names them and the session retains them across every restart.
struct Session {
    project: PathBuf,
    casework_bin: PathBuf,
    native: NativeClients,
    ports: [u16; 3],
    _workspace: tempfile::TempDir,
}

impl Session {
    fn ctl(&self, args: &[&str]) -> Output {
        Command::new(candidate_binary("CASEWORKCTL_BIN", "caseworkctl"))
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
    let override_name = match name {
        "casework" => "CASEWORK_BIN",
        other => panic!("no candidate binary override is defined for {other}"),
    };
    if let Some(path) = env::var_os(override_name) {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "{override_name} does not exist: {}",
            path.display()
        );
        return path;
    }
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

fn candidate_binary(override_name: &str, name: &str) -> PathBuf {
    if let Some(path) = env::var_os(override_name) {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "{override_name} does not exist: {}",
            path.display()
        );
        return path;
    }
    Path::new(env!("CARGO_BIN_EXE_caseworkctl"))
        .parent()
        .expect("the test binary has a build directory")
        .join(name)
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

/// Create one submitted-context review as the admitted producer.
fn create_review_request(session: &Session, report: &Value, reference: &str) -> Value {
    let token = session.token(report, "requester");
    let (status, body) = http(
        "POST",
        &format!(
            "{}/v1/review-requests",
            report["caseworkUrl"].as_str().expect("a Casework URL")
        ),
        Some(&token),
        &[
            ("registry-casework-profile", "requester"),
            ("idempotency-key", reference),
        ],
        Some(json!({
            "kind": "decision",
            "subject": {
                "source": "standalone",
                "type": "batch",
                "id": reference,
                "version": "1",
                "digest": format!("sha256:{:064x}", 1)
            },
            "requesterReference": reference,
            "context": {
                "strategy": "submitted",
                "snapshot": {
                    "summary": "Confirm the prepared synthetic batch",
                    "reference": reference
                }
            }
        })),
    );
    assert_eq!(status, 201, "{body:#}");
    assert!(body["requestId"].is_string(), "{body:#}");
    body
}

/// Every unified review task the Staff client sees in the seeded team's queue.
fn inbox(session: &Session, report: &Value) -> Vec<Value> {
    let token = session.token(report, "staff");
    let (status, body) = http(
        "GET",
        &format!(
            "{}/v1/review-tasks?limit=25",
            report["caseworkUrl"].as_str().expect("a Casework URL")
        ),
        Some(&token),
        &[("registry-casework-profile", "staff")],
        None,
    );
    assert_eq!(status, 200, "{body:#}");
    body["items"]
        .as_array()
        .expect("a review task page")
        .clone()
}

#[test]
#[ignore = "requires Docker and candidate Casework service, CLI, Node, and Python bindings"]
fn dev_serves_a_tutorial_project_through_candidate_facades_and_retains_its_records() {
    let workspace = tempfile::tempdir().expect("a work directory");
    let native = NativeClients::prepare(workspace.path());
    let session = Session {
        project: workspace.path().join("casework"),
        casework_bin: prerequisite("casework"),
        native,
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
    // This test deliberately selects collision-free ports instead of the
    // template's default local issuer port. Keep the governed producer
    // identity aligned with the exact issuer that will mint its token.
    let policy_path = session.project.join("casework.yaml");
    let mut policy: Value = serde_norway::from_slice(
        &fs::read(&policy_path).expect("the initialized policy is readable"),
    )
    .expect("the initialized policy is valid YAML");
    policy["reviewProducers"][0]["issuer"] =
        format!("http://127.0.0.1:{}", session.ports[1]).into();
    policy["reviewProducers"][0]["subject"] =
        registry_thunderid_tooling::local::agent_id("casework-local", "requester").into();
    fs::write(
        &policy_path,
        serde_norway::to_string(&policy).expect("the adjusted policy is valid YAML"),
    )
    .expect("the adjusted policy is writable");

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

    // Exercise the documented migration entry point explicitly. `dev` applies
    // the same embedded migrations before starting, so this also proves that a
    // current candidate reports the already-current database safely.
    let migrated = session.success(&[
        "db",
        "migrate",
        project,
        "--runtime-config",
        first["operatorConfig"]
            .as_str()
            .expect("an operator config"),
    ]);
    assert_eq!(migrated["status"], "migrated", "{migrated:#}");

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

    let accepted = create_review_request(&session, &first, "synthetic-batch-0042");
    let request = accepted["requestId"]
        .as_str()
        .expect("a review request ID")
        .to_owned();

    // The exact unified Node Casework facade reaches the candidate native
    // binding and real service. A producer cannot use that path to read the
    // reviewer inbox, and the permitted Staff call still observes the item.
    let refused = session.native.node(&json!({
        "operation": "refuseUnauthorizedList",
        "baseUrl": first["caseworkUrl"],
        "token": session.token(&first, "requester"),
        "profile": "requester"
    }));
    assert_eq!(refused, json!({"refused": true, "status": 403}));
    let node_page = session.native.node(&json!({
        "operation": "list",
        "baseUrl": first["caseworkUrl"],
        "token": session.token(&first, "staff"),
        "profile": "staff"
    }));
    let items = node_page["items"]
        .as_array()
        .expect("the Node client returned a review task page")
        .clone();
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["requestId"], request);
    assert_eq!(items[0]["queue"], "decisions");

    // A stopped session keeps its records: the same item is in the same inbox
    // after a restart, on the same retained ports. Complete it only after that
    // restart so both the pending and terminal forms cross a process boundary.
    assert_eq!(session.stop(&[])["status"], "stopped");
    let second = session.start();
    let completed = session.native.python(&json!({
        "baseUrl": second["caseworkUrl"],
        "token": session.token(&second, "staff"),
        "profile": "staff",
        "requestId": request
    }));
    assert_eq!(completed["requestId"], request, "{completed:#}");
    assert_eq!(completed["claimedRevision"], 2, "{completed:#}");
    assert!(inbox(&session, &second).is_empty());
    let result_outcome = session.native.node(&json!({
        "operation": "result",
        "baseUrl": second["caseworkUrl"],
        "token": session.token(&second, "requester"),
        "profile": "requester",
        "accepted": accepted
    }));
    assert_eq!(result_outcome["kind"], "available", "{result_outcome:#}");
    let result = result_outcome["value"].clone();
    assert_eq!(result["status"], "answered", "{result:#}");
    assert_eq!(result["outcome"], "confirmed", "{result:#}");

    // Terminal results are retained by the same session too. A newly started
    // runtime serves the producer's exact result and does not resurrect work.
    assert_eq!(session.stop(&[])["status"], "stopped");
    let terminal_restart = session.start();
    assert!(inbox(&session, &terminal_restart).is_empty());
    let retained_result = session.native.node(&json!({
        "operation": "result",
        "baseUrl": terminal_restart["caseworkUrl"],
        "token": session.token(&terminal_restart, "requester"),
        "profile": "requester",
        "accepted": accepted
    }));
    assert_eq!(retained_result["kind"], "available", "{retained_result:#}");
    assert_eq!(retained_result["value"], result);

    // Removal discards them: the same project starts empty and serves again.
    assert_eq!(session.stop(&["--remove"])["status"], "stopped");
    let third = session.start();
    assert_eq!(third["directory"]["teams"], 1, "{third:#}");
    assert!(inbox(&session, &third).is_empty());
    let replacement = create_review_request(&session, &third, "synthetic-batch-0043");
    assert_ne!(replacement["requestId"], request);
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
