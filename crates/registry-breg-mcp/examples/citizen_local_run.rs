// SPDX-License-Identifier: Apache-2.0

//! A scripted local run of the citizen journey against the `breg-mcp` and
//! `breg-review` binaries.
//!
//! `products/breg/acceptance/citizen-address-correction/run-local.sh` builds
//! both binaries and runs this example. It serves the acceptance project from
//! a real Base Registry Engine on the PostgreSQL that `BREG_TEST_DATABASE_URL`
//! names, in a fresh database it drops at the end, behind the test
//! authorization server. The review authority the engine submits to is a
//! loopback stub standing in for Casework. The example writes each binary's
//! runtime configuration and owner-only secrets under the work directory,
//! starts both binaries with their logs beside them, waits until each is
//! ready, and drives the journey the PostgreSQL suite drives in process: MCP
//! tool calls, review-page submission, the stub's approval, and the applier's
//! apply, until `get_application_status` reports `applied`.
//!
//! Usage: `citizen_local_run <breg-mcp> <breg-review> <work-directory>`

#[path = "../tests/support/gateway.rs"]
mod gateway;
#[path = "../tests/support/mock_registry.rs"]
mod mock_registry;
#[path = "../../registry-breg/tests/support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "../tests/support/real_registry.rs"]
mod real_registry;

use std::fs;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use real_registry::{citizen_journey, write_gateway_config, RealRegistry, ReviewPage};

/// How long a binary may take to answer its readiness route.
const READY_WITHIN: Duration = Duration::from_secs(30);

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let arguments: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [breg_mcp, breg_review, work] = arguments.as_slice() else {
        eprintln!("usage: citizen_local_run <breg-mcp> <breg-review> <work-directory>");
        return ExitCode::from(2);
    };

    let gateway_address = free_loopback_address().await;
    let page_address = free_loopback_address().await;
    let resource = format!("http://{gateway_address}/mcp");
    let page_origin = format!("http://{page_address}");

    let fixture = RealRegistry::start(&resource, Some(&page_origin)).await;
    println!(
        "registry: the acceptance project is served on PostgreSQL at {}",
        fixture.base_url
    );
    println!(
        "authorization server: the test server issues at {}",
        fixture.server.issuer()
    );

    let gateway_directory = private_directory(&work.join("gateway"));
    let gateway_config = write_gateway_config(
        &gateway_directory,
        &gateway_address,
        &fixture,
        &format!("{page_origin}/"),
    );
    let page_directory = private_directory(&work.join("review-page"));
    let page_config = ReviewPage::write_config(
        &page_directory,
        page_address.parse().expect("review page address"),
        &page_origin,
        &fixture,
    );

    let gateway_process = Running::spawn(
        "breg-mcp",
        Command::new(breg_mcp)
            .arg("--runtime-config")
            .arg(&gateway_config)
            .arg("serve"),
        &work.join("breg-mcp.log"),
    );
    let page_process = Running::spawn(
        "breg-review",
        Command::new(breg_review)
            .arg("--runtime-config")
            .arg(&page_config),
        &work.join("breg-review.log"),
    );
    let mut processes = [gateway_process, page_process];
    wait_ready(
        &mut processes[0],
        &format!("http://{gateway_address}/ready"),
    )
    .await;
    wait_ready(&mut processes[1], &format!("{page_origin}/ready")).await;

    let page = ReviewPage::served_at(&page_origin);
    citizen_journey(&fixture, &resource, &page).await;

    drop(processes);
    page.finish().await;
    fixture.finish().await;
    println!("local run: the citizen journey reached applied");
    ExitCode::SUCCESS
}

/// A loopback address no listener holds at the moment of asking.
async fn free_loopback_address() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port is free");
    listener.local_addr().expect("loopback address").to_string()
}

/// Create `path` readable by its owner only and return its canonical form.
fn private_directory(path: &Path) -> PathBuf {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .unwrap_or_else(|error| panic!("{} creates: {error}", path.display()));
    path.canonicalize()
        .unwrap_or_else(|error| panic!("{} canonicalizes: {error}", path.display()))
}

/// A child binary, stopped when the run ends, however it ends.
struct Running {
    name: &'static str,
    log: PathBuf,
    child: Child,
}

impl Running {
    fn spawn(name: &'static str, command: &mut Command, log: &Path) -> Self {
        let output = fs::File::create(log)
            .unwrap_or_else(|error| panic!("{} creates: {error}", log.display()));
        let errors = output
            .try_clone()
            .unwrap_or_else(|error| panic!("{} reopens: {error}", log.display()));
        let child = command
            .stdin(Stdio::null())
            .stdout(output)
            .stderr(errors)
            .spawn()
            .unwrap_or_else(|error| panic!("{name} starts: {error}"));
        println!("{name}: started, logging to {}", log.display());
        Self {
            name,
            log: log.to_owned(),
            child,
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            eprintln!("{}: could not be stopped: {error}", self.name);
        }
        if let Err(error) = self.child.wait() {
            eprintln!("{}: could not be reaped: {error}", self.name);
        }
    }
}

/// Poll `url` until it answers 200, failing if the binary exits first or
/// does not become ready in time.
async fn wait_ready(process: &mut Running, url: &str) {
    let http = reqwest::Client::new();
    let deadline = Instant::now() + READY_WITHIN;
    loop {
        if let Some(status) = process.child.try_wait().expect("child status reads") {
            panic!(
                "{} exited with {status} before it was ready; see {}",
                process.name,
                process.log.display()
            );
        }
        let last = match http.get(url).send().await {
            Ok(response) if response.status() == reqwest::StatusCode::OK => {
                println!("{}: ready at {url}", process.name);
                return;
            }
            Ok(response) => format!("answered {}", response.status()),
            Err(error) => format!("unreachable: {error}"),
        };
        assert!(
            Instant::now() < deadline,
            "{} was not ready within {READY_WITHIN:?} ({last}); see {}",
            process.name,
            process.log.display()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
