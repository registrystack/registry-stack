// SPDX-License-Identifier: Apache-2.0

use registry_platform_crypto::PrivateJwk;
use serde_json::json;
use std::{
    fs::OpenOptions,
    io::{Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

pub fn free_address() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve serve-smoke port")
        .local_addr()
        .expect("reserved serve-smoke address")
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create private serve fixture");
    file.write_all(bytes).expect("write private serve fixture");
}

pub fn write_runtime(
    root: &Path,
    address: std::net::SocketAddr,
    issuer: &str,
    jwks_uri: &str,
    token_endpoint: &str,
    registry_base_url: &str,
    gateway_key: &PrivateJwk,
) -> PathBuf {
    let secrets = root.join("secrets");
    std::fs::create_dir(&secrets).expect("create serve secret directory");
    private_file(&secrets.join("audit-key"), &[7; 32]);
    private_file(
        &secrets.join("exchange-key.json"),
        serde_json::to_vec(&json!({
            "kty": gateway_key.kty,
            "kid": gateway_key.kid,
            "alg": gateway_key.alg,
            "crv": gateway_key.crv,
            "x": gateway_key.x,
            "y": gateway_key.y,
            "d": gateway_key.d,
        }))
        .expect("private JWK JSON")
        .as_slice(),
    );

    let port = address.port();
    let runtime = root.join("runtime.json");
    private_file(
        &runtime,
        serde_json::to_vec_pretty(&json!({
            "apiVersion": "id.registrystack.org/formats/platform/mcp-runtime/v1alpha1",
            "kind": "PlatformMcpRuntimeConfig",
            "name": "Serve smoke",
            "logLevel": "info",
            "listener": {
                "bind": address.to_string(),
                "tlsTermination": "development-loopback",
                "networkExposure": "private-address"
            },
            "secretProviders": {"file": {"root": secrets}},
            "resourceServer": {
                "resource": format!("http://localhost:{port}/mcp"),
                "issuer": issuer,
                "jwksSource": {"type": "uri", "uri": jwks_uri},
                "allowInsecureHttp": true,
                "algorithms": ["ES256"],
                "allowedClients": ["chat-host"],
                "requiredScopes": ["citizen:self"],
                "scopeClaim": "scope"
            },
            "audit": {
                "hashKeyRef": "secret:file/audit-key",
                "destination": "file",
                "path": root.join("audit.jsonl")
            },
            "rateLimits": {
                "perPrincipal": {"requestsPerMinute": 30, "burst": 10},
                "perClient": {"requestsPerMinute": 600, "burst": 100}
            },
            "bindings": [{
                "name": "citizen-registry",
                "tools": ["get_my_details"],
                "provider": {
                    "type": "breg",
                    "registry": {
                        "baseUrl": registry_base_url,
                        "accessProfile": "citizen-agent",
                        "audience": "urn:example:breg",
                        "scopes": ["citizen:self"]
                    },
                    "exchange": {
                        "tokenEndpoint": token_endpoint,
                        "clientId": "citizen-gateway",
                        "privateKeyRef": "secret:file/exchange-key.json",
                        "assertionAudience": token_endpoint
                    },
                    "service": {
                        "name": "Citizen details",
                        "description": "Read the citizen's own registry details.",
                        "disclosure": "Only authorized values are returned.",
                        "details": {"recordType": "person"},
                        "application": {"action": "update-details", "targetInput": "person"},
                        "reviewBaseUrl": "http://127.0.0.1:8113/"
                    }
                }
            }]
        }))
        .expect("runtime JSON")
        .as_slice(),
    );
    runtime
}

pub struct ServiceProcess {
    child: Option<Child>,
}

impl ServiceProcess {
    pub fn start(binary: &Path, runtime: &Path) -> Self {
        let mut command = Command::new(binary);
        command.env_clear();
        for name in [
            "DYLD_LIBRARY_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "LD_LIBRARY_PATH",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let child = command
            .args([
                "--runtime-config",
                runtime.to_str().expect("runtime path"),
                "serve",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("registry-mcp serve starts");
        Self { child: Some(child) }
    }

    pub async fn wait_until_ready(&mut self, url: &str) {
        let http = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("readiness client");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .expect("service process")
                .try_wait()
                .expect("poll service process")
            {
                panic!("registry-mcp serve exited before readiness: {status}");
            }
            if http
                .get(url)
                .timeout(Duration::from_secs(1))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                return;
            }
            assert!(Instant::now() < deadline, "serve readiness timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub fn signal_terminate(&mut self) {
        send_sigterm(self.child.as_ref().expect("service process"));
    }

    pub fn assert_running_for(&mut self, duration: Duration) {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            assert!(
                self.child
                    .as_mut()
                    .expect("service process")
                    .try_wait()
                    .expect("poll graceful drain")
                    .is_none(),
                "registry-mcp exited before its in-flight request drained"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    pub fn finish(mut self) -> Output {
        let mut child = self.child.take().expect("service process");
        finish(&mut child)
    }
}

fn send_sigterm(child: &Child) {
    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(signal.success(), "SIGTERM command failed: {signal}");
}

fn finish(child: &mut Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll graceful shutdown") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "registry-mcp did not stop within the graceful bound"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("captured stdout")
        .read_to_end(&mut stdout)
        .expect("read captured stdout");
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("captured stderr")
        .read_to_end(&mut stderr)
        .expect("read captured stderr");
    Output {
        status,
        stdout,
        stderr,
    }
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if child.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
