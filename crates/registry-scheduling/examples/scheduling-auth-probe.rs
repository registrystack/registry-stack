// SPDX-License-Identifier: Apache-2.0

//! Test-only process boundary for proving that a bearer minted by the stock
//! institutional exchange is accepted by Scheduling's real authenticator.
//!
//! The complete input arrives on stdin so the credential never enters argv or
//! a process listing. Output is exactly `allowed` or `refused`; no input or
//! verifier detail is logged.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

use registry_platform_config::write_package;
use registry_scheduling::auth::SchedulingAuthenticator;
use registry_scheduling::config::{package_limits, RuntimeConfig, PACKAGE_COMMAND};
use serde::Deserialize;
use serde_json::json;

const MAXIMUM_INPUT_BYTES: u64 = 1024 * 1024;
const MAXIMUM_VALUE_BYTES: usize = 512;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeInput {
    token: String,
    issuer: String,
    audience: String,
    client: String,
    assertion_issuer: String,
    jwks: serde_json::Value,
    service: String,
    location: String,
    action: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let allowed = match read_input() {
        Ok(input) if validate_input(&input) => authenticate(input).await.unwrap_or(false),
        _ => false,
    };
    if allowed {
        println!("allowed");
        std::process::ExitCode::SUCCESS
    } else {
        println!("refused");
        std::process::ExitCode::FAILURE
    }
}

fn read_input() -> Result<ProbeInput, ()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAXIMUM_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAXIMUM_INPUT_BYTES {
        return Err(());
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn validate_input(input: &ProbeInput) -> bool {
    !input.token.is_empty()
        && input.token.len() <= 64 * 1024
        && [
            &input.issuer,
            &input.audience,
            &input.client,
            &input.assertion_issuer,
            &input.service,
            &input.location,
            &input.action,
        ]
        .into_iter()
        .all(|value| {
            !value.is_empty()
                && value.len() <= MAXIMUM_VALUE_BYTES
                && !value.chars().any(char::is_control)
        })
}

async fn authenticate(input: ProbeInput) -> Result<bool, ()> {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().map_err(|_| ())?)
        .map_err(|_| ())?;
    let package = root.path().join("package");
    write_package(
        &package,
        &BTreeMap::from([(
            registry_scheduling_core::AUTHORED_POLICY_FILE.to_owned(),
            include_bytes!(
                "../../../products/scheduling/examples/standalone-exact-time/scheduling.yaml"
            )
            .to_vec(),
        )]),
        None,
        &package_limits(),
        PACKAGE_COMMAND,
    )
    .map_err(|_| ())?;
    let secrets = root.path().join("secrets");
    fs::create_dir(&secrets).map_err(|_| ())?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
    let jwks_path = secrets.join("issuer-jwks");
    fs::write(&jwks_path, serde_json::to_vec(&input.jwks).map_err(|_| ())?).map_err(|_| ())?;
    fs::set_permissions(&jwks_path, fs::Permissions::from_mode(0o600)).map_err(|_| ())?;
    let assertion_issuers =
        BTreeMap::from([(input.client.clone(), vec![input.assertion_issuer.clone()])]);
    let runtime_path = root.path().join("runtime.json");
    fs::write(
        &runtime_path,
        serde_json::to_vec(&json!({
            "apiVersion": registry_scheduling_core::SCHEDULING_RUNTIME_API_VERSION,
            "kind": registry_scheduling_core::SCHEDULING_RUNTIME_KIND,
            "identity": {"databaseId": "native-task-grant"},
            "package": {"root": package},
            "listener": {"bind": "127.0.0.1:0", "tlsTermination": "development-loopback", "networkExposure": "private-address"},
            "secretProviders": {"file": {"root": secrets}, "environment": {}},
            "database": {"runtimeUrlRef": "secret:env/SCHEDULING_RUNTIME_URL", "migrationUrlRef": "secret:env/SCHEDULING_MIGRATION_URL"},
            "authentication": {"oidc": {
                "issuer": input.issuer.clone(),
                "audience": input.audience.clone(),
                "jwksSource": {"type": "static", "documentRef": "secret:file/issuer-jwks"},
                "allowedClients": [input.client.clone()],
                "assertionIssuers": assertion_issuers,
                "scopeClaim": "scope"
            }},
            "taskGrantStatus": "unchecked-final-fifteen-minutes",
            "audit": {"path": root.path().join("audit.jsonl"), "hashKeyRef": "secret:file/audit-key"},
            "destinations": {},
            "retention": {"receiptRetentionDays": 7}
        }))
        .map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let runtime = RuntimeConfig::load(&runtime_path).map_err(|_| ())?;
    let secrets = registry_scheduling::runtime::secret_resolver(&runtime).map_err(|_| ())?;
    let (verifier, keys) = runtime.oidc_verifier(&secrets).await.map_err(|_| ())?;
    let authenticator = SchedulingAuthenticator::new(&runtime.authentication.oidc, verifier, keys);
    let caller = authenticator
        .authenticate_mutate(&input.token)
        .await
        .map_err(|_| ())?;
    let Some(grant) = caller.grant else {
        return Ok(false);
    };
    Ok(grant
        .bounds()
        .scheduling_permissions()
        .is_some_and(|permissions| {
            permissions.iter().any(|permission| {
                permission.service() == input.service
                    && permission.location() == input.location
                    && permission
                        .actions()
                        .iter()
                        .any(|action| action == &input.action)
            })
        }))
}
