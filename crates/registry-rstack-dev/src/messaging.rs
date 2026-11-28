// SPDX-License-Identifier: Apache-2.0
//! Messaging under `rstack dev`: the package, the `messaging` database, the
//! sinks the project's providers send to, and the runtime configuration the
//! run serves. Messaging verifies tokens against the run's static key set, so
//! a plan that starts it names an HTTPS issuer. This module is part of
//! `products`, which owns the run's directory, tool spawning and logs.
//!
//! An `smtp` provider sends to a Mailpit container and an `http` provider to
//! an in-process mock gateway, both on loopback and both stopped with the run.

use super::{
    super::sinks::{GatewayServer, GatewaySettings, SIGNATURE_HEADER},
    *,
};

/// The kind of connection a declared provider needs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ProviderKind {
    Smtp,
    Http,
}

/// A provider the project's `messaging.yaml` declares, and what the run needs
/// to know of its package to connect it.
pub(super) struct Provider {
    pub(super) id: String,
    pub(super) kind: ProviderKind,
    /// The provider's package declares `receipts: callback`.
    callbacks: bool,
    maximum_concurrent_requests: u64,
}

fn read_yaml(path: &Path, field: &str, what: &str) -> Result<Value> {
    let name = path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    let text = fs::read_to_string(path).map_err(|_| {
        plan::SemanticRefusal::new(
            field,
            format!("The Messaging {what} cannot be read."),
            format!("Restore {name} inside the selected product project."),
        )
    })?;
    let document = registry_platform_yaml::Reader::new(path.display().to_string())
        .scan(text.as_bytes())
        .map_err(|_| {
            plan::SemanticRefusal::new(
                field,
                format!("The Messaging {what} is not valid YAML."),
                format!("Fix {name}, then run the check again."),
            )
        })?;
    Ok(document.map_or(Value::Null, |document| document.to_json_value()))
}

/// The `smtp` and `http` providers the Messaging project declares. Other
/// provider types need no sink and are left out.
pub(super) fn providers(root: &Path, plan: &Plan) -> Result<Vec<Provider>> {
    let Some(project) = product_root(root, plan, Product::Messaging)? else {
        return Ok(Vec::new());
    };
    let manifest = read_yaml(
        &project.root.join("messaging.yaml"),
        &project.field,
        "manifest",
    )?;
    let declared = match &manifest["providers"] {
        Value::Null => None,
        Value::Object(declared) => Some(declared),
        _ => {
            return Err(plan::SemanticRefusal::new(
                &project.field,
                "The Messaging providers are not a mapping from each provider id to its entry.",
                "Key each provider by its id in messaging.yaml, then run the check again.",
            )
            .into());
        }
    };
    let mut providers = Vec::new();
    for (id, entry) in declared.into_iter().flatten() {
        let kind = match entry["type"].as_str() {
            Some("smtp") => ProviderKind::Smtp,
            Some("http") => ProviderKind::Http,
            _ => continue,
        };
        let id = id.to_owned();
        let (callbacks, maximum_concurrent_requests) = if kind == ProviderKind::Http {
            let package = read_yaml(
                &project
                    .root
                    .join("providers")
                    .join(&id)
                    .join("provider.yaml"),
                &project.field,
                &format!("provider package of `{id}`"),
            )?;
            (
                package["capabilities"]["receipts"] == "callback",
                package["capabilities"]["maximumConcurrentRequests"]
                    .as_u64()
                    .unwrap_or(1),
            )
        } else {
            (false, 1)
        };
        providers.push(Provider {
            id,
            kind,
            callbacks,
            maximum_concurrent_requests,
        });
    }
    Ok(providers)
}

/// Whether the project declares an `smtp` provider, so the run starts Mailpit.
pub(super) fn needs_mailpit(root: &Path, plan: &Plan) -> Result<bool> {
    Ok(providers(root, plan)?
        .iter()
        .any(|provider| provider.kind == ProviderKind::Smtp))
}

impl ProductRunner<'_> {
    /// Packages the project, provisions the `messaging` database, starts the
    /// sinks its providers send to and returns the runtime configuration
    /// `messaging serve` reads, after `apply` has migrated the database and
    /// activated the package. `docker` is connected when Mailpit needs it.
    pub(super) fn activate_messaging(
        &mut self,
        database: &mut Database,
        docker: &mut Option<Docker>,
        project: &Path,
        bind: &str,
    ) -> Result<PathBuf> {
        let package = self.root.join("messaging-package");
        self.tool(
            Product::Messaging,
            "package",
            &[
                project.as_os_str(),
                "--output".as_ref(),
                package.as_os_str(),
            ],
        )?;
        let urls = database
            .provision("messaging", false, false)
            .map_err(operational)?;
        let declared = providers(&self.input.project, &self.input.plan)?;
        let connections = self.start_sinks(&declared, docker, bind)?;
        self.messaging_providers = (!declared.is_empty()).then_some(connections);
        let config = self.config(Product::Messaging, "messaging", bind, &package, urls)?;
        let arguments = ["--runtime-config".as_ref(), config.as_os_str()];
        self.tool(Product::Messaging, "apply", &arguments)?;
        Ok(config)
    }

    /// Starts the sink of every declared provider and returns the runtime
    /// configuration's `providers` member that connects each provider to it.
    /// A sink that starts is recorded in the run report even when a later one
    /// fails.
    fn start_sinks(
        &mut self,
        declared: &[Provider],
        docker: &mut Option<Docker>,
        bind: &str,
    ) -> Result<Value> {
        let mut connections = serde_json::Map::new();
        if declared
            .iter()
            .any(|provider| provider.kind == ProviderKind::Smtp)
        {
            write_private(&self.root.join(MAILPIT_MARKER), b"")?;
            if docker.is_none() {
                *docker = Some(Docker::connect()?);
            }
            let mailpit = docker
                .as_ref()
                .context("Docker is not connected")?
                .start_mailpit(&self.input.run_id)?;
            for provider in declared
                .iter()
                .filter(|provider| provider.kind == ProviderKind::Smtp)
            {
                connections.insert(provider.id.clone(), smtp_connection(mailpit.smtp_port));
                self.sinks.insert(
                    provider.id.clone(),
                    json!({
                        "type": "smtp",
                        "smtp": format!("127.0.0.1:{}", mailpit.smtp_port),
                        "url": format!("http://127.0.0.1:{}", mailpit.ui_port),
                    }),
                );
            }
        }
        let http: Vec<_> = declared
            .iter()
            .filter(|provider| provider.kind == ProviderKind::Http)
            .collect();
        if !http.is_empty() {
            let token_file = "messaging-gateway-token";
            let key_file = "messaging-gateway-callback-key";
            let token_ref =
                self.retained_secret("messaging", token_file, random_secret()?.as_bytes())?;
            let key_ref =
                self.retained_secret("messaging", key_file, random_secret()?.as_bytes())?;
            let gateway = GatewayServer::start(GatewaySettings {
                providers: http.iter().map(|provider| provider.id.clone()).collect(),
                token: zeroize::Zeroizing::new(fs::read_to_string(self.root.join(token_file))?),
                callback_key: zeroize::Zeroizing::new(fs::read(self.root.join(key_file))?),
                runtime_origin: format!("http://{bind}"),
            })
            .map_err(operational)?;
            for provider in http {
                let mut connection = json!({
                    "type": "http",
                    "baseUrl": format!("{}/{}/v1/", gateway.origin, provider.id),
                    "attemptTimeoutMilliseconds": 10000,
                    "maximumResponseBytes": 16384,
                    "maximumConcurrentRequests": provider.maximum_concurrent_requests,
                    "redirects": "deny",
                    "authentication": {"type": "static-authorization", "tokenRef": token_ref},
                });
                if provider.callbacks {
                    connection["callbackVerifier"] = json!({
                        "type": "hmac-sha256-body",
                        "header": SIGNATURE_HEADER,
                        "encoding": "hex",
                        "secretRef": key_ref,
                    });
                }
                connections.insert(provider.id.clone(), connection);
                self.sinks.insert(
                    provider.id.clone(),
                    json!({"type": "http", "url": gateway.sent_url()}),
                );
            }
            self.gateway = Some(gateway);
        }
        Ok(Value::Object(connections))
    }
}

fn smtp_connection(port: u16) -> Value {
    json!({
        "type": "smtp",
        "host": "127.0.0.1",
        "port": port,
        "tls": "loopback-plaintext",
    })
}

/// The Messaging runtime configuration the run writes, before its bindings.
/// `providers` connects each declared provider to its sink; a provider it
/// omits is not activated, and a message that needs one fails with
/// `provider-unconfigured`.
pub(super) fn messaging_config(
    plan: &Plan,
    name: &str,
    root: &Path,
    package: &Path,
    identity: &str,
    bind: &str,
    providers: Option<&Value>,
) -> Value {
    let (mut config, oidc) = shared_config(
        plan,
        Product::Messaging,
        name,
        root,
        package,
        &BTreeSet::new(),
    );
    config["apiVersion"] = json!("id.registrystack.org/formats/messaging/runtime/v1alpha1");
    config["kind"] = json!("MessagingRuntimeConfig");
    config["listener"] = json!({"bind": bind, "tlsTermination": "loopback-plaintext"});
    config["identity"] = json!({"databaseId": identity});
    config["authentication"] = json!({"oidc": super::issuer_set(oidc)});
    config["audit"]["destination"] = json!("file");
    config["retention"] = json!({
        "payloadRetentionDays": 7,
        "recordRetentionDays": 90,
        "receiptRetentionDays": 7,
    });
    if let Some(providers) = providers {
        config["providers"] = providers.clone();
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "products": [{
                "product": "messaging", "project": ".", "audience": "urn:example:messaging"
            }],
            "people": {"operator": {
                "subject": "operator", "client": "operations-console",
                "grants": {"messaging": {"profile": "operations", "scopes": ["messaging:operate"]}}
            }},
            "scenarioFile": "tests/scenarios.yaml"
        }))
        .unwrap()
    }

    fn project(providers: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("messaging.yaml"),
            format!("providers: {providers}\n"),
        )
        .unwrap();
        root
    }

    #[test]
    fn smtp_and_http_providers_are_read_with_their_package_capabilities() {
        let root = project(
            "\n  mail-relay: {type: smtp}\n  sms-gateway: {type: http}\n  other: {type: aws-sms}",
        );
        let directory = root.path().join("providers/sms-gateway");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("provider.yaml"),
            "capabilities: {receipts: callback, maximumConcurrentRequests: 8}\n",
        )
        .unwrap();

        let providers = providers(root.path(), &plan()).unwrap();

        assert_eq!(providers.len(), 2);
        assert!(providers[0].id == "mail-relay" && providers[0].kind == ProviderKind::Smtp);
        assert!(providers[1].id == "sms-gateway" && providers[1].kind == ProviderKind::Http);
        assert!(providers[1].callbacks);
        assert_eq!(providers[1].maximum_concurrent_requests, 8);
        assert!(needs_mailpit(root.path(), &plan()).unwrap());
    }

    #[test]
    fn a_project_without_providers_needs_no_sink() {
        let root = project("{}");
        assert!(providers(root.path(), &plan()).unwrap().is_empty());
        assert!(!needs_mailpit(root.path(), &plan()).unwrap());
    }

    #[test]
    fn a_list_of_providers_is_refused_naming_the_mapping() {
        let root = project("\n  - {id: mail-relay, type: smtp}");
        let refusal = providers(root.path(), &plan()).err().unwrap().to_string();
        assert!(refusal.contains("mapping"), "{refusal}");
    }

    #[test]
    fn an_http_provider_without_a_package_is_refused_naming_it() {
        let root = project("\n  sms-gateway: {type: http}");
        let refusal = providers(root.path(), &plan()).err().unwrap().to_string();
        assert!(refusal.contains("sms-gateway"), "{refusal}");
    }

    #[test]
    fn the_runtime_configuration_names_the_run_issuer_keys_and_the_given_providers() {
        let providers = json!({"mail-relay": smtp_connection(2525)});
        let config = messaging_config(
            &plan(),
            "messaging",
            Path::new("/run/root"),
            Path::new("/run/root/messaging-package"),
            "dev-run-messaging",
            "127.0.0.1:9",
            Some(&providers),
        );
        assert_eq!(config["kind"], "MessagingRuntimeConfig");
        assert_eq!(config["listener"]["bind"], "127.0.0.1:9");
        assert_eq!(config["audit"]["destination"], "file");
        let entry = &config["authentication"]["oidc"]["issuers"]["main"];
        assert_eq!(entry["allowedClients"], json!(["operations-console"]));
        assert_eq!(entry["jwksSource"]["type"], "test-issuer");
        assert!(config["authentication"]["oidc"].get("issuer").is_none());
        assert_eq!(config["audit"]["hashKeyCustody"], "development-generated");
        assert_eq!(config["listener"]["tlsTermination"], "loopback-plaintext");
        assert_eq!(config["providers"], providers);
        assert_eq!(
            config["providers"]["mail-relay"]["tls"],
            "loopback-plaintext"
        );
        let bare = messaging_config(
            &plan(),
            "messaging",
            Path::new("/run/root"),
            Path::new("/run/root/messaging-package"),
            "dev-run-messaging",
            "127.0.0.1:9",
            None,
        );
        assert!(bare.get("providers").is_none());
    }
}
