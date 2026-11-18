// SPDX-License-Identifier: Apache-2.0
//! Messaging under `rstack dev`: the package, the `messaging` database and the
//! runtime configuration the run serves. Messaging verifies tokens against the
//! run's static key set, so a plan that starts it names an HTTPS issuer. This
//! module is part of `products`, which owns the run's directory, tool spawning
//! and logs.

use super::*;

impl ProductRunner<'_> {
    /// Packages the project, provisions the `messaging` database and returns
    /// the runtime configuration `messaging serve` reads, after `apply` has
    /// migrated the database and activated the package.
    pub(super) fn activate_messaging(
        &self,
        database: &mut Database,
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
        let config = self.config(Product::Messaging, "messaging", bind, &package, urls)?;
        let arguments = ["--runtime-config".as_ref(), config.as_os_str()];
        self.tool(Product::Messaging, "apply", &arguments)?;
        Ok(config)
    }
}

/// The Messaging runtime configuration the run writes, before its bindings.
/// It activates no provider: a message that needs one fails with
/// `provider-unconfigured`.
pub(super) fn messaging_config(
    plan: &Plan,
    name: &str,
    root: &Path,
    package: &Path,
    identity: &str,
    bind: &str,
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
    config["listener"] = json!({"bind": bind, "tlsTermination": "development-loopback"});
    config["identity"] = json!({"databaseId": identity});
    config["authentication"] = json!({"oidc": oidc});
    config["audit"]["destination"] = json!("file");
    config["retention"] = json!({
        "payloadRetentionDays": 7,
        "recordRetentionDays": 90,
        "receiptRetentionDays": 7,
    });
    config
}

/// Refuses a Messaging project that declares a provider needing a sink the run
/// does not provide. An SMTP provider needs a mail sink and an HTTP provider
/// needs a gateway, and the run starts neither.
pub(super) fn refuse_providers_without_a_sink(root: &Path, plan: &Plan) -> Result<()> {
    let Some(project) = product_root(root, plan, Product::Messaging)? else {
        return Ok(());
    };
    let manifest = project.root.join("messaging.yaml");
    let text = fs::read_to_string(&manifest).map_err(|_| {
        plan::SemanticRefusal::new(
            &project.field,
            "The Messaging manifest cannot be read.",
            "Restore messaging.yaml inside the selected product project.",
        )
    })?;
    let document = registry_platform_yaml::Reader::new(manifest.display().to_string())
        .scan(text.as_bytes())
        .map_err(|_| {
            plan::SemanticRefusal::new(
                &project.field,
                "The Messaging manifest is not valid YAML.",
                "Fix messaging.yaml, then run the check again.",
            )
        })?
        .map(|document| document.to_json_value())
        .unwrap_or(Value::Null);
    for provider in document["providers"].as_array().into_iter().flatten() {
        let kind = provider["type"].as_str().unwrap_or_default();
        let sink = match kind {
            "smtp" => "a mail sink",
            "http" => "a mock gateway",
            _ => continue,
        };
        return Err(plan::SemanticRefusal::new(
            &project.field,
            format!(
                "The Messaging provider `{}` has type {kind}, and `rstack dev` provides no sink for it: the run has no support for {sink}.",
                provider["id"].as_str().unwrap_or("?")
            ),
            "Use a project whose providers need no sink, such as one with no providers, until `rstack dev` supports provider sinks.",
        )
        .into());
    }
    Ok(())
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
    fn a_provider_that_needs_a_sink_is_refused_naming_the_missing_sink() {
        let smtp = project("\n  - {id: mail-relay, type: smtp}");
        let refusal = refuse_providers_without_a_sink(smtp.path(), &plan())
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("mail-relay") && refusal.contains("mail sink"),
            "{refusal}"
        );

        let http = project("\n  - {id: sms-gateway, type: http}");
        let refusal = refuse_providers_without_a_sink(http.path(), &plan())
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("sms-gateway") && refusal.contains("mock gateway"),
            "{refusal}"
        );
    }

    #[test]
    fn a_project_without_providers_is_accepted() {
        let root = project("[]");
        refuse_providers_without_a_sink(root.path(), &plan()).unwrap();
    }

    #[test]
    fn the_runtime_configuration_activates_no_provider_and_names_the_run_issuer_keys() {
        let config = messaging_config(
            &plan(),
            "messaging",
            Path::new("/run/root"),
            Path::new("/run/root/messaging-package"),
            "dev-run-messaging",
            "127.0.0.1:9",
        );
        assert_eq!(config["kind"], "MessagingRuntimeConfig");
        assert_eq!(config["listener"]["bind"], "127.0.0.1:9");
        assert_eq!(config["audit"]["destination"], "file");
        assert_eq!(
            config["authentication"]["oidc"]["allowedClients"],
            json!(["operations-console"])
        );
        assert_eq!(
            config["authentication"]["oidc"]["jwksSource"]["type"],
            "static"
        );
        assert!(config.get("providers").is_none());
    }
}
