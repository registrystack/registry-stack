// SPDX-License-Identifier: Apache-2.0
//! Local-run identity used by BReg's authored example and source tooling.

use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{
    ensure_private, read_json, run_dir, status, Issuer, Product, RunInput,
    MAXIMUM_CAPTURED_INPUT_BYTES, MAXIMUM_RUN_REPORT_BYTES,
};

/// A ready, owner-only run bound to one BReg project directory.
pub struct BregRun {
    root: PathBuf,
    input: RunInput,
    pub project: PathBuf,
    pub origin: String,
    pub package: PathBuf,
    pub instance: String,
    pub issuer: String,
    pub audience: String,
    pub state: PathBuf,
    pub dev_yaml: PathBuf,
    pub principal_claim: String,
    expires_at: u64,
}

impl BregRun {
    /// Open the exact ready run that serves this BReg project.
    pub fn open(run_id: &str, project: &Path) -> Result<Self> {
        let root = run_dir(run_id)?;
        ensure_private(&root, false)?;
        let report = status(run_id)?;
        Self::open_from_report(root, project, &report)
    }

    fn open_from_report(root: PathBuf, project: &Path, report: &Value) -> Result<Self> {
        ensure!(
            report["status"] == "ready",
            "The BReg development run is not ready."
        );
        let input: RunInput = read_json(&root.join("input.json"), MAXIMUM_CAPTURED_INPUT_BYTES)?;
        let entry = input
            .plan
            .products
            .iter()
            .find(|entry| entry.product == Product::Breg)
            .context("This development run does not contain BReg.")?;
        let project = project.canonicalize()?;
        ensure!(
            input.project.join(&entry.project).canonicalize()? == project,
            "This run serves a different BReg project."
        );
        let config: Value = read_json(&root.join("breg-runtime.yaml"), MAXIMUM_RUN_REPORT_BYTES)?;
        let state = input.project_state(&root).unwrap_or_else(|| root.clone());
        ensure_private(&state, false)?;
        let field = |value: &Value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("The run's BReg configuration is incomplete.")
        };
        Ok(Self {
            origin: field(&report["products"]["breg"])?,
            package: PathBuf::from(field(&config["package"]["root"])?),
            instance: field(&config["identity"]["databaseId"])?,
            issuer: input.plan.issuer.clone(),
            audience: entry.audience.clone(),
            expires_at: report["expires_at"]
                .as_u64()
                .context("The run is missing its expiry.")?,
            dev_yaml: input.project.join("dev.yaml"),
            principal_claim: field(&config["authentication"]["authorityClaims"]["principal"])?,
            project,
            root,
            state,
            input,
        })
    }

    /// Acquire a bounded bearer for an explicit client/profile declaration in this run.
    pub fn example_token(&self, client: &str, profile: &str) -> Result<Zeroizing<String>> {
        ensure!(self.input.plan.jwks_uri().is_none(),
            "This run uses an external issuer. Example token issuance requires the runner's issuer.");
        let has_profile = |person: &super::plan::TestPerson| {
            person
                .grants
                .get(&Product::Breg)
                .is_some_and(|grant| grant.profile == profile)
        };
        let person = if let Some(person) = self.input.plan.people.get(client) {
            ensure!(
                has_profile(person),
                "The named development person must declare the example's BReg profile."
            );
            person
        } else {
            let mut matches = self
                .input
                .plan
                .people
                .values()
                .filter(|person| person.client == client && has_profile(person));
            let person = matches.next().context(
                "The example client and profile must be declared in the development plan.",
            )?;
            ensure!(
                matches.next().is_none(),
                "The development plan needs one matching example client and profile."
            );
            person
        };
        let expires_at = super::issuer::token_expiry(self.expires_at, super::clock()?);
        Issuer::load(&self.root)?.token(&self.input, person, Product::Breg, expires_at)
    }

    /// Digest the captured identities without exposing claims or credentials.
    pub fn identities_digest(&self) -> Result<String> {
        Ok(registry_platform_config::sha256_uri(&serde_json::to_vec(
            &self.input.plan.people,
        )?))
    }

    /// Whether this run creates its own development tokens.
    pub fn synthetic_issuer(&self) -> bool {
        self.input.plan.jwks_uri().is_none()
    }

    /// Compare new authoring with the plan captured before starting the run.
    pub fn plan_matches(&self, authored: &Value) -> Result<bool> {
        let mut body = authored.clone();
        let object = body
            .as_object_mut()
            .context("The development plan must be a mapping.")?;
        object.remove("apiVersion");
        object.remove("kind");
        if object.get("issuer").is_some_and(|value| value == "run") {
            object.insert("issuer".to_owned(), Value::String(self.issuer.clone()));
        }
        let plan: super::plan::Plan = serde_json::from_value(body)?;
        Ok(serde_json::to_value(plan)? == serde_json::to_value(&self.input.plan)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(project: &Path, product: &str) -> Value {
        json!({
            "run_id": "0123456789abcdef0123456789abcdef",
            "project": project,
            "ttl_seconds": 120,
            "plan": {
                "issuer": "https://issuer.example.invalid",
                "products": [{"product": product, "project": ".", "audience": "fixture"}],
                "people": {},
                "scenarioFile": "tests/scenarios.yaml"
            },
            "schema_people": [],
            "casework_principals": {},
            "binaries": {}
        })
    }

    fn open(root: &Path, project: &Path, status: &str) -> Result<BregRun> {
        BregRun::open_from_report(
            root.to_owned(),
            project,
            &json!({
                "status": status, "expires_at": 9999999999_u64,
                "products": {"breg": "http://127.0.0.1:42000"}
            }),
        )
    }

    #[test]
    fn refuses_a_run_that_is_not_ready() {
        let root = tempfile::tempdir().unwrap();
        let error = open(root.path(), root.path(), "stopping").err().unwrap();
        assert!(error.to_string().contains("run is not ready"));
    }

    #[test]
    fn refuses_a_run_for_a_different_breg_project() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        crate::write_private(
            &root.path().join("input.json"),
            &serde_json::to_vec(&input(root.path(), "breg")).unwrap(),
        )
        .unwrap();
        let error = open(root.path(), other.path(), "ready").err().unwrap();
        assert!(error.to_string().contains("different BReg project"));
    }

    #[test]
    fn refuses_a_run_without_breg() {
        let root = tempfile::tempdir().unwrap();
        crate::write_private(
            &root.path().join("input.json"),
            &serde_json::to_vec(&input(root.path(), "evidence")).unwrap(),
        )
        .unwrap();
        let error = open(root.path(), root.path(), "ready").err().unwrap();
        assert!(error.to_string().contains("does not contain BReg"));
    }

    #[test]
    fn refuses_external_or_ambiguous_example_token_issuance() {
        let root = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::write_private(
            &root.path().join("breg-runtime.yaml"),
            &serde_json::to_vec(&json!({
                "package": {"root": root.path()},
                "identity": {"databaseId": "fixture"},
                "authentication": {"authorityClaims": {"principal": "sub"}}
            }))
            .unwrap(),
        )
        .unwrap();
        let mut captured = input(root.path(), "breg");
        captured["plan"]["issuer"] = json!("http://127.0.0.1:41000");
        captured["plan"]["externalJwksUri"] = json!("http://127.0.0.1:41000/keys");
        let path = root.path().join("input.json");
        crate::write_private(&path, &serde_json::to_vec(&captured).unwrap()).unwrap();
        let run = open(root.path(), root.path(), "ready").unwrap();
        let error = run.example_token("fixture-client", "author").unwrap_err();
        assert!(error.to_string().contains("external issuer"));

        captured["plan"]
            .as_object_mut()
            .unwrap()
            .remove("externalJwksUri");
        let person = json!({
            "subject": "synthetic", "client": "fixture-client",
            "grants": {"breg": {"profile": "author", "scopes": []}}
        });
        captured["plan"]["people"] = json!({"alice": person.clone(), "bob": person});
        crate::write_private(&path, &serde_json::to_vec(&captured).unwrap()).unwrap();
        let run = open(root.path(), root.path(), "ready").unwrap();
        let error = run.example_token("fixture-client", "author").unwrap_err();
        assert!(error
            .to_string()
            .contains("one matching example client and profile"));
    }

    #[test]
    fn the_token_command_refuses_an_external_issuer_before_loading_the_signer() {
        let root = tempfile::tempdir().unwrap();
        let mut captured = input(root.path(), "breg");
        captured["plan"]["issuer"] = json!("http://127.0.0.1:41000");
        captured["plan"]["externalJwksUri"] = json!("http://127.0.0.1:41000/keys");
        crate::write_private(
            &root.path().join("input.json"),
            &serde_json::to_vec(&captured).unwrap(),
        )
        .unwrap();
        let error = crate::token_from_report(
            root.path(),
            "0123456789abcdef0123456789abcdef",
            "person",
            &json!({"status": "ready"}),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Obtain tokens from that issuer"));
    }
}
