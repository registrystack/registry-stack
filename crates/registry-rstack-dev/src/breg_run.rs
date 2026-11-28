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
