// SPDX-License-Identifier: Apache-2.0
//! Closed product actions mapped by the signed Registry Stack release lock.

use crate::*;

const PRODUCT_BUNDLE_DIR: &str = "/run/registry/bundle";
const PRODUCT_ANCHOR_PATH: &str = "/run/registry/anchor/anchor.json";
const PRODUCT_PREVIOUS_ANCHOR_PATH: &str = "/run/registry/anchor/previous-anchor.json";
const PRODUCT_ANCHOR_TRANSITION_PATH: &str = "/run/registry/anchor/transition.json";
const PRODUCT_STATE_PATH: &str = "/var/lib/registry/state/antirollback.json";
const PRODUCT_MIGRATION_URL_ENV: &str = "REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL";
const PRODUCT_OWNER_ROLE: &str = "registry_notary_owner";
const PRODUCT_RUNTIME_ROLE: &str = "registry_notary_runtime";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
pub(crate) enum ProductAction {
    /// Prepare only the Notary-owned database schema and least-privilege roles.
    #[command(name = "prepare_state_store")]
    PrepareStateStore,
    /// Verify and record sequence-1 acceptance in absent product state, then exit.
    #[command(name = "initialize_state")]
    InitializeState,
    /// Verify exact accepted product state without changing it, then exit.
    #[command(name = "verify_state")]
    VerifyState,
    /// Serve the verified product bundle; absent state is a hard failure.
    #[command(name = "serve")]
    Serve,
}

pub(crate) fn ensure_closed_product_action_arguments(
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.config.is_some()
        || args.bundle_dir.is_some()
        || args.anchor_path.is_some()
        || args.state_path.is_some()
        || args.env_file.is_some()
        || args.env_file_override
        || args.bind.is_some()
        || args.initialize_state
    {
        return Err("product-action accepts no runtime flags".into());
    }
    Ok(())
}

pub(crate) async fn run_product_action(
    action: ProductAction,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ProductAction::PrepareStateStore => prepare_product_state_store().await,
        ProductAction::InitializeState => initialize_product_state().await,
        ProductAction::VerifyState => verify_product_state(),
        ProductAction::Serve => {
            let previous_anchor =
                load_optional_previous_anchor(Path::new(PRODUCT_PREVIOUS_ANCHOR_PATH))?;
            let transition =
                load_optional_anchor_transition(Path::new(PRODUCT_ANCHOR_TRANSITION_PATH))?;
            run_governed_server(canonical_product_input(), previous_anchor, transition).await
        }
    }
}

fn canonical_product_input() -> ServerConfigInput {
    ServerConfigInput::SignedBundle {
        bundle_dir: PathBuf::from(PRODUCT_BUNDLE_DIR),
        anchor_path: PathBuf::from(PRODUCT_ANCHOR_PATH),
        state_path: PathBuf::from(PRODUCT_STATE_PATH),
    }
}

async fn prepare_product_state_store() -> Result<(), Box<dyn std::error::Error>> {
    prepare_product_state_store_at(
        Path::new(PRODUCT_BUNDLE_DIR),
        Path::new(PRODUCT_ANCHOR_PATH),
    )
    .await
}

async fn prepare_product_state_store_at(
    bundle_dir: &Path,
    anchor_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let verified = verify_notary_product_bundle(bundle_dir, anchor_path)?;
    let config = load_verified_notary_config_read_only(&verified)?;
    prepare_postgres_state_store(
        &config.state,
        StateInstallArgs {
            migration_url_env: PRODUCT_MIGRATION_URL_ENV.to_string(),
            owner_role: PRODUCT_OWNER_ROLE.to_string(),
            runtime_role: PRODUCT_RUNTIME_ROLE.to_string(),
        },
    )
    .await?;
    println!("registry-notary prepare_state_store complete");
    Ok(())
}

async fn initialize_product_state() -> Result<(), Box<dyn std::error::Error>> {
    initialize_state_once(canonical_product_input()).await?;
    println!("registry-notary initialize_state complete");
    Ok(())
}

fn verify_product_state() -> Result<(), Box<dyn std::error::Error>> {
    verify_notary_state_read_only(
        Path::new(PRODUCT_BUNDLE_DIR),
        Path::new(PRODUCT_ANCHOR_PATH),
        Path::new(PRODUCT_STATE_PATH),
    )?;
    println!("registry-notary verify_state complete");
    Ok(())
}

fn load_optional_previous_anchor(
    path: &Path,
) -> Result<Option<registry_platform_config::ConfigTrustAnchor>, Box<dyn std::error::Error>> {
    if !closed_artifact_exists(path)? {
        return Ok(None);
    }
    registry_platform_config::load_trust_anchor(path)
        .map(Some)
        .map_err(|error| {
            let code = log_bundle_verification_error(&error);
            Box::new(BundleVerificationFailure::from(code)) as Box<dyn std::error::Error>
        })
}

fn load_optional_anchor_transition(
    path: &Path,
) -> Result<Option<registry_platform_config::AnchorTransitionV1>, Box<dyn std::error::Error>> {
    if !closed_artifact_exists(path)? {
        return Ok(None);
    }
    registry_platform_config::load_anchor_transition(path)
        .map(Some)
        .map_err(|error| {
            let code = log_bundle_verification_error(&error);
            Box::new(BundleVerificationFailure::from(code)) as Box<dyn std::error::Error>
        })
}

fn closed_artifact_exists(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Box::new(BundleVerificationFailure::from(
            BundleVerificationCode::REJECTED_VALIDATION,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    #[test]
    fn closed_product_actions_parse_with_release_lock_names() {
        for (name, expected) in [
            ("prepare_state_store", ProductAction::PrepareStateStore),
            ("initialize_state", ProductAction::InitializeState),
            ("verify_state", ProductAction::VerifyState),
            ("serve", ProductAction::Serve),
        ] {
            let args = Args::try_parse_from(["registry-notary", "product-action", name])
                .expect("closed product action parses");
            assert!(matches!(
                args.command,
                Some(Command::ProductAction { action }) if action == expected
            ));
            ensure_closed_product_action_arguments(&args)
                .expect("closed action has no legacy runtime arguments");
        }
    }

    #[test]
    fn product_actions_reject_legacy_runtime_flags() {
        for legacy in [
            vec!["--config", "notary.yaml"],
            vec!["--bind", "127.0.0.1:8080"],
            vec!["--env-file", "notary.env"],
            vec!["--env-file-override"],
            vec!["--initialize-state"],
        ] {
            let mut argv = vec!["registry-notary"];
            argv.extend(legacy);
            argv.extend(["product-action", "serve"]);
            let args = Args::try_parse_from(argv).expect("legacy global argument parses");
            let error = ensure_closed_product_action_arguments(&args)
                .expect_err("product action rejects legacy runtime argument");
            assert_eq!(error.to_string(), "product-action accepts no runtime flags");
        }
    }

    #[test]
    fn product_actions_use_only_canonical_product_mounts() {
        assert_eq!(
            canonical_product_input(),
            ServerConfigInput::SignedBundle {
                bundle_dir: PathBuf::from("/run/registry/bundle"),
                anchor_path: PathBuf::from("/run/registry/anchor/anchor.json"),
                state_path: PathBuf::from("/var/lib/registry/state/antirollback.json"),
            }
        );
    }

    #[test]
    fn preparation_authority_is_closed_to_notary_database_inputs() {
        assert_eq!(
            PRODUCT_MIGRATION_URL_ENV,
            "REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL"
        );
        assert_eq!(PRODUCT_OWNER_ROLE, "registry_notary_owner");
        assert_eq!(PRODUCT_RUNTIME_ROLE, "registry_notary_runtime");
        for forbidden in [
            "ISSUER",
            "SIGNING",
            "SOURCE",
            "ANTIROLLBACK",
            "CONFIG_BUNDLE",
        ] {
            assert!(
                !PRODUCT_MIGRATION_URL_ENV.contains(forbidden),
                "preparation credential must not grant {forbidden} authority"
            );
        }
    }

    #[tokio::test]
    async fn preparation_does_not_access_acceptance_state_issuer_signer_or_source() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fixture = write_signed_notary_bundle(&tmp);

        let error = prepare_product_state_store_at(&fixture.bundle_dir, &fixture.anchor_path)
            .await
            .expect_err("in-memory state is not a preparable database");

        assert_eq!(
            error.to_string(),
            "state install requires state.storage = postgresql"
        );
        assert!(
            !fixture.state_path.exists(),
            "preparation must not create or read acceptance state"
        );
        for inaccessible in [
            "TEST_NOTARY_LOADER_ISSUER_JWK",
            "TEST_NOTARY_LOADER_API_HASH",
            "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
        ] {
            assert!(
                !error.to_string().contains(inaccessible),
                "preparation accessed a non-database input"
            );
        }
    }
}
