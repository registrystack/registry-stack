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
    /// Preview an exact, advancing, or anchor-rotating state acceptance.
    #[command(name = "preview_state")]
    PreviewState,
    /// Audit and commit the previously previewable state acceptance, then exit.
    #[command(name = "accept_state")]
    AcceptState,
    /// Verify exact accepted product state without changing it, then exit.
    #[command(name = "verify_state")]
    VerifyState,
    /// Serve the verified product bundle; absent state is a hard failure.
    #[command(name = "serve")]
    Serve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
pub(crate) enum DevelopmentAction {
    #[command(name = "prepare_state_store")]
    PrepareStateStore,
    #[command(name = "initialize_state")]
    InitializeState,
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
        || has_disallowed_product_action_bind(args.bind)
        || args.initialize_state
    {
        return Err("product-action accepts no runtime flags".into());
    }
    Ok(())
}

fn has_disallowed_product_action_bind(bind: Option<SocketAddr>) -> bool {
    let ambient = std::env::var("REGISTRY_NOTARY_BIND").ok();
    has_disallowed_product_action_bind_with_ambient(bind, ambient.as_deref())
}

fn has_disallowed_product_action_bind_with_ambient(
    bind: Option<SocketAddr>,
    ambient: Option<&str>,
) -> bool {
    let Some(bind) = bind else {
        return false;
    };

    // The released image sets this legacy server default globally. Closed
    // actions load their listener from the verified bundle and never apply the
    // parsed override, so an identical ambient value is inactive. A distinct
    // CLI override still rejects. Clap no longer exposes the value source once
    // `Args` has been constructed, but an explicit duplicate remains harmless
    // because this path ignores `Args::bind` completely.
    ambient.and_then(|value| value.parse::<SocketAddr>().ok()) != Some(bind)
}

pub(crate) async fn run_product_action(
    action: ProductAction,
    trust_domain: ProductTrustDomainV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let verified = verify_notary_product_bundle_for_domain(
        Path::new(PRODUCT_BUNDLE_DIR),
        Path::new(PRODUCT_ANCHOR_PATH),
        trust_domain,
    )?;
    match action {
        ProductAction::PrepareStateStore => {
            prepare_product_state_store(verified, trust_domain).await
        }
        ProductAction::InitializeState => initialize_product_state(verified, trust_domain).await,
        ProductAction::PreviewState => preview_product_state(&verified),
        ProductAction::AcceptState => accept_product_state(verified, trust_domain).await,
        ProductAction::VerifyState => verify_product_state(&verified),
        ProductAction::Serve => {
            let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(&verified)
                .map_err(map_product_state_error)?;
            FileAntiRollbackStore::new(PRODUCT_STATE_PATH)
                .verify_state(candidate.expectation())
                .map_err(map_product_state_error)?;
            run_governed_server(verified, Path::new(PRODUCT_STATE_PATH), trust_domain).await
        }
    }
}

pub(crate) async fn run_development_action(
    action: DevelopmentAction,
) -> Result<(), Box<dyn std::error::Error>> {
    let action = match action {
        DevelopmentAction::PrepareStateStore => ProductAction::PrepareStateStore,
        DevelopmentAction::InitializeState => ProductAction::InitializeState,
        DevelopmentAction::Serve => ProductAction::Serve,
    };
    run_product_action(action, ProductTrustDomainV1::Development).await
}

#[cfg(test)]
fn canonical_product_input() -> ServerConfigInput {
    ServerConfigInput::SignedBundle {
        bundle_dir: PathBuf::from(PRODUCT_BUNDLE_DIR),
        anchor_path: PathBuf::from(PRODUCT_ANCHOR_PATH),
        state_path: PathBuf::from(PRODUCT_STATE_PATH),
    }
}

#[cfg(test)]
async fn prepare_product_state_store_at(
    bundle_dir: &Path,
    anchor_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let verified = verify_notary_product_bundle(bundle_dir, anchor_path)?;
    prepare_product_state_store(verified, ProductTrustDomainV1::Governed).await
}

async fn prepare_product_state_store(
    verified: VerifiedConfigBundle,
    trust_domain: ProductTrustDomainV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_verified_notary_config_read_only_for_domain(&verified, trust_domain)?;
    let audit_evidence = prepare_state_store_audit_evidence(&verified)?;
    registry_notary_server::emit_prepare_state_store_mutation_intent_audit(
        &config.audit,
        audit_evidence,
    )
    .await?;
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

fn prepare_state_store_audit_evidence(
    verified: &VerifiedConfigBundle,
) -> Result<registry_notary_server::PrepareStateStoreAuditEvidence, Box<dyn std::error::Error>> {
    let anchor_digest = registry_platform_config::trust_anchor_digest(&verified.trust_anchor)
        .map_err(|_| {
            Box::new(BundleVerificationFailure::from(
                BundleVerificationCode::REJECTED_VALIDATION,
            )) as Box<dyn std::error::Error>
        })?;
    Ok(registry_notary_server::PrepareStateStoreAuditEvidence {
        acceptance_identity: verified.manifest.acceptance_identity.clone(),
        bundle_id: verified.manifest.bundle_id.clone(),
        bundle_manifest_hash: verified.manifest_hash.clone(),
        sequence: verified.manifest.sequence,
        signer_kids: verified.signer_kids.clone(),
        previous_config_hash: verified.manifest.previous_config_hash.clone(),
        config_hash: verified.manifest.config_hash.clone(),
        anchor_digest,
        anchor_version: verified.trust_anchor.version,
    })
}

async fn initialize_product_state(
    verified: VerifiedConfigBundle,
    trust_domain: ProductTrustDomainV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_verified_notary_config_read_only_for_domain(&verified, trust_domain)?;
    let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(&verified)
        .map_err(map_product_state_error)?;
    let store = FileAntiRollbackStore::new(PRODUCT_STATE_PATH);
    let plan = store
        .plan_initialize(&candidate)
        .map_err(map_product_state_error)?;
    let evidence = prepare_state_store_audit_evidence(&verified)?;
    store
        .commit_acceptance(plan, move |_| async move {
            registry_notary_server::emit_product_action_mutation_intent_audit(
                &config.audit,
                "initialize_state",
                evidence,
            )
            .await
        })
        .await
        .map_err(map_product_state_error)?;
    println!("registry-notary initialize_state complete");
    Ok(())
}

fn verify_product_state(verified: &VerifiedConfigBundle) -> Result<(), Box<dyn std::error::Error>> {
    let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(verified)
        .map_err(map_product_state_error)?;
    FileAntiRollbackStore::new(PRODUCT_STATE_PATH)
        .verify_state(candidate.expectation())
        .map_err(map_product_state_error)?;
    println!("registry-notary verify_state complete");
    Ok(())
}

type ProductRotationInputs = (
    AcceptanceStatePreviewV1,
    Option<registry_platform_config::ConfigTrustAnchor>,
    Option<registry_platform_config::AnchorTransitionV1>,
);

fn preview_product_acceptance(
    store: &FileAntiRollbackStore,
    candidate: &VerifiedAcceptanceStateV1,
) -> Result<ProductRotationInputs, Box<dyn std::error::Error>> {
    match store.preview_acceptance(candidate, None, None) {
        Ok(preview) => Ok((preview, None, None)),
        Err(AntiRollbackStoreError::AnchorTransitionRequired) => {
            let previous_anchor =
                load_optional_previous_anchor(Path::new(PRODUCT_PREVIOUS_ANCHOR_PATH))?;
            let transition =
                load_optional_anchor_transition(Path::new(PRODUCT_ANCHOR_TRANSITION_PATH))?;
            if previous_anchor.is_some() != transition.is_some() {
                return Err(map_product_state_error(
                    AntiRollbackStoreError::UnexpectedAnchorTransition,
                ));
            }
            let preview = store
                .preview_acceptance(candidate, previous_anchor.as_ref(), transition.as_ref())
                .map_err(map_product_state_error)?;
            Ok((preview, previous_anchor, transition))
        }
        Err(error) => Err(map_product_state_error(error)),
    }
}

fn map_product_state_error<E>(_: E) -> Box<dyn std::error::Error> {
    Box::new(BundleVerificationFailure::from(
        BundleVerificationCode::REJECTED_ROLLBACK,
    ))
}

fn preview_product_state(
    verified: &VerifiedConfigBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(verified)
        .map_err(map_product_state_error)?;
    let (preview, _, _) =
        preview_product_acceptance(&FileAntiRollbackStore::new(PRODUCT_STATE_PATH), &candidate)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "registry.notary.product-action-result.v1",
            "action": "preview_state",
            "status": "previewed",
            "state": preview.as_str(),
        }))?
    );
    Ok(())
}

async fn accept_product_state(
    verified: VerifiedConfigBundle,
    trust_domain: ProductTrustDomainV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let candidate = VerifiedAcceptanceStateV1::from_verified_bundle(&verified)
        .map_err(map_product_state_error)?;
    let store = FileAntiRollbackStore::new(PRODUCT_STATE_PATH);
    let (preview, previous_anchor, transition) = preview_product_acceptance(&store, &candidate)?;
    if preview != AcceptanceStatePreviewV1::Current {
        let config = load_verified_notary_config_read_only_for_domain(&verified, trust_domain)?;
        let plan = store
            .plan_acceptance(&candidate, previous_anchor.as_ref(), transition.as_ref())
            .map_err(map_product_state_error)?;
        let evidence = prepare_state_store_audit_evidence(&verified)?;
        store
            .commit_acceptance(plan, move |_| async move {
                registry_notary_server::emit_product_action_mutation_intent_audit(
                    &config.audit,
                    "accept_state",
                    evidence,
                )
                .await
            })
            .await
            .map_err(map_product_state_error)?;
    }
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "registry.notary.product-action-result.v1",
            "action": "accept_state",
            "status": "succeeded",
            "state": preview.as_str(),
        }))?
    );
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
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(Box::new(BundleVerificationFailure::from(
            BundleVerificationCode::REJECTED_VALIDATION,
        ))),
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

    fn postgres_product_config(audit_path: &Path) -> String {
        notary_bundle_runtime_config()
            .replace("state:\n  storage: in_memory", "state:\n  storage: postgresql")
            .replace(
                "audit:\n  sink: stdout\n  hash_secret_env: TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
                &format!(
                    "audit:\n  sink: file\n  path: {}\n  hash_secret_env: TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
                    audit_path.display()
                ),
            )
    }

    #[test]
    fn closed_product_actions_parse_with_release_lock_names() {
        for (name, expected) in [
            ("prepare_state_store", ProductAction::PrepareStateStore),
            ("initialize_state", ProductAction::InitializeState),
            ("preview_state", ProductAction::PreviewState),
            ("accept_state", ProductAction::AcceptState),
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
    fn development_actions_have_a_distinct_closed_namespace() {
        for (name, expected) in [
            ("prepare_state_store", DevelopmentAction::PrepareStateStore),
            ("initialize_state", DevelopmentAction::InitializeState),
            ("serve", DevelopmentAction::Serve),
        ] {
            let args = Args::try_parse_from(["registry-notary", "development-action", name])
                .expect("closed development action parses");
            assert!(matches!(
                args.command,
                Some(Command::DevelopmentAction { action }) if action == expected
            ));
        }
        for name in ["preview_state", "accept_state", "verify_state"] {
            assert!(
                Args::try_parse_from(["registry-notary", "development-action", name]).is_err(),
                "development namespace must reject governed action {name}"
            );
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
    fn released_image_bind_is_inactive_but_distinct_overrides_reject() {
        let image_bind = "0.0.0.0:8080".parse().expect("image bind parses");
        let distinct_bind = "127.0.0.1:8080".parse().expect("CLI bind parses");

        assert!(!has_disallowed_product_action_bind_with_ambient(
            Some(image_bind),
            Some("0.0.0.0:8080")
        ));
        assert!(has_disallowed_product_action_bind_with_ambient(
            Some(distinct_bind),
            Some("0.0.0.0:8080")
        ));
        assert!(has_disallowed_product_action_bind_with_ambient(
            Some(image_bind),
            None
        ));
        assert!(has_disallowed_product_action_bind_with_ambient(
            Some(image_bind),
            Some("not-a-socket")
        ));
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
    #[allow(clippy::await_holding_lock)]
    async fn preparation_does_not_access_acceptance_state_issuer_signer_or_source() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var(
            "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
            "registry-notary-product-action-audit-secret-32-bytes",
        );
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
        std::env::remove_var("TEST_NOTARY_LOADER_AUDIT_HASH_SECRET");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn preparation_writes_pending_intent_before_database_failure() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var(
            "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
            "registry-notary-product-action-audit-secret-32-bytes",
        );
        std::env::remove_var(PRODUCT_MIGRATION_URL_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        let audit_path = tmp.path().join("audit.jsonl");
        let fixture =
            write_signed_notary_bundle_with_config(&tmp, postgres_product_config(&audit_path));

        prepare_product_state_store_at(&fixture.bundle_dir, &fixture.anchor_path)
            .await
            .expect_err("missing database credential fails after the checked intent audit");

        let records = std::fs::read_to_string(&audit_path).expect("intent audit is retained");
        let record: Value = serde_json::from_str(records.lines().next().expect("one audit record"))
            .expect("audit record parses");
        assert_eq!(
            record["record"]["path"],
            "/__events/product_action.mutation_intent"
        );
        assert_eq!(record["record"]["config"]["action"], "prepare_state_store");
        assert_eq!(record["record"]["config"]["apply_result"], "pending");
        assert_eq!(record["record"]["config"]["applied"], false);
        assert!(
            !fixture.state_path.exists(),
            "database preparation must not acquire anti-rollback authority"
        );

        std::env::remove_var("TEST_NOTARY_LOADER_AUDIT_HASH_SECRET");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn preparation_audit_failure_aborts_before_database_access() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var(
            "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
            "registry-notary-product-action-audit-secret-32-bytes",
        );
        std::env::remove_var(PRODUCT_MIGRATION_URL_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        let audit_path = tmp.path().join("audit-target-is-a-directory");
        std::fs::create_dir(&audit_path).expect("invalid audit target directory");
        let fixture =
            write_signed_notary_bundle_with_config(&tmp, postgres_product_config(&audit_path));

        let error = prepare_product_state_store_at(&fixture.bundle_dir, &fixture.anchor_path)
            .await
            .expect_err("audit failure aborts preparation");

        assert!(
            matches!(
                error.downcast_ref::<registry_notary_server::StandaloneServerError>(),
                Some(registry_notary_server::StandaloneServerError::Audit(_))
            ),
            "audit failure must be returned before the missing database credential: {error}"
        );
        assert!(
            !fixture.state_path.exists(),
            "failed preparation must not mutate anti-rollback state"
        );

        std::env::remove_var("TEST_NOTARY_LOADER_AUDIT_HASH_SECRET");
    }
}
