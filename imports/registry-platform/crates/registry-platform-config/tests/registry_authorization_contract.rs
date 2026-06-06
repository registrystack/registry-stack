use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use registry_platform_config::{
    sha256_uri, ConfigTargetMetadata, ConfigVerificationError, LocalTufRepositoryInput,
    RegistryAcceptedTrustRoots, RegistryTrustRoot, TrustRootRole, TrustRootSigner,
    VerificationContext,
};
use serde_json::json;

const TRUSTED_ROOT_HASH: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_ROOT_HASH: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

fn signer(kid: &str, enabled: bool) -> TrustRootSigner {
    TrustRootSigner {
        kid: kid.to_string(),
        enabled,
    }
}

fn trust_root() -> RegistryTrustRoot {
    RegistryTrustRoot {
        root_id: "ops-root".to_string(),
        production: true,
        tuf_root_sha256: TRUSTED_ROOT_HASH.to_string(),
        valid_from_unix_seconds: None,
        valid_until_unix_seconds: None,
        high_risk_change_classes: set(&["auth_scopes", "signing_key_rotation"]),
        signers: BTreeMap::from([
            ("kid-a".to_string(), signer("kid-a", true)),
            ("kid-b".to_string(), signer("kid-b", true)),
            ("kid-disabled".to_string(), signer("kid-disabled", false)),
        ]),
        roles: vec![TrustRootRole {
            name: "config-admin".to_string(),
            threshold: 2,
            signer_kids: vec!["kid-a".to_string(), "kid-b".to_string()],
            allowed_change_classes: set(&["public_metadata", "auth_scopes"]),
        }],
    }
}

#[test]
fn rejects_missing_explicit_tuf_datastore() {
    let input = LocalTufRepositoryInput {
        root_path: PathBuf::from("/trust/root.json"),
        metadata_dir: PathBuf::from("/repo/metadata"),
        targets_dir: PathBuf::from("/repo/targets"),
        datastore_dir: PathBuf::from(""),
        target_name: "registry-notary.yaml".to_string(),
    };

    assert_eq!(
        input.validate().expect_err("datastore path is required"),
        ConfigVerificationError::EmptyPath("datastore_dir")
    );
}

#[test]
fn parses_target_metadata_and_rejects_hash_or_context_mismatch() {
    let target = b"instance:\n  id: relay-a\n";
    let context = VerificationContext {
        product: "registry-relay".to_string(),
        instance_id: "relay-a".to_string(),
        environment: "production".to_string(),
    };
    let custom = json!({
        "product": "registry-relay",
        "instance_id": "relay-a",
        "environment": "production",
        "stream_id": "default",
        "bundle_id": "bundle-43",
        "sequence": 43,
        "previous_config_hash": "sha256:old",
        "config_hash": sha256_uri(target),
        "change_classes": ["public_metadata"],
        "signer_kids": ["kid-a", "kid-b"],
        "apply_policy": "restart_required"
    });

    let parsed = ConfigTargetMetadata::from_custom_metadata(&custom, target, &context)
        .expect("metadata parses and binds to context");
    assert_eq!(parsed.bundle_id, "bundle-43");
    assert_eq!(parsed.change_classes, set(&["public_metadata"]));
    assert_eq!(parsed.signer_kids, set(&["kid-a", "kid-b"]));

    let wrong_context = VerificationContext {
        instance_id: "relay-b".to_string(),
        ..context.clone()
    };
    assert_eq!(
        ConfigTargetMetadata::from_custom_metadata(&custom, target, &wrong_context)
            .expect_err("instance mismatch is rejected"),
        ConfigVerificationError::ContextMismatch("instance_id")
    );

    let mut wrong_hash = custom.clone();
    wrong_hash["config_hash"] = json!("sha256:not-the-payload");
    assert!(matches!(
        ConfigTargetMetadata::from_custom_metadata(&wrong_hash, target, &context),
        Err(ConfigVerificationError::TargetHashMismatch { .. })
    ));

    let mut missing_signers = custom.clone();
    missing_signers["signer_kids"] = json!([]);
    assert_eq!(
        ConfigTargetMetadata::from_custom_metadata(&missing_signers, target, &context)
            .expect_err("signer kids are required"),
        ConfigVerificationError::MissingSigners
    );
}

#[test]
fn trust_root_deserializes_from_local_config_shape() {
    let root: RegistryTrustRoot = serde_json::from_value(json!({
        "root_id": "ops-root",
        "production": true,
        "tuf_root_sha256": TRUSTED_ROOT_HASH,
        "valid_from_unix_seconds": 1_700_000_000u64,
        "valid_until_unix_seconds": 1_900_000_000u64,
        "high_risk_change_classes": ["auth_scopes"],
        "signers": {
            "kid-a": { "kid": "kid-a", "enabled": true },
            "kid-b": { "kid": "kid-b", "enabled": true }
        },
        "roles": [{
            "name": "config-admin",
            "threshold": 2,
            "signer_kids": ["kid-a", "kid-b"],
            "allowed_change_classes": ["public_metadata", "auth_scopes"]
        }]
    }))
    .expect("trust root deserializes from local config shape");

    root.validate().expect("local trust root is valid");
    root.authorize(
        &set(&["public_metadata"]),
        &["kid-a".to_string(), "kid-b".to_string()],
        TRUSTED_ROOT_HASH,
    )
    .expect("authorized signers satisfy local root");
}

#[test]
fn trust_root_rejects_threshold_greater_than_enabled_keys() {
    let mut root = trust_root();
    root.roles[0].threshold = 3;

    assert_eq!(
        root.validate()
            .expect_err("threshold cannot exceed enabled signers"),
        ConfigVerificationError::ThresholdExceedsEnabledSigners {
            role: "config-admin".to_string(),
            threshold: 3,
            enabled: 2
        }
    );
}

#[test]
fn trust_root_rejects_duplicate_or_disabled_role_signers() {
    let mut duplicate = trust_root();
    duplicate.roles[0].signer_kids = vec!["kid-a".to_string(), "kid-a".to_string()];
    assert_eq!(
        duplicate
            .validate()
            .expect_err("duplicate role signer is rejected"),
        ConfigVerificationError::DuplicateSignerKid {
            role: "config-admin".to_string(),
            kid: "kid-a".to_string()
        }
    );

    let mut disabled = trust_root();
    disabled.roles[0].signer_kids = vec!["kid-a".to_string(), "kid-disabled".to_string()];
    assert_eq!(
        disabled
            .validate()
            .expect_err("disabled role signer is rejected"),
        ConfigVerificationError::DisabledRoleSigner {
            role: "config-admin".to_string(),
            kid: "kid-disabled".to_string()
        }
    );
}

#[test]
fn trust_root_rejects_single_signer_high_risk_production_role() {
    let mut root = trust_root();
    root.roles[0].threshold = 1;

    assert_eq!(
        root.validate()
            .expect_err("high-risk production role requires quorum"),
        ConfigVerificationError::SingleSignerHighRiskProductionRole {
            role: "config-admin".to_string()
        }
    );
}

#[test]
fn registry_authorization_accepts_distinct_role_members_for_all_change_classes() {
    let root = trust_root();

    root.authorize(
        &set(&["public_metadata", "auth_scopes"]),
        &["kid-a".to_string(), "kid-b".to_string()],
        TRUSTED_ROOT_HASH,
    )
    .expect("two distinct role signers authorize both classes");
}

#[test]
fn registry_authorization_ignores_unknown_signers_when_known_quorum_satisfied() {
    let root = trust_root();

    root.authorize(
        &set(&["auth_scopes"]),
        &[
            "kid-a".to_string(),
            "kid-z".to_string(),
            "kid-b".to_string(),
        ],
        TRUSTED_ROOT_HASH,
    )
    .expect("unknown signers do not reject a target with known quorum");
}

#[test]
fn registry_authorization_rejects_disabled_or_insufficient_signers() {
    let root = trust_root();

    assert_eq!(
        root.authorize(
            &set(&["auth_scopes"]),
            &["kid-z".to_string()],
            TRUSTED_ROOT_HASH,
        )
        .expect_err("unknown signer does not satisfy quorum"),
        ConfigVerificationError::UnauthorizedChangeClass {
            change_class: "auth_scopes".to_string()
        }
    );
    assert_eq!(
        root.authorize(
            &set(&["auth_scopes"]),
            &["kid-disabled".to_string()],
            TRUSTED_ROOT_HASH,
        )
        .expect_err("disabled signer is rejected"),
        ConfigVerificationError::DisabledSigner {
            kid: "kid-disabled".to_string()
        }
    );
    assert_eq!(
        root.authorize(
            &set(&["auth_scopes"]),
            &["kid-a".to_string(), "kid-a".to_string()],
            TRUSTED_ROOT_HASH,
        )
        .expect_err("duplicate signatures do not satisfy quorum"),
        ConfigVerificationError::UnauthorizedChangeClass {
            change_class: "auth_scopes".to_string()
        }
    );
}

#[test]
fn registry_authorization_rejects_untrusted_tuf_root_even_with_declared_trusted_kids() {
    let root = trust_root();

    assert_eq!(
        root.authorize(
            &set(&["public_metadata"]),
            &["kid-a".to_string(), "kid-b".to_string()],
            OTHER_ROOT_HASH,
        )
        .expect_err("declared signer kids cannot authorize an untrusted TUF root"),
        ConfigVerificationError::UntrustedTufRoot {
            expected: TRUSTED_ROOT_HASH.to_string(),
            actual: OTHER_ROOT_HASH.to_string(),
        }
    );
}

#[test]
fn registry_authorization_enforces_trust_root_validity_window() {
    let mut root = trust_root();
    root.valid_from_unix_seconds = Some(1_700_000_000);
    root.valid_until_unix_seconds = Some(1_800_000_000);

    root.authorize_at(
        &set(&["public_metadata"]),
        &["kid-a".to_string(), "kid-b".to_string()],
        TRUSTED_ROOT_HASH,
        1_750_000_000,
    )
    .expect("root authorizes inside its local overlap window");

    assert_eq!(
        root.authorize_at(
            &set(&["public_metadata"]),
            &["kid-a".to_string(), "kid-b".to_string()],
            TRUSTED_ROOT_HASH,
            1_699_999_999,
        )
        .expect_err("root is not valid before its local overlap starts"),
        ConfigVerificationError::TrustRootNotYetValid {
            root_id: "ops-root".to_string(),
            valid_from_unix_seconds: 1_700_000_000,
            now_unix_seconds: 1_699_999_999,
        }
    );
    assert_eq!(
        root.authorize_at(
            &set(&["public_metadata"]),
            &["kid-a".to_string(), "kid-b".to_string()],
            TRUSTED_ROOT_HASH,
            1_800_000_000,
        )
        .expect_err("root expires at the end of its local overlap"),
        ConfigVerificationError::TrustRootExpired {
            root_id: "ops-root".to_string(),
            valid_until_unix_seconds: 1_800_000_000,
            now_unix_seconds: 1_800_000_000,
        }
    );
}

#[test]
fn registry_authorization_accepts_locally_bounded_rotated_root_overlap() {
    let old_root = trust_root();
    let mut new_root = trust_root();
    new_root.root_id = "ops-root-v2".to_string();
    new_root.tuf_root_sha256 = OTHER_ROOT_HASH.to_string();
    new_root.valid_from_unix_seconds = Some(1_700_000_000);
    new_root.valid_until_unix_seconds = Some(1_800_000_000);

    old_root
        .authorize_at(
            &set(&["public_metadata"]),
            &["kid-a".to_string(), "kid-b".to_string()],
            TRUSTED_ROOT_HASH,
            1_750_000_000,
        )
        .expect("old root remains authorized during overlap");
    new_root
        .authorize_at(
            &set(&["public_metadata"]),
            &["kid-a".to_string(), "kid-b".to_string()],
            OTHER_ROOT_HASH,
            1_750_000_000,
        )
        .expect("new final root hash is locally authorized during overlap");

    assert_eq!(
        new_root
            .authorize_at(
                &set(&["public_metadata"]),
                &["kid-a".to_string(), "kid-b".to_string()],
                OTHER_ROOT_HASH,
                1_800_000_000,
            )
            .expect_err("new root overlap is bounded"),
        ConfigVerificationError::TrustRootExpired {
            root_id: "ops-root-v2".to_string(),
            valid_until_unix_seconds: 1_800_000_000,
            now_unix_seconds: 1_800_000_000,
        }
    );
}

#[test]
fn accepted_trust_roots_authorize_against_the_matching_current_root() {
    let old_root = trust_root();
    let mut new_root = trust_root();
    new_root.root_id = "ops-root-v2".to_string();
    new_root.tuf_root_sha256 = OTHER_ROOT_HASH.to_string();
    new_root.valid_from_unix_seconds = Some(1_700_000_000);
    new_root.valid_until_unix_seconds = Some(1_800_000_000);
    let roots = RegistryAcceptedTrustRoots {
        accepted_roots: vec![old_root, new_root],
    };

    let authorized = roots
        .authorize_at(
            &set(&["public_metadata"]),
            &["kid-a".to_string(), "kid-b".to_string()],
            OTHER_ROOT_HASH,
            1_750_000_000,
        )
        .expect("new root authorizes during overlap");
    assert_eq!(authorized.root_id, "ops-root-v2");
}

#[test]
fn accepted_trust_roots_reject_empty_or_unmatched_root_sets() {
    let empty = RegistryAcceptedTrustRoots {
        accepted_roots: vec![],
    };
    assert_eq!(
        empty
            .validate()
            .expect_err("accepted roots must be explicit"),
        ConfigVerificationError::MissingAcceptedTrustRoots
    );

    let roots = RegistryAcceptedTrustRoots {
        accepted_roots: vec![trust_root()],
    };
    assert_eq!(
        roots
            .authorize_at(
                &set(&["public_metadata"]),
                &["kid-a".to_string(), "kid-b".to_string()],
                OTHER_ROOT_HASH,
                1_750_000_000,
            )
            .expect_err("no local root accepts the verified final TUF root"),
        ConfigVerificationError::NoAcceptedTrustRootAuthorized { root_count: 1 }
    );
}
