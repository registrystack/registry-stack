// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use chrono::Utc;
use olpc_cjson::CanonicalFormatter;
use registry_platform_config::{
    sha256_uri, LocalTufRepositoryInput, TufConfigVerifier, VerificationContext,
};
use registry_platform_ops::{internal_config_hash, AntiRollbackKey, AntiRollbackRecord};
use serde::Serialize;
use serde_json::json;
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::Target;

const TUF_TARGETS_SIGNER_KID: &str =
    "8ec3a843a0f9328c863cac4046ab1cacbbc67888476ac7acf73d9bcd9a223ada";
const RELAY_STREAM_ID: &str = "lab2-relay";
const NOTARY_STREAM_ID: &str = "lab2-notary";

#[derive(Clone)]
struct RuntimeConfig {
    product: &'static str,
    instance_id: &'static str,
    environment: &'static str,
    stream_id: &'static str,
    target_name: &'static str,
    yaml: String,
    internal_hash: String,
}

#[derive(Clone)]
struct BundleSpec {
    name: &'static str,
    product: &'static str,
    instance_id: &'static str,
    environment: &'static str,
    stream_id: &'static str,
    target_name: &'static str,
    bundle_id: &'static str,
    sequence: u64,
    previous_config_hash: String,
    config_yaml: String,
    change_classes: Vec<&'static str>,
    apply_policy: &'static str,
    custom_signer_kids: Vec<String>,
    sign_with_second_key: bool,
}

#[derive(Serialize)]
struct ManifestArtifact {
    path: String,
    sha256: String,
    role: String,
    secret: bool,
    secret_classification: String,
}

#[derive(Serialize)]
struct Manifest {
    generated_at: String,
    tuf_targets_signer_kid: String,
    tuf_threshold_second_signer_kid: String,
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Serialize)]
struct CredentialCommitmentPayload<'a> {
    product: &'a str,
    credential_type: &'a str,
    credential_id: &'a str,
    fingerprint: &'a str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo = env::current_dir()?;
    let output = repo.join("output/lab2");
    if output.exists() {
        fs::remove_dir_all(&output)?;
    }
    for dir in [
        "runtime-config",
        "tuf-repo",
        "keys",
        "bundles",
        "evidence",
        "state-init",
    ] {
        fs::create_dir_all(output.join(dir))?;
    }

    let fixture_root = tough_fixture("simple-rsa").join("root.json");
    let fixture_key = tough_fixture("snakeoil.pem");
    let fixture_second_key = tough_fixture("snakeoil_2.pem");
    let root_path = output.join("keys/tuf-root.json");
    let second_key_path = output.join("keys/tuf-targets-snakeoil-2.pem");
    fs::copy(&fixture_key, output.join("keys/tuf-targets-snakeoil.pem"))?;
    fs::copy(&fixture_second_key, &second_key_path)?;
    let threshold_second_signer_kid =
        write_threshold_tuf_root(&fixture_root, &fixture_key, &fixture_second_key, &root_path)
            .await?;
    let root_sha = sha256_uri(&fs::read(&root_path)?);

    if let Ok(jwk) = env::var("REGISTRY_NOTARY_ROTATED_ISSUER_JWK") {
        fs::write(output.join("keys/notary-rotated-issuer-private.jwk"), jwk)?;
    }
    if let Ok(jwk) = env::var("REGISTRY_NOTARY_ISSUER_PUBLIC_JWK") {
        fs::write(output.join("keys/notary-current-issuer-public.jwk"), jwk)?;
    }

    let relay = render_relay_runtime_config(&repo, &root_sha, &threshold_second_signer_kid)?;
    let notary = render_notary_runtime_config(&repo, &root_sha, &threshold_second_signer_kid)?;
    fs::write(
        output.join("runtime-config/civil-registry-relay.yaml"),
        &relay.yaml,
    )?;
    fs::copy(
        repo.join("config/relay/civil-registry-relay.metadata.yaml"),
        output.join("runtime-config/civil-registry-relay.metadata.yaml"),
    )?;
    let governed_metadata = relay_governed_metadata_candidate(&fs::read_to_string(
        repo.join("config/relay/civil-registry-relay.metadata.yaml"),
    )?)?;
    fs::write(
        output.join("runtime-config/civil-registry-relay.governed.metadata.yaml"),
        governed_metadata,
    )?;
    fs::write(
        output.join("runtime-config/civil-notary.yaml"),
        &notary.yaml,
    )?;
    write_state_file(
        &output.join("state-init/civil-registry-relay-config-antirollback.json"),
        &serde_json::to_vec_pretty(&initial_record(&relay, 1))?,
    )?;
    write_state_file(
        &output.join("state-init/civil-notary-config-antirollback.json"),
        &serde_json::to_vec_pretty(&initial_record(&notary, 1))?,
    )?;
    write_state_file(
        &output.join("state-init/civil-registry-relay-config-local-approvals.json"),
        b"{\"approvals\":[]}\n",
    )?;
    write_state_file(
        &output.join("state-init/civil-notary-config-local-approvals.json"),
        b"{\"approvals\":[]}\n",
    )?;

    let relay_candidate = relay_public_metadata_candidate(&relay.yaml)?;
    let notary_candidate = notary_rotation_candidate(&notary.yaml)?;
    let relay_candidate_hash = internal_config_hash(relay_candidate.as_bytes());
    let notary_candidate_hash = internal_config_hash(notary_candidate.as_bytes());
    let relay_break_glass = relay_break_glass_candidate(&relay_candidate)?;
    let notary_break_glass = notary_break_glass_candidate(&notary_candidate)?;
    let single_signer = vec![TUF_TARGETS_SIGNER_KID.to_string()];
    let threshold_signers = vec![
        TUF_TARGETS_SIGNER_KID.to_string(),
        threshold_second_signer_kid.clone(),
    ];

    let bundles = vec![
        BundleSpec {
            name: "relay-noop",
            product: relay.product,
            instance_id: relay.instance_id,
            environment: relay.environment,
            stream_id: relay.stream_id,
            target_name: relay.target_name,
            bundle_id: "lab2-relay-noop",
            sequence: 2,
            previous_config_hash: relay.internal_hash.clone(),
            config_yaml: relay.yaml.clone(),
            change_classes: vec!["public_metadata"],
            apply_policy: "live",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "relay-public-metadata",
            product: relay.product,
            instance_id: relay.instance_id,
            environment: relay.environment,
            stream_id: relay.stream_id,
            target_name: relay.target_name,
            bundle_id: "lab2-relay-public-metadata",
            sequence: 3,
            previous_config_hash: relay.internal_hash.clone(),
            config_yaml: relay_candidate.clone(),
            change_classes: vec!["public_metadata"],
            apply_policy: "live",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "relay-threshold-minus-one",
            product: relay.product,
            instance_id: relay.instance_id,
            environment: relay.environment,
            stream_id: relay.stream_id,
            target_name: relay.target_name,
            bundle_id: "lab2-relay-threshold-minus-one",
            sequence: 4,
            previous_config_hash: relay_candidate_hash.clone(),
            config_yaml: relay_candidate.clone(),
            change_classes: vec!["threshold_probe"],
            apply_policy: "live",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "relay-threshold-exact",
            product: relay.product,
            instance_id: relay.instance_id,
            environment: relay.environment,
            stream_id: relay.stream_id,
            target_name: relay.target_name,
            bundle_id: "lab2-relay-threshold-exact",
            sequence: 4,
            previous_config_hash: relay_candidate_hash.clone(),
            config_yaml: relay_candidate.clone(),
            change_classes: vec!["threshold_probe"],
            apply_policy: "live",
            custom_signer_kids: threshold_signers.clone(),
            sign_with_second_key: true,
        },
        BundleSpec {
            name: "relay-spoofed-metadata",
            product: relay.product,
            instance_id: relay.instance_id,
            environment: relay.environment,
            stream_id: relay.stream_id,
            target_name: relay.target_name,
            bundle_id: "lab2-relay-spoofed-metadata",
            sequence: 5,
            previous_config_hash: relay_candidate_hash.clone(),
            config_yaml: relay_candidate.clone(),
            change_classes: vec!["threshold_probe"],
            apply_policy: "live",
            custom_signer_kids: threshold_signers,
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "relay-alternate-root",
            product: relay.product,
            instance_id: relay.instance_id,
            environment: relay.environment,
            stream_id: relay.stream_id,
            target_name: relay.target_name,
            bundle_id: "lab2-relay-alternate-root",
            sequence: 5,
            previous_config_hash: relay_candidate_hash.clone(),
            config_yaml: relay_candidate.clone(),
            change_classes: vec!["public_metadata"],
            apply_policy: "live",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "relay-break-glass",
            product: relay.product,
            instance_id: relay.instance_id,
            environment: relay.environment,
            stream_id: relay.stream_id,
            target_name: relay.target_name,
            bundle_id: "lab2-relay-break-glass",
            sequence: 6,
            previous_config_hash:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            config_yaml: relay_break_glass.clone(),
            change_classes: vec!["public_metadata", "emergency_break_glass"],
            apply_policy: "live",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "relay-break-glass-second",
            product: relay.product,
            instance_id: relay.instance_id,
            environment: relay.environment,
            stream_id: relay.stream_id,
            target_name: relay.target_name,
            bundle_id: "lab2-relay-break-glass-second",
            sequence: 7,
            previous_config_hash:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            config_yaml: relay_break_glass,
            change_classes: vec!["public_metadata", "emergency_break_glass"],
            apply_policy: "live",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "notary-noop",
            product: notary.product,
            instance_id: notary.instance_id,
            environment: notary.environment,
            stream_id: notary.stream_id,
            target_name: notary.target_name,
            bundle_id: "lab2-notary-noop",
            sequence: 2,
            previous_config_hash: notary.internal_hash.clone(),
            config_yaml: notary.yaml.clone(),
            change_classes: vec!["public_metadata"],
            apply_policy: "live",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "notary-signing-key-rotation",
            product: notary.product,
            instance_id: notary.instance_id,
            environment: notary.environment,
            stream_id: notary.stream_id,
            target_name: notary.target_name,
            bundle_id: "lab2-notary-signing-key-rotation",
            sequence: 3,
            previous_config_hash: notary.internal_hash.clone(),
            config_yaml: notary_candidate.clone(),
            change_classes: vec!["signing_key_rotation"],
            apply_policy: "restart_required",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "notary-rollback",
            product: notary.product,
            instance_id: notary.instance_id,
            environment: notary.environment,
            stream_id: notary.stream_id,
            target_name: notary.target_name,
            bundle_id: "lab2-notary-rollback",
            sequence: 1,
            previous_config_hash: notary.internal_hash.clone(),
            config_yaml: notary_candidate.clone(),
            change_classes: vec!["signing_key_rotation"],
            apply_policy: "restart_required",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "notary-threshold-minus-one",
            product: notary.product,
            instance_id: notary.instance_id,
            environment: notary.environment,
            stream_id: notary.stream_id,
            target_name: notary.target_name,
            bundle_id: "lab2-notary-threshold-minus-one",
            sequence: 4,
            previous_config_hash: notary_candidate_hash.clone(),
            config_yaml: notary_candidate.clone(),
            change_classes: vec!["threshold_probe"],
            apply_policy: "restart_required",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "notary-break-glass",
            product: notary.product,
            instance_id: notary.instance_id,
            environment: notary.environment,
            stream_id: notary.stream_id,
            target_name: notary.target_name,
            bundle_id: "lab2-notary-break-glass",
            sequence: 5,
            previous_config_hash:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            config_yaml: notary_break_glass.clone(),
            change_classes: vec!["signing_key_rotation", "emergency_break_glass"],
            apply_policy: "restart_required",
            custom_signer_kids: single_signer.clone(),
            sign_with_second_key: false,
        },
        BundleSpec {
            name: "notary-break-glass-second",
            product: notary.product,
            instance_id: notary.instance_id,
            environment: notary.environment,
            stream_id: notary.stream_id,
            target_name: notary.target_name,
            bundle_id: "lab2-notary-break-glass-second",
            sequence: 6,
            previous_config_hash:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            config_yaml: notary_break_glass,
            change_classes: vec!["signing_key_rotation", "emergency_break_glass"],
            apply_policy: "restart_required",
            custom_signer_kids: single_signer,
            sign_with_second_key: false,
        },
    ];

    for bundle in &bundles {
        let bundle_root_path = if bundle.name == "relay-alternate-root" {
            &fixture_root
        } else {
            &root_path
        };
        write_signed_bundle(
            &output,
            bundle_root_path,
            &fixture_key,
            &fixture_second_key,
            bundle,
        )
        .await?;
        verify_generated_bundle(&output, bundle).await?;
    }

    write_summary(&output, &relay, &notary)?;
    write_manifest(&output, &threshold_second_signer_kid)?;
    println!(
        "generated Lab 2 governed config artifacts under {}",
        output.display()
    );
    Ok(())
}

async fn verify_generated_bundle(
    output: &Path,
    bundle: &BundleSpec,
) -> Result<(), Box<dyn std::error::Error>> {
    TufConfigVerifier::verify_config_target(
        &LocalTufRepositoryInput {
            root_path: output
                .join("tuf-repo")
                .join(bundle.name)
                .join("metadata/1.root.json"),
            metadata_dir: output.join("tuf-repo").join(bundle.name).join("metadata"),
            targets_dir: output.join("tuf-repo").join(bundle.name).join("targets"),
            datastore_dir: output.join("tuf-repo").join(bundle.name).join("datastore"),
            target_name: bundle.target_name.to_string(),
        },
        &VerificationContext {
            product: bundle.product.to_string(),
            instance_id: bundle.instance_id.to_string(),
            environment: bundle.environment.to_string(),
        },
    )
    .await
    .map_err(|error| {
        format!(
            "generated bundle {} failed verification: {error}",
            bundle.name
        )
    })?;
    Ok(())
}

async fn write_threshold_tuf_root(
    fixture_root: &Path,
    primary_key_path: &Path,
    second_key_path: &Path,
    output_root: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut root: serde_json::Value = serde_json::from_slice(&fs::read(fixture_root)?)?;
    let second_signer = LocalKeySource {
        path: second_key_path.to_path_buf(),
    }
    .as_sign()
    .await
    .map_err(|err| format!("failed to load second TUF signing key: {err}"))?;
    let second_key = second_signer.tuf_key();
    let second_key_id = second_key.key_id()?;
    let second_key_id_value = serde_json::to_value(&second_key_id)?;
    let second_key_id = second_key_id_value
        .as_str()
        .ok_or("TUF key id must serialize as a string")?
        .to_string();

    let signed = root
        .get_mut("signed")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("root.signed must be an object")?;
    let keys = signed
        .get_mut("keys")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("root.signed.keys must be an object")?;
    keys.insert(second_key_id.clone(), serde_json::to_value(second_key)?);

    let targets_role = signed
        .get_mut("roles")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|roles| roles.get_mut("targets"))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("root.signed.roles.targets must be an object")?;
    let keyids = targets_role
        .get_mut("keyids")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("root.signed.roles.targets.keyids must be an array")?;
    if !keyids
        .iter()
        .any(|kid| kid.as_str() == Some(second_key_id.as_str()))
    {
        keyids.push(serde_json::Value::String(second_key_id.clone()));
    }

    let primary_signer = LocalKeySource {
        path: primary_key_path.to_path_buf(),
    }
    .as_sign()
    .await
    .map_err(|err| format!("failed to load primary TUF signing key: {err}"))?;
    let signed_payload = root.get("signed").ok_or("root.signed must exist")?;
    let mut canonical = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut canonical, CanonicalFormatter::new());
    signed_payload.serialize(&mut serializer)?;
    let signature = primary_signer
        .sign(&canonical, &SystemRandom::new())
        .await
        .map_err(|err| format!("failed to sign generated TUF root: {err}"))?;
    root["signatures"] = json!([{
        "keyid": TUF_TARGETS_SIGNER_KID,
        "sig": hex_lower(&signature),
    }]);

    fs::write(output_root, serde_json::to_vec_pretty(&root)?)?;
    Ok(second_key_id)
}

fn render_relay_runtime_config(
    repo: &Path,
    root_sha: &str,
    threshold_second_signer_kid: &str,
) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
    let yaml = fs::read_to_string(repo.join("config/relay/civil-registry-relay.yaml"))?;
    let mut value: Value = serde_yaml::from_str(&yaml)?;
    set_mapping(
        root_mapping_mut(&mut value)?,
        "instance",
        serde_yaml::to_value(json!({
            "id": "lab2-civil-registry-relay",
            "environment": "lab2"
        }))?,
    );
    add_admin_scope(
        &mut value,
        &["auth", "api_keys"],
        "civil_relay_ops",
        "registry_relay:admin",
    )?;
    normalize_credential_entries(
        &mut value,
        &["auth", "api_keys"],
        "registry-relay",
        "api_key",
    )?;
    install_trust_root(&mut value, root_sha, threshold_second_signer_kid)?;
    let yaml = serde_yaml::to_string(&value)?;
    Ok(RuntimeConfig {
        product: "registry-relay",
        instance_id: "lab2-civil-registry-relay",
        environment: "lab2",
        stream_id: RELAY_STREAM_ID,
        target_name: "civil-registry-relay.yaml",
        internal_hash: internal_config_hash(yaml.as_bytes()),
        yaml,
    })
}

fn render_notary_runtime_config(
    repo: &Path,
    root_sha: &str,
    threshold_second_signer_kid: &str,
) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
    let yaml = fs::read_to_string(repo.join("config/notary/civil-notary.yaml"))?;
    let mut value: Value = serde_yaml::from_str(&yaml)?;
    set_mapping(
        root_mapping_mut(&mut value)?,
        "instance",
        serde_yaml::to_value(json!({
            "id": "lab2-civil-notary",
            "environment": "lab2"
        }))?,
    );
    let server = mapping_at_mut(&mut value, &["server"])?;
    set_mapping(
        server,
        "admin_listener",
        serde_yaml::to_value(json!({
            "mode": "dedicated",
            "bind": "0.0.0.0:8082"
        }))?,
    );
    add_admin_scope(
        &mut value,
        &["auth", "api_keys"],
        "civil_notary_ops",
        "registry_notary:admin",
    )?;
    ensure_bearer_token(
        &mut value,
        "civil_notary_ops",
        credential_fingerprint_ref(
            "CIVIL_NOTARY_OPS_BEARER_HASH",
            &credential_commitment(
                "registry-notary",
                "bearer_token",
                "civil_notary_ops",
                "CIVIL_NOTARY_OPS_BEARER_HASH",
            )?,
        )?,
        &["registry_notary:ops_read", "registry_notary:admin"],
    )?;
    normalize_credential_entries(
        &mut value,
        &["auth", "api_keys"],
        "registry-notary",
        "api_key",
    )?;
    normalize_credential_entries(
        &mut value,
        &["auth", "bearer_tokens"],
        "registry-notary",
        "bearer_token",
    )?;
    let evidence = mapping_at_mut(&mut value, &["evidence"])?;
    set_mapping(
        evidence,
        "api_base_url",
        Value::String("http://lab2-civil-notary:8080".to_string()),
    );
    let source = mapping_at_mut(&mut value, &["evidence", "source_connections", "civil"])?;
    set_mapping(
        source,
        "base_url",
        Value::String("http://lab2-civil-registry-relay:8080".to_string()),
    );
    install_trust_root(&mut value, root_sha, threshold_second_signer_kid)?;
    let yaml = serde_yaml::to_string(&value)?;
    Ok(RuntimeConfig {
        product: "registry-notary",
        instance_id: "lab2-civil-notary",
        environment: "lab2",
        stream_id: NOTARY_STREAM_ID,
        target_name: "civil-notary.yaml",
        internal_hash: internal_config_hash(yaml.as_bytes()),
        yaml,
    })
}

fn install_trust_root(
    value: &mut Value,
    root_sha: &str,
    threshold_second_signer_kid: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut root_json = json!({
        "root_id": "lab2-ops-root",
        "production": false,
        "tuf_root_sha256": root_sha,
        "high_risk_change_classes": [],
        "signers": {},
        "roles": [
            {
                "name": "config-admin",
                "threshold": 1,
                "signer_kids": [TUF_TARGETS_SIGNER_KID],
                "allowed_change_classes": [
                    "public_metadata",
                    "client_credential_rotation",
                    "client_access_change",
                    "signing_key_rotation",
                    "signing_key_cleanup",
                    "root_transition",
                    "emergency_break_glass"
                ]
            },
            {
                "name": "two-person-threshold-probe",
                "threshold": 2,
                "signer_kids": [TUF_TARGETS_SIGNER_KID, threshold_second_signer_kid],
                "allowed_change_classes": ["threshold_probe"]
            }
        ]
    });
    root_json["signers"][TUF_TARGETS_SIGNER_KID] = json!({
        "kid": TUF_TARGETS_SIGNER_KID,
        "enabled": true
    });
    root_json["signers"][threshold_second_signer_kid] = json!({
        "kid": threshold_second_signer_kid,
        "enabled": true
    });
    let root = serde_yaml::to_value(root_json)?;
    let config_trust = mapping_at_mut(value, &["config_trust"])?;
    set_mapping(config_trust, "accepted_roots", Value::Sequence(vec![root]));
    Ok(())
}

fn add_admin_scope(
    value: &mut Value,
    path: &[&str],
    id: &str,
    scope: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = value_at_mut(value, path)?
        .as_sequence_mut()
        .ok_or("auth entries must be a sequence")?;
    for entry in entries {
        let Some(map) = entry.as_mapping_mut() else {
            continue;
        };
        if map
            .get(Value::String("id".to_string()))
            .and_then(Value::as_str)
            != Some(id)
        {
            continue;
        }
        let scopes = map
            .get_mut(Value::String("scopes".to_string()))
            .and_then(Value::as_sequence_mut)
            .ok_or("auth entry scopes must be a sequence")?;
        if !scopes
            .iter()
            .any(|candidate| candidate.as_str() == Some(scope))
        {
            scopes.push(Value::String(scope.to_string()));
        }
    }
    Ok(())
}

fn ensure_bearer_token(
    value: &mut Value,
    id: &str,
    fingerprint: Value,
    required_scopes: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = value_at_mut(value, &["auth", "bearer_tokens"])?
        .as_sequence_mut()
        .ok_or("auth.bearer_tokens must be a sequence")?;
    for entry in entries.iter_mut() {
        let Some(map) = entry.as_mapping_mut() else {
            continue;
        };
        if map
            .get(Value::String("id".to_string()))
            .and_then(Value::as_str)
            != Some(id)
        {
            continue;
        }
        let scopes = map
            .get_mut(Value::String("scopes".to_string()))
            .and_then(Value::as_sequence_mut)
            .ok_or("bearer token scopes must be a sequence")?;
        for scope in required_scopes {
            if !scopes
                .iter()
                .any(|candidate| candidate.as_str() == Some(scope))
            {
                scopes.push(Value::String((*scope).to_string()));
            }
        }
        return Ok(());
    }
    entries.push(serde_yaml::to_value(json!({
        "id": id,
        "fingerprint": fingerprint,
        "scopes": required_scopes,
    }))?);
    Ok(())
}

fn normalize_credential_entries(
    value: &mut Value,
    path: &[&str],
    product: &str,
    credential_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = value_at_mut(value, path)?
        .as_sequence_mut()
        .ok_or_else(|| format!("{} must be a sequence", path.join(".")))?;
    for entry in entries {
        let map = entry
            .as_mapping_mut()
            .ok_or_else(|| format!("{} entries must be mappings", path.join(".")))?;
        let id = map
            .get(Value::String("id".to_string()))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{} entry missing id", path.join(".")))?
            .to_string();
        let fingerprint_env = credential_fingerprint_env(map).ok_or_else(|| {
            format!("{product} {credential_type} {id} missing fingerprint env ref")
        })?;
        if map.get(Value::String("fingerprint".to_string())).is_none() {
            let commitment =
                credential_commitment(product, credential_type, &id, &fingerprint_env)?;
            set_mapping(
                map,
                "fingerprint",
                credential_fingerprint_ref(&fingerprint_env, &commitment)?,
            );
        }
        map.remove(Value::String("hash_env".to_string()));
    }
    Ok(())
}

fn credential_fingerprint_ref(
    env_name: &str,
    commitment: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_yaml::to_value(json!({
        "provider": "env",
        "name": env_name,
        "commitment": commitment,
    }))?)
}

fn credential_commitment(
    product: &str,
    credential_type: &str,
    credential_id: &str,
    fingerprint_env: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let fingerprint = env::var(fingerprint_env)
        .map_err(|_| format!("{fingerprint_env} is required to render governed config"))?;
    let payload = CredentialCommitmentPayload {
        product,
        credential_type,
        credential_id,
        fingerprint: &fingerprint,
    };
    let encoded = serde_json::to_vec(&payload)?;
    Ok(format!("sha256:{}", hex_lower(&Sha256::digest(&encoded))))
}

fn credential_fingerprint_env(map: &Mapping) -> Option<String> {
    if let Some(env_name) = map
        .get(Value::String("hash_env".to_string()))
        .and_then(Value::as_str)
    {
        return Some(env_name.to_string());
    }
    map.get(Value::String("fingerprint".to_string()))
        .and_then(Value::as_mapping)
        .and_then(|fingerprint| {
            fingerprint
                .get(Value::String("name".to_string()))
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
}

fn relay_public_metadata_candidate(yaml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut value: Value = serde_yaml::from_str(yaml)?;
    let instance = mapping_at_mut(&mut value, &["instance"])?;
    set_mapping(
        instance,
        "owner",
        Value::String("Civil Registration Operations Team".to_string()),
    );
    Ok(serde_yaml::to_string(&value)?)
}

fn relay_governed_metadata_candidate(yaml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut value: Value = serde_yaml::from_str(yaml)?;
    let catalog = mapping_at_mut(&mut value, &["catalog"])?;
    set_mapping(
        catalog,
        "title",
        Value::String("Civil Registry Relay (Governed Config Demo)".to_string()),
    );
    set_mapping(
        catalog,
        "description",
        Value::String(
            "Synthetic civil status metadata served after a signed Lab 2 governed config apply."
                .to_string(),
        ),
    );
    Ok(serde_yaml::to_string(&value)?)
}

fn relay_break_glass_candidate(yaml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value: Value = serde_yaml::from_str(yaml)?;
    Ok(serde_yaml::to_string(&value)?)
}

fn notary_rotation_candidate(yaml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let old_public = "REGISTRY_NOTARY_ISSUER_PUBLIC_JWK";
    let new_private = "REGISTRY_NOTARY_ROTATED_ISSUER_JWK";
    let mut value: Value = serde_yaml::from_str(yaml)?;
    let signing_keys = mapping_at_mut(&mut value, &["evidence", "signing_keys"])?;
    let old_key = signing_keys
        .get_mut(Value::String("civil-evidence-demo".to_string()))
        .and_then(Value::as_mapping_mut)
        .ok_or("civil-evidence-demo signing key missing")?;
    set_mapping(old_key, "status", Value::String("publish_only".to_string()));
    set_mapping(
        old_key,
        "publish_until_unix_seconds",
        Value::Number(serde_yaml::Number::from(1_830_297_600u64)),
    );
    old_key.remove(Value::String("private_jwk_env".to_string()));
    set_mapping(
        old_key,
        "public_jwk_env",
        Value::String(old_public.to_string()),
    );

    signing_keys.insert(
        Value::String("civil-evidence-demo-rotated".to_string()),
        serde_yaml::to_value(json!({
            "provider": "local_jwk_env",
            "private_jwk_env": new_private,
            "alg": "EdDSA",
            "kid": "did:web:civil-evidence.demo.example#civil-evidence-demo-key-2",
            "status": "active"
        }))?,
    );
    rotate_notary_credential_profile_signing_key(
        &mut value,
        "civil-evidence-demo",
        "civil-evidence-demo-rotated",
    )?;
    Ok(serde_yaml::to_string(&value)?)
}

fn rotate_notary_credential_profile_signing_key(
    value: &mut Value,
    old_signing_key: &str,
    new_signing_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let profiles = mapping_at_mut(value, &["evidence", "credential_profiles"])?;
    let mut rotated = 0usize;
    for profile in profiles.values_mut() {
        let Some(profile) = profile.as_mapping_mut() else {
            continue;
        };
        if profile
            .get(Value::String("signing_key".to_string()))
            .and_then(Value::as_str)
            == Some(old_signing_key)
        {
            set_mapping(
                profile,
                "signing_key",
                Value::String(new_signing_key.to_string()),
            );
            rotated += 1;
        }
    }
    if rotated == 0 {
        return Err(format!("no credential profile uses signing_key {old_signing_key}").into());
    }
    Ok(())
}

fn notary_break_glass_candidate(yaml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value: Value = serde_yaml::from_str(yaml)?;
    Ok(serde_yaml::to_string(&value)?)
}

async fn write_signed_bundle(
    output: &Path,
    root_path: &Path,
    primary_key_path: &Path,
    second_key_path: &Path,
    bundle: &BundleSpec,
) -> Result<(), Box<dyn std::error::Error>> {
    let repo_dir = output.join("tuf-repo").join(bundle.name);
    let source_dir = repo_dir.join("source");
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let datastore_dir = repo_dir.join("datastore");
    fs::create_dir_all(&source_dir)?;
    fs::create_dir_all(&datastore_dir)?;
    let target_path = source_dir.join(bundle.target_name);
    fs::write(&target_path, &bundle.config_yaml)?;

    let mut target = Target::from_path(&target_path).await?;
    let custom = json!({
        "product": bundle.product,
        "instance_id": bundle.instance_id,
        "environment": bundle.environment,
        "stream_id": bundle.stream_id,
        "bundle_id": bundle.bundle_id,
        "sequence": bundle.sequence,
        "previous_config_hash": bundle.previous_config_hash,
        "config_hash": sha256_uri(bundle.config_yaml.as_bytes()),
        "change_classes": bundle.change_classes,
        "signer_kids": bundle.custom_signer_kids,
        "apply_policy": bundle.apply_policy
    });
    target.custom = custom
        .as_object()
        .ok_or("custom target metadata must be an object")?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    let mut keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
        path: primary_key_path.to_path_buf(),
    })];
    if bundle.sign_with_second_key {
        keys.push(Box::new(LocalKeySource {
            path: second_key_path.to_path_buf(),
        }));
    }
    let version = NonZeroU64::new(bundle.sequence.max(2)).ok_or("nonzero version")?;
    let mut editor = RepositoryEditor::new(root_path).await?;
    editor.targets_version(version)?;
    editor.targets_expires(Utc::now() + chrono::Duration::days(13))?;
    editor.snapshot_version(version);
    editor.snapshot_expires(Utc::now() + chrono::Duration::days(21));
    editor.timestamp_version(version);
    editor.timestamp_expires(Utc::now() + chrono::Duration::days(3));
    editor.add_target(bundle.target_name, target)?;
    let signed = editor.sign(&keys).await?;
    signed.write(&metadata_dir).await?;
    signed
        .copy_targets(&source_dir, &targets_dir, PathExists::Fail)
        .await?;

    let descriptor = json!({
        "name": bundle.name,
        "product": bundle.product,
        "bundle_id": bundle.bundle_id,
        "sequence": bundle.sequence,
        "target_name": bundle.target_name,
        "root_path": format!("tuf-repo/{}/metadata/1.root.json", bundle.name),
        "metadata_dir": format!("tuf-repo/{}/metadata", bundle.name),
        "targets_dir": format!("tuf-repo/{}/targets", bundle.name),
        "datastore_dir": format!("tuf-repo/{}/datastore", bundle.name),
        "change_classes": bundle.change_classes,
        "apply_policy": bundle.apply_policy,
        "previous_config_hash": bundle.previous_config_hash,
        "config_hash": sha256_uri(bundle.config_yaml.as_bytes())
    });
    fs::write(
        output.join("bundles").join(format!("{}.json", bundle.name)),
        serde_json::to_vec_pretty(&descriptor)?,
    )?;
    Ok(())
}

fn initial_record(config: &RuntimeConfig, sequence: u64) -> AntiRollbackRecord {
    AntiRollbackRecord {
        key: AntiRollbackKey {
            product: config.product.to_string(),
            instance_id: config.instance_id.to_string(),
            environment: config.environment.to_string(),
            stream_id: config.stream_id.to_string(),
        },
        last_sequence: sequence,
        last_config_hash: config.internal_hash.clone(),
        root_version: None,
        break_glass: Default::default(),
        local_approvals: Default::default(),
    }
}

fn write_state_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o666);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn write_summary(
    output: &Path,
    relay: &RuntimeConfig,
    notary: &RuntimeConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = format!(
        r#"# Lab 2 Governed Operations Evidence

1. Simple is improved and still works: see `00-lab1-smoke.txt`.
2. Governance is opt-in: rendered configs under `runtime-config/` contain `accepted_roots`; committed configs do not.
3. Before state is observable: see initial posture JSON files.
4. Safe live change applies: see Relay apply response and final posture.
5. Key rotation applies: see Notary apply response, readiness posture, and credential/JWKS evidence.
6. Guardrails fail closed: see negative-case response JSON files.
7. Break-glass is governed: see break-glass response JSON files and anti-rollback assertions.

## Initial Runtime Hashes

- Relay: `{}`
- Notary: `{}`
"#,
        relay.internal_hash, notary.internal_hash
    );
    fs::write(output.join("evidence/summary.md"), text)?;
    Ok(())
}

fn write_manifest(
    output: &Path,
    threshold_second_signer_kid: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut artifacts = Vec::new();
    collect_artifacts(output, output, &mut artifacts)?;
    artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = Manifest {
        generated_at: Utc::now().to_rfc3339(),
        tuf_targets_signer_kid: TUF_TARGETS_SIGNER_KID.to_string(),
        tuf_threshold_second_signer_kid: threshold_second_signer_kid.to_string(),
        artifacts,
    };
    fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

fn collect_artifacts(
    base: &Path,
    dir: &Path,
    artifacts: &mut Vec<ManifestArtifact>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_artifacts(base, &path, artifacts)?;
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("manifest.json") {
            continue;
        }
        let relative = path
            .strip_prefix(base)?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path)?;
        artifacts.push(ManifestArtifact {
            role: artifact_role(&relative).to_string(),
            secret: is_secret_artifact(&relative),
            secret_classification: if is_secret_artifact(&relative) {
                "secret"
            } else {
                "public"
            }
            .to_string(),
            sha256: hex_lower(&Sha256::digest(&bytes)),
            path: relative,
        });
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn artifact_role(path: &str) -> &str {
    path.split('/').next().unwrap_or("unknown")
}

fn is_secret_artifact(path: &str) -> bool {
    path.starts_with("keys/") && !path.ends_with("public.jwk") && !path.ends_with("tuf-root.json")
}

fn tough_fixture(name: &str) -> PathBuf {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .expect("CARGO_HOME or HOME is set");
    let src_root = cargo_home.join("registry/src");
    let registry = fs::read_dir(&src_root)
        .expect("cargo registry src exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("tough-0.22.0/tests/data").is_dir())
        .expect("tough-0.22.0 source fixture directory exists");
    registry.join("tough-0.22.0/tests/data").join(name)
}

fn root_mapping_mut(value: &mut Value) -> Result<&mut Mapping, Box<dyn std::error::Error>> {
    value
        .as_mapping_mut()
        .ok_or_else(|| "YAML root must be a mapping".into())
}

fn mapping_at_mut<'a>(
    value: &'a mut Value,
    path: &[&str],
) -> Result<&'a mut Mapping, Box<dyn std::error::Error>> {
    value_at_mut(value, path)?
        .as_mapping_mut()
        .ok_or_else(|| format!("{} must be a mapping", path.join(".")).into())
}

fn value_at_mut<'a>(
    value: &'a mut Value,
    path: &[&str],
) -> Result<&'a mut Value, Box<dyn std::error::Error>> {
    let mut current = value;
    for key in path {
        current = current
            .as_mapping_mut()
            .ok_or_else(|| format!("{key} parent must be a mapping"))?
            .get_mut(Value::String((*key).to_string()))
            .ok_or_else(|| format!("missing YAML path {}", path.join(".")))?;
    }
    Ok(current)
}

fn set_mapping(map: &mut Mapping, key: &str, value: Value) {
    map.insert(Value::String(key.to_string()), value);
}
