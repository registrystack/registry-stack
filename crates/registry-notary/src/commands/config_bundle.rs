use crate::*;

pub(crate) async fn config_verify_bundle(
    args: ConfigVerifyBundleArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let verified = match verify_config_bundle(&args.bundle_dir, &args.anchor_path) {
        Ok(verified) => verified,
        Err(error) => {
            let result = bundle_verify_rejection_result(&error);
            print_config_verify_bundle_report(config_verify_bundle_report(
                result,
                "unknown",
                None,
                None,
                None,
                None,
                Some((result, error.to_string())),
            ))?;
            return Err(Box::new(error));
        }
    };
    let key = antirollback_key_from_verified_bundle(&verified);
    if let Err(error) = verify_bundle_state_read_only(
        &args.state_path,
        &key,
        verified.manifest.sequence,
        &verified.manifest.config_hash,
        &verified.manifest_hash,
    ) {
        print_config_verify_bundle_report(config_verify_bundle_report(
            "rejected_rollback",
            &verified.manifest.stream_id,
            Some(verified.manifest.bundle_id.clone()),
            Some(verified.manifest.sequence),
            verified.manifest.previous_config_hash.clone(),
            Some(verified.manifest.config_hash.clone()),
            Some(("rejected_rollback", error.to_string())),
        ))?;
        return Err(Box::new(error));
    }
    let config_text = std::str::from_utf8(&verified.config_bytes)?;
    let parsed = match parse_config_document(config_text).and_then(|parsed| {
        validate_signed_bundle_config_document(&parsed)?;
        Ok(parsed)
    }) {
        Ok(parsed) => parsed,
        Err(error) => {
            print_config_verify_bundle_report(config_verify_bundle_report(
                "rejected_validation",
                &verified.manifest.stream_id,
                Some(verified.manifest.bundle_id.clone()),
                Some(verified.manifest.sequence),
                verified.manifest.previous_config_hash.clone(),
                Some(verified.manifest.config_hash.clone()),
                Some(("rejected_validation", error.to_string())),
            ))?;
            return Err(error);
        }
    };
    if let Err(error) =
        compile_notary_runtime_with_provenance(parsed.config, ConfigSource::SignedBundleFile, None)
    {
        print_config_verify_bundle_report(config_verify_bundle_report(
            "rejected_validation",
            &verified.manifest.stream_id,
            Some(verified.manifest.bundle_id.clone()),
            Some(verified.manifest.sequence),
            verified.manifest.previous_config_hash.clone(),
            Some(verified.manifest.config_hash.clone()),
            Some(("rejected_validation", error.to_string())),
        ))?;
        return Err(Box::new(error));
    }
    print_config_verify_bundle_report(config_verify_bundle_report(
        "verified",
        &verified.manifest.stream_id,
        Some(verified.manifest.bundle_id),
        Some(verified.manifest.sequence),
        verified.manifest.previous_config_hash,
        Some(verified.manifest.config_hash),
        None,
    ))?;
    Ok(())
}

pub(crate) fn print_config_verify_bundle_report(
    report: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

pub(crate) fn config_verify_bundle_report(
    result: &'static str,
    stream_id: &str,
    bundle_id: Option<String>,
    bundle_sequence: Option<u64>,
    previous_config_hash: Option<String>,
    config_hash: Option<String>,
    error: Option<(&'static str, String)>,
) -> Value {
    let errors = error
        .map(|(code, message)| vec![json!({ "code": code, "message": message })])
        .unwrap_or_default();
    json!({
        "schema": "registry.platform.config_apply_report.v1",
        "attempt_id": Ulid::new().to_string(),
        "component": "registry-notary",
        "stream_id": stream_id,
        "source": ConfigSource::SignedBundleFile.as_posture_str(),
        "bundle_id": bundle_id,
        "bundle_sequence": bundle_sequence,
        "previous_config_hash": previous_config_hash,
        "config_hash": config_hash,
        "result": result,
        "restart_required": false,
        "change_classes": [],
        "affected_components": [],
        "warnings": [],
        "errors": errors,
    })
}

pub(crate) fn path_for_json(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(crate) fn required_config_path(
    path: Option<&Path>,
) -> Result<&Path, Box<dyn std::error::Error>> {
    path.ok_or_else(|| "--config is required for this command".into())
}

pub(crate) fn compiled_build_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    if cfg!(feature = "pkcs11") {
        features.push("pkcs11");
    }
    if cfg!(feature = "registry-notary-cel") {
        features.push("registry-notary-cel");
    }
    features
}

pub(crate) fn build_info() -> Value {
    json!({
        "package": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "build_features": compiled_build_features(),
        "capabilities": {
            "signing_providers": {
                "local_jwk_env": true,
                "pkcs11": cfg!(feature = "pkcs11"),
            },
            "cel": cfg!(feature = "registry-notary-cel"),
        },
    })
}
#[cfg(test)]
#[path = "config_bundle/tests.rs"]
mod tests;
