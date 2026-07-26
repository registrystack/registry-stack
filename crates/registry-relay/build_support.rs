// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

pub fn declared_feature_names(manifest: &str) -> Result<Vec<String>, String> {
    let document = manifest
        .parse::<toml::Table>()
        .map_err(|error| format!("Cargo.toml is not valid TOML: {error}"))?;
    let features = document
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "Cargo.toml must contain a [features] table".to_string())?;
    Ok(features
        .keys()
        .filter(|feature| feature.as_str() != "default")
        .cloned()
        .collect())
}

pub fn validate_requested_profile(
    requested: &str,
    declared: &[String],
    enabled: &[String],
) -> Result<(), String> {
    if requested
        .bytes()
        .any(|byte| !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b','))
    {
        return Err("use comma-separated Cargo feature names".to_string());
    }
    if requested.starts_with(',') || requested.ends_with(',') || requested.contains(",,") {
        return Err("feature list must not contain empty entries".to_string());
    }

    let requested = if requested.is_empty() {
        Vec::new()
    } else {
        requested.split(',').map(str::to_string).collect::<Vec<_>>()
    };
    let requested_set = requested.iter().collect::<BTreeSet<_>>();
    if requested_set.len() != requested.len() {
        return Err("feature list must not contain duplicates".to_string());
    }

    let mut canonical = requested.clone();
    canonical.sort();
    if requested != canonical {
        return Err(format!(
            "feature list must use canonical order: {}",
            canonical.join(",")
        ));
    }

    let declared = declared.iter().collect::<BTreeSet<_>>();
    let unknown = requested
        .iter()
        .filter(|feature| !declared.contains(feature))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(format!("unknown Cargo features: {}", unknown.join(",")));
    }

    let enabled = enabled.iter().collect::<BTreeSet<_>>();
    let missing = enabled
        .difference(&requested_set)
        .map(|feature| feature.as_str())
        .collect::<Vec<_>>();
    let inactive = requested_set
        .difference(&enabled)
        .map(|feature| feature.as_str())
        .collect::<Vec<_>>();
    if !missing.is_empty() || !inactive.is_empty() {
        return Err(format!(
            "requested profile does not match Cargo's effective feature set \
             (missing: [{}], inactive: [{}])",
            missing.join(","),
            inactive.join(",")
        ));
    }
    Ok(())
}
