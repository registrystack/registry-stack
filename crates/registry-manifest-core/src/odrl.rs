// SPDX-License-Identifier: Apache-2.0
//! Runtime-free ODRL JSON-LD projection for source-owned policy exports.

use std::collections::{BTreeMap, BTreeSet};

use oxiri::Iri;
use serde_json::{json, Map, Value};
use thiserror::Error;

const ODRL_NAMESPACE: &str = "http://www.w3.org/ns/odrl/2/";
const DCTERMS_NAMESPACE: &str = "http://purl.org/dc/terms/";
const ODRL_PART_OF: &str = "http://www.w3.org/ns/odrl/2/partOf";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub uid: String,
    pub profile: Vec<String>,
    pub permissions: Vec<Permission>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Permission {
    pub target: PolicyAsset,
    pub action: String,
    pub constraints: Vec<Constraint>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PolicyAsset {
    pub uid: String,
    pub part_of: Option<String>,
    pub properties: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Constraint {
    pub left_operand: String,
    pub operator: String,
    pub right_operand: Operand,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Literal(Value),
    Set(Vec<Value>),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OdrlError {
    #[error("{path} must be an absolute HTTP(S) or URN IRI: {value}")]
    InvalidIri { path: String, value: String },
    #[error("policy UID is duplicated: {uid}")]
    DuplicatePolicyUid { uid: String },
    #[error("policy must contain at least one permission: {uid}")]
    EmptyPolicy { uid: String },
    #[error("set operand must contain at least one value: {path}")]
    EmptySet { path: String },
    #[error("literal operand must be a non-null string, boolean, or number: {path}")]
    InvalidLiteral { path: String },
    #[error("asset property aliases a structural member: {path}")]
    StructuralAssetProperty { path: String },
}

/// Render a deterministic JSON-LD collection without inferring any policy.
pub fn render_policy_collection(id: &str, policies: &[Policy]) -> Result<Value, OdrlError> {
    validate_iri(id, "collection.id")?;

    let mut seen = BTreeSet::new();
    for (policy_index, policy) in policies.iter().enumerate() {
        validate_policy(policy, policy_index)?;
        if !seen.insert(policy.uid.as_str()) {
            return Err(OdrlError::DuplicatePolicyUid {
                uid: policy.uid.clone(),
            });
        }
    }

    let mut ordered = policies.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.uid.cmp(&right.uid));
    let graph = ordered.into_iter().map(render_policy).collect::<Vec<_>>();

    Ok(json!({
        "@context": {
            "odrl": ODRL_NAMESPACE,
            "dcterms": DCTERMS_NAMESPACE,
        },
        "@id": id,
        "@graph": graph,
    }))
}

fn validate_policy(policy: &Policy, policy_index: usize) -> Result<(), OdrlError> {
    let path = format!("policies[{policy_index}]");
    validate_iri(&policy.uid, &format!("{path}.uid"))?;
    for (profile_index, profile) in policy.profile.iter().enumerate() {
        validate_iri(profile, &format!("{path}.profile[{profile_index}]"))?;
    }
    if policy.permissions.is_empty() {
        return Err(OdrlError::EmptyPolicy {
            uid: policy.uid.clone(),
        });
    }
    for (permission_index, permission) in policy.permissions.iter().enumerate() {
        validate_permission(
            permission,
            &format!("{path}.permissions[{permission_index}]"),
        )?;
    }
    Ok(())
}

fn validate_permission(permission: &Permission, path: &str) -> Result<(), OdrlError> {
    validate_iri(&permission.action, &format!("{path}.action"))?;
    validate_asset(&permission.target, &format!("{path}.target"))?;
    for (constraint_index, constraint) in permission.constraints.iter().enumerate() {
        validate_constraint(
            constraint,
            &format!("{path}.constraints[{constraint_index}]"),
        )?;
    }
    Ok(())
}

fn validate_asset(asset: &PolicyAsset, path: &str) -> Result<(), OdrlError> {
    validate_iri(&asset.uid, &format!("{path}.uid"))?;
    if let Some(part_of) = asset.part_of.as_deref() {
        validate_iri(part_of, &format!("{path}.part_of"))?;
    }
    for property in asset.properties.keys() {
        let property_path = format!("{path}.properties[{property}]");
        validate_iri(property, &property_path)?;
        if property == ODRL_PART_OF || property == RDF_TYPE {
            return Err(OdrlError::StructuralAssetProperty {
                path: property_path,
            });
        }
    }
    Ok(())
}

fn validate_constraint(constraint: &Constraint, path: &str) -> Result<(), OdrlError> {
    validate_iri(&constraint.left_operand, &format!("{path}.left_operand"))?;
    validate_iri(&constraint.operator, &format!("{path}.operator"))?;
    match &constraint.right_operand {
        Operand::Literal(value) => validate_literal(value, &format!("{path}.right_operand")),
        Operand::Set(values) => {
            if values.is_empty() {
                return Err(OdrlError::EmptySet {
                    path: format!("{path}.right_operand"),
                });
            }
            for (value_index, value) in values.iter().enumerate() {
                validate_literal(value, &format!("{path}.right_operand[{value_index}]"))?;
            }
            Ok(())
        }
    }
}

fn validate_literal(value: &Value, path: &str) -> Result<(), OdrlError> {
    if matches!(value, Value::String(_) | Value::Bool(_) | Value::Number(_)) {
        Ok(())
    } else {
        Err(OdrlError::InvalidLiteral {
            path: path.to_owned(),
        })
    }
}

fn validate_iri(value: &str, path: &str) -> Result<(), OdrlError> {
    let valid = Iri::parse(value).is_ok_and(|iri| match iri.scheme() {
        scheme if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") => {
            iri.authority()
                .is_some_and(|authority| !authority.trim().is_empty())
        }
        scheme if scheme.eq_ignore_ascii_case("urn") => value
            .strip_prefix("urn:")
            .or_else(|| value.strip_prefix("URN:"))
            .is_some_and(|identifier| !identifier.trim().is_empty()),
        _ => false,
    });
    if valid {
        Ok(())
    } else {
        Err(OdrlError::InvalidIri {
            path: path.to_owned(),
            value: value.to_owned(),
        })
    }
}

fn render_policy(policy: &Policy) -> Value {
    let mut profiles = policy.profile.iter().collect::<Vec<_>>();
    profiles.sort();
    profiles.dedup();

    let mut permissions = policy
        .permissions
        .iter()
        .map(render_permission)
        .collect::<Vec<_>>();
    permissions.sort_by_key(Value::to_string);

    json!({
        "@id": policy.uid,
        "@type": "odrl:Set",
        "odrl:uid": iri_object(&policy.uid),
        "odrl:profile": profiles
            .into_iter()
            .map(|profile| iri_object(profile))
            .collect::<Vec<_>>(),
        "odrl:permission": permissions,
    })
}

fn render_permission(permission: &Permission) -> Value {
    let mut constraints = permission
        .constraints
        .iter()
        .map(render_constraint)
        .collect::<Vec<_>>();
    constraints.sort_by_key(Value::to_string);

    let mut rendered = json!({
        "odrl:target": render_asset(&permission.target),
        "odrl:action": iri_object(&permission.action),
    });
    if !constraints.is_empty() {
        rendered["odrl:constraint"] = Value::Array(constraints);
    }
    rendered
}

fn render_asset(asset: &PolicyAsset) -> Value {
    let mut rendered = Map::new();
    rendered.insert("@id".to_owned(), Value::String(asset.uid.clone()));
    rendered.insert("@type".to_owned(), Value::String("odrl:Asset".to_owned()));
    if let Some(part_of) = asset.part_of.as_deref() {
        rendered.insert("odrl:partOf".to_owned(), iri_object(part_of));
    }
    for (property, value) in &asset.properties {
        rendered.insert(property.clone(), value.clone());
    }
    Value::Object(rendered)
}

fn render_constraint(constraint: &Constraint) -> Value {
    json!({
        "odrl:leftOperand": iri_object(&constraint.left_operand),
        "odrl:operator": iri_object(&constraint.operator),
        "odrl:rightOperand": render_operand(&constraint.right_operand),
    })
}

fn render_operand(operand: &Operand) -> Value {
    match operand {
        Operand::Literal(value) => json!({"@value": value}),
        Operand::Set(values) => json!({
            "@list": values
                .iter()
                .map(|value| json!({"@value": value}))
                .collect::<Vec<_>>(),
        }),
    }
}

fn iri_object(iri: &str) -> Value {
    json!({"@id": iri})
}
