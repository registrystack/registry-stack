//! Value-free conversion of an application's persisted accepted Review binding.

use registry_casework_core::{
    PolicyBinding, ReviewRequestAccepted, SubjectBinding, SubmissionDigest,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedBindingValidation {
    pub path: &'static str,
    pub reason: &'static str,
}

/// Validate all four fields before authentication or network effects. Paths
/// and reasons are fixed strings and never include an input member or value.
pub fn accepted_binding(value: Value) -> Result<ReviewRequestAccepted, AcceptedBindingValidation> {
    let invalid = |path, reason| AcceptedBindingValidation { path, reason };
    let object = value
        .as_object()
        .ok_or_else(|| invalid("$", "object-required"))?;
    if object
        .keys()
        .any(|key| !["requestId", "policy", "subject", "submissionDigest"].contains(&key.as_str()))
    {
        return Err(invalid("$", "field-not-declared"));
    }
    let request_id = member::<Uuid>(object, "requestId", "$.requestId")?;
    if request_id.is_nil() {
        return Err(invalid("$.requestId", "binding-invalid"));
    }
    let policy = member::<PolicyBinding>(object, "policy", "$.policy")?;
    policy
        .check()
        .map_err(|_| invalid("$.policy", "binding-invalid"))?;
    let subject = member::<SubjectBinding>(object, "subject", "$.subject")?;
    subject
        .check()
        .map_err(|_| invalid("$.subject", "binding-invalid"))?;
    let submission_digest =
        member::<SubmissionDigest>(object, "submissionDigest", "$.submissionDigest")?;
    Ok(ReviewRequestAccepted {
        request_id,
        policy,
        subject,
        submission_digest,
    })
}

fn member<T: DeserializeOwned>(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
    path: &'static str,
) -> Result<T, AcceptedBindingValidation> {
    let value = object.get(key).ok_or(AcceptedBindingValidation {
        path,
        reason: "field-required",
    })?;
    T::deserialize(value).map_err(|_| AcceptedBindingValidation {
        path,
        reason: "binding-invalid",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepted_binding_reports_bounded_paths_without_input_values() {
        let valid = json!({"requestId":Uuid::new_v4(),"policy":{"id":"review","version":"1","digest":format!("sha256:{}", "a".repeat(64))},"subject":{"source":"registry","type":"case","id":"one","version":"1","digest":format!("sha256:{}", "b".repeat(64))},"submissionDigest":format!("sha256:{}", "c".repeat(64))});
        assert!(accepted_binding(valid.clone()).is_ok());
        let mut nil = valid.clone();
        nil["requestId"] = json!(Uuid::nil());
        assert_eq!(
            accepted_binding(nil).unwrap_err(),
            AcceptedBindingValidation {
                path: "$.requestId",
                reason: "binding-invalid"
            }
        );
        for (key, path) in [
            ("requestId", "$.requestId"),
            ("policy", "$.policy"),
            ("subject", "$.subject"),
            ("submissionDigest", "$.submissionDigest"),
        ] {
            let mut value = valid.clone();
            value[key] = json!("canary-sensitive-binding-value");
            let error = accepted_binding(value).unwrap_err();
            assert_eq!(error.path, path);
            assert_eq!(error.reason, "binding-invalid");
            assert!(!format!("{error:?}").contains("canary"));
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert_eq!(
                accepted_binding(missing).unwrap_err().reason,
                "field-required"
            );
        }
    }
}
