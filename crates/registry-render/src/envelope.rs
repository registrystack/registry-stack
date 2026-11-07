//! The template payload contract. The renderer builds one envelope value,
//! canonicalizes it with RFC 8785 (JCS), injects those exact bytes as
//! `sys.inputs.data`, and hashes the same bytes as `dataSha256`. The
//! injected bytes and the hashed bytes can never diverge.

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::problem::{ProblemKind, RenderProblem};

/// Everything the template receives, in one JSON value.
pub struct EnvelopeInput<'a> {
    pub document_id: &'a str,
    pub document_version: u32,
    pub labels: &'a BTreeMap<String, Value>,
    pub locale: Option<&'a str>,
    pub issued_at: DateTime<Utc>,
    pub data: &'a Value,
    /// Asset name -> exact base64 text as received (hashing covers it).
    pub assets: &'a BTreeMap<String, String>,
    /// The `signing` member, present only on the seal route.
    pub signing: Option<&'a SigningPayload>,
}

/// What a sealed render tells its template, as the `signing` member:
/// `{"mode": "seal", "signerName": ..., "testOnly": ...}`. The plain route
/// never carries it, so a template can print its seal block only on files
/// that are sealed. It holds no key, certificate or subject value beyond
/// the display name the certificate already shows every relying party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningPayload {
    /// The seal certificate's display name (organization, else common
    /// name); absent when the certificate names neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_name: Option<String>,
    /// Whether the runtime file declares `assuranceProfile: local`.
    pub test_only: bool,
}

/// Fixed RFC 3339 rendering of the issuance time: UTC, second precision.
/// Templates display it as a string; it is also the world clock.
pub fn format_issued_at(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Build the envelope value. Field order here is irrelevant to bytes: the
/// canonicalization step is what fixes them.
pub fn build_envelope(input: &EnvelopeInput<'_>) -> Value {
    let mut envelope = Map::new();
    envelope.insert("data".into(), input.data.clone());
    envelope.insert(
        "assets".into(),
        Value::Object(
            input
                .assets
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect(),
        ),
    );
    envelope.insert(
        "labels".into(),
        Value::Object(
            input
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ),
    );
    if let Some(locale) = input.locale {
        envelope.insert("locale".into(), Value::String(locale.to_owned()));
    }
    envelope.insert(
        "issuedAt".into(),
        Value::String(format_issued_at(input.issued_at)),
    );
    let mut document = Map::new();
    document.insert("id".into(), Value::String(input.document_id.to_owned()));
    document.insert(
        "version".into(),
        Value::Number(input.document_version.into()),
    );
    envelope.insert("document".into(), Value::Object(document));
    if let Some(signing) = input.signing {
        let mut member = Map::new();
        member.insert("mode".into(), Value::String("seal".to_owned()));
        if let Some(name) = &signing.signer_name {
            member.insert("signerName".into(), Value::String(name.clone()));
        }
        member.insert("testOnly".into(), Value::Bool(signing.test_only));
        envelope.insert("signing".into(), Value::Object(member));
    }
    Value::Object(envelope)
}

/// Canonicalize with the single Registry Stack RFC 8785 implementation.
/// Every JSON number must be representable; infinities and NaN are refused
/// as data problems, not silently coerced.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, RenderProblem> {
    registry_platform_canonical_json::canonicalize_json(value).map_err(|err| {
        RenderProblem::new(
            ProblemKind::DataInvalid,
            format!("request values cannot be canonically serialized: {err}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalization_is_key_order_independent() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":"x","x":"y"}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":"y","y":"x"},"b":1}"#).unwrap();
        assert_eq!(canonical_bytes(&a).unwrap(), canonical_bytes(&b).unwrap());
    }

    #[test]
    fn envelope_contains_every_template_visible_field() {
        let labels: BTreeMap<String, Value> =
            BTreeMap::from([("ar".to_owned(), serde_json::json!({"title": "وصل"}))]);
        let data = serde_json::json!({"reference": "R-1"});
        let assets = BTreeMap::from([("photo".to_owned(), "aGk=".to_owned())]);
        let at = DateTime::parse_from_rfc3339("2026-09-16T10:32:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let envelope = build_envelope(&EnvelopeInput {
            document_id: "receipt",
            document_version: 3,
            labels: &labels,
            locale: Some("ar"),
            issued_at: at,
            data: &data,
            assets: &assets,
            signing: None,
        });
        assert_eq!(envelope["data"]["reference"], "R-1");
        assert_eq!(envelope["assets"]["photo"], "aGk=");
        assert_eq!(envelope["labels"]["ar"]["title"], "وصل");
        assert_eq!(envelope["locale"], "ar");
        assert_eq!(envelope["issuedAt"], "2026-09-16T10:32:00Z");
        assert_eq!(envelope["document"]["id"], "receipt");
        assert_eq!(envelope["document"]["version"], 3);
        // The renderer version appears nowhere in the envelope.
        let text = envelope.to_string();
        assert!(!text.contains("renderer"));
        assert!(!text.contains("typst"));
    }

    #[test]
    fn the_signing_member_appears_only_on_a_sealed_render() {
        let labels = BTreeMap::new();
        let assets = BTreeMap::new();
        let data = serde_json::json!({});
        let at = DateTime::parse_from_rfc3339("2026-09-16T10:32:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let input = |signing| EnvelopeInput {
            document_id: "licence",
            document_version: 1,
            labels: &labels,
            locale: None,
            issued_at: at,
            data: &data,
            assets: &assets,
            signing,
        };
        assert!(build_envelope(&input(None)).get("signing").is_none());
        let named = SigningPayload {
            signer_name: Some("Ministry of Licensing".to_owned()),
            test_only: false,
        };
        assert_eq!(
            build_envelope(&input(Some(&named)))["signing"],
            serde_json::json!({"mode":"seal","signerName":"Ministry of Licensing","testOnly":false})
        );
        let unnamed_test = SigningPayload {
            signer_name: None,
            test_only: true,
        };
        assert_eq!(
            build_envelope(&input(Some(&unnamed_test)))["signing"],
            serde_json::json!({"mode":"seal","testOnly":true}),
            "a certificate without a display name prints none"
        );
    }
}
