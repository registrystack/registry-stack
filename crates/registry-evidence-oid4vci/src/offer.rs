//! What an offer carries, and what a wallet is handed to redeem it.
//!
//! An offer is created by an adopter against an already authorized request, and
//! it has to survive until a wallet redeems it. What survives is exactly the
//! Evidence request the adopter asked for, held in the bounded store as
//! zeroizing text, so the wallet's later `/credential` call needs nothing but
//! its own proofs to complete. Nothing in this module decides what may be
//! requested: the credential configuration it copies from is the Evidence
//! bundle's, through [`crate::metadata::CredentialCatalog`].
//!
//! Selector values are personal data. They are held only inside a
//! [`crate::store::PreparedRequest`], which zeroizes on drop and redacts its
//! own `Debug`, and they are never logged, never returned, and never placed in
//! an error.

use std::collections::{BTreeMap, BTreeSet};

use registry_evidence_client::{
    AssuranceProfile, EvidenceResponseFormat, ExpectedOutputDocument, HolderBoundRequestSpec,
    HolderPublicKey, SelectorValue, SelectorValueOrigin, SubjectExpectations, SubjectRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::form_urlencoded;
use zeroize::Zeroizing;

use crate::{
    metadata::CredentialConfiguration, PRE_AUTHORIZED_CODE_GRANT_TYPE, TRANSACTION_CODE_INPUT_MODE,
    TRANSACTION_CODE_LENGTH,
};

/// How long an assertion this service asks for may remain valid.
///
/// A holder-bound credential is presented later, by the holder, so its validity
/// is not the length of one relying-party exchange. A day is the widest window
/// this service asks for and the Evidence deployment may hold it shorter.
const MAXIMUM_ASSERTION_LIFETIME_SECONDS: u64 = 86_400;

/// The clock skew this service tolerates between itself and Evidence.
const CLOCK_SKEW_SECONDS: u64 = 60;

/// The three scalar shapes a selector value may take, in a form that survives a
/// round trip through the store.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OfferedSelectorValue {
    Boolean(bool),
    Integer(i64),
    String(String),
}

impl From<OfferedSelectorValue> for SelectorValue {
    fn from(value: OfferedSelectorValue) -> Self {
        match value {
            OfferedSelectorValue::Boolean(value) => Self::Boolean(value),
            OfferedSelectorValue::Integer(value) => Self::Integer(value),
            OfferedSelectorValue::String(value) => Self::String(value),
        }
    }
}

/// One subject as the adopter stated it: a role the credential configuration
/// declares, and the values for it when that role's selector reads them from
/// the request.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestedSubject {
    pub role: String,
    /// Present only for a selector profile whose values originate in the
    /// request. Every other profile is resolved by Evidence from the
    /// authenticated caller, and stating values for one here is refused.
    #[serde(default)]
    pub selector_values: Option<BTreeMap<String, OfferedSelectorValue>>,
}

/// One subject of a stored offer, with the selector profile the credential
/// configuration declared for its role.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfferedSubject {
    pub role: String,
    pub selector_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_values: Option<BTreeMap<String, OfferedSelectorValue>>,
}

/// The Evidence request an offer stands for.
///
/// Written when the offer is created and read when the wallet presents its
/// proofs, so the credential a wallet receives is the one the adopter was
/// authorized for and the configuration is the one that was published then.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfferedRequest {
    pub requirement: String,
    pub purpose: String,
    pub evidence_type: String,
    pub issued_by: String,
    pub provided_by: String,
    pub configuration_revision: String,
    pub assurance_profile: AssuranceProfile,
    pub subjects: Vec<OfferedSubject>,
    pub expected_outputs: Vec<ExpectedOutputDocument>,
}

impl OfferedRequest {
    /// Rebuild the Evidence request, adding the holder keys the wallet proved.
    ///
    /// One request for every key presented together: the batch is the point,
    /// because it is one authorization decision and one source acquisition. The
    /// keys are passed through in the order the proofs arrived and nothing here
    /// derives anything from them.
    #[must_use]
    pub fn into_spec(self, holder_keys: Vec<HolderPublicKey>) -> HolderBoundRequestSpec {
        let subjects = self
            .subjects
            .into_iter()
            .map(|subject| SubjectRequest {
                role: subject.role,
                selector_profile: subject.selector_profile,
                selector_values: subject.selector_values.map(|values| {
                    values
                        .into_iter()
                        .map(|(name, value)| (name, value.into()))
                        .collect()
                }),
            })
            .collect();
        HolderBoundRequestSpec {
            response_format: EvidenceResponseFormat::SdJwtVcBatch,
            requirement: self.requirement,
            purpose: self.purpose,
            evidence_type: self.evidence_type,
            issued_by: self.issued_by,
            provided_by: self.provided_by,
            configuration_revision: self.configuration_revision,
            expected_assurance_profile: self.assurance_profile,
            subjects,
            holder_keys,
            expected_outputs: self.expected_outputs,
            maximum_assertion_lifetime_seconds: MAXIMUM_ASSERTION_LIFETIME_SECONDS,
            clock_skew_seconds: CLOCK_SKEW_SECONDS,
            // A holder-bound response is verified at presentation, by whoever
            // it is presented to. This service verifies nothing and pins
            // nothing, so it adopts the bindings the response carries and
            // hands them on inside the credential.
            subject_expectations: SubjectExpectations::AcceptFirstUse,
        }
    }
}

/// Why an offer request could not be turned into an Evidence request.
///
/// Every variant names a shape fault. None of them carries a selector value, a
/// code, or any other part of the request body.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OfferError {
    #[error("the credential configuration is not offered by this deployment")]
    UnknownConfiguration,
    #[error("the offered subjects do not match the credential configuration")]
    SubjectMismatch,
    #[error("a selector value is not one the credential configuration declares")]
    SelectorMismatch,
}

/// Build the Evidence request one offer stands for.
///
/// The credential configuration is the Evidence bundle's, so this checks the
/// adopter's subjects against it rather than against anything stated here. Each
/// declared subject is answered by exactly one offered subject, so an offer
/// that names one role twice and leaves another unnamed is refused while the
/// offer is being created, rather than by Evidence once a wallet has already
/// spent its pre-authorized code and its access token on it. A profile whose
/// values Evidence resolves from the authenticated caller must carry none, and
/// a profile whose values originate in the request must carry exactly the
/// declared fields.
pub fn offered_request(
    configuration: &CredentialConfiguration,
    catalog_issued_by: &str,
    catalog_provided_by: &str,
    assurance_profile: AssuranceProfile,
    subjects: Vec<RequestedSubject>,
) -> Result<OfferedRequest, OfferError> {
    if subjects.len() != configuration.subjects.len() {
        return Err(OfferError::SubjectMismatch);
    }
    let mut resolved = Vec::with_capacity(subjects.len());
    let mut answered: BTreeSet<usize> = BTreeSet::new();
    for offered in subjects {
        let declared = configuration
            .subjects
            .iter()
            .position(|subject| subject.role == offered.role)
            .filter(|declared| answered.insert(*declared))
            .ok_or(OfferError::SubjectMismatch)?;
        let declared = &configuration.subjects[declared];
        let values = match declared.selector.value_origin {
            SelectorValueOrigin::Request => {
                let values = offered
                    .selector_values
                    .ok_or(OfferError::SelectorMismatch)?;
                if values.len() != declared.selector.fields.len()
                    || !declared
                        .selector
                        .fields
                        .iter()
                        .all(|field| values.contains_key(field.name()))
                {
                    return Err(OfferError::SelectorMismatch);
                }
                Some(values)
            }
            SelectorValueOrigin::AuthenticatedContext | SelectorValueOrigin::AuthenticatedGrant => {
                if offered.selector_values.is_some() {
                    return Err(OfferError::SelectorMismatch);
                }
                None
            }
        };
        resolved.push(OfferedSubject {
            role: declared.role.clone(),
            selector_profile: declared.selector.profile.clone(),
            selector_values: values,
        });
    }
    Ok(OfferedRequest {
        requirement: configuration.id.clone(),
        purpose: configuration.purpose.clone(),
        evidence_type: configuration.vct.clone(),
        issued_by: catalog_issued_by.to_owned(),
        provided_by: catalog_provided_by.to_owned(),
        configuration_revision: configuration.configuration_revision.clone(),
        assurance_profile,
        subjects: resolved,
        expected_outputs: configuration.expected_outputs.clone(),
    })
}

/// The credential offer object a wallet reads.
///
/// The grant member is spelled `pre-authorized_code`, inside the grant type
/// `urn:ietf:params:oauth:grant-type:pre-authorized_code`. Both spellings are
/// what OpenID4VCI 1.0 fixed, and a wallet compares them exactly.
#[must_use]
pub fn credential_offer(
    credential_issuer: &str,
    configuration_id: &str,
    pre_authorized_code: &str,
    with_transaction_code: bool,
) -> Value {
    let mut grant = json!({"pre-authorized_code": pre_authorized_code});
    if with_transaction_code {
        grant["tx_code"] = json!({
            "input_mode": TRANSACTION_CODE_INPUT_MODE,
            "length": TRANSACTION_CODE_LENGTH,
        });
    }
    json!({
        // The identifier as the configuration holds it: the offer names the
        // same issuer a wallet's proof will be compared against.
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [configuration_id],
        "grants": {PRE_AUTHORIZED_CODE_GRANT_TYPE: grant},
    })
}

/// The offer, as the single URI a wallet is given.
#[must_use]
pub fn credential_offer_uri(offer: &Value) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("credential_offer", &offer.to_string())
        .finish();
    format!("openid-credential-offer://?{query}")
}

/// A fresh 256-bit secret, as unpadded base64url text.
///
/// # Panics
///
/// Panics if the OS CSPRNG is unavailable. A delivery service that handed out a
/// predictable pre-authorized code would be worse than one that stopped.
#[must_use]
pub fn generate_secret() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut_slice()).expect("the OS CSPRNG must be available");
    Zeroizing::new(base64_url_no_pad(bytes.as_ref()))
}

/// A fresh transaction code: [`TRANSACTION_CODE_LENGTH`] decimal digits, drawn
/// uniformly by rejecting the values that would bias the modulus.
///
/// # Panics
///
/// Panics if the OS CSPRNG is unavailable, for the same reason as
/// [`generate_secret`].
#[must_use]
pub fn generate_transaction_code() -> Zeroizing<String> {
    let mut code = Zeroizing::new(String::with_capacity(TRANSACTION_CODE_LENGTH));
    while code.len() < TRANSACTION_CODE_LENGTH {
        let mut byte = Zeroizing::new([0u8; 1]);
        getrandom::fill(byte.as_mut_slice()).expect("the OS CSPRNG must be available");
        // 250 is the largest multiple of ten a byte can hold, so every value
        // above it is drawn again rather than folded into a biased digit.
        if byte[0] >= 250 {
            continue;
        }
        code.push(char::from(b'0' + byte[0] % 10));
    }
    code
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::metadata::CredentialCatalog;

    fn configuration() -> (CredentialCatalog, CredentialConfiguration) {
        let catalog = CredentialCatalog::derive(&crate::metadata::tests::document());
        let configuration = catalog
            .get("urn:example:requirement:holder-bound")
            .expect("the holder-bound requirement is published")
            .clone();
        (catalog, configuration)
    }

    pub(crate) fn subject() -> RequestedSubject {
        RequestedSubject {
            role: "primary".to_owned(),
            selector_values: Some(BTreeMap::from([(
                "identifier".to_owned(),
                OfferedSelectorValue::String("value".to_owned()),
            )])),
        }
    }

    /// A configuration declaring two roles, which is what a relationship
    /// between two people needs and what the single-role fixture cannot show.
    fn two_role_configuration() -> (CredentialCatalog, CredentialConfiguration) {
        let (catalog, mut configuration) = configuration();
        let mut second = configuration.subjects[0].clone();
        second.role = "secondary".to_owned();
        configuration.subjects.push(second);
        (catalog, configuration)
    }

    fn subject_for(role: &str) -> RequestedSubject {
        RequestedSubject {
            role: role.to_owned(),
            ..subject()
        }
    }

    fn request() -> OfferedRequest {
        let (catalog, configuration) = configuration();
        offered_request(
            &configuration,
            &catalog.issued_by,
            &catalog.provided_by,
            catalog.assurance_profile,
            vec![subject()],
        )
        .expect("the offered request is built")
    }

    #[test]
    fn an_offered_request_copies_the_configuration_rather_than_the_caller() {
        let offered = request();
        assert_eq!(offered.requirement, "urn:example:requirement:holder-bound");
        assert_eq!(
            offered.evidence_type,
            "urn:example:evidence-type:holder-bound"
        );
        assert_eq!(offered.purpose, "urn:example:purpose:demonstration");
        assert_eq!(offered.configuration_revision, "rev-1");
        assert_eq!(offered.issued_by, "https://registry.example.org");
        assert_eq!(offered.expected_outputs.len(), 1);
    }

    #[test]
    fn a_subject_the_configuration_does_not_declare_is_refused() {
        let (catalog, configuration) = configuration();
        let mut wrong = subject();
        wrong.role = "other".to_owned();
        assert!(matches!(
            offered_request(
                &configuration,
                &catalog.issued_by,
                &catalog.provided_by,
                catalog.assurance_profile,
                vec![wrong],
            ),
            Err(OfferError::SubjectMismatch)
        ));
    }

    /// The two-role fixture the refusal below varies is otherwise accepted, in
    /// either order, so the refusal is attributable to the repeated role rather
    /// than to a configuration this module cannot build a request from at all.
    #[test]
    fn a_two_role_configuration_takes_each_declared_role_once() {
        let (catalog, configuration) = two_role_configuration();
        for order in [["primary", "secondary"], ["secondary", "primary"]] {
            let offered = offered_request(
                &configuration,
                &catalog.issued_by,
                &catalog.provided_by,
                catalog.assurance_profile,
                order.iter().map(|role| subject_for(role)).collect(),
            )
            .expect("the offered request is built");
            assert_eq!(offered.subjects.len(), 2);
        }
    }

    /// A repeated role is a role the offer never named, and the offer is the
    /// last place that can say so: Evidence refuses the same request, but only
    /// after the wallet has spent its pre-authorized code and its access token.
    #[test]
    fn an_offer_repeating_one_declared_role_and_omitting_another_is_refused() {
        let (catalog, configuration) = two_role_configuration();
        for role in ["primary", "secondary"] {
            assert!(
                matches!(
                    offered_request(
                        &configuration,
                        &catalog.issued_by,
                        &catalog.provided_by,
                        catalog.assurance_profile,
                        vec![subject_for(role), subject_for(role)],
                    ),
                    Err(OfferError::SubjectMismatch)
                ),
                "an offer naming {role} twice was accepted"
            );
        }
    }

    #[test]
    fn a_selector_value_the_configuration_does_not_declare_is_refused() {
        let (catalog, configuration) = configuration();
        for values in [
            None,
            Some(BTreeMap::from([(
                "unexpected".to_owned(),
                OfferedSelectorValue::String("value".to_owned()),
            )])),
        ] {
            let mut wrong = subject();
            wrong.selector_values = values;
            assert!(matches!(
                offered_request(
                    &configuration,
                    &catalog.issued_by,
                    &catalog.provided_by,
                    catalog.assurance_profile,
                    vec![wrong],
                ),
                Err(OfferError::SelectorMismatch)
            ));
        }
    }

    #[test]
    fn an_offered_request_survives_the_store_round_trip_intact() {
        let offered = request();
        let text = serde_json::to_string(&offered).expect("the request serializes");
        let restored: OfferedRequest =
            serde_json::from_str(&text).expect("the request deserializes");
        // Compared as documents, because what has to survive the store is the
        // request Evidence will receive rather than the Rust value.
        assert_eq!(
            serde_json::to_value(&restored).expect("the restored request serializes"),
            serde_json::to_value(&offered).expect("the original request serializes")
        );
    }

    #[test]
    fn one_request_carries_every_holder_key_presented_together() {
        let offered = request();
        let keys = vec![holder_key("a"), holder_key("b"), holder_key("c")];
        let spec = offered.into_spec(keys.clone());
        assert_eq!(spec.holder_keys, keys);
        assert_eq!(spec.subjects.len(), 1);
        assert!(matches!(
            spec.response_format,
            EvidenceResponseFormat::SdJwtVcBatch
        ));
    }

    fn holder_key(kid: &str) -> HolderPublicKey {
        HolderPublicKey {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: "x".to_owned(),
            y: "y".to_owned(),
            alg: None,
            kid: Some(kid.to_owned()),
        }
    }

    #[test]
    fn the_offer_states_the_grant_member_openid4vci_fixed() {
        let offer = credential_offer(
            "https://wallet.example.org",
            "urn:example:requirement:holder-bound",
            "code",
            true,
        );
        let grant = &offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
        assert_eq!(grant["pre-authorized_code"], json!("code"));
        assert_eq!(grant["tx_code"]["input_mode"], json!("numeric"));
        assert_eq!(grant["tx_code"]["length"], json!(6));
        assert_eq!(
            offer["credential_configuration_ids"],
            json!(["urn:example:requirement:holder-bound"])
        );
        assert!(grant.get("pre_authorized_code").is_none());
    }

    #[test]
    fn an_offer_without_a_transaction_code_states_none() {
        let offer = credential_offer("https://wallet.example.org", "id", "code", false);
        let grant = &offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
        assert!(grant.get("tx_code").is_none());
    }

    #[test]
    fn the_offer_uri_carries_the_offer_object() {
        let offer = credential_offer("https://wallet.example.org", "id", "code", false);
        let uri = credential_offer_uri(&offer);
        assert!(uri.starts_with("openid-credential-offer://?credential_offer="));
        let (_, encoded) = uri.split_once('=').expect("the query carries a value");
        let decoded: String = form_urlencoded::parse(format!("v={encoded}").as_bytes())
            .map(|(_, value)| value.into_owned())
            .collect();
        let parsed: Value = serde_json::from_str(&decoded).expect("the offer object parses");
        assert_eq!(parsed, offer);
    }

    #[test]
    fn a_transaction_code_is_the_fixed_length_and_is_decimal() {
        for _ in 0..32 {
            let code = generate_transaction_code();
            assert_eq!(code.len(), TRANSACTION_CODE_LENGTH);
            assert!(code.chars().all(|digit| digit.is_ascii_digit()));
        }
    }

    #[test]
    fn two_generated_secrets_differ() {
        assert_ne!(*generate_secret(), *generate_secret());
    }
}
