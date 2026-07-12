// SPDX-License-Identifier: Apache-2.0
//! Restart-only activation of configured Notary-to-Relay journeys.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::relay_client::{
    RelayClientError, RelayConsultationClient, RelayExpectedResult, RelayProfilePin,
    RelayWorkloadCredentialFile,
};
use crate::runtime::{
    ActivatedRelayClientSet, ActivatedRelayConsultations, RelayClientSelectionV1,
    RuntimeRelayConsultationResult, RuntimeRelayExpectedResult,
};
use registry_notary_core::{ClaimEvidenceMode, RuleConfig, StandaloneRegistryNotaryConfig};
use registry_platform_httputil::destination::{
    DestinationProfile, ServiceHopDataDestinationPolicy,
};

use super::StandaloneServerError;

pub(super) async fn activate_relay_from_config(
    config: &StandaloneRegistryNotaryConfig,
) -> Result<Option<Arc<dyn ActivatedRelayConsultations>>, StandaloneServerError> {
    let Some(plans) = activation_plans(config)? else {
        return Ok(None);
    };
    let mut activated = Vec::with_capacity(plans.clients.len());
    for plan in plans.clients {
        let credential = RelayWorkloadCredentialFile::new(plans.connection.token_file.clone())
            .map_err(map_relay_client_error)?;
        let destination_profile = if plans.connection.uses_insecure_url() {
            DestinationProfile::LoopbackDevelopmentHttp
        } else {
            DestinationProfile::ProductionHttps
        };
        let destination = ServiceHopDataDestinationPolicy::new(
            "registry-notary-relay",
            &plans.connection.base_url,
            destination_profile,
            &plans.connection.allowed_private_cidrs,
        )
        .map_err(|_| StandaloneServerError::InvalidRelayDestination)?;
        let expected_result = plan.expected_result.relay()?;
        let selection = RelayClientSelectionV1::new(
            plan.profile.id.as_str(),
            plan.profile.version.as_str(),
            plan.profile.contract_hash.as_str(),
            plan.purpose.as_str(),
            plan.input_names.clone(),
            plan.expected_result.runtime()?,
        )
        .map_err(|_| StandaloneServerError::InvalidRelayActivationPlan)?;
        let retry_plan = RelayRetryPlan {
            connection: plans.connection.clone(),
            pin: RelayProfilePin::new(
                plan.profile.id.as_str(),
                plan.profile.version.as_str(),
                plan.profile.contract_hash.as_str(),
            )
            .map_err(|_| StandaloneServerError::RelayActivation)?,
            purpose: plan.purpose.clone().into_boxed_str(),
            input_names: plan.input_names.clone(),
            expected_result: expected_result.clone(),
        };
        let client = RelayConsultationClient::new(
            destination,
            credential,
            RelayProfilePin::new(
                plan.profile.id.as_str(),
                plan.profile.version.as_str(),
                plan.profile.contract_hash.as_str(),
            )
            .map_err(|_| StandaloneServerError::RelayActivation)?,
            plan.purpose.as_str(),
            plan.input_names,
            expected_result,
        )
        .map_err(map_relay_client_error)?;
        let activated_client =
            retain_profile_activation(client.verify_profile().await, retry_plan)?;
        activated.push((selection, activated_client));
    }
    ActivatedRelayClientSet::new(activated)
        .map(|clients| Some(Arc::new(clients) as Arc<dyn ActivatedRelayConsultations>))
        .map_err(|_| StandaloneServerError::InvalidRelayActivationPlan)
}

fn retain_profile_activation(
    result: Result<crate::relay_client::VerifiedRelayClient, RelayClientError>,
    retry_plan: RelayRetryPlan,
) -> Result<Arc<dyn ActivatedRelayConsultations>, StandaloneServerError> {
    match result {
        Ok(verified) => Ok(Arc::new(verified)),
        Err(RelayClientError::Unavailable) => Ok(Arc::new(PendingRelayProfile::new(retry_plan))),
        Err(error) => Err(map_relay_client_error(error)),
    }
}

#[derive(Clone)]
struct RelayRetryPlan {
    connection: registry_notary_core::RelayConnectionConfig,
    pin: RelayProfilePin,
    purpose: Box<str>,
    input_names: Vec<String>,
    expected_result: RelayExpectedResult,
}

impl RelayRetryPlan {
    fn client(&self) -> Result<RelayConsultationClient, RelayClientError> {
        let destination_profile = if self.connection.uses_insecure_url() {
            DestinationProfile::LoopbackDevelopmentHttp
        } else {
            DestinationProfile::ProductionHttps
        };
        let destination = ServiceHopDataDestinationPolicy::new(
            "registry-notary-relay",
            &self.connection.base_url,
            destination_profile,
            &self.connection.allowed_private_cidrs,
        )
        .map_err(|_| RelayClientError::InvalidConfiguration)?;
        RelayConsultationClient::new(
            destination,
            RelayWorkloadCredentialFile::new(self.connection.token_file.clone())?,
            self.pin.clone(),
            self.purpose.clone(),
            self.input_names.clone(),
            self.expected_result.clone(),
        )
    }
}

struct PendingRelayProfile {
    retry_plan: RelayRetryPlan,
    verified: std::sync::RwLock<Option<Arc<crate::relay_client::VerifiedRelayClient>>>,
    activation: tokio::sync::Mutex<()>,
}

impl PendingRelayProfile {
    fn new(retry_plan: RelayRetryPlan) -> Self {
        Self {
            retry_plan,
            verified: std::sync::RwLock::new(None),
            activation: tokio::sync::Mutex::new(()),
        }
    }

    fn verified(&self) -> Option<Arc<crate::relay_client::VerifiedRelayClient>> {
        self.verified
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl std::fmt::Debug for PendingRelayProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingRelayProfile")
            .field("client", &"[REDACTED]")
            .field("verified", &self.verified().is_some())
            .finish()
    }
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for PendingRelayProfile {
    async fn check_ready(&self) -> Result<(), RelayClientError> {
        if let Some(verified) = self.verified() {
            return verified.verify_current_profile().await;
        }
        let _activation = self.activation.lock().await;
        if let Some(verified) = self.verified() {
            return verified.verify_current_profile().await;
        }
        let verified = Arc::new(self.retry_plan.client()?.verify_profile().await?);
        *self
            .verified
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(verified);
        Ok(())
    }

    fn validate(
        &self,
        key: &crate::runtime::ConsultationGroupKeyV1,
    ) -> Result<(), RelayClientError> {
        self.verified()
            .ok_or(RelayClientError::Unavailable)?
            .validate(key)
    }

    fn canonicalize(
        &self,
        key: crate::runtime::ConsultationGroupKeyV1,
    ) -> Result<crate::runtime::ConsultationGroupKeyV1, RelayClientError> {
        self.verified()
            .ok_or(RelayClientError::Unavailable)?
            .canonicalize(key)
    }

    async fn execute(
        &self,
        key: &crate::runtime::ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
        let verified = self.verified().ok_or(RelayClientError::Unavailable)?;
        ActivatedRelayConsultations::execute(verified.as_ref(), key).await
    }
}

fn map_relay_client_error(error: RelayClientError) -> StandaloneServerError {
    match error {
        RelayClientError::CredentialUnavailable => {
            StandaloneServerError::RelayCredentialUnavailable
        }
        RelayClientError::InvalidCredentials | RelayClientError::Denied => {
            StandaloneServerError::RelayCredentialsRejected
        }
        RelayClientError::ProfileNotFound => StandaloneServerError::RelayProfileNotFound,
        RelayClientError::InvalidProfileMetadata | RelayClientError::InvalidResult => {
            StandaloneServerError::RelayProfileMismatch
        }
        RelayClientError::TransportUnavailable
        | RelayClientError::CapacityUnavailable
        | RelayClientError::RateLimited
        | RelayClientError::Unavailable
        | RelayClientError::UnexpectedStatus => StandaloneServerError::RelayUnavailable,
        RelayClientError::InvalidConfiguration | RelayClientError::InvalidRequest => {
            StandaloneServerError::InvalidRelayActivationPlan
        }
    }
}

struct RelayActivationPlans<'a> {
    connection: &'a registry_notary_core::RelayConnectionConfig,
    clients: Vec<RelayActivationPlan>,
}

struct RelayActivationPlan {
    profile: registry_notary_core::RelayConsultationProfileRef,
    purpose: String,
    input_names: Vec<String>,
    expected_result: PlannedRelayExpectedResult,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RelayActivationBaseKey {
    profile: registry_notary_core::RelayConsultationProfileRef,
    purpose: String,
    input_names: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
enum PlannedRelayExpectedResult {
    FactMap(BTreeMap<String, registry_notary_core::RelayFactContract>),
    ProjectedString(String),
    PresenceOnly,
}

impl PlannedRelayExpectedResult {
    fn relay(&self) -> Result<RelayExpectedResult, StandaloneServerError> {
        match self {
            Self::FactMap(facts) => {
                RelayExpectedResult::fact_map(facts.clone()).map_err(map_relay_client_error)
            }
            Self::ProjectedString(output) => RelayExpectedResult::projected_string(output.clone())
                .map_err(map_relay_client_error),
            Self::PresenceOnly => Ok(RelayExpectedResult::PresenceOnly),
        }
    }

    fn runtime(&self) -> Result<RuntimeRelayExpectedResult, StandaloneServerError> {
        match self {
            Self::FactMap(facts) => RuntimeRelayExpectedResult::fact_map(facts.clone())
                .map_err(|_| StandaloneServerError::InvalidRelayActivationPlan),
            Self::ProjectedString(output) => {
                RuntimeRelayExpectedResult::projected_string(output.clone())
                    .map_err(|_| StandaloneServerError::InvalidRelayActivationPlan)
            }
            Self::PresenceOnly => Ok(RuntimeRelayExpectedResult::PresenceOnly),
        }
    }
}

fn activation_plans(
    config: &StandaloneRegistryNotaryConfig,
) -> Result<Option<RelayActivationPlans<'_>>, StandaloneServerError> {
    let connection = config.evidence.relay.as_ref();
    let mut registry_claims = config
        .evidence
        .claims
        .iter()
        .filter(|claim| claim.evidence_mode.is_registry_backed());
    let first = registry_claims.next();
    let (connection, first) = match (connection, first) {
        (None, None) => return Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            return Err(StandaloneServerError::InvalidRelayActivationPlan)
        }
        (Some(connection), Some(first)) => (connection, first),
    };
    let mut clients = BTreeMap::<RelayActivationBaseKey, PlannedRelayExpectedResult>::new();
    for claim in std::iter::once(first).chain(registry_claims) {
        let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
            return Err(StandaloneServerError::InvalidRelayActivationPlan);
        };
        let (_, consultation) = consultations
            .first_key_value()
            .filter(|_| consultations.len() == 1)
            .ok_or(StandaloneServerError::InvalidRelayActivationPlan)?;
        let input_names = consultation.inputs.keys().cloned().collect::<Vec<_>>();
        if !(1..=4).contains(&input_names.len()) {
            return Err(StandaloneServerError::InvalidRelayActivationPlan);
        }
        let key = RelayActivationBaseKey {
            profile: consultation.profile.clone(),
            purpose: claim
                .purpose
                .clone()
                .ok_or(StandaloneServerError::InvalidRelayActivationPlan)?,
            input_names,
        };
        let expected_result = if consultation.facts.is_empty() {
            match &claim.rule {
                RuleConfig::Extract { field, .. } => {
                    PlannedRelayExpectedResult::ProjectedString(field.clone())
                }
                RuleConfig::Exists { .. } => PlannedRelayExpectedResult::PresenceOnly,
                RuleConfig::Cel { .. } | RuleConfig::Plugin { .. } => {
                    return Err(StandaloneServerError::InvalidRelayActivationPlan)
                }
            }
        } else {
            PlannedRelayExpectedResult::FactMap(consultation.facts.clone())
        };
        match clients.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(expected_result);
            }
            Entry::Occupied(mut entry) => match (entry.get(), &expected_result) {
                (existing, candidate) if existing == candidate => {}
                (
                    PlannedRelayExpectedResult::PresenceOnly,
                    PlannedRelayExpectedResult::ProjectedString(_),
                ) => {
                    entry.insert(expected_result);
                }
                (
                    PlannedRelayExpectedResult::ProjectedString(_),
                    PlannedRelayExpectedResult::PresenceOnly,
                ) => {}
                _ => return Err(StandaloneServerError::InvalidRelayActivationPlan),
            },
        }
    }
    let clients = clients
        .into_iter()
        .map(|(key, expected_result)| RelayActivationPlan {
            profile: key.profile,
            purpose: key.purpose,
            input_names: key.input_names,
            expected_result,
        })
        .collect();
    Ok(Some(RelayActivationPlans {
        connection,
        clients,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_claim(
        claim: &str,
        token_file: &std::path::Path,
    ) -> StandaloneRegistryNotaryConfig {
        serde_norway::from_str(&format!(
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys: []
evidence:
  enabled: true
  relay:
    base_url: http://127.0.0.1:1
    allow_insecure_localhost: true
    token_file: {}
    allowed_private_cidrs: [10.42.0.0/16]
  claims:
{claim}
"#,
            token_file.display(),
        ))
        .expect("test Notary config parses")
    }

    #[tokio::test]
    async fn source_free_config_rejects_an_unused_relay_connection() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let config = config_with_claim(
            r#"    - id: source-free
      title: Source free
      version: "1"
      subject_type: person
      evidence_mode:
        type: self_attested
      value:
        type: boolean
      rule:
        type: cel
        expression: "true""#,
            &directory.path().join("relay.jwt"),
        );

        let error = activate_relay_from_config(&config)
            .await
            .expect_err("unused Relay configuration is rejected");

        assert!(matches!(
            error,
            StandaloneServerError::InvalidRelayActivationPlan
        ));
    }

    #[tokio::test]
    async fn registry_backed_config_requires_token_file_before_network() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let token_file = directory.path().join("relay.jwt");
        let config = config_with_claim(
            r#"    - id: enrollment-status
      title: Enrollment status
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile:
              id: dhis2.tracker.enrollment-status.exact
              version: "1"
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              tracked_entity: target.id
      purpose: benefit-verification
      required_scopes: [registry:consult:dhis2]
      value:
        type: string
      rule:
        type: extract
        source: enrollment
        field: registration_status"#,
            &token_file,
        );

        let error = activate_relay_from_config(&config)
            .await
            .expect_err("missing token file must fail before attempting the Relay destination");

        assert!(matches!(
            error,
            StandaloneServerError::RelayCredentialUnavailable
        ));

        std::fs::write(&token_file, b"opaque-token-SENSITIVE")
            .expect("invalid token fixture writes");
        let error = activate_relay_from_config(&config)
            .await
            .expect_err("invalid token must fail before attempting the Relay destination");
        assert!(matches!(
            error,
            StandaloneServerError::RelayCredentialsRejected
        ));
    }

    #[tokio::test]
    async fn unavailable_profile_is_retained_but_auth_and_contract_failures_abort() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let token_file = directory.path().join("relay.jwt");
        std::fs::write(&token_file, b"opaque-token-SENSITIVE")
            .expect("invalid token fixture writes");
        let connection: registry_notary_core::RelayConnectionConfig =
            serde_norway::from_str(&format!(
                "base_url: http://127.0.0.1:1\nallow_insecure_localhost: true\ntoken_file: {}\n",
                token_file.display()
            ))
            .expect("retry connection parses");
        let retry_plan = RelayRetryPlan {
            connection,
            pin: RelayProfilePin::new(
                "example.snapshot-status.exact",
                "1",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("profile pin is valid"),
            purpose: "benefit-verification".into(),
            input_names: vec!["subject_id".into()],
            expected_result: RelayExpectedResult::PresenceOnly,
        };
        let unavailable =
            retain_profile_activation(Err(RelayClientError::Unavailable), retry_plan.clone())
                .expect("a profile-level 503 is retained as unavailable");
        assert_eq!(
            unavailable
                .check_ready()
                .await
                .expect_err("the retained profile re-verifies through the safe client boundary"),
            RelayClientError::InvalidCredentials
        );

        for (error, expected) in [
            (
                RelayClientError::InvalidCredentials,
                StandaloneServerError::RelayCredentialsRejected,
            ),
            (
                RelayClientError::InvalidProfileMetadata,
                StandaloneServerError::RelayProfileMismatch,
            ),
        ] {
            let actual = retain_profile_activation(Err(error), retry_plan.clone())
                .expect_err("security and contract failures abort activation");
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
        }
    }

    #[test]
    fn exists_only_config_selects_the_sealed_presence_result_contract() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let config = config_with_claim(
            r#"    - id: birth-record-exists
      title: Birth record exists
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          birth_record:
            profile:
              id: opencrvs.birth-record-exists.exact
              version: "1"
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              uin: target.id
      purpose: civil-registration-verification
      required_scopes: [registry:consult:opencrvs]
      value:
        type: boolean
      rule:
        type: exists
        source: birth_record"#,
            &directory.path().join("relay.jwt"),
        );

        let plans = activation_plans(&config)
            .expect("activation plans are valid")
            .expect("Registry-backed activation is present");
        assert!(matches!(
            plans.clients[0].expected_result,
            PlannedRelayExpectedResult::PresenceOnly
        ));
    }

    #[test]
    fn activation_plans_deduplicate_shared_clients_and_keep_independent_profiles() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let config = config_with_claim(
            r#"    - id: enrollment-status
      title: Enrollment status
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile:
              id: dhis2.tracker.enrollment-status.exact
              version: "1"
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              tracked_entity: request.target.identifiers.dhis2_tracked_entity
      purpose: programme-verification
      required_scopes: [registry:programme]
      value: { type: string }
      rule: { type: extract, source: enrollment, field: status }
    - id: enrollment-known
      title: Enrollment known
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile:
              id: dhis2.tracker.enrollment-status.exact
              version: "1"
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              tracked_entity: request.target.identifiers.dhis2_tracked_entity
      purpose: programme-verification
      required_scopes: [registry:programme]
      value: { type: boolean }
      rule: { type: exists, source: enrollment }
    - id: birth-record-known
      title: Birth record known
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          birth_record:
            profile:
              id: opencrvs.birth-record.exact
              version: "1"
              contract_hash: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            inputs:
              uin: request.target.identifiers.UIN
      purpose: civil-verification
      required_scopes: [registry:civil]
      value: { type: boolean }
      rule: { type: exists, source: birth_record }"#,
            &directory.path().join("relay.jwt"),
        );

        let plans = activation_plans(&config)
            .expect("activation plans are valid")
            .expect("Registry-backed activation is present");

        assert_eq!(plans.clients.len(), 2);
        assert!(plans.clients.iter().any(|plan| {
            plan.profile.id == "dhis2.tracker.enrollment-status.exact"
                && plan.purpose == "programme-verification"
                && matches!(
                    plan.expected_result,
                    PlannedRelayExpectedResult::ProjectedString(ref output) if output == "status"
                )
        }));
        assert!(plans.clients.iter().any(|plan| {
            plan.profile.id == "opencrvs.birth-record.exact"
                && plan.purpose == "civil-verification"
                && matches!(
                    plan.expected_result,
                    PlannedRelayExpectedResult::PresenceOnly
                )
        }));
    }
}
