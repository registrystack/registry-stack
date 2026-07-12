// SPDX-License-Identifier: Apache-2.0
//! Restart-only activation of the one initial Notary-to-Relay journey.

use std::sync::Arc;

use crate::relay_client::{
    RelayClientError, RelayConsultationClient, RelayExpectedResult, RelayProfilePin,
    RelayWorkloadCredentialFile,
};
use crate::runtime::ActivatedRelayConsultations;
use registry_notary_core::{ClaimEvidenceMode, RuleConfig, StandaloneRegistryNotaryConfig};
use registry_platform_httputil::destination::{
    DestinationProfile, ServiceHopDataDestinationPolicy,
};

use super::StandaloneServerError;

pub(super) async fn activate_relay_from_config(
    config: &StandaloneRegistryNotaryConfig,
) -> Result<Option<Arc<dyn ActivatedRelayConsultations>>, StandaloneServerError> {
    let Some(plan) = activation_plan(config)? else {
        return Ok(None);
    };
    let credential = RelayWorkloadCredentialFile::new(plan.connection.token_file.clone())
        .map_err(map_relay_client_error)?;
    let destination_profile = if plan.connection.uses_insecure_url() {
        DestinationProfile::LoopbackDevelopmentHttp
    } else {
        DestinationProfile::ProductionHttps
    };
    let destination = ServiceHopDataDestinationPolicy::new(
        "registry-notary-relay",
        &plan.connection.base_url,
        destination_profile,
        &plan.connection.allowed_private_cidrs,
    )
    .map_err(|_| StandaloneServerError::InvalidRelayDestination)?;
    let client = RelayConsultationClient::new(
        destination,
        credential,
        RelayProfilePin::new(plan.profile_id, plan.profile_version, plan.contract_hash)
            .map_err(|_| StandaloneServerError::RelayActivation)?,
        plan.purpose,
        plan.input_name,
        plan.expected_result,
    )
    .map_err(map_relay_client_error)?;
    let verified = client
        .verify_profile()
        .await
        .map_err(map_relay_client_error)?;
    Ok(Some(Arc::new(verified)))
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

struct RelayActivationPlan<'a> {
    connection: &'a registry_notary_core::RelayConnectionConfig,
    profile_id: &'a str,
    profile_version: &'a str,
    contract_hash: &'a str,
    purpose: &'a str,
    input_name: &'a str,
    expected_result: RelayExpectedResult,
}

fn activation_plan(
    config: &StandaloneRegistryNotaryConfig,
) -> Result<Option<RelayActivationPlan<'_>>, StandaloneServerError> {
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
    let ClaimEvidenceMode::RegistryBacked { consultations } = &first.evidence_mode else {
        return Err(StandaloneServerError::InvalidRelayActivationPlan);
    };
    let (_, consultation) = consultations
        .first_key_value()
        .filter(|_| consultations.len() == 1)
        .ok_or(StandaloneServerError::InvalidRelayActivationPlan)?;
    let input_name = consultation
        .inputs
        .first_key_value()
        .filter(|_| consultation.inputs.len() == 1)
        .map(|(name, _)| name.as_str())
        .ok_or(StandaloneServerError::InvalidRelayActivationPlan)?;
    let expected_result = config
        .evidence
        .claims
        .iter()
        .find_map(|claim| match (&claim.evidence_mode, &claim.rule) {
            (ClaimEvidenceMode::RegistryBacked { .. }, RuleConfig::Extract { field, .. }) => {
                Some(field.as_str())
            }
            _ => None,
        })
        .map(RelayExpectedResult::projected_string)
        .transpose()
        .map_err(|_| StandaloneServerError::InvalidRelayActivationPlan)?
        .unwrap_or(RelayExpectedResult::PresenceOnly);
    Ok(Some(RelayActivationPlan {
        connection,
        profile_id: &consultation.profile.id,
        profile_version: &consultation.profile.version,
        contract_hash: &consultation.profile.contract_hash,
        purpose: first
            .purpose
            .as_deref()
            .ok_or(StandaloneServerError::InvalidRelayActivationPlan)?,
        input_name,
        expected_result,
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

        let plan = activation_plan(&config)
            .expect("activation plan is valid")
            .expect("Registry-backed activation is present");
        assert!(matches!(
            plan.expected_result,
            RelayExpectedResult::PresenceOnly
        ));
    }
}
