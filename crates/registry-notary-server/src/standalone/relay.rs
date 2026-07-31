// SPDX-License-Identifier: Apache-2.0
//! Restart-only activation of configured Notary-to-Relay journeys.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use crate::relay_client::{
    RelayClientError, RelayConsultationClient, RelayExpectedResult, RelayProfilePin,
    RelayWorkloadCredentialFile,
};
use crate::runtime::{
    ActivatedRelayClientSet, ActivatedRelayConsultations, RelayClientSelectionV1,
    RuntimeRelayConsultationResult, RuntimeRelayExpectedResult,
};
use registry_notary_core::{ClaimEvidenceMode, DeploymentProfile, StandaloneRegistryNotaryConfig};
use registry_platform_httputil::destination::{
    DestinationProfile, DestinationTlsMaterial, ServiceHopDataDestinationPolicy,
    MAX_DESTINATION_CA_BUNDLE_BYTES,
};

use super::StandaloneServerError;

pub(super) async fn activate_relay_from_config(
    config: &StandaloneRegistryNotaryConfig,
) -> Result<Option<Arc<dyn ActivatedRelayConsultations>>, StandaloneServerError> {
    let Some(plans) = activation_plans(config)? else {
        return Ok(None);
    };
    let root_certificate = plans
        .connection
        .root_certificate_path
        .as_deref()
        .map(read_relay_root_certificate)
        .transpose()
        .map_err(|_| StandaloneServerError::RelayActivation)?
        .map(Arc::<[u8]>::from);
    let mut activated = Vec::with_capacity(plans.clients.len());
    for plan in plans.clients {
        let credential = RelayWorkloadCredentialFile::new(plans.connection.token_file.clone())
            .map_err(map_relay_client_error)?;
        let destination = relay_destination(
            plans.connection,
            root_certificate.as_deref(),
            config.deployment.profile,
        )
        .map_err(|_| StandaloneServerError::InvalidRelayDestination)?;
        let expected_result = plan.expected_result.relay()?;
        let selection = RelayClientSelectionV1::new(
            plan.profile.id.as_str(),
            plan.profile.contract_hash.as_str(),
            plan.purpose.as_str(),
            plan.input_names.clone(),
            plan.expected_result.runtime()?,
        )
        .map_err(|_| StandaloneServerError::InvalidRelayActivationPlan)?;
        let retry_plan = RelayRetryPlan {
            connection: plans.connection.clone(),
            root_certificate: root_certificate.clone(),
            deployment_profile: config.deployment.profile,
            pin: RelayProfilePin::new(
                plan.profile.id.as_str(),
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
            plans.connection.workload_client_id.as_str(),
            RelayProfilePin::new(
                plan.profile.id.as_str(),
                plan.profile.contract_hash.as_str(),
            )
            .map_err(|_| StandaloneServerError::RelayActivation)?,
            plan.purpose.as_str(),
            plan.input_names,
            expected_result,
        )
        .and_then(|client| client.with_max_in_flight(plans.connection.max_in_flight))
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
    root_certificate: Option<Arc<[u8]>>,
    deployment_profile: Option<DeploymentProfile>,
    pin: RelayProfilePin,
    purpose: Box<str>,
    input_names: Vec<String>,
    expected_result: RelayExpectedResult,
}

impl RelayRetryPlan {
    fn client(&self) -> Result<RelayConsultationClient, RelayClientError> {
        let destination = relay_destination(
            &self.connection,
            self.root_certificate.as_deref(),
            self.deployment_profile,
        )
        .map_err(|_| RelayClientError::InvalidConfiguration)?;
        RelayConsultationClient::new(
            destination,
            RelayWorkloadCredentialFile::new(self.connection.token_file.clone())?,
            self.connection.workload_client_id.as_str(),
            self.pin.clone(),
            self.purpose.clone(),
            self.input_names.clone(),
            self.expected_result.clone(),
        )
        .and_then(|client| client.with_max_in_flight(self.connection.max_in_flight))
    }
}

fn relay_destination(
    connection: &registry_notary_core::RelayConnectionConfig,
    root_certificate: Option<&[u8]>,
    deployment_profile: Option<DeploymentProfile>,
) -> Result<ServiceHopDataDestinationPolicy, ()> {
    let destination_profile = if !connection.uses_insecure_url() {
        DestinationProfile::ProductionHttps
    } else if connection.uses_insecure_loopback_url() {
        DestinationProfile::LoopbackDevelopmentHttp
    } else if connection.uses_insecure_private_network_url() {
        DestinationProfile::PrivateServiceHttp
    } else if deployment_profile == Some(DeploymentProfile::Local) {
        DestinationProfile::LocalPrivateDevelopmentHttp
    } else {
        return Err(());
    };
    let mut destination = ServiceHopDataDestinationPolicy::new(
        "registry-notary-relay",
        &connection.base_url,
        destination_profile,
        &connection.allowed_private_cidrs,
    )
    .map_err(|_| ())?;
    if let Some(root_certificate) = root_certificate {
        destination = destination.require_configured_tls();
        let material =
            DestinationTlsMaterial::from_pem(Some(root_certificate), None).map_err(|_| ())?;
        destination
            .install_configured_tls(material)
            .map_err(|_| ())?;
    }
    Ok(destination)
}

fn read_relay_root_certificate(path: &Path) -> Result<Vec<u8>, ()> {
    let mut file = open_relay_root_certificate(path)?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() {
        return Err(());
    }
    validate_relay_root_certificate_metadata(&metadata)?;
    let maximum = u64::try_from(MAX_DESTINATION_CA_BUNDLE_BYTES).map_err(|_| ())?;
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| ())?);
    file.by_ref()
        .take(maximum.checked_add(1).ok_or(())?)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > MAX_DESTINATION_CA_BUNDLE_BYTES {
        return Err(());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_relay_root_certificate(path: &Path) -> Result<File, ()> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_relay_root_certificate(path: &Path) -> Result<File, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink() {
        return Err(());
    }
    File::open(path).map_err(|_| ())
}

#[cfg(unix)]
fn validate_relay_root_certificate_metadata(metadata: &fs::Metadata) -> Result<(), ()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mode = metadata.permissions().mode();
    let owner = metadata.uid();
    let effective_user = rustix::process::geteuid().as_raw();
    if mode & 0o177 != 0 || mode & 0o400 == 0 || (owner != 0 && owner != effective_user) {
        return Err(());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_relay_root_certificate_metadata(_metadata: &fs::Metadata) -> Result<(), ()> {
    Ok(())
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
        RelayClientError::ContractMismatch
        | RelayClientError::InvalidProfileMetadata
        | RelayClientError::InvalidResult => StandaloneServerError::RelayProfileMismatch,
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
    OutputMap(BTreeMap<String, registry_notary_core::RelayOutputContract>),
}

impl PlannedRelayExpectedResult {
    fn relay(&self) -> Result<RelayExpectedResult, StandaloneServerError> {
        match self {
            Self::OutputMap(outputs) => {
                RelayExpectedResult::output_map(outputs.clone()).map_err(map_relay_client_error)
            }
        }
    }

    fn runtime(&self) -> Result<RuntimeRelayExpectedResult, StandaloneServerError> {
        match self {
            Self::OutputMap(outputs) => RuntimeRelayExpectedResult::output_map(outputs.clone())
                .map_err(|_| StandaloneServerError::InvalidRelayActivationPlan),
        }
    }
}

fn activation_plans(
    config: &StandaloneRegistryNotaryConfig,
) -> Result<Option<RelayActivationPlans<'_>>, StandaloneServerError> {
    let connection = config.evidence.relay.as_ref();
    let mut registry_claims = config.evidence.claims.iter();
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
        if !(1..=16).contains(&input_names.len()) {
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
        if consultation.outputs.is_empty() {
            return Err(StandaloneServerError::InvalidRelayActivationPlan);
        }
        let expected_result = PlannedRelayExpectedResult::OutputMap(consultation.outputs.clone());
        match clients.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(expected_result);
            }
            Entry::Occupied(entry) => match (entry.get(), &expected_result) {
                (existing, candidate) if existing == candidate => {}
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

    fn local_private_connection(
        base_url: &str,
        allowed_private_cidrs: &[&str],
    ) -> registry_notary_core::RelayConnectionConfig {
        let mut connection: registry_notary_core::RelayConnectionConfig =
            serde_norway::from_str(&format!(
                "base_url: {base_url}\nworkload_client_id: registry-notary\ntoken_file: /run/secrets/relay.jwt\n"
            ))
            .expect("test Relay connection parses");
        connection.allowed_private_cidrs = allowed_private_cidrs
            .iter()
            .map(|cidr| cidr.parse().expect("test CIDR parses"))
            .collect();
        connection
    }

    #[test]
    fn local_private_relay_destination_is_exact_and_profile_bound() {
        let connection = local_private_connection("http://10.89.0.4:8080", &["10.89.0.4/32"]);
        relay_destination(&connection, None, Some(DeploymentProfile::Local))
            .expect("local exact private HTTP destination activates");

        for profile in [
            None,
            Some(DeploymentProfile::HostedLab),
            Some(DeploymentProfile::Production),
            Some(DeploymentProfile::EvidenceGrade),
        ] {
            assert!(relay_destination(&connection, None, profile).is_err());
        }

        for (base_url, cidrs) in [
            ("http://10.89.0.4:8080", vec![]),
            ("http://10.89.0.4:8080", vec!["10.89.0.0/24"]),
            ("http://10.89.0.4:8080", vec!["10.89.0.5/32"]),
            ("http://relay.internal.example:8080", vec!["10.89.0.4/32"]),
            ("http://169.254.169.254:8080", vec!["169.254.169.254/32"]),
            ("http://100.100.100.200:8080", vec!["100.100.100.200/32"]),
            ("http://0.0.0.0:8080", vec!["0.0.0.0/32"]),
        ] {
            let connection = local_private_connection(base_url, &cidrs);
            assert!(
                relay_destination(&connection, None, Some(DeploymentProfile::Local)).is_err(),
                "unexpectedly activated {base_url} with {cidrs:?}"
            );
        }
    }

    #[test]
    fn private_service_relay_destination_activates_without_transport_ceremony() {
        let mut connection =
            local_private_connection("http://registry-relay-consultation:8080", &[]);
        connection.allow_insecure_private_network = true;
        for profile in [
            DeploymentProfile::Local,
            DeploymentProfile::HostedLab,
            DeploymentProfile::Production,
            DeploymentProfile::EvidenceGrade,
        ] {
            relay_destination(&connection, None, Some(profile))
                .expect("signed private service HTTP destination activates");
        }
    }

    #[cfg(unix)]
    #[test]
    fn relay_root_certificate_loader_requires_owner_only_regular_file() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("relay-ca.pem");
        std::fs::write(&root, b"bounded-public-root").expect("root writes");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o600))
            .expect("permissions set");
        assert_eq!(
            read_relay_root_certificate(&root).expect("owner-only root loads"),
            b"bounded-public-root"
        );

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o644))
            .expect("permissions widen");
        assert!(read_relay_root_certificate(&root).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o600))
            .expect("permissions restore");
        let link = directory.path().join("relay-ca-link.pem");
        symlink(&root, &link).expect("symlink creates");
        assert!(read_relay_root_certificate(&link).is_err());
    }

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
  api_keys: []
evidence:
  enabled: true
  relay:
    base_url: http://127.0.0.1:1
    workload_client_id: registry-notary
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
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              tracked_entity: target.id
            outputs:
              registration_status: { type: string, nullable: true, max_bytes: 64 }
      purpose: benefit-verification
      required_scopes: [registry:consult:dhis2]
      value:
        type: string
        nullable: true
      rule:
        type: consultation_output
        consultation: enrollment
        output: registration_status"#,
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
                "base_url: http://127.0.0.1:1\nworkload_client_id: registry-notary\nallow_insecure_localhost: true\ntoken_file: {}\n",
                token_file.display()
            ))
            .expect("retry connection parses");
        let retry_plan = RelayRetryPlan {
            connection,
            root_certificate: None,
            deployment_profile: Some(DeploymentProfile::Local),
            pin: RelayProfilePin::new(
                "example.snapshot-status.exact",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("profile pin is valid"),
            purpose: "benefit-verification".into(),
            input_names: vec!["subject_id".into()],
            expected_result: RelayExpectedResult::output_map(BTreeMap::from([(
                "status".to_string(),
                registry_notary_core::RelayOutputContract::String {
                    nullable: false,
                    max_bytes: 64,
                },
            )]))
            .expect("output contract is valid"),
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
    fn consultation_matched_config_selects_the_declared_output_contract() {
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
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              uin: target.id
            outputs:
              record_type: { type: string, nullable: false, max_bytes: 64 }
      purpose: civil-registration-verification
      required_scopes: [registry:consult:opencrvs]
      value:
        type: boolean
      rule:
        type: consultation_matched
        consultation: birth_record"#,
            &directory.path().join("relay.jwt"),
        );

        let plans = activation_plans(&config)
            .expect("activation plans are valid")
            .expect("Registry-backed activation is present");
        assert!(matches!(
            plans.clients[0].expected_result,
            PlannedRelayExpectedResult::OutputMap(ref outputs)
                if matches!(outputs.get("record_type"), Some(registry_notary_core::RelayOutputContract::String { nullable: false, max_bytes: 64 }))
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
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              tracked_entity: request.target.identifiers.dhis2_tracked_entity
            outputs:
              status: { type: string, nullable: true, max_bytes: 64 }
      purpose: programme-verification
      required_scopes: [registry:programme]
      value: { type: string }
      rule: { type: consultation_output, consultation: enrollment, output: status }
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
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              tracked_entity: request.target.identifiers.dhis2_tracked_entity
            outputs:
              status: { type: string, nullable: true, max_bytes: 64 }
      purpose: programme-verification
      required_scopes: [registry:programme]
      value: { type: boolean }
      rule: { type: consultation_matched, consultation: enrollment }
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
              contract_hash: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            inputs:
              uin: request.target.identifiers.UIN
            outputs:
              record_type: { type: string, nullable: false, max_bytes: 64 }
      purpose: civil-verification
      required_scopes: [registry:civil]
      value: { type: boolean }
      rule: { type: consultation_matched, consultation: birth_record }"#,
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
                    PlannedRelayExpectedResult::OutputMap(_)
                )
        }));
        assert!(plans.clients.iter().any(|plan| {
            plan.profile.id == "opencrvs.birth-record.exact"
                && plan.purpose == "civil-verification"
                && matches!(
                    plan.expected_result,
                    PlannedRelayExpectedResult::OutputMap(_)
                )
        }));
    }
}
