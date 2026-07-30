use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use crate::approved_set::{ApprovedBaselineSetV1, ApprovedLaneV1, PortableArtifactLocator};
use crate::release_lock::{
    verify_installed_release_lock, verify_release_lock_for_package, LockedOperatorFileFormatV1,
    LockedOperatorFileV1, LockedRuntimeActionV1, LockedRuntimeMountV1, LockedServiceHardeningV1,
    VerifiedPostgresqlRuntimeV1, VerifiedProductRuntimeV1, VerifiedReleaseLockV1,
    VerifiedRuntimeMappingV1, VerifiedSupportingRuntimeV1,
};
use anyhow::{anyhow, bail, Context, Result};
use registry_platform_config::ProductAcceptanceIdentityV1;
use registry_platform_crypto::canonicalize_json;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

pub const DEPLOYMENT_PLAN_SCHEMA_ID: &str = "io.registrystack.deployment_plan";
pub const DEPLOYMENT_PLAN_SCHEMA_VERSION: &str = "1.0";
pub const DEPLOYMENT_BINDING_SCHEMA_ID: &str = "io.registrystack.deployment_binding";
pub const DEPLOYMENT_BINDING_SCHEMA_VERSION: &str = "1.0";
pub const DEPLOYMENT_MANIFEST_SCHEMA_ID: &str = "io.registrystack.deployment_manifest";
pub const DEPLOYMENT_MANIFEST_SCHEMA_VERSION: &str = "1.0";
pub const DEPLOYMENT_OWNERSHIP_REPORT_SCHEMA_ID: &str =
    "io.registrystack.deployment_ownership_report";
pub const DEPLOYMENT_OWNERSHIP_REPORT_SCHEMA_VERSION: &str = "1.0";
pub const DEPLOYMENT_OPERATOR_FILES_SCHEMA_ID: &str = "io.registrystack.deployment_operator_files";
pub const DEPLOYMENT_OPERATOR_FILES_SCHEMA_VERSION: &str = "1.0";

const MAX_PORTABLE_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PACKAGE_FILE_BYTES: u64 = 256 * 1024 * 1024;

const RELAY_PUBLIC: &str = "relay-public";
const RELAY_CONSULTATION: &str = "relay-consultation";
const NOTARY: &str = "notary";
const POSTGRESQL: &str = "postgresql-state-plane";
const NAMESPACE_HOLDER: &str = "private-namespace-holder";

const SERVICE_RELAY_PUBLIC: &str = "registry-relay-public";
const SERVICE_RELAY_CONSULTATION: &str = "registry-relay-consultation";
const SERVICE_NOTARY: &str = "registry-notary";
const SERVICE_POSTGRESQL: &str = "registry-postgres";
const SERVICE_RUNTIME_SECRET_STAGER: &str = "registry-runtime-stage-secrets";
const SERVICE_NAMESPACE_HOLDER: &str = "registry-private-namespace";
const NETWORK_EDGE: &str = "registry-edge";
const NETWORK_PRIVATE: &str = "registry-private";
const PRIVATE_NETWORK_MODE: &str = "service:registry-private-namespace";
const COMPOSE_MINIMUM_VERSION: [u16; 3] = [2, 35, 0];
pub(crate) const OPERATOR_FILE_IDS: [&str; 21] = [
    "notary-initialize-environment",
    "notary-prepare-environment",
    "notary-relay-workload-credential",
    "notary-serve-environment",
    "notary-signing-key",
    "notary-tls-certificate",
    "notary-tls-private-key",
    "postgresql-admin-password",
    "postgresql-bootstrap-environment",
    "postgresql-tls-certificate",
    "postgresql-tls-private-key",
    "relay-consultation-initialize-environment",
    "relay-consultation-prepare-environment",
    "relay-consultation-serve-environment",
    "relay-consultation-tls-certificate",
    "relay-consultation-tls-private-key",
    "relay-public-initialize-environment",
    "relay-public-prepare-environment",
    "relay-public-serve-environment",
    "relay-public-tls-certificate",
    "relay-public-tls-private-key",
];

const SERVICE_POSTGRESQL_BOOTSTRAP: &str = "registry-postgres-bootstrap";

const INITIALIZATION_SERVICES: [&str; 7] = [
    SERVICE_POSTGRESQL_BOOTSTRAP,
    "registry-relay-public-prepare-state",
    "registry-relay-consultation-prepare-state",
    "registry-notary-prepare-state",
    "registry-relay-public-initialize",
    "registry-relay-consultation-initialize",
    "registry-notary-initialize",
];

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ImageIdentityV1(String);

impl ImageIdentityV1 {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
            bail!("image identity must use an explicit sha256 digest");
        };
        if repository.is_empty()
            || repository.chars().any(char::is_whitespace)
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("image identity must be a repository plus a lowercase 64-hex sha256 digest");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ImageIdentityV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ManagedTopologyImagesV1 {
    pub relay: ImageIdentityV1,
    pub notary: ImageIdentityV1,
    pub postgresql_state_plane: ImageIdentityV1,
    pub private_namespace_holder: ImageIdentityV1,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductLaneV1 {
    RelayPublic,
    RelayConsultation,
    Notary,
}

impl ProductLaneV1 {
    fn from_approved(lane: ApprovedLaneV1) -> Self {
        match lane {
            ApprovedLaneV1::RelayPublic => Self::RelayPublic,
            ApprovedLaneV1::RelayConsultation => Self::RelayConsultation,
            ApprovedLaneV1::Notary => Self::Notary,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::RelayPublic => RELAY_PUBLIC,
            Self::RelayConsultation => RELAY_CONSULTATION,
            Self::Notary => NOTARY,
        }
    }

    fn service(self) -> &'static str {
        match self {
            Self::RelayPublic => SERVICE_RELAY_PUBLIC,
            Self::RelayConsultation => SERVICE_RELAY_CONSULTATION,
            Self::Notary => SERVICE_NOTARY,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeActionV1 {
    BootstrapStatePlane,
    PrepareStateStore,
    Serve,
    InitializeState,
    VerifyState,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportingWorkloadRecipeV1 {
    PostgresqlStatePlane,
    PrivateNamespaceHolder,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum MountRoleV1 {
    #[serde(rename = "bundle")]
    Bundle,
    #[serde(rename = "anchor")]
    Anchor,
    #[serde(rename = "anti-rollback-state")]
    AntiRollbackState,
    #[serde(rename = "secret")]
    Secret,
    #[serde(rename = "certificate")]
    Certificate,
    #[serde(rename = "audit")]
    Audit,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointClassV1 {
    PublicApplication,
    PrivateApplication,
    Administration,
    Metrics,
    Posture,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointExposureV1 {
    OperatorBound,
    PrivateNamespaceOnly,
    LoopbackOnly,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedReactivationActionV1 {
    VerifyState,
    RestoreConsistencyGroup,
    RestartConsistencyGroup,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedRestartActionV1 {
    Restart,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductWorkloadV1 {
    pub id: String,
    pub product_lane: ProductLaneV1,
    pub action: RuntimeActionV1,
    pub image_identity: ImageIdentityV1,
    pub immutable_inputs: Vec<String>,
    pub mount_roles: Vec<MountRoleV1>,
    pub secret_consumers: Vec<String>,
    pub state_roles: Vec<String>,
    pub endpoint_classes: Vec<EndpointClassV1>,
    pub network_relationships: Vec<String>,
    pub dependencies: Vec<String>,
    pub health_semantics: String,
    pub restart_action: ExpectedRestartActionV1,
    pub reactivation_action: ExpectedReactivationActionV1,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportingWorkloadV1 {
    pub id: String,
    pub recipe: SupportingWorkloadRecipeV1,
    pub image_identity: ImageIdentityV1,
    pub secret_consumers: Vec<String>,
    pub state_roles: Vec<String>,
    pub endpoint_classes: Vec<EndpointClassV1>,
    pub network_relationships: Vec<String>,
    pub dependencies: Vec<String>,
    pub health_semantics: String,
    pub restart_action: ExpectedRestartActionV1,
    pub reactivation_action: ExpectedReactivationActionV1,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeploymentWorkloadV1 {
    Product(ProductWorkloadV1),
    Supporting(SupportingWorkloadV1),
}

impl DeploymentWorkloadV1 {
    fn id(&self) -> &str {
        match self {
            Self::Product(workload) => &workload.id,
            Self::Supporting(workload) => &workload.id,
        }
    }

    fn dependencies(&self) -> &[String] {
        match self {
            Self::Product(workload) => &workload.dependencies,
            Self::Supporting(workload) => &workload.dependencies,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitializationActionV1 {
    pub id: String,
    pub workload: String,
    pub action: RuntimeActionV1,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadGroupV1 {
    pub id: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureRequirementV1 {
    pub endpoint_class: EndpointClassV1,
    pub exposure: EndpointExposureV1,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentPlanV1 {
    pub schema_id: String,
    pub schema_version: String,
    pub single_instance: bool,
    pub workloads: Vec<DeploymentWorkloadV1>,
    pub initialization_actions: Vec<InitializationActionV1>,
    pub private_co_location_groups: Vec<WorkloadGroupV1>,
    pub recovery_consistency_groups: Vec<WorkloadGroupV1>,
    pub exposure_requirements: Vec<ExposureRequirementV1>,
}

impl DeploymentPlanV1 {
    pub fn managed_single_node(images: &ManagedTopologyImagesV1) -> Self {
        let product = |lane: ProductLaneV1,
                       image_identity: ImageIdentityV1,
                       mount_roles: Vec<MountRoleV1>,
                       secret_consumers: Vec<&str>,
                       state_roles: Vec<&str>,
                       endpoint_classes: Vec<EndpointClassV1>,
                       network_relationships: Vec<&str>,
                       dependencies: Vec<&str>,
                       health_semantics: &str| {
            DeploymentWorkloadV1::Product(ProductWorkloadV1 {
                id: lane.id().to_string(),
                product_lane: lane,
                action: RuntimeActionV1::Serve,
                image_identity,
                immutable_inputs: vec![
                    format!("{}-bundle", lane.id()),
                    format!("{}-anchor", lane.id()),
                ],
                mount_roles,
                secret_consumers: strings(secret_consumers),
                state_roles: strings(state_roles),
                endpoint_classes,
                network_relationships: strings(network_relationships),
                dependencies: strings(dependencies),
                health_semantics: health_semantics.to_string(),
                restart_action: ExpectedRestartActionV1::Restart,
                reactivation_action: ExpectedReactivationActionV1::VerifyState,
            })
        };
        let common_mounts = vec![
            MountRoleV1::Bundle,
            MountRoleV1::Anchor,
            MountRoleV1::AntiRollbackState,
            MountRoleV1::Certificate,
            MountRoleV1::Audit,
        ];
        Self {
            schema_id: DEPLOYMENT_PLAN_SCHEMA_ID.to_string(),
            schema_version: DEPLOYMENT_PLAN_SCHEMA_VERSION.to_string(),
            single_instance: true,
            workloads: vec![
                product(
                    ProductLaneV1::RelayPublic,
                    images.relay.clone(),
                    common_mounts.clone(),
                    vec!["relay-public-tls"],
                    vec!["relay-public-anti-rollback", "relay-public-audit"],
                    vec![
                        EndpointClassV1::PublicApplication,
                        EndpointClassV1::Metrics,
                        EndpointClassV1::Posture,
                    ],
                    vec!["edge"],
                    vec![],
                    "relay-public-health",
                ),
                product(
                    ProductLaneV1::RelayConsultation,
                    images.relay.clone(),
                    common_mounts,
                    vec!["relay-consultation-tls"],
                    vec![
                        "relay-consultation-anti-rollback",
                        "relay-consultation-audit",
                    ],
                    vec![
                        EndpointClassV1::PrivateApplication,
                        EndpointClassV1::Metrics,
                        EndpointClassV1::Posture,
                    ],
                    vec!["private-consultation-namespace"],
                    vec![POSTGRESQL, NAMESPACE_HOLDER],
                    "relay-consultation-health",
                ),
                product(
                    ProductLaneV1::Notary,
                    images.notary.clone(),
                    vec![
                        MountRoleV1::Bundle,
                        MountRoleV1::Anchor,
                        MountRoleV1::AntiRollbackState,
                        MountRoleV1::Secret,
                        MountRoleV1::Certificate,
                        MountRoleV1::Audit,
                    ],
                    vec!["notary-tls", "notary-signing-key"],
                    vec!["notary-anti-rollback", "notary-audit"],
                    vec![
                        EndpointClassV1::PrivateApplication,
                        EndpointClassV1::Administration,
                        EndpointClassV1::Metrics,
                        EndpointClassV1::Posture,
                    ],
                    vec!["private-consultation-namespace"],
                    vec![RELAY_CONSULTATION, POSTGRESQL, NAMESPACE_HOLDER],
                    "notary-health",
                ),
                DeploymentWorkloadV1::Supporting(SupportingWorkloadV1 {
                    id: POSTGRESQL.to_string(),
                    recipe: SupportingWorkloadRecipeV1::PostgresqlStatePlane,
                    image_identity: images.postgresql_state_plane.clone(),
                    secret_consumers: strings(vec!["postgresql-tls", "postgresql-credentials"]),
                    state_roles: strings(vec!["postgresql-data"]),
                    endpoint_classes: vec![EndpointClassV1::PrivateApplication],
                    network_relationships: strings(vec!["private-consultation-namespace"]),
                    dependencies: strings(vec![NAMESPACE_HOLDER]),
                    health_semantics: "postgresql-health".to_string(),
                    restart_action: ExpectedRestartActionV1::Restart,
                    reactivation_action: ExpectedReactivationActionV1::RestoreConsistencyGroup,
                }),
                DeploymentWorkloadV1::Supporting(SupportingWorkloadV1 {
                    id: NAMESPACE_HOLDER.to_string(),
                    recipe: SupportingWorkloadRecipeV1::PrivateNamespaceHolder,
                    image_identity: images.private_namespace_holder.clone(),
                    secret_consumers: Vec::new(),
                    state_roles: Vec::new(),
                    endpoint_classes: Vec::new(),
                    network_relationships: strings(vec!["private"]),
                    dependencies: Vec::new(),
                    health_semantics: "namespace-holder-health".to_string(),
                    restart_action: ExpectedRestartActionV1::Restart,
                    reactivation_action: ExpectedReactivationActionV1::RestartConsistencyGroup,
                }),
            ],
            initialization_actions: vec![
                initialization(
                    "bootstrap-postgresql-state-plane",
                    POSTGRESQL,
                    RuntimeActionV1::BootstrapStatePlane,
                ),
                initialization(
                    "prepare-relay-public-state",
                    RELAY_PUBLIC,
                    RuntimeActionV1::PrepareStateStore,
                ),
                initialization(
                    "prepare-relay-consultation-state",
                    RELAY_CONSULTATION,
                    RuntimeActionV1::PrepareStateStore,
                ),
                initialization(
                    "prepare-notary-state",
                    NOTARY,
                    RuntimeActionV1::PrepareStateStore,
                ),
                initialization(
                    "initialize-relay-public",
                    RELAY_PUBLIC,
                    RuntimeActionV1::InitializeState,
                ),
                initialization(
                    "initialize-relay-consultation",
                    RELAY_CONSULTATION,
                    RuntimeActionV1::InitializeState,
                ),
                initialization(
                    "initialize-notary",
                    NOTARY,
                    RuntimeActionV1::InitializeState,
                ),
            ],
            private_co_location_groups: vec![WorkloadGroupV1 {
                id: "private-consultation-namespace".to_string(),
                members: strings(vec![
                    RELAY_CONSULTATION,
                    NOTARY,
                    POSTGRESQL,
                    NAMESPACE_HOLDER,
                ]),
            }],
            recovery_consistency_groups: vec![
                WorkloadGroupV1 {
                    id: "consultation-state".to_string(),
                    members: strings(vec![RELAY_CONSULTATION, NOTARY, POSTGRESQL]),
                },
                WorkloadGroupV1 {
                    id: "relay-public-state".to_string(),
                    members: strings(vec![RELAY_PUBLIC]),
                },
            ],
            exposure_requirements: vec![
                exposure(
                    EndpointClassV1::PublicApplication,
                    EndpointExposureV1::OperatorBound,
                ),
                exposure(
                    EndpointClassV1::PrivateApplication,
                    EndpointExposureV1::PrivateNamespaceOnly,
                ),
                exposure(
                    EndpointClassV1::Administration,
                    EndpointExposureV1::LoopbackOnly,
                ),
                exposure(EndpointClassV1::Metrics, EndpointExposureV1::LoopbackOnly),
                exposure(EndpointClassV1::Posture, EndpointExposureV1::LoopbackOnly),
            ],
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_schema(
            &self.schema_id,
            &self.schema_version,
            DEPLOYMENT_PLAN_SCHEMA_ID,
            DEPLOYMENT_PLAN_SCHEMA_VERSION,
        )?;
        if !self.single_instance {
            bail!("DeploymentPlanV1 supports exactly one instance");
        }
        let ids: BTreeSet<_> = self
            .workloads
            .iter()
            .map(DeploymentWorkloadV1::id)
            .collect();
        let expected_ids = BTreeSet::from([
            RELAY_PUBLIC,
            RELAY_CONSULTATION,
            NOTARY,
            POSTGRESQL,
            NAMESPACE_HOLDER,
        ]);
        if ids != expected_ids || ids.len() != self.workloads.len() {
            bail!("DeploymentPlanV1 must contain the complete closed five-workload topology");
        }
        for workload in &self.workloads {
            if workload
                .dependencies()
                .iter()
                .any(|id| !ids.contains(id.as_str()))
            {
                bail!("DeploymentPlanV1 contains a dependency on an unknown workload");
            }
            match workload {
                DeploymentWorkloadV1::Product(product) => {
                    if product.id != product.product_lane.id()
                        || product.action != RuntimeActionV1::Serve
                        || product.immutable_inputs
                            != [
                                format!("{}-bundle", product.id),
                                format!("{}-anchor", product.id),
                            ]
                    {
                        bail!("product workload identity or immutable inputs are inconsistent");
                    }
                }
                DeploymentWorkloadV1::Supporting(supporting) => {
                    let expected = match supporting.recipe {
                        SupportingWorkloadRecipeV1::PostgresqlStatePlane => POSTGRESQL,
                        SupportingWorkloadRecipeV1::PrivateNamespaceHolder => NAMESPACE_HOLDER,
                    };
                    if supporting.id != expected {
                        bail!("supporting workload id does not match its closed recipe");
                    }
                }
            }
        }
        let expected_initialization = [
            (
                "bootstrap-postgresql-state-plane",
                POSTGRESQL,
                RuntimeActionV1::BootstrapStatePlane,
            ),
            (
                "prepare-relay-public-state",
                RELAY_PUBLIC,
                RuntimeActionV1::PrepareStateStore,
            ),
            (
                "prepare-relay-consultation-state",
                RELAY_CONSULTATION,
                RuntimeActionV1::PrepareStateStore,
            ),
            (
                "prepare-notary-state",
                NOTARY,
                RuntimeActionV1::PrepareStateStore,
            ),
            (
                "initialize-relay-public",
                RELAY_PUBLIC,
                RuntimeActionV1::InitializeState,
            ),
            (
                "initialize-relay-consultation",
                RELAY_CONSULTATION,
                RuntimeActionV1::InitializeState,
            ),
            (
                "initialize-notary",
                NOTARY,
                RuntimeActionV1::InitializeState,
            ),
        ];
        if self.initialization_actions.len() != expected_initialization.len()
            || !self
                .initialization_actions
                .iter()
                .zip(expected_initialization)
                .all(|(actual, expected)| {
                    (actual.id.as_str(), actual.workload.as_str(), actual.action) == expected
                })
        {
            bail!("DeploymentPlanV1 initialization actions are incomplete or out of order");
        }
        validate_group(
            &self.private_co_location_groups,
            "private-consultation-namespace",
            &[RELAY_CONSULTATION, NOTARY, POSTGRESQL, NAMESPACE_HOLDER],
        )?;
        if self.recovery_consistency_groups
            != [
                WorkloadGroupV1 {
                    id: "consultation-state".to_string(),
                    members: strings(vec![RELAY_CONSULTATION, NOTARY, POSTGRESQL]),
                },
                WorkloadGroupV1 {
                    id: "relay-public-state".to_string(),
                    members: strings(vec![RELAY_PUBLIC]),
                },
            ]
        {
            bail!("DeploymentPlanV1 recovery consistency groups are incomplete");
        }
        let exposures: BTreeMap<_, _> = self
            .exposure_requirements
            .iter()
            .map(|item| (item.endpoint_class, item.exposure))
            .collect();
        let expected_exposures = BTreeMap::from([
            (
                EndpointClassV1::PublicApplication,
                EndpointExposureV1::OperatorBound,
            ),
            (
                EndpointClassV1::PrivateApplication,
                EndpointExposureV1::PrivateNamespaceOnly,
            ),
            (
                EndpointClassV1::Administration,
                EndpointExposureV1::LoopbackOnly,
            ),
            (EndpointClassV1::Metrics, EndpointExposureV1::LoopbackOnly),
            (EndpointClassV1::Posture, EndpointExposureV1::LoopbackOnly),
        ]);
        if exposures != expected_exposures || exposures.len() != self.exposure_requirements.len() {
            bail!("DeploymentPlanV1 exposure requirements are incomplete");
        }
        let relay_public = self.product(ProductLaneV1::RelayPublic)?;
        let relay_consultation = self.product(ProductLaneV1::RelayConsultation)?;
        if relay_public.image_identity != relay_consultation.image_identity {
            bail!("public and consultation Relay workloads must use one locked Relay image");
        }
        let expected = Self::managed_single_node(&ManagedTopologyImagesV1 {
            relay: relay_public.image_identity.clone(),
            notary: self.product(ProductLaneV1::Notary)?.image_identity.clone(),
            postgresql_state_plane: self
                .supporting(SupportingWorkloadRecipeV1::PostgresqlStatePlane)?
                .image_identity
                .clone(),
            private_namespace_holder: self
                .supporting(SupportingWorkloadRecipeV1::PrivateNamespaceHolder)?
                .image_identity
                .clone(),
        });
        if self != &expected {
            bail!("DeploymentPlanV1 differs from the closed managed single-node topology");
        }
        Ok(())
    }

    fn product(&self, lane: ProductLaneV1) -> Result<&ProductWorkloadV1> {
        self.workloads
            .iter()
            .find_map(|workload| match workload {
                DeploymentWorkloadV1::Product(product) if product.product_lane == lane => {
                    Some(product)
                }
                _ => None,
            })
            .ok_or_else(|| anyhow!("DeploymentPlanV1 is missing product lane {}", lane.id()))
    }

    fn supporting(&self, recipe: SupportingWorkloadRecipeV1) -> Result<&SupportingWorkloadV1> {
        self.workloads
            .iter()
            .find_map(|workload| match workload {
                DeploymentWorkloadV1::Supporting(supporting) if supporting.recipe == recipe => {
                    Some(supporting)
                }
                _ => None,
            })
            .ok_or_else(|| anyhow!("DeploymentPlanV1 is missing a supporting recipe"))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoopbackPortsV1 {
    pub relay_public: u16,
    pub notary: u16,
    pub relay_public_metrics: u16,
    pub relay_consultation_metrics: u16,
    pub notary_metrics: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentBindingV1 {
    pub schema_id: String,
    pub schema_version: String,
    pub package_id: String,
    pub environment: String,
    pub loopback_address: String,
    pub ports: LoopbackPortsV1,
    pub edge_network_name: Option<String>,
    pub secret_files: BTreeMap<String, String>,
    pub certificate_files: BTreeMap<String, String>,
    pub durable_volume_prefix: String,
    pub restart_policy: String,
    pub logging_policy: String,
}

impl DeploymentBindingV1 {
    pub fn safe_default(package_id: impl Into<String>, environment: impl Into<String>) -> Self {
        Self {
            schema_id: DEPLOYMENT_BINDING_SCHEMA_ID.to_string(),
            schema_version: DEPLOYMENT_BINDING_SCHEMA_VERSION.to_string(),
            package_id: package_id.into(),
            environment: environment.into(),
            loopback_address: "127.0.0.1".to_string(),
            ports: LoopbackPortsV1 {
                relay_public: 4242,
                notary: 4255,
                relay_public_metrics: 9242,
                relay_consultation_metrics: 9243,
                notary_metrics: 9255,
            },
            edge_network_name: None,
            secret_files: OPERATOR_FILE_IDS
                .into_iter()
                .map(|id| (id.to_string(), format!("operator/secrets/{id}")))
                .collect(),
            certificate_files: BTreeMap::new(),
            durable_volume_prefix: "registry".to_string(),
            restart_policy: "unless-stopped".to_string(),
            logging_policy: "local-bounded".to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_schema(
            &self.schema_id,
            &self.schema_version,
            DEPLOYMENT_BINDING_SCHEMA_ID,
            DEPLOYMENT_BINDING_SCHEMA_VERSION,
        )?;
        validate_id("package_id", &self.package_id)?;
        validate_id("environment", &self.environment)?;
        validate_id("durable_volume_prefix", &self.durable_volume_prefix)?;
        if self.loopback_address != "127.0.0.1" && self.loopback_address != "::1" {
            bail!("managed host publishing must use an explicit loopback address");
        }
        let ports = [
            self.ports.relay_public,
            self.ports.notary,
            self.ports.relay_public_metrics,
            self.ports.relay_consultation_metrics,
            self.ports.notary_metrics,
        ];
        if ports.contains(&0) || ports.iter().collect::<BTreeSet<_>>().len() != ports.len() {
            bail!("managed loopback ports must be non-zero and distinct");
        }
        if self.restart_policy != "unless-stopped" || self.logging_policy != "local-bounded" {
            bail!("deployment binding selects an unsupported managed policy");
        }
        let expected_secrets = BTreeSet::from(OPERATOR_FILE_IDS);
        if self
            .secret_files
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != expected_secrets
        {
            bail!("deployment binding secret consumer inventory is incomplete");
        }
        for locator in self
            .secret_files
            .values()
            .chain(self.certificate_files.values())
        {
            validate_package_relative_path(locator)?;
            if !locator.starts_with("operator/") {
                bail!("secret and certificate locators must remain operator-owned");
            }
        }
        if let Some(network) = &self.edge_network_name {
            validate_id("edge_network_name", network)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LockedProductRuntimeV1 {
    pub serve: LockedRuntimeActionV1,
    pub prepare_state_store: LockedRuntimeActionV1,
    pub initialize_state: LockedRuntimeActionV1,
    pub verify_state: LockedRuntimeActionV1,
    pub health_probe: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LockedSupportingRuntimeV1 {
    pub command: Vec<String>,
    pub health_probe: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LockedPostgresqlRuntimeV1 {
    pub serve: LockedRuntimeActionV1,
    pub bootstrap: LockedRuntimeActionV1,
    pub health_probe: Vec<String>,
    pub server_environment: Vec<String>,
    pub hardening: LockedServiceHardeningV1,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LockedRuntimeMappingV1 {
    pub relay_public: LockedProductRuntimeV1,
    pub relay_consultation: LockedProductRuntimeV1,
    pub notary: LockedProductRuntimeV1,
    pub postgresql_state_plane: LockedPostgresqlRuntimeV1,
    pub private_namespace_holder: LockedSupportingRuntimeV1,
    pub operator_files: Vec<LockedOperatorFileV1>,
}

impl LockedRuntimeMappingV1 {
    pub fn validate(&self) -> Result<()> {
        for (label, command) in [
            ("public Relay serve", &self.relay_public.serve.command),
            (
                "public Relay prepare_state_store",
                &self.relay_public.prepare_state_store.command,
            ),
            (
                "public Relay initialize_state",
                &self.relay_public.initialize_state.command,
            ),
            (
                "public Relay verify_state",
                &self.relay_public.verify_state.command,
            ),
            ("public Relay health", &self.relay_public.health_probe),
            (
                "consultation Relay serve",
                &self.relay_consultation.serve.command,
            ),
            (
                "consultation Relay prepare_state_store",
                &self.relay_consultation.prepare_state_store.command,
            ),
            (
                "consultation Relay initialize_state",
                &self.relay_consultation.initialize_state.command,
            ),
            (
                "consultation Relay verify_state",
                &self.relay_consultation.verify_state.command,
            ),
            (
                "consultation Relay health",
                &self.relay_consultation.health_probe,
            ),
            ("Notary serve", &self.notary.serve.command),
            (
                "Notary prepare_state_store",
                &self.notary.prepare_state_store.command,
            ),
            (
                "Notary initialize_state",
                &self.notary.initialize_state.command,
            ),
            ("Notary verify_state", &self.notary.verify_state.command),
            ("Notary health", &self.notary.health_probe),
            (
                "PostgreSQL state-plane recipe",
                &self.postgresql_state_plane.serve.command,
            ),
            (
                "PostgreSQL state-plane bootstrap",
                &self.postgresql_state_plane.bootstrap.command,
            ),
            (
                "PostgreSQL state-plane health",
                &self.postgresql_state_plane.health_probe,
            ),
            (
                "private namespace-holder recipe",
                &self.private_namespace_holder.command,
            ),
            (
                "private namespace-holder health",
                &self.private_namespace_holder.health_probe,
            ),
        ] {
            if command.is_empty() || command.iter().any(|part| part.is_empty()) {
                bail!("{label} mapping is empty");
            }
        }
        Ok(())
    }

    fn product(&self, lane: ProductLaneV1) -> &LockedProductRuntimeV1 {
        match lane {
            ProductLaneV1::RelayPublic => &self.relay_public,
            ProductLaneV1::RelayConsultation => &self.relay_consultation,
            ProductLaneV1::Notary => &self.notary,
        }
    }

    fn from_verified(value: VerifiedRuntimeMappingV1) -> Self {
        Self {
            relay_public: LockedProductRuntimeV1::from_verified(value.relay_public()),
            relay_consultation: LockedProductRuntimeV1::from_verified(value.relay_consultation()),
            notary: LockedProductRuntimeV1::from_verified(value.notary()),
            postgresql_state_plane: LockedPostgresqlRuntimeV1::from_verified(
                value.postgresql_state_plane(),
            ),
            private_namespace_holder: LockedSupportingRuntimeV1::from_verified(
                value.private_namespace_holder(),
            ),
            operator_files: value.operator_files().to_vec(),
        }
    }
}

impl LockedProductRuntimeV1 {
    fn from_verified(value: &VerifiedProductRuntimeV1) -> Self {
        Self {
            serve: value.serve_action().clone(),
            prepare_state_store: value.prepare_state_store_action().clone(),
            initialize_state: value.initialize_state_action().clone(),
            verify_state: value.verify_state_action().clone(),
            health_probe: value.health_probe().to_vec(),
        }
    }
}

impl LockedPostgresqlRuntimeV1 {
    fn from_verified(value: &VerifiedPostgresqlRuntimeV1) -> Self {
        Self {
            serve: value.serve().clone(),
            bootstrap: value.bootstrap().clone(),
            health_probe: value.health_probe().to_vec(),
            server_environment: value.server_environment().to_vec(),
            hardening: value.hardening().clone(),
        }
    }
}

impl LockedSupportingRuntimeV1 {
    fn from_verified(value: &VerifiedSupportingRuntimeV1) -> Self {
        Self {
            command: value.command().to_vec(),
            health_probe: value.health_probe().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RenderedComposeModelsV1 {
    pub ordinary: Value,
    pub initialization: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenderedComposePackageV1 {
    pub compose_yaml: String,
    pub initialization_yaml: String,
    pub postgresql_server_environment: String,
    pub models: RenderedComposeModelsV1,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentOperatorFileInventoryV1 {
    pub schema_id: String,
    pub schema_version: String,
    pub files: Vec<DeploymentOperatorFileV1>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentOperatorFileV1 {
    pub id: String,
    pub path: String,
    pub consumers: Vec<String>,
    pub format: LockedOperatorFileFormatV1,
    pub mode: String,
    pub allowed_owners: Vec<String>,
    pub required_keys: Vec<String>,
}

fn operator_file_inventory(
    runtime: &LockedRuntimeMappingV1,
    binding: &DeploymentBindingV1,
) -> Result<DeploymentOperatorFileInventoryV1> {
    let mut consumers = BTreeMap::<String, BTreeSet<String>>::new();
    for (lane, product) in [
        ("relay-public", &runtime.relay_public),
        ("relay-consultation", &runtime.relay_consultation),
        ("notary", &runtime.notary),
    ] {
        for (action_name, action) in [
            ("serve", &product.serve),
            ("prepare_state_store", &product.prepare_state_store),
            ("initialize_state", &product.initialize_state),
            ("verify_state", &product.verify_state),
        ] {
            add_action_consumers(&mut consumers, &format!("{lane}:{action_name}"), action);
        }
    }
    add_action_consumers(
        &mut consumers,
        "postgresql-state-plane:serve",
        &runtime.postgresql_state_plane.serve,
    );
    add_action_consumers(
        &mut consumers,
        "postgresql-state-plane:bootstrap",
        &runtime.postgresql_state_plane.bootstrap,
    );
    let files = runtime
        .operator_files
        .iter()
        .map(|file| {
            let path = binding
                .secret_files
                .get(&file.id)
                .ok_or_else(|| anyhow!("binding is missing operator file {}", file.id))?;
            let file_consumers = consumers
                .remove(&file.id)
                .ok_or_else(|| anyhow!("operator file {} has no runtime consumer", file.id))?;
            Ok(DeploymentOperatorFileV1 {
                id: file.id.clone(),
                path: path.clone(),
                consumers: file_consumers.into_iter().collect(),
                format: file.format,
                mode: file.mode.clone(),
                allowed_owners: file.allowed_owners.clone(),
                required_keys: file.required_keys.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if !consumers.is_empty() {
        bail!("runtime action references an operator file outside the signed inventory");
    }
    Ok(DeploymentOperatorFileInventoryV1 {
        schema_id: DEPLOYMENT_OPERATOR_FILES_SCHEMA_ID.to_string(),
        schema_version: DEPLOYMENT_OPERATOR_FILES_SCHEMA_VERSION.to_string(),
        files,
    })
}

fn add_action_consumers(
    consumers: &mut BTreeMap<String, BTreeSet<String>>,
    action_name: &str,
    action: &LockedRuntimeActionV1,
) {
    for file_id in &action.environment_files {
        consumers
            .entry(file_id.clone())
            .or_default()
            .insert(format!("{action_name}:environment"));
    }
    for projection in &action.secret_files {
        consumers
            .entry(projection.file_id.clone())
            .or_default()
            .insert(format!("{action_name}:{}", projection.target));
    }
}

pub fn render_compose_package(
    verified_inputs: &VerifiedDeploymentInputsV1,
    binding: &DeploymentBindingV1,
) -> Result<RenderedComposePackageV1> {
    let plan = &verified_inputs.plan;
    let runtime = &verified_inputs.runtime;
    plan.validate()?;
    binding.validate()?;
    runtime.validate()?;

    let ordinary = render_ordinary_model(plan, binding, runtime, &verified_inputs.lanes)?;
    let initialization =
        render_initialization_model(plan, binding, runtime, &verified_inputs.lanes)?;
    Ok(RenderedComposePackageV1 {
        compose_yaml: serde_norway::to_string(&ordinary)
            .context("failed to serialize managed Compose model")?,
        initialization_yaml: serde_norway::to_string(&initialization)
            .context("failed to serialize managed initialization model")?,
        postgresql_server_environment: format!(
            "{}\n",
            runtime.postgresql_state_plane.server_environment.join("\n")
        ),
        models: RenderedComposeModelsV1 {
            ordinary,
            initialization,
        },
    })
}

#[derive(Debug, Clone)]
struct VerifiedLanePackageSourceV1 {
    lane: ProductLaneV1,
    bundle_dir: PathBuf,
    anchor_file: PathBuf,
    anchor_history: Vec<(PathBuf, PathBuf)>,
    manifest_digest_component: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeploymentReleaseMetadataV1 {
    pub generator_release: String,
    pub minimum_compose_version: String,
    pub postgresql_major: u16,
}

impl DeploymentReleaseMetadataV1 {
    pub fn validate(&self) -> Result<()> {
        if self.generator_release.trim().is_empty() {
            bail!("deployment generator release identity must not be empty");
        }
        let compose_parts = self
            .minimum_compose_version
            .split('.')
            .map(str::parse::<u16>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("minimum Compose version must be numeric major.minor.patch")?;
        if compose_parts.len() != 3 || compose_parts.as_slice() < &[2, 35, 0] {
            bail!("managed deployment requires Docker Compose 2.35.0 or later");
        }
        if self.postgresql_major == 0 {
            bail!("release-owned PostgreSQL major must be non-zero");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DeploymentPackageRenderRequestV1 {
    pub output_dir: PathBuf,
    pub binding: DeploymentBindingV1,
    pub verified_inputs: VerifiedDeploymentInputsV1,
}

#[derive(Debug, Clone)]
pub struct DeploymentGenerateRequestV1 {
    pub approved_set_file: PathBuf,
    pub output_dir: PathBuf,
}

pub struct DeploymentVerifyRequestV1<'a> {
    pub package_dir: &'a Path,
    pub expected_approved_set_file: Option<&'a Path>,
    pub parent_compose_files: &'a [PathBuf],
    pub externally_recorded_closure_sha256: Option<String>,
}

/// The single generation authority assembled after product-lane and release
/// verification. Its fields are private so a caller cannot independently mix
/// an approved set, image plan, command mapping, and release lock.
#[derive(Debug, Clone)]
pub struct VerifiedDeploymentInputsV1 {
    plan: DeploymentPlanV1,
    runtime: LockedRuntimeMappingV1,
    release_metadata: DeploymentReleaseMetadataV1,
    normalized_approved_set: ApprovedBaselineSetV1,
    source_approved_set_sha256: String,
    normalized_approved_set_sha256: String,
    registry_release_lock: Vec<u8>,
    registry_release_lock_sha256: String,
    lanes: Vec<VerifiedLanePackageSourceV1>,
    acceptance_identity: ProductAcceptanceIdentityV1,
}

impl VerifiedDeploymentInputsV1 {
    /// Production generation accepts only a verified installed release-lock
    /// capability. Images, runtime recipes, compatibility metadata, and the
    /// exact copied lock envelope are all derived from that one authority.
    pub(crate) fn from_verified_components(
        approved_set_file: &Path,
        release_lock: &VerifiedReleaseLockV1,
    ) -> Result<Self> {
        let approved_root = approved_set_file
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let (plan, runtime, release_metadata) = deployment_authority(release_lock)?;
        Self::from_components(
            approved_set_file,
            approved_root,
            plan,
            runtime,
            release_metadata,
            release_lock.envelope_bytes().to_vec(),
            release_lock.envelope_sha256().to_string(),
            true,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_test_components(
        approved_set_file: &Path,
        registry_release_lock_file: &Path,
        plan: DeploymentPlanV1,
        runtime: LockedRuntimeMappingV1,
        release_metadata: DeploymentReleaseMetadataV1,
        acceptance_identity: ProductAcceptanceIdentityV1,
    ) -> Result<Self> {
        let approved_root = approved_set_file
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let registry_release_lock =
            read_bounded(registry_release_lock_file, MAX_PORTABLE_DOCUMENT_BYTES)
                .context("failed to read test Registry release lock")?;
        let registry_release_lock_sha256 = sha256_uri(&registry_release_lock);
        Self::from_components(
            approved_set_file,
            approved_root,
            plan,
            runtime,
            release_metadata,
            registry_release_lock,
            registry_release_lock_sha256,
            false,
            Some(acceptance_identity),
        )
    }

    fn from_verified_package(
        package_dir: &Path,
        release_lock: &VerifiedReleaseLockV1,
    ) -> Result<Self> {
        let generated = package_dir.join("generated");
        let approved_set_file = generated.join("inputs/approved-baseline-set.v1.json");
        let (plan, runtime, release_metadata) = deployment_authority(release_lock)?;
        Self::from_components(
            &approved_set_file,
            &generated,
            plan,
            runtime,
            release_metadata,
            release_lock.envelope_bytes().to_vec(),
            release_lock.envelope_sha256().to_string(),
            true,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_components(
        approved_set_file: &Path,
        approved_artifact_root: &Path,
        plan: DeploymentPlanV1,
        runtime: LockedRuntimeMappingV1,
        release_metadata: DeploymentReleaseMetadataV1,
        registry_release_lock: Vec<u8>,
        registry_release_lock_sha256: String,
        independently_verify_lanes: bool,
        test_acceptance_identity: Option<ProductAcceptanceIdentityV1>,
    ) -> Result<Self> {
        plan.validate()?;
        runtime.validate()?;
        release_metadata.validate()?;
        let source_approved_set = if independently_verify_lanes {
            crate::approved_set::load_approved_baseline_set_with_root(
                approved_set_file,
                approved_artifact_root,
            )?
        } else {
            #[cfg(test)]
            {
                crate::approved_set::load_approved_baseline_set_structure(approved_set_file)?
            }
            #[cfg(not(test))]
            unreachable!("structural approved-set loading is test-only");
        };
        let acceptance_identity = if independently_verify_lanes {
            crate::approved_set::verify_approved_lane_from_set_with_root(
                approved_set_file,
                ApprovedLaneV1::RelayPublic,
                approved_artifact_root,
            )?
            .acceptance_identity()
            .clone()
        } else {
            test_acceptance_identity
                .ok_or_else(|| anyhow!("test deployment identity is unavailable"))?
        };
        acceptance_identity
            .validate()
            .context("deployment acceptance identity is invalid")?;
        let source_approved_set_sha256 = source_approved_set.digest()?;
        let canonical_root = fs::canonicalize(approved_artifact_root)
            .context("failed to resolve approved-set artifact root")?;
        let mut normalized_approved_set = source_approved_set.clone();
        let mut lanes = Vec::new();
        for approved_lane in ApprovedLaneV1::ALL {
            let lane = ProductLaneV1::from_approved(approved_lane);
            let source_entry = source_approved_set.lanes.get(approved_lane);
            let bundle_dir =
                resolve_approved_artifact(&canonical_root, &source_entry.locators.bundle)?;
            let signed_manifest =
                resolve_approved_artifact(&canonical_root, &source_entry.locators.signed_manifest)?;
            if signed_manifest != bundle_dir.join("manifest.json") {
                bail!("approved lane manifest locator must identify bundle/manifest.json");
            }
            let anchor_file =
                resolve_approved_artifact(&canonical_root, &source_entry.locators.anchor)?;
            let anchor_history = source_entry
                .locators
                .anchor_transitions
                .iter()
                .map(|link| {
                    Ok((
                        resolve_approved_artifact(&canonical_root, &link.predecessor_anchor)?,
                        resolve_approved_artifact(&canonical_root, &link.transition)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let manifest_digest_component =
                digest_path_component(&source_entry.signed_manifest_digest)?;
            let bundle_locator = format!("bundles/{}/{manifest_digest_component}", lane.id());
            let normalized_entry = normalized_lane_mut(&mut normalized_approved_set, approved_lane);
            normalized_entry.locators.bundle =
                PortableArtifactLocator::new(bundle_locator.clone())?;
            normalized_entry.locators.signed_manifest =
                PortableArtifactLocator::new(format!("{bundle_locator}/manifest.json"))?;
            normalized_entry.locators.anchor =
                PortableArtifactLocator::new(format!("anchors/{}/anchor.json", lane.id()))?;
            normalized_entry.locators.anchor_transitions = anchor_history
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    Ok(crate::approved_set::ApprovedAnchorTransitionLinkV1 {
                        predecessor_anchor: PortableArtifactLocator::new(format!(
                            "anchors/{}/history/{index:04}.anchor.json",
                            lane.id()
                        ))?,
                        transition: PortableArtifactLocator::new(format!(
                            "anchors/{}/history/{index:04}.transition.json",
                            lane.id()
                        ))?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            lanes.push(VerifiedLanePackageSourceV1 {
                lane,
                bundle_dir,
                anchor_file,
                anchor_history,
                manifest_digest_component,
            });
        }
        normalized_approved_set.validate()?;
        let normalized_approved_set_sha256 = normalized_approved_set.digest()?;
        if registry_release_lock.len() as u64 > MAX_PORTABLE_DOCUMENT_BYTES
            || registry_release_lock_sha256 != sha256_uri(&registry_release_lock)
        {
            bail!("verified Registry release lock envelope is invalid");
        }
        Ok(Self {
            plan,
            runtime,
            release_metadata,
            normalized_approved_set,
            source_approved_set_sha256,
            normalized_approved_set_sha256,
            registry_release_lock,
            registry_release_lock_sha256,
            lanes,
            acceptance_identity,
        })
    }
}

fn deployment_authority(
    release_lock: &VerifiedReleaseLockV1,
) -> Result<(
    DeploymentPlanV1,
    LockedRuntimeMappingV1,
    DeploymentReleaseMetadataV1,
)> {
    let images = release_lock.managed_images();
    let plan = DeploymentPlanV1::managed_single_node(&ManagedTopologyImagesV1 {
        relay: ImageIdentityV1::parse(images.relay())?,
        notary: ImageIdentityV1::parse(images.notary())?,
        postgresql_state_plane: ImageIdentityV1::parse(images.postgresql_state_plane())?,
        private_namespace_holder: ImageIdentityV1::parse(images.private_namespace_holder())?,
    });
    let runtime = LockedRuntimeMappingV1::from_verified(release_lock.runtime_mapping());
    let release_metadata = DeploymentReleaseMetadataV1 {
        generator_release: release_lock.product_version().to_string(),
        minimum_compose_version: release_lock.minimum_compose_version().to_string(),
        postgresql_major: release_lock.postgresql_major_version(),
    };
    plan.validate()?;
    runtime.validate()?;
    release_metadata.validate()?;
    Ok((plan, runtime, release_metadata))
}

pub fn generate_deployment_package(
    request: DeploymentGenerateRequestV1,
) -> Result<DeploymentPackageRenderReportV1> {
    let installed_release_lock = verified_installed_release_lock()?;
    let verified_inputs = VerifiedDeploymentInputsV1::from_verified_components(
        &request.approved_set_file,
        &installed_release_lock,
    )?;
    generate_deployment_package_core(&request, verified_inputs, None, true)
}

#[cfg(test)]
pub(crate) fn generate_deployment_package_with_test_inputs(
    request: DeploymentGenerateRequestV1,
    verified_inputs: VerifiedDeploymentInputsV1,
    preceding_inputs: Option<&VerifiedDeploymentInputsV1>,
) -> Result<DeploymentPackageRenderReportV1> {
    generate_deployment_package_core(&request, verified_inputs, preceding_inputs, false)
}

pub fn verify_generated_deployment(
    request: DeploymentVerifyRequestV1<'_>,
) -> Result<DeploymentOwnershipReportV1> {
    let installed_release_lock = verified_installed_release_lock()?;
    let installed_inputs = VerifiedDeploymentInputsV1::from_verified_package(
        request.package_dir,
        &installed_release_lock,
    )
    .context("installed release deployment projection is invalid")?;
    let expected_approved_baseline_set_sha256 = request
        .expected_approved_set_file
        .map(|path| {
            crate::approved_set::load_approved_baseline_set(path)
                .and_then(|set| set.digest())
                .context("expected approved set failed independent verification")
        })
        .transpose()?;
    verify_deployment_package(&DeploymentPackageVerificationRequestV1 {
        package_dir: request.package_dir,
        verified_inputs: &installed_inputs,
        parent_compose_files: request.parent_compose_files,
        expected_inputs: ExpectedGenerationInputsV1 {
            source_approved_baseline_set_sha256: expected_approved_baseline_set_sha256,
            registry_release_lock_sha256: None,
            externally_recorded_closure_sha256: request.externally_recorded_closure_sha256,
        },
    })
}

fn generate_deployment_package_core(
    request: &DeploymentGenerateRequestV1,
    verified_inputs: VerifiedDeploymentInputsV1,
    preceding_test_inputs: Option<&VerifiedDeploymentInputsV1>,
    use_production_verifier: bool,
) -> Result<DeploymentPackageRenderReportV1> {
    if output_is_absent_or_empty(&request.output_dir)? {
        let binding = safe_binding_for_inputs(&verified_inputs)?;
        return render_deployment_package(&DeploymentPackageRenderRequestV1 {
            output_dir: request.output_dir.clone(),
            binding,
            verified_inputs,
        });
    }

    let previous = request.output_dir.join("generated.previous");
    match fs::symlink_metadata(&previous) {
        Ok(_) => {
            bail!("deployment regeneration refuses an unresolved generated.previous closure")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).context("failed to inspect the preceding generated closure")
        }
    }

    let preceding_inputs = if use_production_verifier {
        load_verified_package_inputs(&request.output_dir)?
    } else {
        preceding_test_inputs
            .cloned()
            .ok_or_else(|| anyhow!("test regeneration requires preceding package authority"))?
    };
    if preceding_inputs.acceptance_identity.project != verified_inputs.acceptance_identity.project
        || preceding_inputs.acceptance_identity.environment
            != verified_inputs.acceptance_identity.environment
    {
        bail!("deployment regeneration cannot change the signed project or environment identity");
    }

    let binding_bytes = read_bounded_regular_file(
        &request.output_dir.join("binding.yaml"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )?;
    let binding: DeploymentBindingV1 = serde_norway::from_slice(&binding_bytes)
        .context("existing deployment binding is not a supported closed document")?;
    binding.validate()?;
    let preceding_manifest: DeploymentManifestV1 = read_json(
        &request
            .output_dir
            .join("generated/deployment-manifest.v1.json"),
    )?;
    let binding_changed = preceding_manifest.binding_sha256 != sha256_uri(&binding_bytes);
    let product_or_evidence_update = preceding_manifest.source_approved_baseline_set_sha256
        != verified_inputs.source_approved_set_sha256
        || preceding_manifest.registry_release_lock_sha256
            != verified_inputs.registry_release_lock_sha256;
    if binding_changed && product_or_evidence_update {
        bail!(
            "deployment regeneration cannot combine a binding change with a product or evidence update"
        );
    }
    let expected_binding = safe_binding_for_inputs(&verified_inputs)?;
    if binding.package_id != expected_binding.package_id
        || binding.environment != expected_binding.environment
    {
        bail!("existing deployment binding does not match the signed package identity");
    }

    let verification_request = DeploymentPackageVerificationRequestV1 {
        package_dir: &request.output_dir,
        verified_inputs: &verified_inputs,
        parent_compose_files: &[],
        expected_inputs: ExpectedGenerationInputsV1 {
            source_approved_baseline_set_sha256: Some(
                verified_inputs.source_approved_set_sha256.clone(),
            ),
            ..ExpectedGenerationInputsV1::default()
        },
    };
    let preceding_report = if use_production_verifier {
        verify_deployment_package(&verification_request)?
    } else {
        verify_deployment_package_with_package_inputs(
            &verification_request,
            &preceding_inputs,
            false,
        )?
    };
    let may_regenerate = preceding_report.ownership == DeploymentOwnershipStateV1::Managed
        || (preceding_report.ownership == DeploymentOwnershipStateV1::Adapted
            && preceding_report.in_place_regeneration_safe);
    if !may_regenerate {
        bail!(
            "deployment regeneration refuses a package outside managed or override-only ownership"
        );
    }
    if preceding_report.ownership == DeploymentOwnershipStateV1::Managed
        && preceding_report.package_freshness == PackageFreshnessV1::Current
    {
        return existing_render_report(&request.output_dir, &verified_inputs, &binding);
    }
    if preceding_inputs.release_metadata.postgresql_major
        != verified_inputs.release_metadata.postgresql_major
    {
        bail!("deployment regeneration refuses a PostgreSQL major transition");
    }

    let parent = request
        .output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let candidate_parent = tempfile::Builder::new()
        .prefix(".registry-stack-regeneration-")
        .tempdir_in(parent)
        .context("failed to stage deployment regeneration")?;
    let package_name = request
        .output_dir
        .file_name()
        .ok_or_else(|| anyhow!("deployment output directory has no package name"))?;
    let candidate = candidate_parent.path().join(package_name);
    let mut candidate_report = render_deployment_package(&DeploymentPackageRenderRequestV1 {
        output_dir: candidate.clone(),
        binding: binding.clone(),
        verified_inputs: verified_inputs.clone(),
    })?;
    let override_path = request.output_dir.join("operator-override.yaml");
    match fs::symlink_metadata(&override_path) {
        Ok(_) => copy_regular_file(&override_path, &candidate.join("operator-override.yaml"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect the operator override"),
    }
    let candidate_verification = DeploymentPackageVerificationRequestV1 {
        package_dir: &candidate,
        verified_inputs: &verified_inputs,
        parent_compose_files: &[],
        expected_inputs: ExpectedGenerationInputsV1 {
            source_approved_baseline_set_sha256: Some(
                verified_inputs.source_approved_set_sha256.clone(),
            ),
            externally_recorded_closure_sha256: Some(
                candidate_report.externally_recorded_closure_sha256.clone(),
            ),
            ..ExpectedGenerationInputsV1::default()
        },
    };
    let candidate_ownership = if use_production_verifier {
        let candidate_inventory = operator_file_inventory(&verified_inputs.runtime, &binding)?;
        let operator_violations = verify_operator_files(&request.output_dir, &candidate_inventory);
        if !operator_violations.is_empty() {
            bail!("candidate operator-file inventory is not satisfied by the current package");
        }
        verify_deployment_package_with_package_inputs(
            &candidate_verification,
            &verified_inputs,
            false,
        )?
    } else {
        verify_deployment_package_with_package_inputs(
            &candidate_verification,
            &verified_inputs,
            false,
        )?
    };
    if !(candidate_ownership.ownership == DeploymentOwnershipStateV1::Managed
        || (candidate_ownership.ownership == DeploymentOwnershipStateV1::Adapted
            && candidate_ownership.in_place_regeneration_safe))
    {
        bail!("staged deployment closure failed managed verification");
    }

    let generated = request.output_dir.join("generated");
    let candidate_generated = candidate.join("generated");
    fs::rename(&generated, &previous)
        .context("failed to retain the preceding generated closure")?;
    if let Err(error) = fs::rename(&candidate_generated, &generated) {
        let rollback = fs::rename(&previous, &generated);
        if let Err(rollback_error) = rollback {
            return Err(error).context(format!(
                "failed to publish the candidate closure and failed to restore the preceding closure: {rollback_error}"
            ));
        }
        return Err(error).context("failed to publish the candidate generated closure");
    }
    candidate_report.output_dir = request.output_dir.clone();
    Ok(candidate_report)
}

fn verified_installed_release_lock() -> Result<VerifiedReleaseLockV1> {
    let executable = std::env::current_exe().context("running Registryctl path is unavailable")?;
    let sibling = executable
        .parent()
        .ok_or_else(|| anyhow!("running Registryctl has no parent directory"))?
        .join("registry-release-lock.v1.json");
    verify_installed_release_lock(&sibling)
}

fn load_verified_package_inputs(package_dir: &Path) -> Result<VerifiedDeploymentInputsV1> {
    let release_lock_bytes = read_bounded_regular_file(
        &package_dir.join("generated/inputs/registry-release-lock.v1.json"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )?;
    let release_lock = verify_release_lock_for_package(&release_lock_bytes)
        .context("package Registry release lock verification failed")?;
    VerifiedDeploymentInputsV1::from_verified_package(package_dir, &release_lock)
}

fn safe_binding_for_inputs(inputs: &VerifiedDeploymentInputsV1) -> Result<DeploymentBindingV1> {
    let identity = &inputs.acceptance_identity;
    identity
        .validate()
        .context("signed deployment identity is invalid")?;
    let identity_bytes = canonicalize_json(&json!({
        "project": identity.project,
        "environment": identity.environment,
    }))?;
    let digest = hex::encode(Sha256::digest(&identity_bytes));
    Ok(DeploymentBindingV1::safe_default(
        format!("registry-{}", &digest[..24]),
        identity.environment.clone(),
    ))
}

fn output_is_absent_or_empty(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("deployment output must be an absent or regular directory");
            }
            Ok(fs::read_dir(path)?.next().is_none())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error).context("failed to inspect deployment output"),
    }
}

fn existing_render_report(
    output_dir: &Path,
    inputs: &VerifiedDeploymentInputsV1,
    binding: &DeploymentBindingV1,
) -> Result<DeploymentPackageRenderReportV1> {
    let manifest: DeploymentManifestV1 =
        read_json(&output_dir.join("generated/deployment-manifest.v1.json"))?;
    Ok(DeploymentPackageRenderReportV1 {
        output_dir: output_dir.to_path_buf(),
        source_approved_baseline_set_sha256: manifest.source_approved_baseline_set_sha256.clone(),
        externally_recorded_closure_sha256: manifest.generated_closure_sha256.clone(),
        manifest,
        models: render_compose_package(inputs, binding)?.models,
    })
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentManifestV1 {
    pub schema_id: String,
    pub schema_version: String,
    pub generator_release: String,
    pub minimum_compose_version: String,
    pub environment: String,
    pub package_id: String,
    pub postgresql_major: u16,
    pub plan_sha256: String,
    pub binding_sha256: String,
    pub source_approved_baseline_set_sha256: String,
    pub normalized_approved_baseline_set_sha256: String,
    pub registry_release_lock_sha256: String,
    pub copied_input_roots: BTreeMap<String, String>,
    pub generated_files: BTreeMap<String, String>,
    pub generated_closure_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeploymentPackageRenderReportV1 {
    pub output_dir: PathBuf,
    pub manifest: DeploymentManifestV1,
    pub models: RenderedComposeModelsV1,
    pub source_approved_baseline_set_sha256: String,
    /// Record this outside the transferred package and compare it before the
    /// first initialization.
    pub externally_recorded_closure_sha256: String,
}

pub fn render_deployment_package(
    request: &DeploymentPackageRenderRequestV1,
) -> Result<DeploymentPackageRenderReportV1> {
    let inputs = &request.verified_inputs;
    inputs.plan.validate()?;
    request.binding.validate()?;
    inputs.runtime.validate()?;
    inputs.release_metadata.validate()?;
    validate_first_generation_target(&request.output_dir)?;

    let rendered = render_compose_package(inputs, &request.binding)?;
    let operator_inventory = operator_file_inventory(&inputs.runtime, &request.binding)?;
    let parent = request
        .output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create package parent {}", parent.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".registry-stack-package-")
        .tempdir_in(parent)
        .context("failed to create deployment-package staging directory")?;
    let root = staging.path();
    create_owner_only_dir(&root.join("operator"))?;
    create_owner_only_dir(&root.join("operator/secrets"))?;
    create_owner_only_dir(&root.join("operator/certificates"))?;
    fs::create_dir_all(root.join("generated/inputs"))?;
    fs::create_dir_all(root.join("generated/bundles"))?;
    fs::create_dir_all(root.join("generated/anchors"))?;

    write_yaml(root.join("binding.yaml"), &request.binding)?;
    write_bytes(root.join("generated/compose.empty.env"), b"")?;
    write_bytes(
        root.join("generated/postgresql-server.env"),
        rendered.postgresql_server_environment.as_bytes(),
    )?;
    write_bytes(
        root.join("generated/compose.yaml"),
        rendered.compose_yaml.as_bytes(),
    )?;
    write_bytes(
        root.join("generated/compose.initialize.yaml"),
        rendered.initialization_yaml.as_bytes(),
    )?;
    write_json(root.join("generated/deployment-plan.v1.json"), &inputs.plan)?;
    write_json(
        root.join("generated/operator-files.v1.json"),
        &operator_inventory,
    )?;
    write_bytes(
        root.join("generated/RUNBOOK.md"),
        runbook(
            request
                .output_dir
                .file_name()
                .and_then(|name| name.to_str()),
            &inputs.runtime,
            &operator_inventory,
        )
        .as_bytes(),
    )?;
    write_canonical_json(
        root.join("generated/inputs/approved-baseline-set.v1.json"),
        &inputs.normalized_approved_set,
    )?;
    write_bytes(
        root.join("generated/inputs/registry-release-lock.v1.json"),
        &inputs.registry_release_lock,
    )?;
    for lane in &inputs.lanes {
        copy_tree(
            &lane.bundle_dir,
            &root
                .join("generated/bundles")
                .join(lane.lane.id())
                .join(&lane.manifest_digest_component),
        )?;
        copy_regular_file(
            &lane.anchor_file,
            &root
                .join("generated/anchors")
                .join(lane.lane.id())
                .join("anchor.json"),
        )?;
        for (index, (predecessor_anchor, transition)) in lane.anchor_history.iter().enumerate() {
            copy_regular_file(
                predecessor_anchor,
                &root
                    .join("generated/anchors")
                    .join(lane.lane.id())
                    .join("history")
                    .join(format!("{index:04}.anchor.json")),
            )?;
            copy_regular_file(
                transition,
                &root
                    .join("generated/anchors")
                    .join(lane.lane.id())
                    .join("history")
                    .join(format!("{index:04}.transition.json")),
            )?;
        }
    }

    let plan_bytes = fs::read(root.join("generated/deployment-plan.v1.json"))?;
    let binding_bytes = fs::read(root.join("binding.yaml"))?;
    let approved_bytes = fs::read(root.join("generated/inputs/approved-baseline-set.v1.json"))?;
    let release_lock_bytes = fs::read(root.join("generated/inputs/registry-release-lock.v1.json"))?;
    let generated_files = digest_generated_files(&root.join("generated"), true)?;
    let copied_input_roots = copied_input_roots(root, &inputs.lanes)?;
    let generated_closure_sha256 = generated_closure_digest(
        &generated_files,
        &sha256_uri(&plan_bytes),
        &sha256_uri(&binding_bytes),
        &inputs.source_approved_set_sha256,
        &sha256_uri(&approved_bytes),
        &sha256_uri(&release_lock_bytes),
        &copied_input_roots,
    )?;
    let manifest = DeploymentManifestV1 {
        schema_id: DEPLOYMENT_MANIFEST_SCHEMA_ID.to_string(),
        schema_version: DEPLOYMENT_MANIFEST_SCHEMA_VERSION.to_string(),
        generator_release: inputs.release_metadata.generator_release.clone(),
        minimum_compose_version: inputs.release_metadata.minimum_compose_version.clone(),
        environment: request.binding.environment.clone(),
        package_id: request.binding.package_id.clone(),
        postgresql_major: inputs.release_metadata.postgresql_major,
        plan_sha256: sha256_uri(&plan_bytes),
        binding_sha256: sha256_uri(&binding_bytes),
        source_approved_baseline_set_sha256: inputs.source_approved_set_sha256.clone(),
        normalized_approved_baseline_set_sha256: inputs.normalized_approved_set_sha256.clone(),
        registry_release_lock_sha256: inputs.registry_release_lock_sha256.clone(),
        copied_input_roots,
        generated_files,
        generated_closure_sha256,
    };
    write_json(
        root.join("generated/deployment-manifest.v1.json"),
        &manifest,
    )?;

    if request.output_dir.exists() {
        fs::remove_dir(&request.output_dir).with_context(|| {
            format!(
                "failed to replace empty deployment output {}",
                request.output_dir.display()
            )
        })?;
    }
    let staged = staging.keep();
    fs::rename(&staged, &request.output_dir).with_context(|| {
        format!(
            "failed to publish deployment package {}",
            request.output_dir.display()
        )
    })?;
    Ok(DeploymentPackageRenderReportV1 {
        output_dir: request.output_dir.clone(),
        source_approved_baseline_set_sha256: manifest.source_approved_baseline_set_sha256.clone(),
        externally_recorded_closure_sha256: manifest.generated_closure_sha256.clone(),
        manifest,
        models: rendered.models,
    })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentOwnershipStateV1 {
    Managed,
    Adapted,
    Invalid,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageFreshnessV1 {
    Current,
    Stale,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentVerificationScopeV1 {
    Package,
    PackageAndParent,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentOwnershipReportV1 {
    pub schema_id: String,
    pub schema_version: String,
    pub verification_scope: DeploymentVerificationScopeV1,
    pub ownership: DeploymentOwnershipStateV1,
    pub package_freshness: PackageFreshnessV1,
    pub adapted_files: Vec<String>,
    pub verified_guarantees: Vec<String>,
    pub operator_owned_guarantees: Vec<String>,
    pub violations: Vec<String>,
    pub in_place_regeneration_safe: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct EffectiveComposeModelsV1 {
    pub standalone_ordinary: Value,
    pub initialization: Value,
    pub parent: Option<Value>,
}

#[derive(Debug, Clone, Default)]
pub struct ExpectedGenerationInputsV1 {
    pub source_approved_baseline_set_sha256: Option<String>,
    pub registry_release_lock_sha256: Option<String>,
    pub externally_recorded_closure_sha256: Option<String>,
}

pub struct DeploymentPackageVerificationRequestV1<'a> {
    pub package_dir: &'a Path,
    pub verified_inputs: &'a VerifiedDeploymentInputsV1,
    pub parent_compose_files: &'a [PathBuf],
    pub expected_inputs: ExpectedGenerationInputsV1,
}

pub fn verify_deployment_package(
    request: &DeploymentPackageVerificationRequestV1<'_>,
) -> Result<DeploymentOwnershipReportV1> {
    let release_lock_bytes = read_bounded_regular_file(
        &request
            .package_dir
            .join("generated/inputs/registry-release-lock.v1.json"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )
    .context("failed to read the package Registry release lock")?;
    let package_release_lock = verify_release_lock_for_package(&release_lock_bytes)
        .context("package Registry release lock verification failed")?;
    let package_inputs = VerifiedDeploymentInputsV1::from_verified_package(
        request.package_dir,
        &package_release_lock,
    )
    .context("package deployment inputs failed independent verification")?;
    verify_deployment_package_with_package_inputs(request, &package_inputs, true)
}

#[cfg(test)]
pub(crate) fn verify_deployment_package_with_test_inputs(
    request: &DeploymentPackageVerificationRequestV1<'_>,
) -> Result<DeploymentOwnershipReportV1> {
    verify_deployment_package_with_package_inputs(request, request.verified_inputs, false)
}

fn verify_deployment_package_with_package_inputs(
    request: &DeploymentPackageVerificationRequestV1<'_>,
    package_inputs: &VerifiedDeploymentInputsV1,
    verify_operator_material: bool,
) -> Result<DeploymentOwnershipReportV1> {
    let binding_bytes = read_bounded_regular_file(
        &request.package_dir.join("binding.yaml"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )
    .context("failed to read deployment binding")?;
    let binding: DeploymentBindingV1 = serde_norway::from_slice(&binding_bytes)
        .context("deployment binding is not a supported closed document")?;
    binding.validate()?;
    let rendered = render_compose_package(package_inputs, &binding)?;
    let manifest: DeploymentManifestV1 = read_json(
        &request
            .package_dir
            .join("generated/deployment-manifest.v1.json"),
    )?;
    let expected_models = if sha256_uri(&binding_bytes) == manifest.binding_sha256 {
        normalize_rendered_models(request.package_dir, &rendered)?
    } else {
        normalize_managed_base_models(request.package_dir)?
    };
    let effective_models =
        normalize_package_models(request.package_dir, request.parent_compose_files)?;
    verify_deployment_package_core(
        request,
        package_inputs,
        &effective_models,
        &expected_models,
        verify_operator_material,
    )
}

#[cfg(test)]
pub(crate) fn verify_deployment_package_with_models(
    request: &DeploymentPackageVerificationRequestV1<'_>,
    effective_models: &EffectiveComposeModelsV1,
) -> Result<DeploymentOwnershipReportV1> {
    let rendered = render_compose_package(
        request.verified_inputs,
        &serde_norway::from_slice::<DeploymentBindingV1>(&read_bounded_regular_file(
            &request.package_dir.join("binding.yaml"),
            MAX_PORTABLE_DOCUMENT_BYTES,
        )?)?,
    )?;
    let binding_bytes = read_bounded_regular_file(
        &request.package_dir.join("binding.yaml"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )?;
    let manifest: DeploymentManifestV1 = read_json(
        &request
            .package_dir
            .join("generated/deployment-manifest.v1.json"),
    )?;
    let expected_models = if sha256_uri(&binding_bytes) == manifest.binding_sha256 {
        let expected_initialization =
            merge_compose_delta(&rendered.models.ordinary, &rendered.models.initialization)?;
        EffectiveComposeModelsV1 {
            standalone_ordinary: rendered.models.ordinary,
            initialization: expected_initialization,
            parent: None,
        }
    } else {
        stored_rendered_models(request.package_dir)?
    };
    verify_deployment_package_core(
        request,
        request.verified_inputs,
        effective_models,
        &expected_models,
        false,
    )
}

fn verify_deployment_package_core(
    request: &DeploymentPackageVerificationRequestV1<'_>,
    package_inputs: &VerifiedDeploymentInputsV1,
    effective_models: &EffectiveComposeModelsV1,
    expected_models: &EffectiveComposeModelsV1,
    verify_operator_material: bool,
) -> Result<DeploymentOwnershipReportV1> {
    let inputs = package_inputs;
    let installed_inputs = request.verified_inputs;
    inputs.plan.validate()?;
    inputs.runtime.validate()?;
    let binding_bytes = read_bounded_regular_file(
        &request.package_dir.join("binding.yaml"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )
    .context("failed to read deployment binding")?;
    let package_binding = serde_norway::from_slice::<DeploymentBindingV1>(&binding_bytes);
    let binding_valid = package_binding
        .as_ref()
        .is_ok_and(|binding| binding.validate().is_ok());
    if !binding_valid {
        return Ok(ownership_report(
            DeploymentOwnershipStateV1::Invalid,
            PackageFreshnessV1::NotApplicable,
            if request.parent_compose_files.is_empty() {
                DeploymentVerificationScopeV1::Package
            } else {
                DeploymentVerificationScopeV1::PackageAndParent
            },
            OwnershipDetailsV1 {
                adapted_files: Vec::new(),
                verified_guarantees: Vec::new(),
                operator_owned_guarantees: Vec::new(),
                violations: vec![
                    "deployment binding is not a supported closed document".to_string()
                ],
                in_place_regeneration_safe: false,
            },
        ));
    }
    let Ok(package_binding) = package_binding else {
        unreachable!("invalid package bindings return before rendering");
    };
    let canonical = render_compose_package(inputs, &package_binding)?;
    let operator_inventory = operator_file_inventory(&inputs.runtime, &package_binding)?;
    let manifest: DeploymentManifestV1 = read_json(
        &request
            .package_dir
            .join("generated/deployment-manifest.v1.json"),
    )?;
    require_schema(
        &manifest.schema_id,
        &manifest.schema_version,
        DEPLOYMENT_MANIFEST_SCHEMA_ID,
        DEPLOYMENT_MANIFEST_SCHEMA_VERSION,
    )?;

    let mut adapted_files = Vec::new();
    let mut violations = Vec::new();
    let verification_scope = if effective_models.parent.is_some() {
        DeploymentVerificationScopeV1::PackageAndParent
    } else {
        DeploymentVerificationScopeV1::Package
    };
    let actual_generated = digest_generated_files(&request.package_dir.join("generated"), true)?;
    let mut generated_intact = actual_generated == manifest.generated_files;
    let binding_digest = sha256_uri(&binding_bytes);
    let binding_is_stale = binding_digest != manifest.binding_sha256;
    let expected_fixed_files = expected_fixed_generated_files(
        &canonical,
        inputs,
        &package_binding,
        request
            .package_dir
            .file_name()
            .and_then(|name| name.to_str()),
    )?;
    for (path, digest) in &expected_fixed_files {
        if binding_is_stale && matches!(path.as_str(), "compose.yaml" | "compose.initialize.yaml") {
            continue;
        }
        if actual_generated.get(path) != Some(digest) {
            generated_intact = false;
            adapted_files.push(format!("generated/{path}"));
        }
    }
    for path in actual_generated.keys() {
        let is_copied_input = inputs.lanes.iter().any(|lane| {
            path.starts_with(&format!(
                "bundles/{}/{}/",
                lane.lane.id(),
                lane.manifest_digest_component
            )) || path.starts_with(&format!("anchors/{}/", lane.lane.id()))
        });
        if !expected_fixed_files.contains_key(path) && !is_copied_input {
            generated_intact = false;
            adapted_files.push(format!("generated/{path}"));
        }
    }
    if !generated_intact {
        for path in manifest
            .generated_files
            .keys()
            .chain(actual_generated.keys())
            .cloned()
            .collect::<BTreeSet<_>>()
        {
            if manifest.generated_files.get(&path) != actual_generated.get(&path) {
                adapted_files.push(format!("generated/{path}"));
            }
        }
    }
    let mut stale = binding_is_stale;
    if package_binding.environment != manifest.environment
        || package_binding.package_id != manifest.package_id
    {
        generated_intact = false;
        adapted_files.push("generated/deployment-manifest.v1.json".to_string());
    }
    let plan_bytes = read_bounded(
        &request
            .package_dir
            .join("generated/deployment-plan.v1.json"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )?;
    let approved_bytes = read_bounded(
        &request
            .package_dir
            .join("generated/inputs/approved-baseline-set.v1.json"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )?;
    let release_lock_bytes = read_bounded_regular_file(
        &request
            .package_dir
            .join("generated/inputs/registry-release-lock.v1.json"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )?;
    let copied_input_roots = copied_input_roots_from_package(request.package_dir)?;
    if copied_input_roots != copied_input_roots_from_verified_inputs(inputs)? {
        generated_intact = false;
        adapted_files.push("generated/copied-inputs".to_string());
    }
    let closure_digest = generated_closure_digest(
        &actual_generated,
        &sha256_uri(&plan_bytes),
        &manifest.binding_sha256,
        &manifest.source_approved_baseline_set_sha256,
        &sha256_uri(&approved_bytes),
        &sha256_uri(&release_lock_bytes),
        &copied_input_roots,
    )?;
    let release_metadata = DeploymentReleaseMetadataV1 {
        generator_release: manifest.generator_release.clone(),
        minimum_compose_version: manifest.minimum_compose_version.clone(),
        postgresql_major: manifest.postgresql_major,
    };
    if release_metadata.validate().is_err()
        || release_metadata != inputs.release_metadata
        || manifest.plan_sha256 != sha256_uri(&plan_bytes)
        || manifest.normalized_approved_baseline_set_sha256 != sha256_uri(&approved_bytes)
        || manifest.registry_release_lock_sha256 != sha256_uri(&release_lock_bytes)
        || manifest.copied_input_roots != copied_input_roots
        || manifest.generated_closure_sha256 != closure_digest
    {
        generated_intact = false;
        adapted_files.push("generated/deployment-manifest.v1.json".to_string());
    }
    match serde_json::from_slice::<DeploymentPlanV1>(&plan_bytes) {
        Ok(plan) if plan == inputs.plan && plan.validate().is_ok() => {}
        _ => {
            generated_intact = false;
            adapted_files.push("generated/deployment-plan.v1.json".to_string());
        }
    }
    if request.package_dir.join(".env").exists()
        || request.package_dir.join("generated/.env").exists()
    {
        violations.push("deployment package contains an unexpected implicit .env".to_string());
    }
    if verify_operator_material {
        violations.extend(verify_operator_files(
            request.package_dir,
            &operator_inventory,
        ));
    }
    stale |= manifest.registry_release_lock_sha256 != installed_inputs.registry_release_lock_sha256;
    if let Some(expected) = &request.expected_inputs.source_approved_baseline_set_sha256 {
        stale |= expected != &manifest.source_approved_baseline_set_sha256;
    }
    if let Some(expected) = &request.expected_inputs.registry_release_lock_sha256 {
        stale |= expected != &manifest.registry_release_lock_sha256;
    }
    if let Some(expected) = &request.expected_inputs.externally_recorded_closure_sha256 {
        if expected != &manifest.generated_closure_sha256 {
            violations.push(
                "generated closure root does not match the externally recorded value".to_string(),
            );
        }
    }

    let override_path = request.package_dir.join("operator-override.yaml");
    let override_metadata = fs::symlink_metadata(&override_path).ok();
    let has_override = override_metadata.is_some();
    let override_verified = override_metadata.as_ref().is_some_and(|metadata| {
        !metadata.file_type().is_symlink()
            && metadata.is_file()
            && metadata.len() <= MAX_PORTABLE_DOCUMENT_BYTES
            && read_bounded(&override_path, MAX_PORTABLE_DOCUMENT_BYTES)
                .ok()
                .and_then(|bytes| serde_norway::from_slice::<Value>(&bytes).ok())
                .is_some_and(|value| value.is_object())
    });
    if has_override {
        adapted_files.push("operator-override.yaml".to_string());
        if !override_verified {
            adapted_files.push("operator-override.yaml:unverified".to_string());
        }
    }
    {
        let models = effective_models;
        validate_hard_effective_model(
            &expected_models.standalone_ordinary,
            &models.standalone_ordinary,
            &inputs.plan,
            &inputs.runtime,
            &mut violations,
        );
        let expected_initialization = initialization_with_effective_ordinary(
            &expected_models.initialization,
            &models.standalone_ordinary,
        );
        if expected_initialization
            .as_ref()
            .is_none_or(|expected| &models.initialization != expected)
        {
            violations.push(
                "initialization effective model changed a product-owned one-shot action"
                    .to_string(),
            );
        }
        if models.standalone_ordinary != expected_models.standalone_ordinary && !has_override {
            adapted_files.push("effective:standalone".to_string());
        }
        if let Some(parent) = &models.parent {
            validate_parent_model(&models.standalone_ordinary, parent, &mut violations);
        }
    }
    adapted_files.sort();
    adapted_files.dedup();
    violations.sort();
    violations.dedup();

    if !violations.is_empty() {
        return Ok(ownership_report(
            DeploymentOwnershipStateV1::Invalid,
            PackageFreshnessV1::NotApplicable,
            verification_scope,
            OwnershipDetailsV1 {
                adapted_files,
                verified_guarantees: Vec::new(),
                operator_owned_guarantees: Vec::new(),
                violations,
                in_place_regeneration_safe: false,
            },
        ));
    }
    if !adapted_files.is_empty() || !generated_intact {
        let override_only = override_verified
            && generated_intact
            && adapted_files == ["operator-override.yaml".to_string()];
        return Ok(ownership_report(
            DeploymentOwnershipStateV1::Adapted,
            PackageFreshnessV1::NotApplicable,
            verification_scope,
            OwnershipDetailsV1 {
                adapted_files,
                verified_guarantees: vec![
                    "locked images and product runtime actions retain their hard invariants"
                        .to_string(),
                    "initialization actions remain separately selected".to_string(),
                ],
                operator_owned_guarantees: vec![
                    "effective orchestration outside the managed closure".to_string(),
                ],
                violations: Vec::new(),
                in_place_regeneration_safe: override_only,
            },
        ));
    }
    Ok(ownership_report(
        DeploymentOwnershipStateV1::Managed,
        if stale {
            PackageFreshnessV1::Stale
        } else {
            PackageFreshnessV1::Current
        },
        verification_scope,
        OwnershipDetailsV1 {
            adapted_files: Vec::new(),
            verified_guarantees: vec![
                "generator-owned closure matches its manifest".to_string(),
                "ordinary and initialization effective models preserve hard invariants".to_string(),
            ],
            operator_owned_guarantees: if verify_operator_material {
                vec![
                    "operator files have the signed format, mode, owner, and consumer inventory"
                        .to_string(),
                ]
            } else {
                Vec::new()
            },
            violations: Vec::new(),
            in_place_regeneration_safe: true,
        },
    ))
}

fn render_ordinary_model(
    plan: &DeploymentPlanV1,
    binding: &DeploymentBindingV1,
    runtime: &LockedRuntimeMappingV1,
    lanes: &[VerifiedLanePackageSourceV1],
) -> Result<Value> {
    let relay_public = plan.product(ProductLaneV1::RelayPublic)?;
    let relay_consultation = plan.product(ProductLaneV1::RelayConsultation)?;
    let notary = plan.product(ProductLaneV1::Notary)?;
    let postgresql = plan.supporting(SupportingWorkloadRecipeV1::PostgresqlStatePlane)?;
    let namespace = plan.supporting(SupportingWorkloadRecipeV1::PrivateNamespaceHolder)?;

    let mut services = Map::new();
    let mut namespace_holder = supporting_service(
        &namespace.image_identity,
        &runtime.private_namespace_holder,
        json!({NETWORK_PRIVATE: {"aliases": [SERVICE_POSTGRESQL]}}),
        None,
        json!({}),
        &binding.restart_policy,
    );
    // Services which join another service's network namespace cannot publish
    // their own ports. The holder is therefore the sole owner of loopback
    // publishing for the co-located consultation group.
    namespace_holder["ports"] = json!([
        format!("{}:{}:4255", binding.loopback_address, binding.ports.notary),
        format!(
            "{}:{}:9243",
            binding.loopback_address, binding.ports.relay_consultation_metrics
        ),
        format!(
            "{}:{}:9255",
            binding.loopback_address, binding.ports.notary_metrics
        )
    ]);
    services.insert(SERVICE_NAMESPACE_HOLDER.to_string(), namespace_holder);
    services.insert(
        SERVICE_RUNTIME_SECRET_STAGER.to_string(),
        secret_staging_service(&postgresql.image_identity, runtime, binding)?,
    );
    let mut postgres = hardened_service(
        &postgresql.image_identity,
        &runtime.postgresql_state_plane.serve.command,
        &runtime.postgresql_state_plane.health_probe,
        json!({}),
        Some(PRIVATE_NETWORK_MODE),
        dependency_map(&[
            (SERVICE_NAMESPACE_HOLDER, "service_healthy"),
            (
                SERVICE_RUNTIME_SECRET_STAGER,
                "service_completed_successfully",
            ),
        ]),
        &binding.restart_policy,
    );
    apply_hardening(&mut postgres, &runtime.postgresql_state_plane.hardening);
    apply_runtime_action_inputs(
        &mut postgres,
        &runtime.postgresql_state_plane.serve,
        None,
        binding,
        None,
        "postgresql-serve",
    )?;
    postgres["env_file"] = json!(["./postgresql-server.env"]);
    services.insert(SERVICE_POSTGRESQL.to_string(), postgres);
    services.insert(
        SERVICE_RELAY_PUBLIC.to_string(),
        product_service(
            relay_public,
            runtime.product(ProductLaneV1::RelayPublic),
            binding,
            bundle_source(lanes, ProductLaneV1::RelayPublic)?,
            json!({NETWORK_EDGE: {}}),
            None,
            dependency_map(&[(
                SERVICE_RUNTIME_SECRET_STAGER,
                "service_completed_successfully",
            )]),
        )?,
    );
    services.insert(
        SERVICE_RELAY_CONSULTATION.to_string(),
        product_service(
            relay_consultation,
            runtime.product(ProductLaneV1::RelayConsultation),
            binding,
            bundle_source(lanes, ProductLaneV1::RelayConsultation)?,
            json!({}),
            Some(PRIVATE_NETWORK_MODE),
            dependency_map(&[
                (SERVICE_NAMESPACE_HOLDER, "service_healthy"),
                (SERVICE_POSTGRESQL, "service_healthy"),
                (
                    SERVICE_RUNTIME_SECRET_STAGER,
                    "service_completed_successfully",
                ),
            ]),
        )?,
    );
    services.insert(
        SERVICE_NOTARY.to_string(),
        product_service(
            notary,
            runtime.product(ProductLaneV1::Notary),
            binding,
            bundle_source(lanes, ProductLaneV1::Notary)?,
            json!({}),
            Some(PRIVATE_NETWORK_MODE),
            dependency_map(&[
                (SERVICE_NAMESPACE_HOLDER, "service_healthy"),
                (SERVICE_POSTGRESQL, "service_healthy"),
                (SERVICE_RELAY_CONSULTATION, "service_healthy"),
                (
                    SERVICE_RUNTIME_SECRET_STAGER,
                    "service_completed_successfully",
                ),
            ]),
        )?,
    );

    let edge = binding
        .edge_network_name
        .as_ref()
        .map_or_else(|| json!({}), |name| json!({"external": true, "name": name}));
    let mut volumes = Map::from_iter([
        (
            format!("{}-postgresql-data", binding.durable_volume_prefix),
            json!({}),
        ),
        (
            format!("{}-relay-public-state", binding.durable_volume_prefix),
            json!({}),
        ),
        (
            format!("{}-relay-public-audit", binding.durable_volume_prefix),
            json!({}),
        ),
        (
            format!("{}-relay-consultation-state", binding.durable_volume_prefix),
            json!({}),
        ),
        (
            format!("{}-relay-consultation-audit", binding.durable_volume_prefix),
            json!({}),
        ),
        (
            format!("{}-notary-state", binding.durable_volume_prefix),
            json!({}),
        ),
        (
            format!("{}-notary-audit", binding.durable_volume_prefix),
            json!({}),
        ),
    ]);
    volumes.extend(secret_stage_volumes(runtime, binding));
    Ok(json!({
        "name": binding.package_id,
        "services": services,
        "networks": {
            NETWORK_EDGE: edge,
            NETWORK_PRIVATE: {"internal": true}
        },
        "volumes": volumes,
        "secrets": render_secrets(binding)
    }))
}

fn render_initialization_model(
    plan: &DeploymentPlanV1,
    binding: &DeploymentBindingV1,
    runtime: &LockedRuntimeMappingV1,
    lanes: &[VerifiedLanePackageSourceV1],
) -> Result<Value> {
    // This file is deliberately a delta. Selecting it is an explicit operator
    // action; the ordinary model cannot discover any one-shot service.
    let mut model = json!({"services": {}});
    let services = model
        .get_mut("services")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("internal rendered Compose model has no services"))?;
    for action in &plan.initialization_actions {
        if action.action == RuntimeActionV1::BootstrapStatePlane {
            if action.workload != POSTGRESQL {
                bail!("state-plane bootstrap targets an unknown supporting workload");
            }
            let postgresql = plan.supporting(SupportingWorkloadRecipeV1::PostgresqlStatePlane)?;
            let recipe = &runtime.postgresql_state_plane;
            let mut service = hardened_service(
                &postgresql.image_identity,
                &recipe.bootstrap.command,
                &recipe.health_probe,
                json!({NETWORK_PRIVATE: {}}),
                None,
                dependency_map(&[
                    (SERVICE_POSTGRESQL, "service_healthy"),
                    (
                        SERVICE_RUNTIME_SECRET_STAGER,
                        "service_completed_successfully",
                    ),
                ]),
                "no",
            );
            apply_hardening(&mut service, &recipe.hardening);
            apply_runtime_action_inputs(
                &mut service,
                &recipe.bootstrap,
                None,
                binding,
                None,
                "postgresql-bootstrap",
            )?;
            service
                .as_object_mut()
                .expect("service object")
                .remove("healthcheck");
            services.insert(SERVICE_POSTGRESQL_BOOTSTRAP.to_string(), service);
            continue;
        }
        let lane = match action.workload.as_str() {
            RELAY_PUBLIC => ProductLaneV1::RelayPublic,
            RELAY_CONSULTATION => ProductLaneV1::RelayConsultation,
            NOTARY => ProductLaneV1::Notary,
            _ => bail!("initialization action targets an unknown product workload"),
        };
        let product = plan.product(lane)?;
        let runtime = runtime.product(lane);
        let (service_name, command) = match action.action {
            RuntimeActionV1::PrepareStateStore => (
                format!("{}-prepare-state", lane.service()),
                &runtime.prepare_state_store,
            ),
            RuntimeActionV1::InitializeState => (
                format!("{}-initialize", lane.service()),
                &runtime.initialize_state,
            ),
            _ => bail!("initialization model contains a non-initialization action"),
        };
        let (networks, network_mode, dependencies) = if lane == ProductLaneV1::RelayPublic {
            (
                json!({NETWORK_EDGE: {}}),
                None,
                dependency_map(&[(
                    SERVICE_RUNTIME_SECRET_STAGER,
                    "service_completed_successfully",
                )]),
            )
        } else {
            (
                json!({}),
                Some(PRIVATE_NETWORK_MODE),
                dependency_map(&[
                    (SERVICE_NAMESPACE_HOLDER, "service_started"),
                    (SERVICE_POSTGRESQL, "service_healthy"),
                    (
                        SERVICE_RUNTIME_SECRET_STAGER,
                        "service_completed_successfully",
                    ),
                ]),
            )
        };
        let mut service = hardened_service(
            &product.image_identity,
            &command.command,
            &runtime.health_probe,
            networks,
            network_mode,
            dependencies,
            "no",
        );
        apply_runtime_action_inputs(
            &mut service,
            command,
            Some(lane),
            binding,
            Some(bundle_source(lanes, lane)?),
            &format!(
                "{}-{}",
                lane.id(),
                match action.action {
                    RuntimeActionV1::PrepareStateStore => "prepare",
                    RuntimeActionV1::InitializeState => "initialize",
                    _ => unreachable!(),
                }
            ),
        )?;
        match action.action {
            RuntimeActionV1::PrepareStateStore => {
                service
                    .as_object_mut()
                    .expect("service object")
                    .remove("healthcheck");
            }
            RuntimeActionV1::InitializeState => {
                service
                    .as_object_mut()
                    .expect("service object")
                    .remove("healthcheck");
            }
            _ => unreachable!("action was checked above"),
        }
        services.insert(service_name, service);
    }
    Ok(model)
}

fn product_service(
    workload: &ProductWorkloadV1,
    runtime: &LockedProductRuntimeV1,
    binding: &DeploymentBindingV1,
    bundle_source: String,
    networks: Value,
    network_mode: Option<&str>,
    dependencies: Value,
) -> Result<Value> {
    let lane = workload.product_lane;
    let mut service = hardened_service(
        &workload.image_identity,
        &runtime.serve.command,
        &runtime.health_probe,
        networks,
        network_mode,
        dependencies,
        &binding.restart_policy,
    );
    apply_runtime_action_inputs(
        &mut service,
        &runtime.serve,
        Some(lane),
        binding,
        Some(bundle_source),
        &format!("{}-serve", lane.id()),
    )?;
    if lane == ProductLaneV1::RelayPublic {
        service["ports"] = json!([
            format!(
                "{}:{}:4242",
                binding.loopback_address, binding.ports.relay_public
            ),
            format!(
                "{}:{}:9242",
                binding.loopback_address, binding.ports.relay_public_metrics
            )
        ]);
    }
    Ok(service)
}

fn apply_hardening(service: &mut Value, hardening: &LockedServiceHardeningV1) {
    service["user"] = json!(hardening.user);
    service["read_only"] = json!(hardening.read_only_root_filesystem);
    service["cap_drop"] = json!(hardening.cap_drop);
    service["security_opt"] = json!(hardening.security_opt);
    service["tmpfs"] = json!(hardening.tmpfs);
}

fn secret_staging_service(
    image: &ImageIdentityV1,
    runtime: &LockedRuntimeMappingV1,
    binding: &DeploymentBindingV1,
) -> Result<Value> {
    let stages = secret_stage_actions(runtime);
    let mut script = String::from("umask 077\n");
    let mut mounts = Vec::new();
    let mut source_files = BTreeSet::new();
    for (stage_id, action) in stages {
        if action.secret_files.is_empty() {
            continue;
        }
        let output = format!("/registryctl-stage/output/{stage_id}");
        mounts.push(named_volume(
            staged_secret_volume_name(binding, stage_id),
            &output,
        ));
        for projection in &action.secret_files {
            let target = projection
                .target
                .strip_prefix("/run/secrets/")
                .filter(|target| !target.is_empty() && !target.contains('/'))
                .ok_or_else(|| anyhow!("secret target is outside /run/secrets"))?;
            source_files.insert(projection.file_id.clone());
            script.push_str(&format!(
                "/usr/bin/install -m {} /run/secrets/{} {}/{}\n",
                projection.mode, projection.file_id, output, target
            ));
            script.push_str(&format!(
                "/usr/bin/chown {}:{} {}/{}\n",
                projection.uid, projection.gid, output, target
            ));
        }
    }
    Ok(json!({
        "image": image.as_str(),
        "entrypoint": ["/bin/sh", "-ceu"],
        "command": [script],
        "user": "0:0",
        "read_only": true,
        "cap_drop": ["ALL"],
        "cap_add": ["CHOWN"],
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": ["/tmp"],
        "network_mode": "none",
        "volumes": mounts,
        "secrets": source_files
            .into_iter()
            .map(|file_id| json!({
                "source": format!("registry-{file_id}"),
                "target": file_id
            }))
            .collect::<Vec<_>>(),
        "restart": "no"
    }))
}

fn secret_stage_actions(
    runtime: &LockedRuntimeMappingV1,
) -> Vec<(&'static str, &LockedRuntimeActionV1)> {
    vec![
        ("relay-public-serve", &runtime.relay_public.serve),
        (
            "relay-public-prepare",
            &runtime.relay_public.prepare_state_store,
        ),
        (
            "relay-public-initialize",
            &runtime.relay_public.initialize_state,
        ),
        (
            "relay-consultation-serve",
            &runtime.relay_consultation.serve,
        ),
        (
            "relay-consultation-prepare",
            &runtime.relay_consultation.prepare_state_store,
        ),
        (
            "relay-consultation-initialize",
            &runtime.relay_consultation.initialize_state,
        ),
        ("notary-serve", &runtime.notary.serve),
        ("notary-prepare", &runtime.notary.prepare_state_store),
        ("notary-initialize", &runtime.notary.initialize_state),
        ("postgresql-serve", &runtime.postgresql_state_plane.serve),
        (
            "postgresql-bootstrap",
            &runtime.postgresql_state_plane.bootstrap,
        ),
    ]
}

fn staged_secret_volume_name(binding: &DeploymentBindingV1, stage_id: &str) -> String {
    format!(
        "{}-operator-files-{stage_id}",
        binding.durable_volume_prefix
    )
}

fn secret_stage_volumes(
    runtime: &LockedRuntimeMappingV1,
    binding: &DeploymentBindingV1,
) -> Map<String, Value> {
    secret_stage_actions(runtime)
        .into_iter()
        .filter(|(_, action)| !action.secret_files.is_empty())
        .map(|(stage_id, _)| (staged_secret_volume_name(binding, stage_id), json!({})))
        .collect()
}

fn apply_runtime_action_inputs(
    service: &mut Value,
    action: &LockedRuntimeActionV1,
    lane: Option<ProductLaneV1>,
    binding: &DeploymentBindingV1,
    bundle_source: Option<String>,
    stage_id: &str,
) -> Result<()> {
    let mut mounts = action
        .mounts
        .iter()
        .map(|mount| runtime_mount(mount, lane, binding, bundle_source.as_deref()))
        .collect::<Result<Vec<_>>>()?;
    if !action.environment_files.is_empty() {
        service["env_file"] = json!(action
            .environment_files
            .iter()
            .map(|id| operator_file_path(binding, id))
            .collect::<Result<Vec<_>>>()?);
    }
    if !action.secret_files.is_empty() {
        mounts.push(named_volume_read_only(
            staged_secret_volume_name(binding, stage_id),
            "/run/secrets",
        ));
    }
    if !mounts.is_empty() {
        service["volumes"] = json!(mounts);
    }
    Ok(())
}

fn runtime_mount(
    mount: &LockedRuntimeMountV1,
    lane: Option<ProductLaneV1>,
    binding: &DeploymentBindingV1,
    bundle_source: Option<&str>,
) -> Result<Value> {
    let source = match mount.source {
        crate::release_lock::LockedMountSourceV1::Bundle => bundle_source
            .map(str::to_string)
            .ok_or_else(|| anyhow!("bundle mount is missing its verified source"))?,
        crate::release_lock::LockedMountSourceV1::Anchor => {
            format!(
                "./anchors/{}",
                lane.ok_or_else(|| anyhow!("anchor mount is missing a product lane"))?
                    .id()
            )
        }
        crate::release_lock::LockedMountSourceV1::AntiRollbackState => format!(
            "{}-{}-state",
            binding.durable_volume_prefix,
            lane.ok_or_else(|| anyhow!("state mount is missing a product lane"))?
                .id()
        ),
        crate::release_lock::LockedMountSourceV1::Audit => format!(
            "{}-{}-audit",
            binding.durable_volume_prefix,
            lane.ok_or_else(|| anyhow!("audit mount is missing a product lane"))?
                .id()
        ),
        crate::release_lock::LockedMountSourceV1::PostgresqlData => {
            format!("{}-postgresql-data", binding.durable_volume_prefix)
        }
    };
    Ok(
        if matches!(
            mount.source,
            crate::release_lock::LockedMountSourceV1::Bundle
                | crate::release_lock::LockedMountSourceV1::Anchor
        ) {
            let mut value = immutable_bind(source, &mount.target);
            value["read_only"] = json!(mount.read_only);
            value
        } else {
            let mut value = named_volume(source, &mount.target);
            value["read_only"] = json!(mount.read_only);
            value
        },
    )
}

fn operator_file_path(binding: &DeploymentBindingV1, id: &str) -> Result<String> {
    binding
        .secret_files
        .get(id)
        .map(|path| format!("../{path}"))
        .ok_or_else(|| anyhow!("binding is missing operator file {id}"))
}

fn supporting_service(
    image: &ImageIdentityV1,
    runtime: &LockedSupportingRuntimeV1,
    networks: Value,
    network_mode: Option<&str>,
    dependencies: Value,
    restart: &str,
) -> Value {
    hardened_service(
        image,
        &runtime.command,
        &runtime.health_probe,
        networks,
        network_mode,
        dependencies,
        restart,
    )
}

fn hardened_service(
    image: &ImageIdentityV1,
    command: &[String],
    health_probe: &[String],
    networks: Value,
    network_mode: Option<&str>,
    dependencies: Value,
    restart: &str,
) -> Value {
    let mut value = json!({
        "image": image.as_str(),
        "command": command,
        "read_only": true,
        "user": "65532:65532",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": ["/tmp"],
        "healthcheck": {
            "test": health_probe,
            "interval": "30s",
            "timeout": "5s",
            "retries": 3
        },
        "depends_on": dependencies,
        "restart": restart,
        "networks": networks
    });
    if let Some(mode) = network_mode {
        value["network_mode"] = Value::String(mode.to_string());
        value.as_object_mut().expect("object").remove("networks");
    }
    value
}

fn immutable_bind(source: String, target: &str) -> Value {
    json!({
        "type": "bind",
        "source": source,
        "target": target,
        "read_only": true,
        "bind": {"create_host_path": false}
    })
}

fn named_volume(source: String, target: &str) -> Value {
    json!({
        "type": "volume",
        "source": source,
        "target": target,
        "read_only": false
    })
}

fn named_volume_read_only(source: String, target: &str) -> Value {
    let mut value = named_volume(source, target);
    value["read_only"] = json!(true);
    value
}

fn bundle_source(lanes: &[VerifiedLanePackageSourceV1], lane: ProductLaneV1) -> Result<String> {
    let source = lanes
        .iter()
        .find(|source| source.lane == lane)
        .ok_or_else(|| anyhow!("verified deployment inputs are missing lane {}", lane.id()))?;
    Ok(format!(
        "./bundles/{}/{}",
        lane.id(),
        source.manifest_digest_component
    ))
}

fn render_secrets(binding: &DeploymentBindingV1) -> Value {
    let mut secrets = Map::new();
    for (consumer, locator) in &binding.secret_files {
        secrets.insert(
            format!("registry-{consumer}"),
            json!({"file": format!("../{locator}")}),
        );
    }
    Value::Object(secrets)
}

fn dependency_map(items: &[(&str, &str)]) -> Value {
    let mut dependencies = Map::new();
    for (service, condition) in items {
        dependencies.insert(
            (*service).to_string(),
            json!({"condition": condition, "required": true}),
        );
    }
    Value::Object(dependencies)
}

fn normalize_rendered_models(
    package_dir: &Path,
    rendered: &RenderedComposePackageV1,
) -> Result<EffectiveComposeModelsV1> {
    let parent = package_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary = tempfile::Builder::new()
        .prefix(".registry-compose-canonical-")
        .tempdir_in(parent)
        .context("failed to stage canonical Compose normalization")?;
    let generated = temporary.path().join("generated");
    fs::create_dir_all(&generated)?;
    write_bytes(generated.join("compose.empty.env"), b"")?;
    write_bytes(
        generated.join("postgresql-server.env"),
        rendered.postgresql_server_environment.as_bytes(),
    )?;
    write_bytes(
        generated.join("compose.yaml"),
        rendered.compose_yaml.as_bytes(),
    )?;
    write_bytes(
        generated.join("compose.initialize.yaml"),
        rendered.initialization_yaml.as_bytes(),
    )?;
    let ordinary = compose_config(
        &generated.join("compose.empty.env"),
        &[generated.join("compose.yaml")],
    )?;
    let initialization = compose_config(
        &generated.join("compose.empty.env"),
        &[
            generated.join("compose.yaml"),
            generated.join("compose.initialize.yaml"),
        ],
    )?;
    Ok(EffectiveComposeModelsV1 {
        standalone_ordinary: scrub_normalized_bind_sources(ordinary),
        initialization: scrub_normalized_bind_sources(initialization),
        parent: None,
    })
}

fn normalize_managed_base_models(package_dir: &Path) -> Result<EffectiveComposeModelsV1> {
    let generated = package_dir.join("generated");
    let empty_env = generated.join("compose.empty.env");
    let base = generated.join("compose.yaml");
    let initialization_delta = generated.join("compose.initialize.yaml");
    Ok(EffectiveComposeModelsV1 {
        standalone_ordinary: scrub_normalized_bind_sources(compose_config(
            &empty_env,
            std::slice::from_ref(&base),
        )?),
        initialization: scrub_normalized_bind_sources(compose_config(
            &empty_env,
            &[base, initialization_delta],
        )?),
        parent: None,
    })
}

#[cfg(test)]
fn stored_rendered_models(package_dir: &Path) -> Result<EffectiveComposeModelsV1> {
    let ordinary: Value = serde_norway::from_slice(&read_bounded(
        &package_dir.join("generated/compose.yaml"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )?)?;
    let initialization_delta: Value = serde_norway::from_slice(&read_bounded(
        &package_dir.join("generated/compose.initialize.yaml"),
        MAX_PORTABLE_DOCUMENT_BYTES,
    )?)?;
    let initialization = merge_compose_delta(&ordinary, &initialization_delta)?;
    Ok(EffectiveComposeModelsV1 {
        standalone_ordinary: ordinary,
        initialization,
        parent: None,
    })
}

fn normalize_package_models(
    package_dir: &Path,
    parent_compose_files: &[PathBuf],
) -> Result<EffectiveComposeModelsV1> {
    require_compose_version()?;
    let generated = package_dir.join("generated");
    let base = generated.join("compose.yaml");
    let initialization_delta = generated.join("compose.initialize.yaml");
    let empty_env = generated.join("compose.empty.env");
    let override_file = package_dir.join("operator-override.yaml");
    let has_override = override_file.is_file();
    for path in [&base, &initialization_delta] {
        reject_compose_include_features(path, false)?;
    }
    if has_override {
        reject_compose_include_features(&override_file, false)?;
    }
    reject_implicit_env(package_dir)?;
    reject_implicit_env(&generated)?;

    let mut ordinary_files = vec![base.clone()];
    if has_override {
        ordinary_files.push(override_file.clone());
    }
    let mut initialization_files = vec![base.clone(), initialization_delta];
    if has_override {
        initialization_files.push(override_file.clone());
    }
    let ordinary = scrub_normalized_bind_sources(compose_config(&empty_env, &ordinary_files)?);
    let initialization =
        scrub_normalized_bind_sources(compose_config(&empty_env, &initialization_files)?);
    let parent = if parent_compose_files.is_empty() {
        None
    } else {
        let included = validate_parent_include_graph(parent_compose_files)?;
        let expected = if has_override {
            vec![fs::canonicalize(&base)?, fs::canonicalize(&override_file)?]
        } else {
            vec![fs::canonicalize(&base)?]
        };
        if !contains_ordered_paths(&included, &expected) {
            bail!(
                "parent Compose model does not include the package base and override in the documented order"
            );
        }
        Some(scrub_normalized_bind_sources(compose_config(
            &empty_env,
            parent_compose_files,
        )?))
    };
    Ok(EffectiveComposeModelsV1 {
        standalone_ordinary: ordinary,
        initialization,
        parent,
    })
}

fn require_compose_version() -> Result<()> {
    let output = Command::new("docker")
        .args(["compose", "version", "--short"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("Docker Compose is unavailable")?;
    if !output.status.success() {
        bail!("Docker Compose is unavailable");
    }
    let version =
        String::from_utf8(output.stdout).context("Docker Compose returned a non-UTF-8 version")?;
    let numeric = version.trim().trim_start_matches('v');
    let parts = numeric
        .split('.')
        .take(3)
        .map(|part| {
            part.split_once('-')
                .map_or(part, |(number, _)| number)
                .parse::<u16>()
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Docker Compose returned an unsupported version")?;
    if parts.len() != 3 || parts.as_slice() < &COMPOSE_MINIMUM_VERSION {
        bail!("managed deployment verification requires Docker Compose 2.35.0 or later");
    }
    Ok(())
}

fn compose_config(empty_env: &Path, compose_files: &[PathBuf]) -> Result<Value> {
    if compose_files.is_empty() {
        bail!("Compose normalization requires at least one explicit file");
    }
    let mut command = Command::new("docker");
    command
        .args(["compose", "--env-file"])
        .arg(empty_env)
        .stdin(Stdio::null())
        .stderr(Stdio::piped());
    for file in compose_files {
        command.arg("-f").arg(file);
    }
    let output = command
        .args([
            "config",
            "--no-interpolate",
            "--no-env-resolution",
            "--format",
            "json",
        ])
        .output()
        .context("failed to invoke Docker Compose normalization")?;
    if !output.status.success() {
        bail!("Docker Compose rejected the deployment model");
    }
    serde_json::from_slice(&output.stdout)
        .context("Docker Compose returned an invalid normalized JSON model")
}

fn reject_implicit_env(directory: &Path) -> Result<()> {
    if directory.join(".env").exists() {
        bail!("Compose verification refuses an implicit .env");
    }
    Ok(())
}

fn reject_compose_include_features(
    path: &Path,
    allow_local_includes: bool,
) -> Result<Vec<PathBuf>> {
    let bytes = read_bounded(path, MAX_PORTABLE_DOCUMENT_BYTES)?;
    let document: Value = serde_norway::from_slice(&bytes)
        .with_context(|| format!("failed to parse Compose file {}", path.display()))?;
    let Some(include) = document.get("include") else {
        return Ok(Vec::new());
    };
    if !allow_local_includes {
        bail!("package Compose files must not introduce an include graph");
    }
    parse_local_include_entries(include, path.parent().unwrap_or_else(|| Path::new(".")))
}

fn parse_local_include_entries(include: &Value, base: &Path) -> Result<Vec<PathBuf>> {
    let items = include
        .as_array()
        .ok_or_else(|| anyhow!("Compose include must be a finite local list"))?;
    let mut paths = Vec::new();
    for item in items {
        match item {
            Value::String(path) => paths.push(resolve_local_compose_path(base, path)?),
            Value::Object(mapping) => {
                if mapping.contains_key("env_file") {
                    bail!("Compose include-level env_file is outside managed verification");
                }
                if mapping
                    .keys()
                    .any(|key| !matches!(key.as_str(), "path" | "project_directory"))
                {
                    bail!("Compose include uses an unsupported option");
                }
                match mapping.get("project_directory") {
                    Some(Value::String(path)) => {
                        resolve_local_directory(base, path)?;
                    }
                    Some(_) => bail!("Compose include project_directory must be literal"),
                    None => {}
                }
                match mapping.get("path") {
                    Some(Value::String(path)) => {
                        paths.push(resolve_local_compose_path(base, path)?)
                    }
                    Some(Value::Array(values)) => {
                        for value in values {
                            let path = value
                                .as_str()
                                .ok_or_else(|| anyhow!("Compose include path must be literal"))?;
                            paths.push(resolve_local_compose_path(base, path)?);
                        }
                    }
                    _ => bail!("Compose include path must be a literal path or path list"),
                }
            }
            _ => bail!("Compose include entry must be a literal local path"),
        }
    }
    Ok(paths)
}

fn resolve_local_compose_path(base: &Path, value: &str) -> Result<PathBuf> {
    if value.contains('$')
        || value.contains("://")
        || value.starts_with("git@")
        || value.starts_with("oci:")
    {
        bail!("remote or non-literal Compose includes are outside managed verification");
    }
    let path = base.join(value);
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("failed to resolve local Compose include {}", path.display()))?;
    if !canonical.is_file() {
        bail!("Compose include must identify a local regular file");
    }
    Ok(canonical)
}

fn resolve_local_directory(base: &Path, value: &str) -> Result<PathBuf> {
    if value.contains('$') || value.contains("://") {
        bail!("Compose project_directory must be a literal local directory");
    }
    let path = fs::canonicalize(base.join(value))
        .context("failed to resolve Compose include project_directory")?;
    if !path.is_dir() {
        bail!("Compose include project_directory must be a local directory");
    }
    reject_implicit_env(&path)?;
    Ok(path)
}

fn validate_parent_include_graph(parent_files: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut queue = parent_files
        .iter()
        .map(fs::canonicalize)
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut visited = BTreeSet::new();
    let mut included = Vec::new();
    let mut index = 0usize;
    while index < queue.len() {
        if queue.len() > 64 {
            bail!("Compose include graph exceeds its managed bound");
        }
        let path = queue[index].clone();
        index += 1;
        if !visited.insert(path.clone()) {
            continue;
        }
        reject_implicit_env(path.parent().unwrap_or_else(|| Path::new(".")))?;
        let children = reject_compose_include_features(&path, true)?;
        included.extend(children.iter().cloned());
        queue.extend(children);
    }
    Ok(included)
}

fn contains_ordered_paths(actual: &[PathBuf], expected: &[PathBuf]) -> bool {
    actual
        .windows(expected.len())
        .any(|window| window == expected)
}

fn scrub_normalized_bind_sources(mut model: Value) -> Value {
    if let Some(services) = model.get_mut("services").and_then(Value::as_object_mut) {
        for service in services.values_mut() {
            if let Some(environment_files) =
                service.get_mut("env_file").and_then(Value::as_array_mut)
            {
                for environment_file in environment_files {
                    let file = match environment_file {
                        Value::String(file) => file,
                        Value::Object(item) => {
                            let Some(file) = item.get("path").and_then(Value::as_str) else {
                                continue;
                            };
                            let normalized = normalized_operator_or_generated_path(file);
                            item["path"] = Value::String(normalized);
                            continue;
                        }
                        _ => continue,
                    };
                    *file = normalized_operator_or_generated_path(file);
                }
            }
            if let Some(mounts) = service.get_mut("volumes").and_then(Value::as_array_mut) {
                for mount in mounts {
                    if mount.get("type").and_then(Value::as_str) != Some("bind") {
                        continue;
                    }
                    let Some(source) = mount.get("source").and_then(Value::as_str) else {
                        continue;
                    };
                    if let Some((_, suffix)) = source.rsplit_once("/generated/") {
                        mount["source"] = Value::String(format!("./{suffix}"));
                    }
                }
            }
        }
    }
    if let Some(secrets) = model.get_mut("secrets").and_then(Value::as_object_mut) {
        for secret in secrets.values_mut() {
            let Some(file) = secret.get("file").and_then(Value::as_str) else {
                continue;
            };
            if let Some((_, suffix)) = file.rsplit_once("/operator/") {
                secret["file"] = Value::String(format!("../operator/{suffix}"));
            }
        }
    }
    model
}

fn normalized_operator_or_generated_path(file: &str) -> String {
    if let Some((_, suffix)) = file.rsplit_once("/operator/") {
        format!("../operator/{suffix}")
    } else if let Some((_, suffix)) = file.rsplit_once("/generated/") {
        format!("./{suffix}")
    } else {
        file.to_string()
    }
}

fn validate_hard_effective_model(
    expected: &Value,
    actual: &Value,
    plan: &DeploymentPlanV1,
    runtime: &LockedRuntimeMappingV1,
    violations: &mut Vec<String>,
) {
    let Some(expected_services) = expected.get("services").and_then(Value::as_object) else {
        violations.push("internal canonical model has no service inventory".to_string());
        return;
    };
    let Some(actual_services) = actual.get("services").and_then(Value::as_object) else {
        violations.push("ordinary effective model has no service inventory".to_string());
        return;
    };
    for (lane, service_name) in [
        (ProductLaneV1::RelayPublic, SERVICE_RELAY_PUBLIC),
        (ProductLaneV1::RelayConsultation, SERVICE_RELAY_CONSULTATION),
        (ProductLaneV1::Notary, SERVICE_NOTARY),
    ] {
        let Some(service) = actual_services.get(service_name) else {
            violations.push(format!("ordinary effective model omits {service_name}"));
            continue;
        };
        let expected_image = plan
            .product(lane)
            .map(|workload| workload.image_identity.as_str())
            .unwrap_or_default();
        check_equal(
            service,
            "image",
            &json!(expected_image),
            service_name,
            violations,
        );
        check_equal(
            service,
            "command",
            &json!(runtime.product(lane).serve.command),
            service_name,
            violations,
        );
        check_optional_equal(
            service,
            "entrypoint",
            expected_services
                .get(service_name)
                .and_then(|expected| expected.get("entrypoint")),
            service_name,
            violations,
        );
        check_equal(
            service,
            "depends_on",
            expected_services
                .get(service_name)
                .and_then(|expected| expected.get("depends_on"))
                .unwrap_or(&Value::Null),
            service_name,
            violations,
        );
        check_hardening(service, service_name, violations);
        check_protected_mounts(service, service_name, violations);
        check_security_owned_projection(
            expected_services.get(service_name),
            service,
            service_name,
            violations,
        );
    }
    match (
        expected_services.get(SERVICE_RUNTIME_SECRET_STAGER),
        actual_services.get(SERVICE_RUNTIME_SECRET_STAGER),
    ) {
        (Some(expected_stage), Some(actual_stage)) => {
            check_security_owned_projection(
                Some(expected_stage),
                actual_stage,
                SERVICE_RUNTIME_SECRET_STAGER,
                violations,
            );
            if actual_stage.get("network_mode") != Some(&json!("none"))
                || actual_stage.get("cap_add") != Some(&json!(["CHOWN"]))
            {
                violations.push(
                    "runtime secret stager lost its isolated narrow CHOWN contract".to_string(),
                );
            }
        }
        _ => violations.push("ordinary effective model omits runtime secret staging".to_string()),
    }
    for (service_name, service) in actual_services {
        if service_name != SERVICE_RUNTIME_SECRET_STAGER
            && service
                .get("cap_add")
                .and_then(Value::as_array)
                .is_some_and(|caps| caps.iter().any(|cap| cap == "CHOWN"))
        {
            violations.push(format!(
                "{service_name} inherited the secret stager CHOWN capability"
            ));
        }
    }
    for (recipe, service_name, command) in [
        (
            SupportingWorkloadRecipeV1::PostgresqlStatePlane,
            SERVICE_POSTGRESQL,
            &runtime.postgresql_state_plane.serve.command,
        ),
        (
            SupportingWorkloadRecipeV1::PrivateNamespaceHolder,
            SERVICE_NAMESPACE_HOLDER,
            &runtime.private_namespace_holder.command,
        ),
    ] {
        let Some(service) = actual_services.get(service_name) else {
            violations.push(format!("ordinary effective model omits {service_name}"));
            continue;
        };
        let expected_image = plan
            .supporting(recipe)
            .map(|workload| workload.image_identity.as_str())
            .unwrap_or_default();
        check_equal(
            service,
            "image",
            &json!(expected_image),
            service_name,
            violations,
        );
        check_equal(
            service,
            "command",
            &json!(command),
            service_name,
            violations,
        );
        check_optional_equal(
            service,
            "entrypoint",
            expected_services
                .get(service_name)
                .and_then(|expected| expected.get("entrypoint")),
            service_name,
            violations,
        );
        check_equal(
            service,
            "depends_on",
            expected_services
                .get(service_name)
                .and_then(|expected| expected.get("depends_on"))
                .unwrap_or(&Value::Null),
            service_name,
            violations,
        );
        check_hardening(service, service_name, violations);
        check_security_owned_projection(
            expected_services.get(service_name),
            service,
            service_name,
            violations,
        );
    }
    for service_name in [
        SERVICE_RELAY_CONSULTATION,
        SERVICE_NOTARY,
        SERVICE_POSTGRESQL,
    ] {
        if actual_services
            .get(service_name)
            .and_then(|service| service.get("network_mode"))
            != Some(&json!(PRIVATE_NETWORK_MODE))
        {
            violations.push(format!(
                "{service_name} left the private co-location namespace"
            ));
        }
    }
    if let Some(postgres) = actual_services.get(SERVICE_POSTGRESQL) {
        check_state_mount(postgres, SERVICE_POSTGRESQL, violations);
    }
    for name in INITIALIZATION_SERVICES {
        if actual_services.contains_key(name) {
            violations.push(format!(
                "ordinary effective model exposes initialization service {name}"
            ));
        }
    }
    if expected_services
        .keys()
        .any(|name| !actual_services.contains_key(name))
    {
        violations.push("ordinary effective model lost a governed workload".to_string());
    }
    for name in actual_services.keys() {
        if name.starts_with("registry-") && !expected_services.contains_key(name) {
            violations.push(format!(
                "ordinary effective model added unowned Registry Stack service {name}"
            ));
        }
    }
    for field in ["networks", "volumes", "secrets"] {
        if actual.get(field) != expected.get(field) {
            violations.push(format!(
                "ordinary effective model changed the security-owned {field} projection"
            ));
        }
    }
}

fn check_security_owned_projection(
    expected: Option<&Value>,
    actual: &Value,
    name: &str,
    violations: &mut Vec<String>,
) {
    let Some(expected) = expected else {
        return;
    };
    let mut projected = actual.clone();
    let Some(object) = projected.as_object_mut() else {
        violations.push(format!("{name} is not a Compose service object"));
        return;
    };
    if let Some(labels) = object.get_mut("labels").and_then(Value::as_object_mut) {
        labels.retain(|key, _| key.starts_with("io.registrystack."));
        if labels.is_empty() {
            object.remove("labels");
        }
    }
    if object
        .get("deploy")
        .is_some_and(is_allowed_resource_limit_adaptation)
    {
        object.remove("deploy");
    }
    if object
        .get("logging")
        .is_some_and(is_allowed_logging_adaptation)
    {
        object.remove("logging");
    }
    if &projected != expected {
        violations.push(format!(
            "{name} changed its exact security-owned service projection"
        ));
    }
}

fn is_allowed_resource_limit_adaptation(value: &Value) -> bool {
    let Some(deploy) = value.as_object() else {
        return false;
    };
    if deploy.keys().any(|key| key != "resources") {
        return false;
    }
    let Some(resources) = deploy.get("resources").and_then(Value::as_object) else {
        return false;
    };
    if resources.keys().any(|key| key != "limits") {
        return false;
    }
    resources
        .get("limits")
        .and_then(Value::as_object)
        .is_some_and(|limits| {
            !limits.is_empty()
                && limits
                    .keys()
                    .all(|key| matches!(key.as_str(), "cpus" | "memory" | "pids"))
        })
}

fn is_allowed_logging_adaptation(value: &Value) -> bool {
    let Some(logging) = value.as_object() else {
        return false;
    };
    logging
        .keys()
        .all(|key| matches!(key.as_str(), "driver" | "options"))
        && logging.get("driver").and_then(Value::as_str) == Some("local")
        && logging
            .get("options")
            .and_then(Value::as_object)
            .is_none_or(|options| {
                options
                    .keys()
                    .all(|key| matches!(key.as_str(), "max-size" | "max-file"))
            })
}

fn validate_parent_model(standalone: &Value, parent: &Value, violations: &mut Vec<String>) {
    let Some(standalone_services) = standalone.get("services").and_then(Value::as_object) else {
        return;
    };
    let Some(parent_services) = parent.get("services").and_then(Value::as_object) else {
        violations.push("parent effective model has no service inventory".to_string());
        return;
    };
    for service_name in [
        SERVICE_RELAY_PUBLIC,
        SERVICE_RELAY_CONSULTATION,
        SERVICE_NOTARY,
        SERVICE_POSTGRESQL,
        SERVICE_NAMESPACE_HOLDER,
    ] {
        if parent_services.get(service_name) != standalone_services.get(service_name) {
            violations.push(format!(
                "parent model changed governed service {service_name}"
            ));
        }
    }
    let protected_volumes = standalone
        .get("volumes")
        .and_then(Value::as_object)
        .map(|volumes| volumes.keys().map(String::as_str).collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let protected_secrets = standalone
        .get("secrets")
        .and_then(Value::as_object)
        .map(|secrets| secrets.keys().map(String::as_str).collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let protected_sources = standalone_services
        .values()
        .flat_map(|service| {
            service
                .get("volumes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(volume_source)
        })
        .collect::<BTreeSet<_>>();
    for (name, service) in parent_services {
        if standalone_services.contains_key(name) {
            continue;
        }
        let networks = service
            .get("networks")
            .and_then(Value::as_object)
            .map(|networks| networks.keys().map(String::as_str).collect::<BTreeSet<_>>())
            .unwrap_or_default();
        let network_mode = service.get("network_mode").and_then(Value::as_str);
        if networks.contains(NETWORK_PRIVATE)
            || network_mode == Some(PRIVATE_NETWORK_MODE)
            || network_mode.is_some_and(|mode| {
                mode.strip_prefix("service:")
                    .is_some_and(|target| standalone_services.contains_key(target))
            })
        {
            violations.push(format!(
                "parent service {name} joined a private product boundary"
            ));
        }
        if service
            .get("networks")
            .and_then(Value::as_object)
            .is_some_and(|networks| {
                networks.values().any(|network| {
                    network
                        .get("aliases")
                        .and_then(Value::as_array)
                        .is_some_and(|aliases| !aliases.is_empty())
                })
            })
        {
            violations.push(format!(
                "parent service {name} uses a network alias around a governed endpoint"
            ));
        }
        if service.get("extends").is_some() {
            violations.push(format!("parent service {name} extends a governed service"));
        }
        for field in ["links", "external_links", "ipc", "pid"] {
            if service.get(field).is_some() {
                violations.push(format!(
                    "parent service {name} uses {field} across a governed boundary"
                ));
            }
        }
        if service
            .get("secrets")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|item| {
                    item.as_str()
                        .or_else(|| item.get("source").and_then(Value::as_str))
                        .is_some_and(|secret| protected_secrets.contains(secret))
                })
            })
        {
            violations.push(format!(
                "parent service {name} consumes a product-owned secret"
            ));
        }
        if service
            .get("volumes")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|item| {
                    volume_source(item).is_some_and(|source| {
                        protected_volumes.contains(source) || protected_sources.contains(source)
                    })
                })
            })
        {
            violations.push(format!(
                "parent service {name} mounts product-owned durable state"
            ));
        }
    }
}

fn initialization_with_effective_ordinary(
    canonical_initialization: &Value,
    effective_ordinary: &Value,
) -> Option<Value> {
    let mut expected = canonical_initialization.clone();
    let expected_services = expected.get_mut("services")?.as_object_mut()?;
    let ordinary_services = effective_ordinary.get("services")?.as_object()?;
    for service_name in [
        SERVICE_RELAY_PUBLIC,
        SERVICE_RELAY_CONSULTATION,
        SERVICE_NOTARY,
        SERVICE_POSTGRESQL,
        SERVICE_NAMESPACE_HOLDER,
    ] {
        expected_services.insert(
            service_name.to_string(),
            ordinary_services.get(service_name)?.clone(),
        );
    }
    Some(expected)
}

#[cfg(test)]
pub(crate) fn merge_compose_delta(base: &Value, delta: &Value) -> Result<Value> {
    fn merge(target: &mut Value, overlay: &Value) {
        match (target, overlay) {
            (Value::Object(target), Value::Object(overlay)) => {
                for (key, value) in overlay {
                    match target.get_mut(key) {
                        Some(current) => merge(current, value),
                        None => {
                            target.insert(key.clone(), value.clone());
                        }
                    }
                }
            }
            (target, overlay) => *target = overlay.clone(),
        }
    }
    if !base.is_object() || !delta.is_object() {
        bail!("Compose base and initialization delta must be objects");
    }
    let mut merged = base.clone();
    merge(&mut merged, delta);
    Ok(merged)
}

fn check_hardening(service: &Value, name: &str, violations: &mut Vec<String>) {
    check_equal(service, "read_only", &json!(true), name, violations);
    check_equal(service, "cap_drop", &json!(["ALL"]), name, violations);
    if service
        .get("security_opt")
        .and_then(Value::as_array)
        .is_none_or(|values| !values.iter().any(|value| value == "no-new-privileges:true"))
    {
        violations.push(format!("{name} removed no-new-privileges"));
    }
    if service
        .get("user")
        .and_then(Value::as_str)
        .is_none_or(|user| user == "0" || user.starts_with("0:"))
    {
        violations.push(format!("{name} does not use a non-root identity"));
    }
    if service.get("privileged") == Some(&json!(true)) {
        violations.push(format!("{name} enables privileged execution"));
    }
}

fn check_protected_mounts(service: &Value, name: &str, violations: &mut Vec<String>) {
    let mounts = service
        .get("volumes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for target in ["/run/registry/bundle", "/run/registry/anchor"] {
        let matching = mounts
            .iter()
            .find(|mount| mount.get("target").and_then(Value::as_str) == Some(target));
        if matching.is_none_or(|mount| mount.get("read_only") != Some(&json!(true))) {
            violations.push(format!("{name} lost its read-only {target} mount"));
        }
    }
    check_state_mount(service, name, violations);
}

fn check_state_mount(service: &Value, name: &str, violations: &mut Vec<String>) {
    let has_state = service
        .get("volumes")
        .and_then(Value::as_array)
        .is_some_and(|mounts| {
            mounts.iter().any(|mount| {
                mount.as_str().is_some_and(|value| {
                    value.ends_with(":/var/lib/registry/state")
                        || value.ends_with(":/var/lib/postgresql/data")
                }) || mount.get("target").and_then(Value::as_str) == Some("/var/lib/registry/state")
                    || mount.get("target").and_then(Value::as_str)
                        == Some("/var/lib/postgresql/data")
            })
        });
    if !has_state {
        violations.push(format!("{name} lost its product-owned durable state"));
    }
}

fn check_equal(
    service: &Value,
    field: &str,
    expected: &Value,
    name: &str,
    violations: &mut Vec<String>,
) {
    if service.get(field) != Some(expected) {
        violations.push(format!("{name} changed its locked {field}"));
    }
}

fn check_optional_equal(
    service: &Value,
    field: &str,
    expected: Option<&Value>,
    name: &str,
    violations: &mut Vec<String>,
) {
    if service.get(field) != expected {
        violations.push(format!("{name} changed its locked {field}"));
    }
}

fn volume_source(value: &Value) -> Option<&str> {
    value
        .as_str()
        .and_then(|mount| mount.split_once(':').map(|(source, _)| source))
        .or_else(|| value.get("source").and_then(Value::as_str))
}

fn digest_generated_files(
    generated: &Path,
    exclude_manifest: bool,
) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    collect_digests(generated, generated, exclude_manifest, &mut files)?;
    Ok(files)
}

fn expected_fixed_generated_files(
    rendered: &RenderedComposePackageV1,
    inputs: &VerifiedDeploymentInputsV1,
    binding: &DeploymentBindingV1,
    package_name: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut plan = serde_json::to_vec_pretty(&inputs.plan)?;
    plan.push(b'\n');
    let approved = canonicalize_json(&serde_json::to_value(&inputs.normalized_approved_set)?)?;
    let inventory = operator_file_inventory(&inputs.runtime, binding)?;
    let mut inventory_bytes = serde_json::to_vec_pretty(&inventory)?;
    inventory_bytes.push(b'\n');
    let files = [
        ("compose.empty.env", Vec::new()),
        (
            "postgresql-server.env",
            rendered.postgresql_server_environment.as_bytes().to_vec(),
        ),
        ("compose.yaml", rendered.compose_yaml.as_bytes().to_vec()),
        (
            "compose.initialize.yaml",
            rendered.initialization_yaml.as_bytes().to_vec(),
        ),
        ("deployment-plan.v1.json", plan),
        ("operator-files.v1.json", inventory_bytes),
        (
            "RUNBOOK.md",
            runbook(package_name, &inputs.runtime, &inventory).into_bytes(),
        ),
        ("inputs/approved-baseline-set.v1.json", approved),
        (
            "inputs/registry-release-lock.v1.json",
            inputs.registry_release_lock.clone(),
        ),
    ];
    Ok(files
        .into_iter()
        .map(|(path, bytes)| (path.to_string(), sha256_uri(&bytes)))
        .collect())
}

fn copied_input_roots_from_verified_inputs(
    inputs: &VerifiedDeploymentInputsV1,
) -> Result<BTreeMap<String, String>> {
    let temporary = tempfile::tempdir().context("failed to stage copied-input verification")?;
    let root = temporary.path();
    for lane in &inputs.lanes {
        copy_tree(
            &lane.bundle_dir,
            &root
                .join("generated/bundles")
                .join(lane.lane.id())
                .join(&lane.manifest_digest_component),
        )?;
        copy_regular_file(
            &lane.anchor_file,
            &root
                .join("generated/anchors")
                .join(lane.lane.id())
                .join("anchor.json"),
        )?;
        for (index, (predecessor_anchor, transition)) in lane.anchor_history.iter().enumerate() {
            copy_regular_file(
                predecessor_anchor,
                &root
                    .join("generated/anchors")
                    .join(lane.lane.id())
                    .join("history")
                    .join(format!("{index:04}.anchor.json")),
            )?;
            copy_regular_file(
                transition,
                &root
                    .join("generated/anchors")
                    .join(lane.lane.id())
                    .join("history")
                    .join(format!("{index:04}.transition.json")),
            )?;
        }
    }
    copied_input_roots(root, &inputs.lanes)
}

fn copied_input_roots(
    package_root: &Path,
    lanes: &[VerifiedLanePackageSourceV1],
) -> Result<BTreeMap<String, String>> {
    let mut roots = BTreeMap::new();
    for lane in lanes {
        for kind in ["bundles", "anchors"] {
            let files = digest_generated_files(
                &package_root
                    .join("generated")
                    .join(kind)
                    .join(lane.lane.id())
                    .join(if kind == "bundles" {
                        Path::new(&lane.manifest_digest_component)
                    } else {
                        Path::new("")
                    }),
                false,
            )?;
            roots.insert(
                format!(
                    "{}-{}",
                    lane.lane.id(),
                    if kind == "bundles" {
                        "bundle"
                    } else {
                        "anchor"
                    }
                ),
                sha256_uri(&serde_json::to_vec(&files)?),
            );
        }
    }
    Ok(roots)
}

fn copied_input_roots_from_package(package_root: &Path) -> Result<BTreeMap<String, String>> {
    let mut roots = BTreeMap::new();
    let normalized: ApprovedBaselineSetV1 =
        read_json(&package_root.join("generated/inputs/approved-baseline-set.v1.json"))?;
    normalized.validate()?;
    for approved_lane in ApprovedLaneV1::ALL {
        let lane = ProductLaneV1::from_approved(approved_lane);
        let entry = normalized.lanes.get(approved_lane);
        for (kind, locator) in [
            ("bundles", entry.locators.bundle.as_path()),
            (
                "anchors",
                entry
                    .locators
                    .anchor
                    .as_path()
                    .parent()
                    .ok_or_else(|| anyhow!("normalized anchor locator has no parent"))?,
            ),
        ] {
            let files =
                digest_generated_files(&package_root.join("generated").join(locator), false)?;
            roots.insert(
                format!(
                    "{}-{}",
                    lane.id(),
                    if kind == "bundles" {
                        "bundle"
                    } else {
                        "anchor"
                    }
                ),
                sha256_uri(&serde_json::to_vec(&files)?),
            );
        }
    }
    Ok(roots)
}

fn generated_closure_digest(
    generated_files: &BTreeMap<String, String>,
    plan_sha256: &str,
    binding_sha256: &str,
    source_approved_baseline_set_sha256: &str,
    normalized_approved_baseline_set_sha256: &str,
    registry_release_lock_sha256: &str,
    copied_input_roots: &BTreeMap<String, String>,
) -> Result<String> {
    let value = json!({
        "source_approved_baseline_set_sha256": source_approved_baseline_set_sha256,
        "normalized_approved_baseline_set_sha256": normalized_approved_baseline_set_sha256,
        "binding_sha256": binding_sha256,
        "copied_input_roots": copied_input_roots,
        "generated_files": generated_files,
        "plan_sha256": plan_sha256,
        "registry_release_lock_sha256": registry_release_lock_sha256,
    });
    Ok(sha256_uri(&serde_json::to_vec(&value)?))
}

fn collect_digests(
    root: &Path,
    current: &Path,
    exclude_manifest: bool,
    output: &mut BTreeMap<String, String>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(current)
        .with_context(|| format!("failed to inspect package path {}", current.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("deployment package generated closure must not contain symbolic links");
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(current)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            collect_digests(root, &entry.path(), exclude_manifest, output)?;
        }
        return Ok(());
    }
    if !metadata.is_file() || metadata.len() > MAX_PACKAGE_FILE_BYTES {
        bail!("deployment package contains an unsupported or oversized generated entry");
    }
    let relative = normalized_relative_path(root, current)?;
    if exclude_manifest && relative == "deployment-manifest.v1.json" {
        return Ok(());
    }
    let bytes = read_bounded(current, MAX_PACKAGE_FILE_BYTES)?;
    output.insert(relative, sha256_uri(&bytes));
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to inspect package source {}", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("bundle and anchor package sources must be real directories");
    }
    fs::create_dir_all(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    if entries.is_empty() {
        bail!("bundle and anchor package sources must not be empty");
    }
    for entry in entries {
        let path = entry.path();
        let target = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("bundle and anchor package sources must not contain symbolic links");
        } else if metadata.is_dir() {
            copy_tree(&path, &target)?;
        } else if metadata.is_file() {
            copy_regular_file(&path, &target)?;
        } else {
            bail!("bundle and anchor package sources contain an unsupported entry");
        }
    }
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to inspect package source {}", source.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_PACKAGE_FILE_BYTES
    {
        bail!("deployment package source must be a bounded regular file");
    }
    let bytes = read_bounded(source, MAX_PACKAGE_FILE_BYTES)?;
    write_bytes(destination.to_path_buf(), &bytes)
}

fn validate_first_generation_target(output: &Path) -> Result<()> {
    if !output.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(output)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("deployment output must be absent or an empty real directory");
    }
    if fs::read_dir(output)?.next().transpose()?.is_some() {
        bail!("deployment output must be absent or empty on first generation");
    }
    Ok(())
}

fn normalized_lane_mut(
    approved_set: &mut ApprovedBaselineSetV1,
    lane: ApprovedLaneV1,
) -> &mut crate::approved_set::ApprovedLaneEntryV1 {
    match lane {
        ApprovedLaneV1::RelayPublic => &mut approved_set.lanes.relay_public,
        ApprovedLaneV1::RelayConsultation => &mut approved_set.lanes.relay_consultation,
        ApprovedLaneV1::Notary => &mut approved_set.lanes.notary,
    }
}

fn resolve_approved_artifact(root: &Path, locator: &PortableArtifactLocator) -> Result<PathBuf> {
    let joined = root.join(locator.as_path());
    let metadata = fs::symlink_metadata(&joined)
        .with_context(|| format!("failed to inspect approved artifact {}", joined.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("approved deployment artifact must not be a symbolic link");
    }
    let canonical = fs::canonicalize(&joined)
        .with_context(|| format!("failed to resolve approved artifact {}", joined.display()))?;
    if !canonical.starts_with(root) {
        bail!("approved deployment artifact escaped its bounded closure root");
    }
    Ok(canonical)
}

fn digest_path_component(digest: &str) -> Result<String> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        bail!("signed manifest digest must use sha256");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("signed manifest digest is not canonical lowercase sha256");
    }
    Ok(hex.to_string())
}

fn normalized_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root)?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| anyhow!("deployment package path is not UTF-8"))?,
            ),
            _ => bail!("deployment package path is not normalized"),
        }
    }
    if parts.is_empty() {
        bail!("deployment package relative path is empty");
    }
    Ok(parts.join("/"))
}

fn validate_package_relative_path(path: &str) -> Result<()> {
    let parsed = Path::new(path);
    if parsed.is_absolute()
        || parsed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("deployment binding locator must be a normalized package-relative path");
    }
    Ok(())
}

fn validate_id(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{field} must be a non-empty portable identifier");
    }
    Ok(())
}

fn validate_group(groups: &[WorkloadGroupV1], id: &str, members: &[&str]) -> Result<()> {
    if groups
        != [WorkloadGroupV1 {
            id: id.to_string(),
            members: strings(members.to_vec()),
        }]
    {
        bail!("DeploymentPlanV1 private co-location group is incomplete");
    }
    Ok(())
}

fn initialization(id: &str, workload: &str, action: RuntimeActionV1) -> InitializationActionV1 {
    InitializationActionV1 {
        id: id.to_string(),
        workload: workload.to_string(),
        action,
    }
}

fn exposure(
    endpoint_class: EndpointClassV1,
    exposure: EndpointExposureV1,
) -> ExposureRequirementV1 {
    ExposureRequirementV1 {
        endpoint_class,
        exposure,
    }
}

fn strings(values: Vec<&str>) -> Vec<String> {
    values.into_iter().map(str::to_string).collect()
}

fn require_schema(actual_id: &str, actual_version: &str, id: &str, version: &str) -> Result<()> {
    if actual_id != id || actual_version != version {
        bail!("unsupported portable document schema {actual_id} {actual_version}");
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file =
        fs::File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        bail!("deployment package file exceeds its size limit");
    }
    Ok(bytes)
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        bail!("deployment package input must be a bounded regular non-symlink file");
    }
    read_bounded(path, max_bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = read_bounded(path, MAX_PORTABLE_DOCUMENT_BYTES)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse strict JSON document {}", path.display()))
}

fn write_json(path: PathBuf, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes(path, &bytes)
}

fn write_canonical_json(path: PathBuf, value: &impl Serialize) -> Result<()> {
    let json = serde_json::to_value(value)?;
    let bytes = canonicalize_json(&json)?;
    write_bytes(path, &bytes)
}

fn write_yaml(path: PathBuf, value: &impl Serialize) -> Result<()> {
    let rendered = serde_norway::to_string(value)?;
    write_bytes(path, rendered.as_bytes())
}

fn write_bytes(path: PathBuf, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn verify_operator_files(
    package_dir: &Path,
    inventory: &DeploymentOperatorFileInventoryV1,
) -> Vec<String> {
    let mut violations = Vec::new();
    for file in &inventory.files {
        let path = package_dir.join(&file.path);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => {
                violations.push(format!(
                    "operator file {} is not a regular non-symlink file",
                    file.id
                ));
                continue;
            }
            Err(_) => {
                violations.push(format!("operator file {} is missing", file.id));
                continue;
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let expected_mode = u32::from_str_radix(&file.mode, 8).unwrap_or(u32::MAX);
            if metadata.mode() & 0o777 != expected_mode {
                violations.push(format!(
                    "operator file {} does not have mode {}",
                    file.id, file.mode
                ));
            }
            let owner = format!("{}:{}", metadata.uid(), metadata.gid());
            let allowed = file.allowed_owners.iter().any(|expected| {
                let numeric = match expected.as_str() {
                    "root:root" => "0:0",
                    "65532:65532" => "65532:65532",
                    "999:999" => "999:999",
                    _ => "",
                };
                owner == numeric
            });
            if !allowed {
                violations.push(format!(
                    "operator file {} is not owned by an allowed runtime identity",
                    file.id
                ));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            violations.push(format!(
                "operator file {} ownership cannot be verified on this platform",
                file.id
            ));
        }
        match read_bounded_regular_file(&path, MAX_PORTABLE_DOCUMENT_BYTES) {
            Ok(bytes) if operator_file_content_is_valid(file, &bytes) => {}
            Ok(_) | Err(_) => violations.push(format!(
                "operator file {} does not match its signed value-free format schema",
                file.id
            )),
        }
    }
    violations
}

fn operator_file_content_is_valid(file: &DeploymentOperatorFileV1, bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    match file.format {
        LockedOperatorFileFormatV1::Dotenv => valid_operator_dotenv(bytes, &file.required_keys),
        LockedOperatorFileFormatV1::PemCertificate => {
            let Ok(text) = std::str::from_utf8(bytes) else {
                return false;
            };
            text.contains("-----BEGIN CERTIFICATE-----")
                && text.contains("-----END CERTIFICATE-----")
                && !text.contains("PRIVATE KEY")
        }
        LockedOperatorFileFormatV1::PemPrivateKey => {
            let Ok(text) = std::str::from_utf8(bytes) else {
                return false;
            };
            [
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN EC PRIVATE KEY-----",
            ]
            .iter()
            .any(|marker| text.contains(marker))
                && text.contains("-----END ")
        }
        LockedOperatorFileFormatV1::JsonWebKey => serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .is_some_and(|object| {
                object.get("kty").and_then(Value::as_str).is_some() && object.len() >= 2
            }),
        LockedOperatorFileFormatV1::CompactJwt => std::str::from_utf8(bytes)
            .ok()
            .map(str::trim_end)
            .is_some_and(|token| {
                let parts = token.split('.').collect::<Vec<_>>();
                parts.len() == 3
                    && parts.iter().all(|part| {
                        !part.is_empty()
                            && part.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                            })
                    })
            }),
        LockedOperatorFileFormatV1::Opaque => bytes
            .iter()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace()),
    }
}

fn valid_operator_dotenv(bytes: &[u8], required_keys: &[String]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut keys = BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        if value.is_empty()
            || key.is_empty()
            || !key
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || !keys.insert(key)
            || value.bytes().any(|byte| byte == 0)
        {
            return false;
        }
    }
    if required_keys.is_empty() {
        !keys.is_empty()
    } else {
        keys == required_keys.iter().map(String::as_str).collect()
    }
}

fn create_owner_only_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("failed to create owner-only directory {}", path.display()))
}

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

struct OwnershipDetailsV1 {
    adapted_files: Vec<String>,
    verified_guarantees: Vec<String>,
    operator_owned_guarantees: Vec<String>,
    violations: Vec<String>,
    in_place_regeneration_safe: bool,
}

fn ownership_report(
    ownership: DeploymentOwnershipStateV1,
    package_freshness: PackageFreshnessV1,
    verification_scope: DeploymentVerificationScopeV1,
    details: OwnershipDetailsV1,
) -> DeploymentOwnershipReportV1 {
    DeploymentOwnershipReportV1 {
        schema_id: DEPLOYMENT_OWNERSHIP_REPORT_SCHEMA_ID.to_string(),
        schema_version: DEPLOYMENT_OWNERSHIP_REPORT_SCHEMA_VERSION.to_string(),
        verification_scope,
        ownership,
        package_freshness,
        adapted_files: details.adapted_files,
        verified_guarantees: details.verified_guarantees,
        operator_owned_guarantees: details.operator_owned_guarantees,
        violations: details.violations,
        in_place_regeneration_safe: details.in_place_regeneration_safe,
    }
}

fn runbook(
    package_name: Option<&str>,
    runtime: &LockedRuntimeMappingV1,
    inventory: &DeploymentOperatorFileInventoryV1,
) -> String {
    let package_name = package_name.unwrap_or("registry-stack");
    let relay_public_verify = shell_command(&runtime.relay_public.verify_state.command);
    let relay_consultation_verify = shell_command(&runtime.relay_consultation.verify_state.command);
    let notary_verify = shell_command(&runtime.notary.verify_state.command);
    let operator_files = inventory
        .files
        .iter()
        .map(|file| {
            format!(
                "| `{}` | {} | `{}` | `{}` | `{}` |",
                file.path,
                file.consumers
                    .iter()
                    .map(|consumer| format!("`{consumer}`"))
                    .collect::<Vec<_>>()
                    .join("<br>"),
                operator_file_format(file.format),
                file.mode,
                file.allowed_owners.join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# Registry Stack deployment\n\n\
Package: `{package_name}`\n\n\
Record the approved-set digest and generated closure root printed by `registryctl deploy generate` outside this package. After transfer, run `registryctl deploy verify --package .` and compare both externally recorded values before any initialization.\n\n\
## Required operator files\n\n\
The signed inventory is also recorded at `generated/operator-files.v1.json`. Before any first-install command, create every owner-only regular file below, then run `registryctl deploy verify --package .`. Do not create placeholders or print file values. Add `-f operator-override.yaml` as the final file argument to every command below when that file exists.\n\n\
| Path | Consumers and targets | Format | Mode | Allowed owners |\n\
|---|---|---|---|---|\n\
{operator_files}\n\n\
## First installation only\n\n\
```text\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml config --no-interpolate --no-env-resolution --quiet\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-runtime-stage-secrets\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-postgres-bootstrap\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-relay-public-prepare-state\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-relay-consultation-prepare-state\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-notary-prepare-state\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-relay-public-initialize\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-relay-consultation-initialize\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-notary-initialize\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml up --detach --wait --wait-timeout 120\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml ps\n\
```\n\n\
Never run an initialize service for an existing instance. Ordinary startup fails closed when anti-rollback state is missing.\n\n\
## Ordinary start and stop\n\n\
```text\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml config --no-interpolate --no-env-resolution --quiet\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-runtime-stage-secrets\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-relay-public {relay_public_verify}\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-relay-consultation {relay_consultation_verify}\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-notary {notary_verify}\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml up --detach --wait --wait-timeout 120\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml ps\n\
docker compose --env-file generated/compose.empty.env -f generated/compose.yaml down\n\
```\n\n\
## Product or image update\n\n\
Before shutdown, run `registryctl deploy verify --package .` against the current package and the candidate package, render and verify the candidate effective Compose model, verify every operator file against `generated/operator-files.v1.json`, verify each current and candidate bundle and anchor, and run all three current `verify_state` actions above. Preserve the intact current closure as `generated.previous/` before publishing the candidate. Stop externally reachable dependent services before a private-lane contract change. Start and verify PostgreSQL and the consultation Relay before starting Notary or any externally reachable dependant. The manual abort boundary is the first successful product acceptance that advances durable anti-rollback state. Before that boundary, restore the intact `generated.previous/` closure and restart it. After that boundary, only complete the forward update, restore a coherent snapshot at the same or newer accepted sequence, or replace the affected instance identity. Never start an older closure or restore a pre-update sequence. Remove `generated.previous/` only after all affected lanes report the new accepted sequence.\n\n\
## State recovery\n\n\
Quiesce the complete `relay-public-state` or `consultation-state` recovery consistency group before snapshot or restore. A coherent backup includes the lane anti-rollback and audit state, PostgreSQL data where declared, this package, approved set, bundle, anchor, instance, stream, and accepted sequence identities. After restoring the exact lane, instance, and stream, run the three read-only `verify_state` commands above before ordinary startup. Partial or older recovery must be manually aborted.\n\n\
If no coherent backup exists, provision a new instance identity, review and sign every affected lane, generate a new package, and follow first installation. Reinitializing the same identity is not recovery and is unsupported. Rollback is unsupported.\n\n\
## Operations\n\n\
Use `docker compose ... ps` for value-free health and `docker compose ... logs <registry-service>` for product-separated logs. Metrics are published only on the configured loopback ports. Administration and posture remain private. Resolve a documented readiness latch before using the product-owned clear action. Preserve signed audit retention policy, and treat storage exhaustion as a fail-closed incident requiring a coherent recovery-group snapshot or restore.\n\
"
    )
}

fn operator_file_format(format: LockedOperatorFileFormatV1) -> &'static str {
    match format {
        LockedOperatorFileFormatV1::Dotenv => "dotenv",
        LockedOperatorFileFormatV1::PemCertificate => "pem_certificate",
        LockedOperatorFileFormatV1::PemPrivateKey => "pem_private_key",
        LockedOperatorFileFormatV1::JsonWebKey => "json_web_key",
        LockedOperatorFileFormatV1::CompactJwt => "compact_jwt",
        LockedOperatorFileFormatV1::Opaque => "opaque",
    }
}

fn shell_command(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| format!("'{}'", part.replace('\'', "'\"'\"'")))
        .collect::<Vec<_>>()
        .join(" ")
}
