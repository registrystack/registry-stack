// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
#[path = "../../src/approved_set.rs"]
pub mod approved_set;

pub use registryctl::SIGNING_INPUT_MARKER_FILE;

pub mod trust {
    use std::path::Path;

    use anyhow::Result;
    use registry_platform_config::ProductAcceptanceIdentityV1;

    pub struct SigningInputMarkerV1 {
        pub acceptance_identity: ProductAcceptanceIdentityV1,
    }

    pub fn load_signing_input_marker(_input: &Path) -> Result<SigningInputMarkerV1> {
        unreachable!("actual lane verification is not used by pure assembler tests")
    }
}

pub mod project_authoring {
    use std::path::Path;

    use anyhow::Result;

    use super::approved_set::{ApprovedLaneV1, ReviewedBuildUpdateV1};

    pub struct ReviewedBuildRecordV1 {
        pub project: String,
        pub environment: String,
        pub preceding_approved_set_digest: Option<String>,
        pub affected_lanes: Vec<ApprovedLaneV1>,
        pub bindings: ReviewedBuildUpdateV1,
    }

    impl ReviewedBuildRecordV1 {
        pub fn validate(&self) -> Result<()> {
            unreachable!("high-level command adapter is not used by pure assembler tests")
        }
    }

    pub fn load_current_reviewed_build_record(
        _project_directory: &Path,
        _environment: &str,
    ) -> Result<ReviewedBuildRecordV1> {
        unreachable!("high-level command adapter is not used by pure assembler tests")
    }

    pub fn reviewed_project_id(_project_directory: &Path, _environment: &str) -> Result<String> {
        unreachable!("high-level command adapter is not used by pure assembler tests")
    }
}

use std::path::Path;

use anyhow::Result;
use approved_set::{
    ApprovedLaneEntryV1, ApprovedLaneLocatorsV1, ApprovedLaneV1, CrossLaneInterfaceDigestsV1,
    LaneVerificationRequestV1, LaneVerificationSourceV1, PortableArtifactLocator,
    ReviewedLaneBindingV1, VerifiedApprovedLaneV1,
};
use registry_platform_config::{
    ProductAcceptanceIdentityV1, ProductAcceptanceProductV1, ProductTrustDomainV1,
};

pub fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

pub fn portable(value: impl Into<String>) -> PortableArtifactLocator {
    PortableArtifactLocator::new(value).expect("test locator is portable")
}

pub fn entry(
    lane: ApprovedLaneV1,
    generation: &str,
    reviewed_digest: char,
    signing_digest: char,
    interface_digest: Option<char>,
) -> ApprovedLaneEntryV1 {
    let lane_name = lane.to_string();
    let root = format!("{generation}/{lane_name}");
    ApprovedLaneEntryV1 {
        locators: ApprovedLaneLocatorsV1 {
            bundle: portable(format!("{root}/bundle")),
            signed_manifest: portable(format!("{root}/bundle/manifest.json")),
            anchor: portable(format!("{root}/anchor.json")),
            anchor_transitions: Vec::new(),
        },
        signed_manifest_digest: digest(match lane {
            ApprovedLaneV1::RelayPublic => '1',
            ApprovedLaneV1::RelayConsultation => '2',
            ApprovedLaneV1::Notary => '3',
        }),
        bundle_digest: digest(match lane {
            ApprovedLaneV1::RelayPublic => '4',
            ApprovedLaneV1::RelayConsultation => '5',
            ApprovedLaneV1::Notary => '6',
        }),
        anchor_digest: digest(match lane {
            ApprovedLaneV1::RelayPublic => '7',
            ApprovedLaneV1::RelayConsultation => '8',
            ApprovedLaneV1::Notary => '9',
        }),
        lane_scoped_reviewed_input_digest: digest(reviewed_digest),
        signing_input_closure_digest: digest(signing_digest),
        interfaces: CrossLaneInterfaceDigestsV1 {
            consultation_relay_notary: interface_digest.map(digest),
        },
    }
}

pub fn identity(lane: ApprovedLaneV1, project: &str) -> ProductAcceptanceIdentityV1 {
    ProductAcceptanceIdentityV1 {
        trust_domain: ProductTrustDomainV1::Governed,
        project: project.to_string(),
        environment: "production".to_string(),
        lane: lane.acceptance_lane(),
        product: match lane {
            ApprovedLaneV1::RelayPublic | ApprovedLaneV1::RelayConsultation => {
                ProductAcceptanceProductV1::RegistryRelay
            }
            ApprovedLaneV1::Notary => ProductAcceptanceProductV1::RegistryNotary,
        },
        stream: format!("{project}-stream"),
        instance: format!("{project}-{lane}"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verified(
    lane: ApprovedLaneV1,
    project: &str,
    generation: &str,
    sequence: u64,
    config_digest: char,
    previous_config_digest: Option<char>,
    reviewed_digest: char,
    signing_digest: char,
    interface_digest: Option<char>,
) -> VerifiedApprovedLaneV1 {
    VerifiedApprovedLaneV1::from_independent_verification(
        lane,
        identity(lane, project),
        sequence,
        digest(config_digest),
        previous_config_digest.map(digest),
        entry(
            lane,
            generation,
            reviewed_digest,
            signing_digest,
            interface_digest,
        ),
    )
    .expect("test lane evidence is structurally verified")
}

pub fn initial_lane(lane: ApprovedLaneV1) -> VerifiedApprovedLaneV1 {
    let (reviewed, signing, interface) = match lane {
        ApprovedLaneV1::RelayPublic => ('a', 'd', None),
        ApprovedLaneV1::RelayConsultation => ('b', 'e', Some('c')),
        ApprovedLaneV1::Notary => ('c', 'f', Some('c')),
    };
    verified(
        lane,
        "example-project",
        "approved",
        1,
        match lane {
            ApprovedLaneV1::RelayPublic => 'a',
            ApprovedLaneV1::RelayConsultation => 'b',
            ApprovedLaneV1::Notary => 'c',
        },
        None,
        reviewed,
        signing,
        interface,
    )
}

pub fn replacement_lane(lane: ApprovedLaneV1) -> VerifiedApprovedLaneV1 {
    let (reviewed, signing, interface, previous) = match lane {
        ApprovedLaneV1::RelayPublic => ('7', '8', None, 'a'),
        ApprovedLaneV1::RelayConsultation => ('7', '8', Some('9'), 'b'),
        ApprovedLaneV1::Notary => ('8', '9', Some('9'), 'c'),
    };
    verified(
        lane,
        "example-project",
        "approved-next",
        2,
        match lane {
            ApprovedLaneV1::RelayPublic => 'd',
            ApprovedLaneV1::RelayConsultation => 'e',
            ApprovedLaneV1::Notary => 'f',
        },
        Some(previous),
        reviewed,
        signing,
        interface,
    )
}

pub fn reviewed_binding(lane: ApprovedLaneV1) -> ReviewedLaneBindingV1 {
    replacement_lane(lane).entry().reviewed_binding()
}

pub fn verifier_for_initial(request: LaneVerificationRequestV1) -> Result<VerifiedApprovedLaneV1> {
    assert!(matches!(
        request.source,
        LaneVerificationSourceV1::LaneDirectory(_)
    ));
    Ok(initial_lane(request.lane))
}

pub fn path_set(root: &Path) -> approved_set::InitialApprovedSetInputs {
    approved_set::InitialApprovedSetInputs {
        relay_public: root.join("relay-public"),
        relay_consultation: root.join("relay-consultation"),
        notary: root.join("notary"),
    }
}
