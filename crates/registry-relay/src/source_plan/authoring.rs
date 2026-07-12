// SPDX-License-Identifier: Apache-2.0
//! Offline compiler for generated Relay consultation artifacts.
//!
//! This surface shares the runtime's strict parser, normalization, validation,
//! policy derivation, and domain-separated typed hashes. It accepts no secret
//! material and performs no source or filesystem access.

use registry_platform_crypto::canonicalize_json;

use super::artifact::{
    author_integration_pack, author_public_contract, parse_private_binding, sha256_label,
};
use super::SourcePlanArtifactError;

/// One normalized low-level artifact and both hashes needed by bundle authoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredArtifact {
    canonical_json: Box<[u8]>,
    typed_hash: Box<str>,
    raw_sha256: Box<str>,
}

impl AuthoredArtifact {
    /// Canonical JSON bytes that should be written to the generated bundle.
    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    /// Domain-separated typed identity consumed by Relay compilation.
    #[must_use]
    pub fn typed_hash(&self) -> &str {
        &self.typed_hash
    }

    /// Raw SHA-256 label of the canonical bytes for Config Bundle closure.
    #[must_use]
    pub fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }
}

/// Generated consultation contract plus its compiler-derived PDP commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredConsultationContract {
    artifact: AuthoredArtifact,
    policy_hash: Box<str>,
}

impl AuthoredConsultationContract {
    #[must_use]
    pub const fn artifact(&self) -> &AuthoredArtifact {
        &self.artifact
    }

    #[must_use]
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
}

/// Normalize and hash one reviewed integration pack with the runtime compiler.
pub fn compile_integration_pack(bytes: &[u8]) -> Result<AuthoredArtifact, SourcePlanArtifactError> {
    let pack = author_integration_pack(bytes)?;
    Ok(authored_artifact(
        pack.canonical_json(),
        pack.identity().hash().as_str(),
    ))
}

/// Derive the policy hash, normalize, and hash one consultation contract.
///
/// The input must carry a syntactically valid `policy.hash`; its value is
/// replaced by the compiler-derived commitment before the contract is hashed.
pub fn compile_consultation_contract(
    bytes: &[u8],
) -> Result<AuthoredConsultationContract, SourcePlanArtifactError> {
    let contract = author_public_contract(bytes)?;
    Ok(AuthoredConsultationContract {
        artifact: authored_artifact(
            contract.canonical_json(),
            contract.identity().contract_hash().as_str(),
        ),
        policy_hash: contract.policy_identity.hash().as_str().into(),
    })
}

/// Normalize and hash one secret-free private Relay binding.
pub fn compile_private_binding(bytes: &[u8]) -> Result<AuthoredArtifact, SourcePlanArtifactError> {
    let binding = parse_private_binding(bytes)?;
    let value = serde_json::to_value(&binding.document)
        .map_err(|_| SourcePlanArtifactError::Canonicalization)?;
    let canonical_json =
        canonicalize_json(&value).map_err(|_| SourcePlanArtifactError::Canonicalization)?;
    Ok(authored_artifact(&canonical_json, binding.hash().as_str()))
}

fn authored_artifact(canonical_json: &[u8], typed_hash: &str) -> AuthoredArtifact {
    AuthoredArtifact {
        canonical_json: canonical_json.into(),
        typed_hash: typed_hash.into(),
        raw_sha256: sha256_label(canonical_json).into(),
    }
}

#[cfg(test)]
mod tests {
    use registry_platform_crypto::parse_json_strict;

    use super::*;
    use crate::source_plan::{
        CompiledSourcePlanRegistry, EvidenceClass, PinnedEvidenceArtifact,
        PinnedSourcePlanArtifact, SourcePlanArtifactBundle,
    };

    const PACK: &[u8] =
        include_bytes!("../../profiles/dhis2-2.41.9-enrollment-status/integration-pack.json");
    const CONTRACT: &[u8] =
        include_bytes!("../../profiles/dhis2-2.41.9-enrollment-status/public-contract.json");
    const BINDING: &[u8] = include_bytes!(
        "../../profiles/dhis2-2.41.9-enrollment-status/private-binding.example.json"
    );
    const CONFORMANCE: &[u8] =
        include_bytes!("../../profiles/dhis2-2.41.9-enrollment-status/evidence/conformance.json");
    const NEGATIVE_SECURITY: &[u8] = include_bytes!(
        "../../profiles/dhis2-2.41.9-enrollment-status/evidence/negative-security.json"
    );
    const MINIMIZATION: &[u8] =
        include_bytes!("../../profiles/dhis2-2.41.9-enrollment-status/evidence/minimization.json");

    #[test]
    fn authoring_outputs_feed_the_exact_runtime_compiler_without_hash_duplication() {
        let pack = compile_integration_pack(PACK).expect("pack authoring");
        let contract = compile_consultation_contract(CONTRACT).expect("contract authoring");
        let binding = compile_private_binding(BINDING).expect("binding authoring");

        let contracts = [PinnedSourcePlanArtifact::new(
            contract.artifact().canonical_json(),
            contract.artifact().typed_hash(),
        )];
        let packs = [PinnedSourcePlanArtifact::new(
            pack.canonical_json(),
            pack.typed_hash(),
        )];
        let bindings = [binding.canonical_json()];
        let evidence_hashes = [
            sha256_label(CONFORMANCE),
            sha256_label(NEGATIVE_SECURITY),
            sha256_label(MINIMIZATION),
        ];
        let evidence = [
            PinnedEvidenceArtifact::new(
                EvidenceClass::Conformance,
                CONFORMANCE,
                &evidence_hashes[0],
            ),
            PinnedEvidenceArtifact::new(
                EvidenceClass::NegativeSecurity,
                NEGATIVE_SECURITY,
                &evidence_hashes[1],
            ),
            PinnedEvidenceArtifact::new(
                EvidenceClass::Minimization,
                MINIMIZATION,
                &evidence_hashes[2],
            ),
        ];
        let registry = CompiledSourcePlanRegistry::compile(
            &SourcePlanArtifactBundle::new(&contracts, &packs, &bindings).with_evidence(&evidence),
        )
        .expect("generated artifacts compile at runtime");
        assert_eq!(registry.len(), 1);
        for artifact in [contract.artifact(), &pack, &binding] {
            assert_eq!(
                artifact.raw_sha256(),
                sha256_label(artifact.canonical_json())
            );
        }
    }

    #[test]
    fn contract_authoring_replaces_placeholder_with_the_derived_policy_hash() {
        let mut value = parse_json_strict(CONTRACT).expect("strict maintained contract");
        value["spec"]["authorization"]["policy"]["hash"] =
            serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
        let placeholder = serde_json::to_vec(&value).expect("placeholder contract");

        let generated =
            compile_consultation_contract(&placeholder).expect("derived policy contract");
        let maintained = compile_consultation_contract(CONTRACT).expect("maintained contract");
        assert_eq!(generated, maintained);
        assert_ne!(
            generated.policy_hash(),
            format!("sha256:{}", "0".repeat(64))
        );
    }
}
