// SPDX-License-Identifier: Apache-2.0

//! Digest-pinned provider envelope validation before route extraction.
//!
//! The checked schema retains the shared compiler's bounded JSON Schema
//! grammar, disabled external resolution and full format validation. It carries
//! neither a provider response nor any authority to read a file or URL.
use registry_adapter_core::ScriptReference;
use serde_json::Value;
use thiserror::Error;

use crate::{
    artifacts::{ArtifactSource, PackArtifactBytes},
    evidence::{check_provider_schema, CheckedEvidenceSchema},
};

const MAXIMUM_SCHEMA_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderSchemaError {
    #[error("the reviewed provider schema is missing, exceeds its bound or has changed")]
    Artifact,
    #[error("the provider schema is not a bounded closed JSON Schema")]
    Schema,
}

#[derive(Debug)]
pub struct ProviderSchema {
    checked: CheckedEvidenceSchema,
}

impl ProviderSchema {
    pub fn compile(
        reference: &ScriptReference,
        artifacts: &PackArtifactBytes,
    ) -> Result<Self, ProviderSchemaError> {
        Self::compile_from(reference, artifacts)
    }

    pub(crate) fn compile_from<S: ArtifactSource + ?Sized>(
        reference: &ScriptReference,
        artifacts: &S,
    ) -> Result<Self, ProviderSchemaError> {
        let bytes = artifacts
            .read_bounded(&reference.path, MAXIMUM_SCHEMA_BYTES)
            .map_err(|_| ProviderSchemaError::Artifact)?;
        if registry_platform_config::sha256_uri(&bytes) != reference.digest.as_str() {
            return Err(ProviderSchemaError::Artifact);
        }
        let schema = serde_json::from_slice(&bytes).map_err(|_| ProviderSchemaError::Schema)?;
        let checked = check_provider_schema(schema).map_err(|_| ProviderSchemaError::Schema)?;
        Ok(Self { checked })
    }

    #[must_use]
    pub fn validate(&self, body: &Value) -> bool {
        self.checked.validate(body)
    }
}
