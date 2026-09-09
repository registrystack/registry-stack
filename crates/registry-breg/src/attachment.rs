// SPDX-License-Identifier: Apache-2.0

//! Engine-owned attachment mutations. Bytes never enter record JSON or diagnostics.

use std::fmt;

use sha2::{Digest, Sha256};

#[cfg(feature = "runtime")]
use crate::model::CompiledRoute;
use crate::model::HttpMethod;

/// Downloads carry no filename: no slot metadata holds one, and deriving one would
/// echo authored configuration text back into a response header.
pub(crate) const DOWNLOAD_CONTENT_DISPOSITION: &str = "attachment";

/// Binary routes retain the parent authority but have their own stable wire identity.
#[cfg(feature = "runtime")]
pub(crate) fn route(base: &CompiledRoute, slot_id: &str, method: HttpMethod) -> CompiledRoute {
    let mut route = base.clone();
    route.id = operation_id(&base.id, slot_id, method);
    route.path = format!("{}/attachments/{slot_id}", base.path);
    route.method = method;
    route
}

pub(crate) fn operation_id(base: &str, slot_id: &str, method: HttpMethod) -> String {
    let method = match method {
        HttpMethod::Get => "get",
        HttpMethod::Patch => "patch",
        HttpMethod::Delete => "delete",
        HttpMethod::Post => "post",
    };
    format!("{base}.attachment.{slot_id}.{method}")
}

#[derive(Clone, Eq, PartialEq)]
pub struct AttachmentMutation {
    pub slot_id: String,
    /// Both content type and bytes are absent for removal.
    pub content_type: Option<String>,
    pub bytes: Option<Vec<u8>>,
}

impl AttachmentMutation {
    pub fn sha256(&self) -> Option<String> {
        self.bytes.as_ref().map(|bytes| {
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        })
    }
}

impl fmt::Debug for AttachmentMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentMutation")
            .field("slot_id", &self.slot_id)
            .field("content_type", &self.content_type)
            .field("byte_size", &self.bytes.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}
