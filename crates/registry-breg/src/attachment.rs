// SPDX-License-Identifier: Apache-2.0

//! Engine-owned attachment mutations. Bytes never enter record JSON or diagnostics.

use std::fmt;

use sha2::{Digest, Sha256};

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
