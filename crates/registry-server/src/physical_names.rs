// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::diagnostics::Diagnostic;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EntityPhysicalNames {
    pub table: String,
    pub fields: BTreeMap<String, String>,
    pub constraints: BTreeMap<String, String>,
    pub indexes: BTreeMap<String, String>,
    pub policies: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PhysicalNameInventory {
    pub entities: BTreeMap<String, EntityPhysicalNames>,
}

pub(crate) struct PhysicalNameBuilder {
    used: BTreeSet<String>,
}

impl PhysicalNameBuilder {
    pub(crate) fn new() -> Self {
        Self {
            used: BTreeSet::new(),
        }
    }

    pub(crate) fn derive(
        &mut self,
        kind: &str,
        stable_id: &str,
        path: &str,
    ) -> Result<String, Diagnostic> {
        let suffix_bytes = 8;
        let suffix_len = suffix_bytes * 2;
        let slug_limit = 63_usize
            .saturating_sub("rs_".len() + kind.len() + 1 + 1 + suffix_len)
            .max(1);
        let slug: String = stable_id
            .bytes()
            .map(|byte| match byte {
                b'A'..=b'Z' => (byte + 32) as char,
                b'a'..=b'z' | b'0'..=b'9' | b'_' => byte as char,
                _ => '_',
            })
            .take(slug_limit)
            .collect();
        let digest = Sha256::digest(format!("registry-server:{kind}:{stable_id}").as_bytes());
        let suffix = hex_prefix(&digest, suffix_bytes);
        let name = format!("rs_{kind}_{slug}_{suffix}");
        if name.len() > 63 || !self.used.insert(name.clone()) {
            return Err(Diagnostic::error(
                "physical_name.collision",
                path,
                "stable identifiers do not produce a unique PostgreSQL name",
            ));
        }
        Ok(name)
    }
}

pub(crate) fn hex_prefix(bytes: &[u8], count: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(count * 2);
    for byte in bytes.iter().take(count) {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
