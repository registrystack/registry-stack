// SPDX-License-Identifier: Apache-2.0
//! Explicit syntax edges of product-owned authoring contracts.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProductKind {
    Breg,
    Casework,
    Scheduling,
    Messaging,
    Discovery,
    Manifest,
    Render,
    EvidenceOid4vci,
}

impl ProductKind {
    pub const ALL: [Self; 8] = [
        Self::Breg,
        Self::Casework,
        Self::Scheduling,
        Self::Messaging,
        Self::Discovery,
        Self::Manifest,
        Self::Render,
        Self::EvidenceOid4vci,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Breg => "breg",
            Self::Casework => "casework",
            Self::Scheduling => "scheduling",
            Self::Messaging => "messaging",
            Self::Discovery => "discovery",
            Self::Manifest => "manifest",
            Self::Render => "render",
            Self::EvidenceOid4vci => "evidence-oid4vci",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Scope {
    Global,
    /// Search enclosing mappings for this dotted field, skipping this many immediate parents.
    Ancestor {
        skip: usize,
        field: &'static str,
    },
    Composite(&'static [(usize, &'static str)]),
    /// Scope declarations and references to the same authored document.
    Document,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NameRule {
    /// Slash-separated keys; `*` visits sequence items or mapping values, `$key` mapping keys.
    pub path: &'static str,
    pub kind: &'static str,
    pub scope: Scope,
    /// Append another scalar in the same enclosing mapping, separated by `/`.
    pub suffix: Option<&'static str>,
    pub reports_unresolved: bool,
    /// Legacy aliases only apply when the owning mapping omits this current spelling.
    pub ignored_when_present: Option<&'static str>,
    pub only_when: Option<(&'static str, &'static str)>,
}

impl NameRule {
    pub const fn global(path: &'static str, kind: &'static str) -> Self {
        Self {
            path,
            kind,
            scope: Scope::Global,
            suffix: None,
            reports_unresolved: true,
            ignored_when_present: None,
            only_when: None,
        }
    }
    pub const fn scoped(
        path: &'static str,
        kind: &'static str,
        skip: usize,
        field: &'static str,
    ) -> Self {
        Self {
            path,
            kind,
            scope: Scope::Ancestor { skip, field },
            suffix: None,
            reports_unresolved: true,
            ignored_when_present: None,
            only_when: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FileRule {
    pub path: &'static str,
    pub prefix: &'static str,
    pub suffix: &'static str,
    pub relative_to_document: bool,
    /// Whether the target is loaded as an authoring document. Only YAML and JSON targets are
    /// loaded, whatever this says; keys, scripts, and fonts remain navigation targets.
    pub index_target: bool,
}

impl FileRule {
    pub const fn root(path: &'static str, index_target: bool) -> Self {
        Self {
            path,
            prefix: "",
            suffix: "",
            relative_to_document: false,
            index_target,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DocumentRules {
    /// Root-relative slash pattern; `*` one component, `**` any depth. `@document` is the entry.
    pub pattern: &'static str,
    pub declarations: &'static [NameRule],
    pub references: &'static [NameRule],
    pub files: &'static [FileRule],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ProductSpec {
    pub product: ProductKind,
    pub marker: &'static str,
    pub discriminator: &'static str,
    pub version_prefix: &'static str,
    pub kind: &'static str,
    pub documents: &'static [DocumentRules],
}
