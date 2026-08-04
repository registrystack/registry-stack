//! Interchange types for the source-suggest pipeline.
//!
//! The pipeline is: load and resolve an OpenAPI document, flatten one
//! operation's response schema into candidate leaves, collect a selection and
//! bound decisions (from flags or the interactive prompts), narrow to the
//! closed schema subset, then emit draft artifacts. Every stage communicates
//! through the types here so the interactive front-end and the flag-driven
//! front-end share one deterministic core.

use std::{collections::BTreeMap, path::PathBuf};

/// Where the OpenAPI document is read from.
///
/// The two cases stay distinguishable all the way to the reproduce line, so
/// the command printed at the end of a run names the same document the run
/// actually read. Deciding which case a `--openapi` argument is happens once,
/// before anything is read, so an unusable URL fails before the operator is
/// asked a single question.
#[derive(Debug, Clone)]
pub enum SpecSource {
    File(PathBuf),
    Url(url::Url),
}

impl SpecSource {
    /// The document as it should be named in a message or echoed back in the
    /// reproduce command.
    pub fn display(&self) -> String {
        match self {
            SpecSource::File(path) => path.to_string_lossy().into_owned(),
            SpecSource::Url(url) => url.to_string(),
        }
    }
}

/// One operation in the OpenAPI document: an uppercase HTTP method and the
/// literal path template, e.g. `GET` and `/records/{id}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationKey {
    pub method: String,
    pub path: String,
}

/// One selectable operation, as listed to the user.
#[derive(Debug, Clone)]
pub struct OperationSummary {
    pub key: OperationKey,
    pub summary: Option<String>,
    /// (status code, media type) pairs carrying a JSON response schema.
    pub json_responses: Vec<(String, String)>,
}

/// A response schema with every local `$ref` inlined and the dialect
/// normalized: OpenAPI 3.0 `nullable: true` is rewritten to the 3.1 type
/// pair `[T, "null"]`, so downstream stages handle one form.
#[derive(Debug, Clone)]
pub struct ResolvedSchema(pub serde_json::Value);

/// The marker left in place of a schema node that repeats a `$ref` already on
/// the resolution stack. Cutting the repeat bounds an otherwise infinite
/// expansion without discarding the rest of the operation; the marker declares
/// no type, so no stage can mistake it for something projectable, and the
/// flattener names the recursion it stands for.
pub const RECURSIVE_REF_KEY: &str = "x-evidencectl-recursive-ref";

/// A resolved response schema with the readings the resolver made on the way.
///
/// A note records where the document was ambiguous or unrepresentable and what
/// was done about it: a cut recursion, or a type read from a structural
/// keyword. Every note is reported to the operator, because a reading the tool
/// made on their behalf is one they may need to disagree with.
#[derive(Debug, Clone)]
pub struct ResolvedResponse {
    pub schema: ResolvedSchema,
    pub notes: Vec<String>,
}

/// One selectable leaf of the resolved schema, presented to the user and
/// mapped one-to-one onto a projection allowlist entry.
///
/// Pointers are in the extended projection form defined by ADAPTER-API.md:
/// RFC 6901 segments with `~0`/`~1` escapes, and the reserved segment `*`
/// visiting every element of an array (`/results/*/trackingId`). The emit
/// stage derives `get_path` pointers from these by substituting a numeric
/// index for `*`, because `get_path` is plain RFC 6901 and does not accept
/// `*`.
#[derive(Debug, Clone)]
pub struct CandidateLeaf {
    /// Extended projection pointer into the projected tree.
    pub pointer: String,
    /// Human label for the leaf's type, e.g. `string (date)`, `integer`.
    pub type_label: String,
    /// True when the spec admits an explicit null for this leaf.
    pub nullable: bool,
    pub description: Option<String>,
}

/// What kind of bound the closed subset demands and the spec did not supply.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BoundKind {
    /// Arrays must declare `maxItems` between 1 and 256.
    ArrayMaxItems,
    /// Integers must carry both `minimum` and `maximum` (or enum/const).
    IntegerRange,
    /// Strings need `minLength`/`maxLength` (or format/enum/const).
    StringLength,
}

/// Where a suggested bound value came from. Shown to the user so a default
/// is confirmed with its provenance, never adopted blind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// Stated in the OpenAPI document itself.
    Spec,
    /// Derived mechanically from a `format` the subset does not admit,
    /// e.g. `uuid` becoming fixed length bounds.
    Format,
    /// Observed in the sample response and widened.
    Sample,
    /// Derived from a page-size parameter in the spec.
    PageSize,
    /// The closed subset's own ceiling, used because the document states a
    /// bound above it. This is deliberately not [`Provenance::Spec`]: the
    /// number in the draft is not the number the document states, and
    /// crediting the document for it would tell a reviewer the source promised
    /// something it never promised.
    SubsetCeiling,
    /// Chosen by the operator at the prompt, either where nothing could be
    /// derived or in place of a suggestion they edited. Nothing the tool
    /// derived carries this: it is the one provenance that is not a
    /// derivation.
    Operator,
}

/// One concrete bound value with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedBound {
    pub values: BoundValues,
    pub provenance: Provenance,
}

/// The value shape per bound kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundValues {
    MaxItems(u64),
    IntegerRange { minimum: i64, maximum: i64 },
    StringLength { min_length: u64, max_length: u64 },
}

/// One decision the closed subset requires at `pointer`, with the best
/// suggestion the pipeline could derive, if any.
#[derive(Debug, Clone)]
pub struct BoundNeed {
    pub pointer: String,
    pub kind: BoundKind,
    pub suggestion: Option<SuggestedBound>,
}

/// Raw observations from a sample response, keyed by pointer. Widening
/// policy belongs to the narrowing stage, not here.
#[derive(Debug, Clone, Default)]
pub struct Observations {
    pub by_pointer: BTreeMap<String, Observed>,
}

/// What one leaf (or array) looked like in the sample.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub min_integer: Option<i64>,
    pub max_integer: Option<i64>,
    pub max_string_bytes: Option<u64>,
    pub max_array_items: Option<u64>,
    pub saw_null: bool,
}

/// The complete set of decisions the deterministic core consumes. The
/// interactive front-end and the flag parser both produce exactly this.
#[derive(Debug, Clone)]
pub struct Decisions {
    pub operation: OperationKey,
    pub status: String,
    pub media_type: String,
    pub source_id: String,
    /// Selected projection allowlist entries (extended-pointer form), in
    /// presentation order. The pipeline must reject or normalize a
    /// selection containing both an ancestor and its descendant, because
    /// bundle validation fails overlapping projection paths.
    pub selection: Vec<String>,
    /// Confirmed bound values, keyed by (pointer, kind). A need absent here
    /// is emitted as an explicit TODO and the draft fails `evidence check`
    /// until the operator supplies it: the tool never invents a bound.
    pub resolutions: BTreeMap<(String, BoundKind), BoundValues>,
}

impl BoundKind {
    /// Stable key form for maps and reports.
    pub fn label(&self) -> &'static str {
        match self {
            BoundKind::ArrayMaxItems => "maxItems",
            BoundKind::IntegerRange => "integer bounds",
            BoundKind::StringLength => "string length bounds",
        }
    }
}

/// The narrowed response schema plus everything still owed by a human.
#[derive(Debug, Clone)]
pub struct NarrowOutcome {
    /// The closed-subset schema as a YAML-ready value. Unresolved bounds are
    /// omitted (never invented), so `evidence check` rejects the draft until
    /// the operator fills them.
    pub schema: serde_json::Value,
    /// Bounds still unresolved, in schema order.
    pub unresolved: Vec<BoundNeed>,
}

/// One draft file to write, bundle-relative.
#[derive(Debug, Clone)]
pub struct DraftFile {
    pub bundle_relative_path: String,
    pub contents: String,
}

/// Everything the emit stage produces for one source.
#[derive(Debug, Clone)]
pub struct DraftArtifacts {
    pub files: Vec<DraftFile>,
    /// A deliberately incomplete `sources.<id>` YAML block containing only
    /// facts mechanically established by the OpenAPI selection.
    pub source_block: String,
    /// Human report: what was derived, from where, and what remains.
    pub report: String,
    /// The fully-flagged non-interactive invocation reproducing this run.
    pub equivalent_command: String,
}
