// SPDX-License-Identifier: Apache-2.0
//! Bounded, revision-bound workspace analysis shared by non-editor consumers.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::refs::SymbolKind;

const API_VERSION: &str = "id.registrystack.org/formats/platform/workspace-analysis/v1alpha1";
// A 16 MiB authorized source snapshot expands to roughly 21.4 MiB when base64 encoded. Keep the
// transport envelope larger than that exact-source ceiling so the advertised source budget is
// reachable after JSON field and fact overhead.
const MAX_REQUEST_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILES: usize = 10_000;
const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_DEFINITIONS: usize = 20_000;
const DEFAULT_MAX_REFERENCES: usize = 50_000;
const DEFAULT_MAX_DEPTH: usize = 32;
const DEFAULT_MAX_RESULTS: usize = 2_000;
const DEFAULT_MAX_PATHS: usize = 2_000;

#[derive(Debug, Clone)]
pub struct WorkspaceAnalysisError {
    code: &'static str,
    message: String,
}

impl WorkspaceAnalysisError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn response(&self) -> Value {
        json!({
            "apiVersion": API_VERSION,
            "error": { "code": self.code, "message": self.message },
        })
    }
}

impl fmt::Display for WorkspaceAnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for WorkspaceAnalysisError {}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    api_version: String,
    operation: Operation,
    workspace_binding: String,
    revision: String,
    files: Vec<FileInput>,
    facts: Facts,
    #[serde(default)]
    before: Option<SnapshotInput>,
    #[serde(default)]
    target: Option<Identity>,
    #[serde(default)]
    targets: Vec<Identity>,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    limits: Limits,
}

#[derive(Debug, Copy, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Operation {
    Analyze,
    Impact,
    References,
    Definition,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotInput {
    workspace_binding: String,
    revision: String,
    files: Vec<FileInput>,
    facts: Facts,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileInput {
    path: String,
    state: String,
    sha256: String,
    bytes_base64: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
struct Facts {
    definitions: Vec<DefinitionFact>,
    mentions: Vec<MentionFact>,
    mappings: Vec<MappingFact>,
    native_parts: Vec<String>,
    generation: Option<GenerationFacts>,
    coverage_gaps: Vec<CoverageGap>,
    check_groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DefinitionFact {
    scope: String,
    name: String,
    file: String,
    pointer: String,
    #[serde(default)]
    owner: Option<Identity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MentionFact {
    source: MentionIdentity,
    target: MentionIdentity,
    kind: String,
    file: String,
    pointer: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum MentionIdentity {
    Identity(Identity),
    Scoped { scope: String, name: String },
}

impl MentionIdentity {
    fn into_identity(self) -> Identity {
        match self {
            Self::Identity(identity) => identity,
            Self::Scoped { scope, name } => Identity::Object { scope, name },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappingFact {
    owner: Identity,
    authored: Identity,
    generated: Identity,
    product: String,
    file: String,
    pointer: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationFacts {
    snapshot: Snapshot,
    generator: Generator,
    files: Vec<GenerationFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot {
    workspace_binding: String,
    revision: String,
    content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generator {
    id: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationFile {
    path: String,
    source: GenerationSource,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationSource {
    #[serde(rename = "type")]
    source_type: String,
    product: String,
    #[serde(default)]
    workspace_path: Option<String>,
    items: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
struct Limits {
    max_definitions: Option<usize>,
    max_references: Option<usize>,
    max_depth: Option<usize>,
    max_results: Option<usize>,
    max_paths: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Identity {
    Object { scope: String, name: String },
    AuthoredFile { path: String },
    GeneratedFile { path: String },
}

impl Identity {
    fn key(&self) -> String {
        match self {
            Self::Object { scope, name } => format!("{scope}:{name}"),
            Self::AuthoredFile { path } => format!("authored-file:{path}"),
            Self::GeneratedFile { path } => format!("generated-file:{path}"),
        }
    }

    fn authored(path: impl Into<String>) -> Self {
        Self::AuthoredFile { path: path.into() }
    }

    fn generated(path: impl Into<String>) -> Self {
        Self::GeneratedFile { path: path.into() }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Location {
    file: String,
    pointer: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DefinitionKind {
    Document,
    AuthoredFile,
    GeneratedOutput,
}

#[derive(Debug, Clone, Serialize)]
struct Definition {
    identity: Identity,
    kind: DefinitionKind,
    location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<Identity>,
}

#[derive(Debug, Clone, Serialize)]
struct Reference {
    id: String,
    kind: String,
    source: Identity,
    target: Identity,
    location: Location,
    resolution: &'static str,
    provider: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileOutput {
    path: String,
    content_hash: String,
    state: String,
}

#[derive(Debug, Clone, Serialize)]
struct Provenance {
    authored: Identity,
    generated: Identity,
    product: String,
    generator: Generator,
}

#[derive(Debug, Clone, Serialize)]
struct DeclaredMapping {
    owner: Identity,
    authored: Identity,
    generated: Identity,
    product: String,
    location: Location,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct CoverageGap {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Coverage {
    status: &'static str,
    gaps: Vec<CoverageGap>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Analysis {
    api_version: &'static str,
    snapshot: Snapshot,
    files: Vec<FileOutput>,
    definitions: Vec<Definition>,
    references: Vec<Reference>,
    declared_mappings: Vec<DeclaredMapping>,
    provenance: Vec<Provenance>,
    check_groups: Vec<String>,
    coverage: Coverage,
}

#[derive(Debug)]
struct DecodedFile {
    output: FileOutput,
    bytes: Vec<u8>,
}

pub fn execute_workspace_analysis(input: Value) -> Result<Value, WorkspaceAnalysisError> {
    let request: Request = serde_json::from_value(input)
        .map_err(|error| WorkspaceAnalysisError::new("invalid-input", error.to_string()))?;
    validate_request_header(&request)?;
    let after = analyze_snapshot(
        request.workspace_binding,
        request.revision,
        request.files,
        request.facts,
        &request.limits,
    )?;
    let engine = engine();
    match request.operation {
        Operation::Analyze => {
            Ok(json!({ "apiVersion": API_VERSION, "engine": engine, "analysis": after }))
        }
        Operation::References => {
            let target = request.target.ok_or_else(|| {
                WorkspaceAnalysisError::new("invalid-input", "references requires target")
            })?;
            validate_identity(&target)?;
            let result = find_references(&after, target, request.max_results.unwrap_or(1_000))?;
            Ok(
                json!({ "apiVersion": API_VERSION, "engine": engine, "analysis": after, "references": result }),
            )
        }
        Operation::Definition => {
            let target = request.target.ok_or_else(|| {
                WorkspaceAnalysisError::new("invalid-input", "definition requires target")
            })?;
            validate_identity(&target)?;
            let result = find_definitions(&after, &target, request.max_results.unwrap_or(1_000))?;
            Ok(
                json!({ "apiVersion": API_VERSION, "engine": engine, "analysis": after, "definition": result }),
            )
        }
        Operation::Impact => {
            for target in &request.targets {
                validate_identity(target)?;
            }
            let before = request
                .before
                .map(|input| {
                    analyze_snapshot(
                        input.workspace_binding,
                        input.revision,
                        input.files,
                        input.facts,
                        &request.limits,
                    )
                })
                .transpose()?;
            let impact =
                analyze_impact(&after, before.as_ref(), &request.targets, &request.limits)?;
            Ok(
                json!({ "apiVersion": API_VERSION, "engine": engine, "analysis": after, "impact": impact }),
            )
        }
    }
}

pub fn run_workspace_analysis_stdio() -> Result<(), WorkspaceAnalysisError> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| WorkspaceAnalysisError::new("input-error", error.to_string()))?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(WorkspaceAnalysisError::new(
            "request-limit",
            format!("workspace analysis input exceeds {MAX_REQUEST_BYTES} bytes"),
        ));
    }
    let input = serde_json::from_slice(&bytes)
        .map_err(|error| WorkspaceAnalysisError::new("invalid-json", error.to_string()))?;
    let output = execute_workspace_analysis(input)?;
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer(&mut writer, &output)
        .map_err(|error| WorkspaceAnalysisError::new("output-error", error.to_string()))?;
    writer
        .write_all(b"\n")
        .map_err(|error| WorkspaceAnalysisError::new("output-error", error.to_string()))
}

fn engine() -> Value {
    json!({ "name": "registry-language-server", "version": env!("CARGO_PKG_VERSION") })
}

fn validate_request_header(request: &Request) -> Result<(), WorkspaceAnalysisError> {
    if request.api_version != API_VERSION {
        return Err(WorkspaceAnalysisError::new(
            "unsupported-version",
            format!(
                "unsupported workspace analysis apiVersion {}",
                request.api_version
            ),
        ));
    }
    if request.workspace_binding.trim().is_empty() || request.revision.trim().is_empty() {
        return Err(WorkspaceAnalysisError::new(
            "invalid-input",
            "workspaceBinding and revision must be non-empty",
        ));
    }
    Ok(())
}

fn analyze_snapshot(
    workspace_binding: String,
    revision: String,
    inputs: Vec<FileInput>,
    facts: Facts,
    limits: &Limits,
) -> Result<Analysis, WorkspaceAnalysisError> {
    if workspace_binding.trim().is_empty() || revision.trim().is_empty() {
        return Err(WorkspaceAnalysisError::new(
            "invalid-input",
            "workspaceBinding and revision must be non-empty",
        ));
    }
    let max_definitions = bounded_limit(
        "maxDefinitions",
        limits.max_definitions,
        DEFAULT_MAX_DEFINITIONS,
        DEFAULT_MAX_DEFINITIONS,
        false,
    )?;
    let max_references = bounded_limit(
        "maxReferences",
        limits.max_references,
        DEFAULT_MAX_REFERENCES,
        DEFAULT_MAX_REFERENCES,
        false,
    )?;
    let files = decode_files(inputs)?;
    let snapshot = snapshot(&workspace_binding, &revision, &files);
    let authorized: HashSet<&str> = files.iter().map(|file| file.output.path.as_str()).collect();
    let mut gaps = facts.coverage_gaps;
    let mut definitions = Vec::with_capacity(files.len() + facts.definitions.len());
    for file in &files {
        definitions.push(Definition {
            identity: Identity::authored(file.output.path.clone()),
            kind: DefinitionKind::AuthoredFile,
            location: Location {
                file: file.output.path.clone(),
                pointer: String::new(),
            },
            owner: None,
        });
        match file.output.state.as_str() {
            "unread" | "unreadable" => gaps.push(CoverageGap {
                code: "source-unreadable".to_owned(),
                message: "The authorized file was classified as unreadable by the source provider."
                    .to_owned(),
                file: Some(file.output.path.clone()),
            }),
            _ => {}
        }
    }
    for fact in facts.definitions {
        validate_name("scope", &fact.scope)?;
        validate_name("name", &fact.name)?;
        validate_location(&fact.file, &fact.pointer, &authorized)?;
        if let Some(owner) = &fact.owner {
            validate_authorized_identity(owner, &authorized)?;
        }
        definitions.push(Definition {
            identity: Identity::Object {
                scope: fact.scope,
                name: fact.name,
            },
            kind: DefinitionKind::Document,
            location: Location {
                file: fact.file,
                pointer: fact.pointer,
            },
            owner: fact.owner,
        });
    }
    definitions.sort_by_key(|definition| definition.identity.key());
    if definitions.len() > max_definitions {
        let total = definitions.len();
        definitions.truncate(max_definitions);
        gaps.push(CoverageGap {
            code: "result-limit".to_owned(),
            message: format!(
                "Workspace analysis retained {max_definitions} of {total} definitions."
            ),
            file: None,
        });
    }

    let mut mappings = Vec::new();
    let mut products = BTreeSet::new();
    let mut breg_targets = BTreeMap::new();
    if let Some(generation) = facts
        .generation
        .as_ref()
        .filter(|generation| generation.snapshot == snapshot)
    {
        for file in &generation.files {
            if file.source.source_type == "native" && file.source.product == "breg" {
                if let Some(authored) = &file.source.workspace_path {
                    breg_targets
                        .entry(authored.clone())
                        .or_insert_with(|| file.path.clone());
                }
            }
        }
    }
    for mapping in facts.mappings {
        validate_identity(&mapping.owner)?;
        require_identity_kind(&mapping.authored, "authored-file")?;
        require_identity_kind(&mapping.generated, "generated-file")?;
        validate_identity(&mapping.authored)?;
        if let Identity::AuthoredFile { path } = &mapping.authored {
            if !authorized.contains(path.as_str()) {
                gaps.push(CoverageGap {
                    code: "source-unreadable".to_owned(),
                    message: "A declared native mapping names an authored source that is absent from this exact snapshot; the relationship is retained but its source is not indexed.".to_owned(),
                    file: Some(path.clone()),
                });
            }
        }
        if let Identity::GeneratedFile { path } = &mapping.generated {
            validate_generated_path(path)?;
        }
        validate_name("product", &mapping.product)?;
        validate_location(&mapping.file, &mapping.pointer, &authorized)?;
        products.insert(mapping.product.clone());
        if mapping.product == "breg" {
            if let (
                Identity::AuthoredFile { path: authored },
                Identity::GeneratedFile { path: generated },
            ) = (&mapping.authored, &mapping.generated)
            {
                breg_targets.insert(authored.clone(), generated.clone());
            }
        }
        mappings.push(DeclaredMapping {
            owner: mapping.owner,
            authored: mapping.authored,
            generated: mapping.generated,
            product: mapping.product,
            location: Location {
                file: mapping.file,
                pointer: mapping.pointer,
            },
        });
    }
    mappings.sort_by_key(|mapping| {
        format!(
            "{}\0{}\0{}",
            mapping.owner.key(),
            mapping.location.file,
            mapping.location.pointer
        )
    });

    let mut pending = Vec::new();
    for mention in facts.mentions {
        let source = mention.source.into_identity();
        let target = mention.target.into_identity();
        validate_authorized_identity(&source, &authorized)?;
        // A safe missing target is a semantic unresolved reference, not an authority to read it.
        // Sources and fact locations must belong to the captured snapshot; targets may name an
        // expected-absent authored file so deletion and missing-source impact remains visible.
        validate_identity(&target)?;
        if let Identity::GeneratedFile { path } = &target {
            validate_generated_path(path)?;
        }
        validate_name("reference kind", &mention.kind)?;
        validate_location(&mention.file, &mention.pointer, &authorized)?;
        pending.push(PendingReference {
            kind: mention.kind,
            source,
            target,
            location: Location {
                file: mention.file,
                pointer: mention.pointer,
            },
            provider: "workspace-v1",
        });
    }
    add_native_breg_facts(
        &files,
        &facts.native_parts,
        &breg_targets,
        &mut definitions,
        &mut pending,
        &mut gaps,
    )?;

    let mut provenance = Vec::new();
    if let Some(generation) = facts.generation {
        if generation.snapshot != snapshot {
            gaps.push(CoverageGap {
                code: "generation-revision-mismatch".to_owned(),
                message: "Generation facts do not match the exact workspace analysis snapshot."
                    .to_owned(),
                file: None,
            });
        } else {
            validate_name("generator id", &generation.generator.id)?;
            validate_name("generator version", &generation.generator.version)?;
            let defined: HashSet<String> = definitions
                .iter()
                .map(|definition| definition.identity.key())
                .collect();
            let mut generated_paths = HashSet::new();
            for generated_fact in generation.files {
                validate_generated_path(&generated_fact.path)?;
                if !generated_paths.insert(generated_fact.path.clone()) {
                    return Err(WorkspaceAnalysisError::new(
                        "invalid-input",
                        format!(
                            "generation facts contain {} more than once",
                            generated_fact.path
                        ),
                    ));
                }
                validate_name("product", &generated_fact.source.product)?;
                if generated_fact.source.source_type != "native"
                    && generated_fact.source.source_type != "product"
                {
                    return Err(WorkspaceAnalysisError::new(
                        "invalid-input",
                        "generation source type must be native or product",
                    ));
                }
                let generated = Identity::generated(generated_fact.path.clone());
                definitions.push(Definition {
                    identity: generated.clone(),
                    kind: DefinitionKind::GeneratedOutput,
                    location: Location {
                        file: generated_fact.path.clone(),
                        pointer: String::new(),
                    },
                    owner: None,
                });
                products.insert(generated_fact.source.product.clone());
                let mut sources = Vec::new();
                if generated_fact.source.source_type == "native" {
                    let path = generated_fact.source.workspace_path.ok_or_else(|| {
                        WorkspaceAnalysisError::new(
                            "invalid-input",
                            "native generation source requires workspacePath",
                        )
                    })?;
                    validate_path(&path)?;
                    sources.push(Identity::authored(path));
                }
                for item in generated_fact.source.items {
                    sources.push(parse_scoped_identity(&item)?);
                }
                for source in sources {
                    if !defined.contains(&source.key()) {
                        gaps.push(CoverageGap {
                            code: "generation-source-unresolved".to_owned(),
                            message: format!(
                                "Generated output {} names unavailable authored source {}.",
                                generated_fact.path,
                                source.key()
                            ),
                            file: Some(generated_fact.path.clone()),
                        });
                        continue;
                    }
                    provenance.push(Provenance {
                        authored: source.clone(),
                        generated: generated.clone(),
                        product: generated_fact.source.product.clone(),
                        generator: generation.generator.clone(),
                    });
                    pending.push(PendingReference {
                        kind: "generated-from".to_owned(),
                        source: generated.clone(),
                        target: source,
                        location: Location {
                            file: generated_fact.path.clone(),
                            pointer: String::new(),
                        },
                        provider: "generation",
                    });
                }
            }
        }
    } else {
        gaps.push(CoverageGap {
            code: "generation-provenance-unavailable".to_owned(),
            message: "No exact-revision generation facts were supplied.".to_owned(),
            file: None,
        });
    }

    definitions.sort_by_key(|definition| definition.identity.key());
    if definitions.len() > max_definitions {
        let total = definitions.len();
        definitions.truncate(max_definitions);
        gaps.push(CoverageGap {
            code: "result-limit".to_owned(),
            message: format!(
                "Workspace analysis retained {max_definitions} of {total} definitions."
            ),
            file: None,
        });
    }
    let references = finalize_references(pending, &definitions, max_references, &mut gaps);
    provenance.sort_by_key(|entry| format!("{}\0{}", entry.authored.key(), entry.generated.key()));
    ensure_incomplete_coverage(&mut gaps);
    let mut check_groups: BTreeSet<String> = facts.check_groups.into_iter().collect();
    for product in products {
        check_groups.insert(format!("product:{product}"));
    }
    Ok(Analysis {
        api_version: API_VERSION,
        snapshot,
        files: files.into_iter().map(|file| file.output).collect(),
        definitions,
        references,
        declared_mappings: mappings,
        provenance,
        check_groups: check_groups.into_iter().collect(),
        coverage: coverage(gaps, false),
    })
}

fn decode_files(inputs: Vec<FileInput>) -> Result<Vec<DecodedFile>, WorkspaceAnalysisError> {
    if inputs.len() > MAX_FILES {
        return Err(WorkspaceAnalysisError::new(
            "request-limit",
            format!("workspace analysis accepts at most {MAX_FILES} files"),
        ));
    }
    let mut paths = HashSet::new();
    let mut total = 0usize;
    let mut files = Vec::with_capacity(inputs.len());
    for input in inputs {
        validate_path(&input.path)?;
        validate_name("file state", &input.state)?;
        if !paths.insert(input.path.clone()) {
            return Err(WorkspaceAnalysisError::new(
                "duplicate-file",
                format!("workspace analysis received {} more than once", input.path),
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&input.bytes_base64)
            .map_err(|error| WorkspaceAnalysisError::new("invalid-input", error.to_string()))?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(WorkspaceAnalysisError::new(
                "request-limit",
                format!(
                    "{} exceeds the {MAX_FILE_BYTES}-byte file limit",
                    input.path
                ),
            ));
        }
        total = total.checked_add(bytes.len()).ok_or_else(|| {
            WorkspaceAnalysisError::new("request-limit", "file byte total overflowed")
        })?;
        if total > MAX_TOTAL_FILE_BYTES {
            return Err(WorkspaceAnalysisError::new(
                "request-limit",
                format!("workspace files exceed {MAX_TOTAL_FILE_BYTES} decoded bytes"),
            ));
        }
        validate_sha256(&input.sha256)?;
        let observed = sha256(&bytes);
        if observed != input.sha256 {
            return Err(WorkspaceAnalysisError::new(
                "content-hash-mismatch",
                format!("{} bytes do not match the supplied SHA-256", input.path),
            ));
        }
        files.push(DecodedFile {
            output: FileOutput {
                path: input.path,
                content_hash: observed,
                state: input.state,
            },
            bytes,
        });
    }
    files.sort_by(|left, right| left.output.path.cmp(&right.output.path));
    Ok(files)
}

fn add_native_breg_facts(
    files: &[DecodedFile],
    native_parts: &[String],
    breg_targets: &BTreeMap<String, String>,
    definitions: &mut Vec<Definition>,
    pending: &mut Vec<PendingReference>,
    gaps: &mut Vec<CoverageGap>,
) -> Result<(), WorkspaceAnalysisError> {
    let by_path: HashMap<&str, &DecodedFile> = files
        .iter()
        .map(|file| (file.output.path.as_str(), file))
        .collect();
    let mut declared = HashSet::new();
    let mut parsed = BTreeMap::new();
    let mut authored_by_virtual = BTreeMap::new();
    let root = PathBuf::from("/__registry_workspace_analysis__/registry");
    for native in native_parts {
        validate_path(native)?;
        if !declared.insert(native.as_str()) {
            return Err(WorkspaceAnalysisError::new(
                "invalid-input",
                format!("native part {native} is declared more than once"),
            ));
        }
        let file = by_path.get(native.as_str()).ok_or_else(|| {
            WorkspaceAnalysisError::new(
                "file-out-of-scope",
                format!("native part {native} is not in the authorized file snapshot"),
            )
        })?;
        let Some(target) = breg_targets.get(native) else {
            gaps.push(native_provider_gap(
                native,
                "No BReg generated-path mapping identifies this native part's product contract.",
            ));
            continue;
        };
        let Some(relative) = target.strip_prefix("registry/") else {
            gaps.push(native_provider_gap(
                native,
                "The BReg native mapping does not target the registry product root.",
            ));
            continue;
        };
        if !matches!(
            Path::new(relative)
                .extension()
                .and_then(|value| value.to_str()),
            Some("yaml" | "yml" | "json")
        ) {
            gaps.push(native_provider_gap(
                native,
                "The bounded BReg provider indexes declarative YAML and JSON, not opaque native code.",
            ));
            continue;
        }
        let Ok(source) = std::str::from_utf8(&file.bytes) else {
            gaps.push(CoverageGap {
                code: "source-unreadable".to_owned(),
                message: "The bounded BReg provider requires UTF-8 for declarative YAML and JSON native parts; the exact binary bytes remain hash-bound but opaque.".to_owned(),
                file: Some(native.clone()),
            });
            continue;
        };
        let virtual_path = root.join(relative);
        match crate::yaml::parse_yaml(source) {
            Ok(document) => {
                authored_by_virtual.insert(virtual_path.clone(), native.clone());
                parsed.insert(virtual_path, document);
            }
            Err(_) => gaps.push(CoverageGap {
                code: "source-unreadable".to_owned(),
                message: "The bounded BReg provider could not parse this declarative native part."
                    .to_owned(),
                file: Some(native.clone()),
            }),
        }
    }
    if parsed.is_empty() {
        return Ok(());
    }
    let indexed = crate::products::build_index(&root, crate::products::ProductKind::Breg, &parsed);
    let mut existing: HashSet<String> = definitions
        .iter()
        .map(|definition| definition.identity.key())
        .collect();
    for symbol in indexed.symbols {
        let Some(identity) = breg_identity(symbol.kind, &symbol.name) else {
            continue;
        };
        if existing.contains(&identity.key()) {
            continue;
        }
        let Some(authored) = authored_by_virtual.get(&symbol.location.path) else {
            continue;
        };
        definitions.push(Definition {
            identity: identity.clone(),
            kind: DefinitionKind::Document,
            location: Location {
                file: authored.clone(),
                pointer: String::new(),
            },
            owner: Some(Identity::authored(authored.clone())),
        });
        existing.insert(identity.key());
    }
    for reference in indexed.references {
        let Some(target) = breg_identity(reference.target.kind, &reference.target.name) else {
            continue;
        };
        let Some(authored) = authored_by_virtual.get(&reference.location.path) else {
            continue;
        };
        let label = reference.target.kind.label();
        pending.push(PendingReference {
            kind: format!("native-{}", slug(label)),
            source: Identity::authored(authored.clone()),
            target,
            location: Location {
                file: authored.clone(),
                pointer: String::new(),
            },
            provider: "native-breg",
        });
    }
    for authored in authored_by_virtual.values() {
        gaps.push(CoverageGap {
            code: "reference-family-unavailable".to_owned(),
            message: "The native BReg provider resolved supported object relationships, but its walker ranges cannot yet be represented as exact JSON pointers; native reference locations identify the whole file.".to_owned(),
            file: Some(authored.clone()),
        });
    }
    Ok(())
}

fn breg_identity(kind: SymbolKind, name: &str) -> Option<Identity> {
    let SymbolKind::Product(crate::products::ProductKind::Breg, label) = kind else {
        return None;
    };
    let scope = match label {
        "BReg record type" => "records",
        "BReg action" => "actions",
        "BReg access profile" => "roles",
        _ => return None,
    };
    Some(Identity::Object {
        scope: scope.to_owned(),
        name: name.to_owned(),
    })
}

fn native_provider_gap(path: &str, message: &str) -> CoverageGap {
    CoverageGap {
        code: "native-provider-unavailable".to_owned(),
        message: message.to_owned(),
        file: Some(path.to_owned()),
    }
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn snapshot(binding: &str, revision: &str, files: &[DecodedFile]) -> Snapshot {
    let mut manifest = Vec::new();
    for file in files {
        manifest.extend_from_slice(file.output.path.as_bytes());
        manifest.push(0);
        manifest.extend_from_slice(file.output.state.as_bytes());
        manifest.push(0);
        manifest.extend_from_slice(file.output.content_hash.as_bytes());
        manifest.push(b'\n');
    }
    Snapshot {
        workspace_binding: binding.to_owned(),
        revision: revision.to_owned(),
        content_hash: sha256(&manifest),
    }
}

#[derive(Debug)]
struct PendingReference {
    kind: String,
    source: Identity,
    target: Identity,
    location: Location,
    provider: &'static str,
}

fn finalize_references(
    pending: Vec<PendingReference>,
    definitions: &[Definition],
    max_references: usize,
    gaps: &mut Vec<CoverageGap>,
) -> Vec<Reference> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for definition in definitions {
        *counts.entry(definition.identity.key()).or_default() += 1;
    }
    let mut by_id = BTreeMap::new();
    for item in pending {
        let target_key = item.target.key();
        let resolution = match counts.get(&target_key).copied().unwrap_or(0) {
            0 => "unresolved",
            1 => "resolved",
            _ => "ambiguous",
        };
        let id = format!(
            "{}:{}:{}#{}->{}",
            item.kind,
            item.source.key(),
            item.location.file,
            item.location.pointer,
            target_key
        );
        by_id.entry(id.clone()).or_insert(Reference {
            id,
            kind: item.kind,
            source: item.source,
            target: item.target,
            location: item.location,
            resolution,
            provider: item.provider,
        });
    }
    for reference in by_id.values() {
        if reference.resolution == "unresolved" {
            gaps.push(CoverageGap {
                code: "unresolved-reference".to_owned(),
                message: format!(
                    "{} does not resolve {} at this revision.",
                    reference.kind,
                    reference.target.key()
                ),
                file: Some(reference.location.file.clone()),
            });
        } else if reference.resolution == "ambiguous" {
            gaps.push(CoverageGap {
                code: "ambiguous-reference".to_owned(),
                message: format!(
                    "{} has more than one typed target for {} at this revision.",
                    reference.kind,
                    reference.target.key()
                ),
                file: Some(reference.location.file.clone()),
            });
        }
    }
    let total = by_id.len();
    let references = by_id.into_values().take(max_references).collect();
    if total > max_references {
        gaps.push(CoverageGap {
            code: "result-limit".to_owned(),
            message: format!("Workspace analysis retained {max_references} of {total} references."),
            file: None,
        });
    }
    references
}

fn find_references(
    analysis: &Analysis,
    target: Identity,
    max_results: usize,
) -> Result<Value, WorkspaceAnalysisError> {
    let max_results = bounded_limit(
        "maxResults",
        Some(max_results),
        1_000,
        DEFAULT_MAX_REFERENCES,
        false,
    )?;
    let key = target.key();
    let exists = analysis
        .definitions
        .iter()
        .any(|definition| definition.identity.key() == key);
    let mut all: Vec<(&str, &Reference)> = analysis
        .references
        .iter()
        .filter_map(|reference| {
            if reference.target.key() == key {
                Some(("incoming", reference))
            } else if reference.source.key() == key {
                Some(("outgoing", reference))
            } else {
                None
            }
        })
        .collect();
    all.sort_by(|left, right| left.1.id.cmp(&right.1.id));
    let truncated = all.len() > max_results;
    all.truncate(max_results);
    let incoming: Vec<&Reference> = all
        .iter()
        .filter_map(|(direction, reference)| (*direction == "incoming").then_some(*reference))
        .collect();
    let outgoing: Vec<&Reference> = all
        .iter()
        .filter_map(|(direction, reference)| (*direction == "outgoing").then_some(*reference))
        .collect();
    let mut gaps = analysis.coverage.gaps.clone();
    if !exists {
        gaps.push(CoverageGap {
            code: "target-unavailable".to_owned(),
            message: format!("Analysis has no definition for {key}."),
            file: None,
        });
    }
    if truncated {
        gaps.push(CoverageGap {
            code: "result-limit".to_owned(),
            message: format!("Reference query retained {max_results} results."),
            file: None,
        });
    }
    Ok(json!({
        "target": target,
        "targetExists": exists,
        "incoming": incoming,
        "outgoing": outgoing,
        "truncated": truncated,
        "coverage": coverage(gaps, !exists),
    }))
}

fn find_definitions(
    analysis: &Analysis,
    target: &Identity,
    max_results: usize,
) -> Result<Value, WorkspaceAnalysisError> {
    let max_results = bounded_limit(
        "maxResults",
        Some(max_results),
        1_000,
        DEFAULT_MAX_DEFINITIONS,
        false,
    )?;
    let key = target.key();
    let mut matches: Vec<&Definition> = analysis
        .definitions
        .iter()
        .filter(|definition| definition.identity.key() == key)
        .collect();
    let truncated = matches.len() > max_results;
    matches.truncate(max_results);
    let mut gaps = analysis.coverage.gaps.clone();
    if matches.is_empty() {
        gaps.push(CoverageGap {
            code: "target-unavailable".to_owned(),
            message: format!("Analysis has no definition for {key}."),
            file: None,
        });
    }
    if truncated {
        gaps.push(CoverageGap {
            code: "result-limit".to_owned(),
            message: format!("Definition query retained {max_results} results."),
            file: None,
        });
    }
    Ok(json!({
        "target": target,
        "targetExists": !matches.is_empty(),
        "definitions": matches,
        "truncated": truncated,
        "coverage": coverage(gaps, matches.is_empty()),
    }))
}

#[derive(Debug, Clone, Serialize)]
struct Affected {
    identity: Identity,
    reason: &'static str,
    changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<Location>,
}

#[derive(Debug, Clone, Serialize)]
struct ImpactPath {
    from: Identity,
    to: Identity,
    references: Vec<String>,
}

fn analyze_impact(
    after: &Analysis,
    before: Option<&Analysis>,
    targets: &[Identity],
    limits: &Limits,
) -> Result<Value, WorkspaceAnalysisError> {
    if let Some(before) = before {
        if before.snapshot.workspace_binding != after.snapshot.workspace_binding {
            return Err(WorkspaceAnalysisError::new(
                "workspace-binding-mismatch",
                "impact analysis cannot combine different workspace bindings",
            ));
        }
        if before.snapshot.revision == after.snapshot.revision
            && before.snapshot.content_hash != after.snapshot.content_hash
        {
            return Err(WorkspaceAnalysisError::new(
                "mixed-revision",
                "the same workspace revision names different source bytes",
            ));
        }
    }
    let max_depth = bounded_limit(
        "maxDepth",
        limits.max_depth,
        DEFAULT_MAX_DEPTH,
        DEFAULT_MAX_DEPTH,
        true,
    )?;
    let max_results = bounded_limit(
        "maxResults",
        limits.max_results,
        DEFAULT_MAX_RESULTS,
        DEFAULT_MAX_RESULTS,
        false,
    )?;
    let max_paths = bounded_limit(
        "maxPaths",
        limits.max_paths,
        DEFAULT_MAX_PATHS,
        DEFAULT_MAX_PATHS,
        false,
    )?;
    let mut gaps = before
        .map(|analysis| analysis.coverage.gaps.clone())
        .unwrap_or_default();
    gaps.extend(after.coverage.gaps.clone());
    let before_files: BTreeMap<&str, &str> = before
        .unwrap_or(after)
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.content_hash.as_str()))
        .collect();
    let after_files: BTreeMap<&str, &str> = after
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.content_hash.as_str()))
        .collect();
    let changed_files: Vec<String> = if before.is_some() {
        before_files
            .keys()
            .chain(after_files.keys())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|path| before_files.get(path) != after_files.get(path))
            .map(str::to_owned)
            .collect()
    } else {
        Vec::new()
    };
    let before_refs: BTreeMap<&str, &Reference> = before
        .map(|analysis| {
            analysis
                .references
                .iter()
                .map(|reference| (reference.id.as_str(), reference))
                .collect()
        })
        .unwrap_or_default();
    let after_refs: BTreeMap<&str, &Reference> = after
        .references
        .iter()
        .map(|reference| (reference.id.as_str(), reference))
        .collect();
    let added: Vec<&Reference> = if before.is_some() {
        after_refs
            .iter()
            .filter_map(|(id, reference)| (!before_refs.contains_key(id)).then_some(*reference))
            .collect()
    } else {
        Vec::new()
    };
    let removed: Vec<&Reference> = if before.is_some() {
        before_refs
            .iter()
            .filter_map(|(id, reference)| (!after_refs.contains_key(id)).then_some(*reference))
            .collect()
    } else {
        Vec::new()
    };
    let mut definitions = BTreeMap::new();
    for definition in before
        .into_iter()
        .flat_map(|analysis| analysis.definitions.iter())
        .chain(after.definitions.iter())
    {
        definitions.insert(definition.identity.key(), definition);
    }
    for target in targets {
        if !definitions.contains_key(&target.key()) {
            gaps.push(CoverageGap {
                code: "target-unavailable".to_owned(),
                message: format!("Impact analysis has no definition for {}.", target.key()),
                file: None,
            });
        }
    }
    let changed_file_set: HashSet<&str> = changed_files.iter().map(String::as_str).collect();
    let mut changed_keys = BTreeSet::new();
    if let Some(before) = before {
        for path in &changed_files {
            changed_keys.insert(Identity::authored(path.clone()).key());
        }
        let before_defs: BTreeMap<String, &Definition> = before
            .definitions
            .iter()
            .map(|definition| (definition.identity.key(), definition))
            .collect();
        let after_defs: BTreeMap<String, &Definition> = after
            .definitions
            .iter()
            .map(|definition| (definition.identity.key(), definition))
            .collect();
        for key in before_defs
            .keys()
            .chain(after_defs.keys())
            .cloned()
            .collect::<BTreeSet<_>>()
        {
            match (before_defs.get(&key), after_defs.get(&key)) {
                (Some(left), Some(right))
                    if left.location.file == right.location.file
                        && !changed_file_set.contains(left.location.file.as_str()) => {}
                _ => {
                    changed_keys.insert(key);
                }
            }
        }
    }
    let mut seeds: BTreeMap<String, (Identity, &'static str)> = BTreeMap::new();
    for target in targets {
        add_seed(&mut seeds, target.clone(), "target");
    }
    for key in &changed_keys {
        if let Some(definition) = definitions.get(key) {
            add_seed(&mut seeds, definition.identity.clone(), "changed");
        }
    }
    for reference in added.iter().chain(removed.iter()) {
        add_seed(&mut seeds, reference.source.clone(), "reference-change");
        add_seed(&mut seeds, reference.target.clone(), "reference-change");
    }
    let mut consumers: BTreeMap<String, Vec<&Reference>> = BTreeMap::new();
    let mut edge_ids = HashSet::new();
    for reference in before
        .into_iter()
        .flat_map(|analysis| analysis.references.iter())
        .chain(after.references.iter())
    {
        let edge = format!(
            "{}\0{}\0{}",
            reference.target.key(),
            reference.source.key(),
            reference.id
        );
        if edge_ids.insert(edge) {
            consumers
                .entry(reference.target.key())
                .or_default()
                .push(reference);
        }
    }
    for values in consumers.values_mut() {
        values.sort_by(|left, right| left.id.cmp(&right.id));
    }
    let mut affected: BTreeMap<String, Affected> = BTreeMap::new();
    let mut paths = Vec::new();
    let mut truncated = false;
    for (seed_key, (seed, seed_reason)) in seeds {
        if affected.len() >= max_results && !affected.contains_key(&seed_key) {
            truncated = true;
            continue;
        }
        let mut queue = VecDeque::from([(seed.clone(), 0usize, Vec::<String>::new())]);
        let mut visited = HashSet::new();
        while let Some((current, depth, reference_path)) = queue.pop_front() {
            let current_key = current.key();
            if !visited.insert(current_key.clone()) {
                continue;
            }
            if affected.len() >= max_results && !affected.contains_key(&current_key) {
                truncated = true;
                continue;
            }
            let reason = if depth == 0 { seed_reason } else { "dependent" };
            let replace = affected
                .get(&current_key)
                .is_none_or(|existing| reason_priority(reason) > reason_priority(existing.reason));
            if replace {
                affected.insert(
                    current_key.clone(),
                    Affected {
                        identity: current.clone(),
                        reason,
                        changed: changed_keys.contains(&current_key),
                        location: definitions
                            .get(&current_key)
                            .map(|definition| definition.location.clone()),
                    },
                );
            }
            if depth > 0 {
                if paths.len() < max_paths {
                    paths.push(ImpactPath {
                        from: seed.clone(),
                        to: current.clone(),
                        references: reference_path.clone(),
                    });
                } else {
                    truncated = true;
                }
            }
            let next = consumers
                .get(&current_key)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if depth >= max_depth {
                if !next.is_empty() {
                    truncated = true;
                }
                continue;
            }
            for edge in next {
                if affected.len() >= max_results && !affected.contains_key(&edge.source.key()) {
                    truncated = true;
                    continue;
                }
                let mut next_path = reference_path.clone();
                next_path.push(edge.id.clone());
                queue.push_back((edge.source.clone(), depth + 1, next_path));
            }
        }
    }
    if truncated {
        gaps.push(CoverageGap {
            code: "traversal-limit".to_owned(),
            message: "Impact traversal reached its depth, result or path limit.".to_owned(),
            file: None,
        });
    }
    let affected_values: Vec<Affected> = affected.into_values().collect();
    let affected_keys: HashSet<String> = affected_values
        .iter()
        .map(|item| item.identity.key())
        .collect();
    let mut affected_files: BTreeSet<String> = changed_files.iter().cloned().collect();
    for item in &affected_values {
        if let Some(location) = &item.location {
            affected_files.insert(location.file.clone());
        }
        match &item.identity {
            Identity::AuthoredFile { path } | Identity::GeneratedFile { path } => {
                affected_files.insert(path.clone());
            }
            Identity::Object { .. } => {}
        }
    }
    let mut products = BTreeSet::new();
    for analysis in before.into_iter().chain(std::iter::once(after)) {
        for provenance in &analysis.provenance {
            if affected_keys.contains(&provenance.authored.key())
                || affected_keys.contains(&provenance.generated.key())
            {
                products.insert(provenance.product.clone());
            }
        }
        for mapping in &analysis.declared_mappings {
            if affected_keys.contains(&mapping.owner.key())
                || affected_keys.contains(&mapping.authored.key())
                || affected_keys.contains(&mapping.generated.key())
            {
                products.insert(mapping.product.clone());
            }
        }
    }
    let check_groups: BTreeSet<&str> = before
        .into_iter()
        .flat_map(|analysis| analysis.check_groups.iter())
        .chain(after.check_groups.iter())
        .map(String::as_str)
        .collect();
    Ok(json!({
        "after": after.snapshot,
        "before": before.map(|analysis| &analysis.snapshot),
        "targets": targets,
        "affected": affected_values,
        "affectedFiles": affected_files,
        "products": products,
        "checkGroups": check_groups,
        "paths": paths,
        "changes": {
            "files": changed_files,
            "addedReferences": added,
            "removedReferences": removed,
        },
        "truncated": truncated,
        "coverage": coverage(gaps, false),
    }))
}

fn add_seed(
    seeds: &mut BTreeMap<String, (Identity, &'static str)>,
    identity: Identity,
    reason: &'static str,
) {
    let key = identity.key();
    match seeds.get(&key) {
        Some((_, earlier)) if reason_priority(earlier) >= reason_priority(reason) => {}
        _ => {
            seeds.insert(key, (identity, reason));
        }
    }
}

fn reason_priority(reason: &str) -> u8 {
    match reason {
        "target" => 4,
        "changed" => 3,
        "reference-change" => 2,
        _ => 1,
    }
}

fn coverage(mut gaps: Vec<CoverageGap>, unavailable: bool) -> Coverage {
    gaps.sort();
    gaps.dedup();
    Coverage {
        status: if unavailable {
            "unavailable"
        } else if gaps.is_empty() {
            "complete"
        } else {
            "partial"
        },
        gaps,
    }
}

fn ensure_incomplete_coverage(gaps: &mut Vec<CoverageGap>) {
    if !gaps
        .iter()
        .any(|gap| gap.code == "reference-family-unavailable")
    {
        gaps.push(CoverageGap {
            code: "reference-family-unavailable".to_owned(),
            message: "The normalized provider facts do not establish references inside opaque code or unregistered source families.".to_owned(),
            file: None,
        });
    }
}

fn validate_identity(identity: &Identity) -> Result<(), WorkspaceAnalysisError> {
    match identity {
        Identity::Object { scope, name } => {
            validate_name("scope", scope)?;
            validate_name("name", name)
        }
        Identity::AuthoredFile { path } | Identity::GeneratedFile { path } => validate_path(path),
    }
}

fn require_identity_kind(
    identity: &Identity,
    expected: &str,
) -> Result<(), WorkspaceAnalysisError> {
    validate_identity(identity)?;
    let matches = matches!(
        (expected, identity),
        ("authored-file", Identity::AuthoredFile { .. })
            | ("generated-file", Identity::GeneratedFile { .. })
    );
    if !matches {
        return Err(WorkspaceAnalysisError::new(
            "invalid-input",
            format!("mapping {expected} must use kind {expected}"),
        ));
    }
    Ok(())
}

fn validate_authorized_identity(
    identity: &Identity,
    authorized: &HashSet<&str>,
) -> Result<(), WorkspaceAnalysisError> {
    validate_identity(identity)?;
    if let Identity::AuthoredFile { path } = identity {
        if !authorized.contains(path.as_str()) {
            return Err(WorkspaceAnalysisError::new(
                "file-out-of-scope",
                format!("authored identity {path} is not in the authorized file snapshot"),
            ));
        }
    } else if let Identity::GeneratedFile { path } = identity {
        validate_generated_path(path)?;
    }
    Ok(())
}

fn parse_scoped_identity(value: &str) -> Result<Identity, WorkspaceAnalysisError> {
    let (scope, name) = value.split_once(':').ok_or_else(|| {
        WorkspaceAnalysisError::new(
            "invalid-input",
            format!("generation item {value:?} is not a scoped identity"),
        )
    })?;
    validate_name("scope", scope)?;
    validate_name("name", name)?;
    Ok(Identity::Object {
        scope: scope.to_owned(),
        name: name.to_owned(),
    })
}

fn validate_location(
    file: &str,
    pointer: &str,
    authorized: &HashSet<&str>,
) -> Result<(), WorkspaceAnalysisError> {
    validate_path(file)?;
    if !authorized.contains(file) {
        return Err(WorkspaceAnalysisError::new(
            "file-out-of-scope",
            format!("fact location {file} is not in the authorized file snapshot"),
        ));
    }
    if !pointer.is_empty() && !pointer.starts_with('/') {
        return Err(WorkspaceAnalysisError::new(
            "invalid-input",
            format!("location pointer {pointer:?} is not a JSON pointer"),
        ));
    }
    if pointer.len() > 4_096 || pointer.chars().any(char::is_control) {
        return Err(WorkspaceAnalysisError::new(
            "invalid-input",
            "location pointer is too long or contains control characters",
        ));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), WorkspaceAnalysisError> {
    let safe = !path.is_empty()
        && path.len() <= 4_096
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
    if !safe {
        return Err(WorkspaceAnalysisError::new(
            "invalid-path",
            format!("workspace path {path:?} is not a normalized relative path"),
        ));
    }
    Ok(())
}

fn validate_generated_path(path: &str) -> Result<(), WorkspaceAnalysisError> {
    validate_path(path)?;
    let mut segments = path.split('/');
    if segments.next() == Some("workspace")
        || path.split('/').any(|segment| segment.starts_with('.'))
    {
        return Err(WorkspaceAnalysisError::new(
            "invalid-path",
            format!("generated path {path:?} is outside the bounded generated namespace"),
        ));
    }
    Ok(())
}

fn validate_name(label: &str, value: &str) -> Result<(), WorkspaceAnalysisError> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(WorkspaceAnalysisError::new(
            "invalid-input",
            format!("{label} must be a non-empty bounded string without control characters"),
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), WorkspaceAnalysisError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(WorkspaceAnalysisError::new(
            "invalid-input",
            "sha256 must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn bounded_limit(
    name: &str,
    requested: Option<usize>,
    default: usize,
    maximum: usize,
    allow_zero: bool,
) -> Result<usize, WorkspaceAnalysisError> {
    let value = requested.unwrap_or(default);
    if (!allow_zero && value == 0) || value > maximum {
        return Err(WorkspaceAnalysisError::new(
            "invalid-limit",
            format!(
                "{name} must be {} and at most {maximum}",
                if allow_zero {
                    "non-negative"
                } else {
                    "positive"
                }
            ),
        ));
    }
    Ok(value)
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
