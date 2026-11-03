//! Recording final offline Adapter facts into an authored fixture.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::{ArgAction, Args};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::{build, evidence_binary, fixtures, source_import::ProjectLock, OutputFormat};

const FACT_RECORD_API_VERSION: &str =
    "id.registrystack.org/internal/evidence/fixture-fact-record/v1alpha1";
const FACT_RECORD_KIND: &str = "EvidenceFixtureFactRecord";
const MAX_PRIVATE_RECORD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PRIVATE_ERROR_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixtureRecordRefusal {
    FixtureNotSynthetic,
    FixtureNotCoequal,
    FixturePathNotPlain,
    FixturePathOutsideProject,
    FixtureExpectationRefused,
    ProjectValidationRefused,
    RecordRunRefused,
    CandidateEvaluationRefused,
    FixturePatchUnavailable,
    ConcurrentEdit,
}

impl FixtureRecordRefusal {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::FixtureNotSynthetic => "evidence.fixtures-record-facts.fixture-not-synthetic",
            Self::FixtureNotCoequal => "evidence.fixtures-record-facts.fixture-not-coequal",
            Self::FixturePathNotPlain => "evidence.fixtures-record-facts.fixture-path-not-plain",
            Self::FixturePathOutsideProject => {
                "evidence.fixtures-record-facts.fixture-path-outside-project"
            }
            Self::FixtureExpectationRefused => {
                "evidence.fixtures-record-facts.fixture-expectation-refused"
            }
            Self::ProjectValidationRefused => {
                "evidence.fixtures-record-facts.project-validation-refused"
            }
            Self::RecordRunRefused => "evidence.fixtures-record-facts.record-run-refused",
            Self::CandidateEvaluationRefused => {
                "evidence.fixtures-record-facts.candidate-evaluation-refused"
            }
            Self::FixturePatchUnavailable => {
                "evidence.fixtures-record-facts.fixture-patch-unavailable"
            }
            Self::ConcurrentEdit => "evidence.fixtures-record-facts.concurrent-edit",
        }
    }

    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::FixtureNotSynthetic => {
                "Fact recording is limited to fixtures declared synthetic."
            }
            Self::FixtureNotCoequal => {
                "Fact recording is limited to coequal acceptance fixtures."
            }
            Self::FixturePathNotPlain => {
                "The selected fixture path is not a plain local project path."
            }
            Self::FixturePathOutsideProject => {
                "The selected fixture resolves outside the editable project."
            }
            Self::FixtureExpectationRefused => {
                "The selected fixture or private record does not satisfy the fact-recording expectation contract."
            }
            Self::ProjectValidationRefused => {
                "The compiled project or target was refused before fixture fact recording."
            }
            Self::RecordRunRefused => {
                "The matching Evidence runtime refused the private fixture fact recording stage."
            }
            Self::CandidateEvaluationRefused => {
                "The patched candidate did not pass ordinary fixture evaluation."
            }
            Self::FixturePatchUnavailable => {
                "The fixture facts could not be edited without risking another authored member."
            }
            Self::ConcurrentEdit => {
                "The authored fixture changed before the fact record could be published."
            }
        }
    }

    pub(crate) fn suggested_action(self) -> &'static str {
        match self {
            Self::FixtureNotSynthetic => {
                "Use a reviewed synthetic fixture with syntheticOnly: true, then rerun fixtures record-facts."
            }
            Self::FixtureNotCoequal => {
                "Use a coequal fixture with coequalAcceptanceDefinition: true, then rerun fixtures record-facts."
            }
            Self::FixturePathNotPlain | Self::FixturePathOutsideProject => {
                "Select a plain project-relative fixture with no symlink path components, then rerun fixtures record-facts."
            }
            Self::FixtureExpectationRefused => {
                "Run the ordinary fixture test with --explain, correct the fixture expectation, and rerun fixtures record-facts."
            }
            Self::ProjectValidationRefused => {
                "Run evidencectl check for the same project and target, correct its findings, and rerun fixtures record-facts."
            }
            Self::RecordRunRefused => {
                "Run the ordinary fixture test with --explain, correct the pack or fixture behavior, and rerun fixtures record-facts."
            }
            Self::CandidateEvaluationRefused => {
                "Run the ordinary fixture test with --explain, correct the non-fact expectation or pack behavior, and rerun fixtures record-facts."
            }
            Self::FixturePatchUnavailable => {
                "Keep expectedFacts as a mapping member in its case, correct malformed fixture source, and rerun fixtures record-facts."
            }
            Self::ConcurrentEdit => {
                "Review the concurrent fixture edit, keep the intended authored changes, and rerun fixtures record-facts."
            }
        }
    }
}

impl std::fmt::Display for FixtureRecordRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for FixtureRecordRefusal {}

#[derive(Clone, Copy, Debug)]
enum PrivateFixtureOperation {
    ProjectValidation,
    RecordFacts,
    CandidateEvaluation,
}

impl PrivateFixtureOperation {
    fn label(self) -> &'static str {
        match self {
            Self::ProjectValidation => "the private bundle check",
            Self::RecordFacts => "the private fixture fact recording run",
            Self::CandidateEvaluation => "the ordinary candidate fixture evaluation",
        }
    }

    fn refusal(self) -> FixtureRecordRefusal {
        match self {
            Self::ProjectValidation => FixtureRecordRefusal::ProjectValidationRefused,
            Self::RecordFacts => FixtureRecordRefusal::RecordRunRefused,
            Self::CandidateEvaluation => FixtureRecordRefusal::CandidateEvaluationRefused,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct RecordFactsArgs {
    /// Editable Evidence project directory; defaults to the current directory.
    #[arg(value_name = "PROJECT", default_value = ".")]
    pub(crate) project: PathBuf,

    /// Complete deployment target used for the offline fixture compilation.
    #[arg(long, value_name = "TARGET")]
    pub(crate) target: PathBuf,

    /// Exact project-relative fixture path referenced by one definition.
    #[arg(long, value_name = "FIXTURE")]
    pub(crate) fixture: String,

    /// Apply the fact record to the maintained authored fixture.
    #[arg(long, action = ArgAction::SetTrue, required = true)]
    write: bool,

    /// Path to the evidence binary; defaults to `evidence` on PATH.
    #[arg(long)]
    evidence_bin: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureFactRecord {
    api_version: String,
    kind: String,
    evaluated_cases: usize,
    matched_facts: BTreeMap<String, Map<String, Value>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordReport<'a> {
    proof_boundary: &'static str,
    fixture: &'a str,
    evaluated_cases: usize,
    matched_cases: usize,
    changed: bool,
}

pub(crate) fn run(args: RecordFactsArgs, format: OutputFormat) -> Result<ExitCode> {
    if !args.write {
        bail!("--write is required to record fixture facts");
    }
    if args.project.join("runtime.yaml").exists() {
        return Err(FixtureRecordRefusal::FixtureExpectationRefused.into());
    }
    if !args
        .project
        .join(registry_evidence_authoring::project::PROJECT_FILE)
        .is_file()
    {
        return Err(FixtureRecordRefusal::FixtureExpectationRefused.into());
    }

    let evidence_bin = evidence_binary::resolve_matching(args.evidence_bin.as_deref())?;
    let _lock = ProjectLock::acquire(&args.project)
        .with_context(|| format!("locking editable project {}", args.project.display()))?;
    let fixture_paths = fixtures::project_fixture_paths(&args.project)?;
    let selected = fixtures::select_fixture_paths(&fixture_paths, Some(&args.fixture))?;
    let fixture = *selected
        .first()
        .ok_or(FixtureRecordRefusal::FixtureExpectationRefused)?;
    if Path::new(fixture)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(FixtureRecordRefusal::FixturePathNotPlain.into());
    }
    require_plain_fixture_path(&args.project, Path::new(fixture))?;
    let fixture_path = args.project.join(fixture);
    let project_root = fs::canonicalize(&args.project).context("resolving editable project")?;
    let resolved_fixture =
        fs::canonicalize(&fixture_path).context("resolving selected authored fixture")?;
    if !resolved_fixture.starts_with(&project_root) {
        return Err(FixtureRecordRefusal::FixturePathOutsideProject.into());
    }
    let original = crate::authored::read_authored_file(&fixture_path, "Evidence fixture")?;
    require_recordable_fixture(&original)?;

    let compilation =
        build::compile_target_fixture_project(&args.project, &args.target, &evidence_bin)
            .context("compiling normalized project with complete target authority")?;
    run_private_evidence(
        &evidence_bin,
        &[
            "bundle-check".into(),
            "--bundle".into(),
            compilation.bundle_path.as_os_str().to_owned(),
            "--runtime-config".into(),
            compilation.runtime_path.as_os_str().to_owned(),
            "--json".into(),
        ],
        PrivateFixtureOperation::ProjectValidation,
    )?;

    let command = vec![
        "bundle-record-fixture-facts".into(),
        "--bundle".into(),
        compilation.bundle_path.as_os_str().to_owned(),
        "--fixture".into(),
        std::ffi::OsString::from(fixture),
        "--authority-document".into(),
        compilation
            .bundle_path
            .parent()
            .context("compiled bundle has no parent")?
            .join("compiled-authority.yaml")
            .into_os_string(),
    ];
    let private_record = run_private_evidence(
        &evidence_bin,
        &command,
        PrivateFixtureOperation::RecordFacts,
    )?;
    let record: FixtureFactRecord = serde_json::from_slice(&private_record)
        .map_err(|_| FixtureRecordRefusal::RecordRunRefused)?;
    if record.api_version != FACT_RECORD_API_VERSION || record.kind != FACT_RECORD_KIND {
        return Err(FixtureRecordRefusal::RecordRunRefused.into());
    }

    let candidate = patch_fixture(&original, &record)
        .map_err(|_| FixtureRecordRefusal::FixturePatchUnavailable)?;
    require_recordable_fixture(&candidate)?;
    require_only_expected_facts_changed(&original, &candidate)
        .map_err(|_| FixtureRecordRefusal::FixtureExpectationRefused)?;
    let evaluated_cases = record.evaluated_cases;
    let matched_cases = record.matched_facts.len();
    drop(record);
    drop(private_record);

    stage_candidate_fixture(&compilation.bundle_path, Path::new(fixture), &candidate)?;
    let ordinary_output = run_private_evidence(
        &evidence_bin,
        &[
            "bundle-evaluate".into(),
            "--bundle".into(),
            compilation.bundle_path.as_os_str().to_owned(),
            "--fixture".into(),
            std::ffi::OsString::from(fixture),
            "--authority-document".into(),
            compilation
                .bundle_path
                .parent()
                .context("compiled bundle has no parent")?
                .join("compiled-authority.yaml")
                .into_os_string(),
        ],
        PrivateFixtureOperation::CandidateEvaluation,
    )?;
    drop(ordinary_output);

    let changed = candidate != original;
    if changed {
        publish_if_unchanged(&fixture_path, &original, &candidate)?;
    }

    let report = RecordReport {
        proof_boundary: "final offline Adapter pack matches; no provider or derived value was interpreted by evidencectl",
        fixture,
        evaluated_cases,
        matched_cases,
        changed,
    };
    match format {
        OutputFormat::Human => println!(
            "Recorded facts for {} matched case(s) in {} ({} case(s) evaluated, {}).",
            report.matched_cases,
            report.fixture,
            report.evaluated_cases,
            if changed {
                "fixture updated"
            } else {
                "no change"
            }
        ),
        OutputFormat::Json => {
            let members = serde_json::to_value(report).context("encoding fact record report")?;
            crate::print_report(&crate::report::success(
                "fixtures record-facts",
                if changed { "written" } else { "unchanged" },
                members,
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn require_plain_fixture_path(project: &Path, relative: &Path) -> Result<()> {
    let components = relative.components().collect::<Vec<_>>();
    let mut path = project.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            return Err(FixtureRecordRefusal::FixturePathNotPlain.into());
        };
        path.push(component);
        let metadata =
            fs::symlink_metadata(&path).context("inspecting selected authored fixture path")?;
        if metadata.file_type().is_symlink()
            || (index + 1 == components.len() && !metadata.is_file())
            || (index + 1 < components.len() && !metadata.is_dir())
        {
            return Err(FixtureRecordRefusal::FixturePathNotPlain.into());
        }
    }
    Ok(())
}

fn run_private_evidence(
    evidence_bin: &Path,
    arguments: &[std::ffi::OsString],
    operation: PrivateFixtureOperation,
) -> Result<Vec<u8>> {
    let what = operation.label();
    let mut stdout = tempfile::tempfile().context("creating a private Evidence output capture")?;
    let stderr = tempfile::tempfile().context("creating a private Evidence error capture")?;
    let mut child = Command::new(evidence_bin)
        .args(arguments)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .spawn()
        .with_context(|| format!("starting {what}"))?;
    let status = evidence_binary::wait_bounded(
        &mut child,
        what,
        evidence_binary::DELEGATED_RUN_DEADLINE,
        &|| Ok(()),
        &|| {
            evidence_binary::capture_over_limit(&stdout, MAX_PRIVATE_RECORD_BYTES)
                || evidence_binary::capture_over_limit(&stderr, MAX_PRIVATE_ERROR_BYTES)
        },
    )?;
    if !status.success() {
        return Err(operation.refusal().into());
    }
    evidence_binary::drain_capture(&mut stdout, MAX_PRIVATE_RECORD_BYTES, what)
}

fn require_recordable_fixture(bytes: &[u8]) -> Result<()> {
    let document = registry_platform_yaml::Reader::new("fixture").read(
        bytes,
        &registry_platform_yaml::Expect::one(&fixtures::FIXTURE_FORMAT),
    )?;
    let value = document.to_json_value();
    if value.get("syntheticOnly") != Some(&Value::Bool(true)) {
        return Err(FixtureRecordRefusal::FixtureNotSynthetic.into());
    }
    if value.get("coequalAcceptanceDefinition") != Some(&Value::Bool(true)) {
        return Err(FixtureRecordRefusal::FixtureNotCoequal.into());
    }
    Ok(())
}

fn require_only_expected_facts_changed(original: &[u8], candidate: &[u8]) -> Result<()> {
    fn without_expected_facts(bytes: &[u8]) -> Result<Value> {
        let document = registry_platform_yaml::Reader::new("fixture").read(
            bytes,
            &registry_platform_yaml::Expect::one(&fixtures::FIXTURE_FORMAT),
        )?;
        let mut value = document.to_json_value();
        let cases = value
            .get_mut("cases")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("fixture cases are unavailable"))?;
        for case in cases {
            case.as_object_mut()
                .ok_or_else(|| anyhow!("fixture case is not an object"))?
                .remove("expectedFacts");
        }
        Ok(value)
    }

    if without_expected_facts(original)? != without_expected_facts(candidate)? {
        bail!("fixture fact recording changed a member outside expectedFacts");
    }
    Ok(())
}

fn stage_candidate_fixture(bundle: &Path, relative: &Path, candidate: &[u8]) -> Result<()> {
    let path = bundle.join(relative);
    replace_sealed_private_file(&path, candidate, ".fixture-facts-candidate-")?;

    let sum_path = bundle.join(registry_platform_config::SUM_FILE);
    let sums = fs::read_to_string(&sum_path).context("reading private compilation checksums")?;
    if !sums.ends_with('\n') {
        bail!("private compilation checksums are malformed");
    }
    let relative = relative
        .to_str()
        .context("compiled fixture path is not UTF-8")?;
    let digest = hex::encode(Sha256::digest(candidate));
    let mut updated = String::with_capacity(sums.len());
    let mut replaced = false;
    for line in sums.lines() {
        let Some((_, entry)) = line.split_once("  ") else {
            bail!("private compilation checksums are malformed");
        };
        if entry == relative {
            if replaced {
                bail!("private compilation names the candidate fixture more than once");
            }
            updated.push_str(&digest);
            updated.push_str("  ");
            updated.push_str(relative);
            updated.push('\n');
            replaced = true;
        } else {
            updated.push_str(line);
            updated.push('\n');
        }
    }
    if !replaced {
        bail!("private compilation checksums do not name the candidate fixture");
    }
    replace_sealed_private_file(&sum_path, updated.as_bytes(), ".fixture-facts-sums-")
}

fn replace_sealed_private_file(path: &Path, contents: &[u8], prefix: &str) -> Result<()> {
    let parent = path
        .parent()
        .context("private compilation file has no parent directory")?;
    let directory_permissions = fs::metadata(parent)?.permissions();
    let fixture_permissions = fs::metadata(path)?.permissions();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .context("opening private compilation for candidate validation")?;
    let staged_result: Result<()> = (|| {
        let mut staged = tempfile::Builder::new()
            .prefix(prefix)
            .tempfile_in(parent)
            .context("staging candidate fixture for ordinary evaluation")?;
        staged.write_all(contents)?;
        staged.as_file_mut().sync_all()?;
        staged.as_file_mut().set_permissions(fixture_permissions)?;
        staged
            .persist(path)
            .map_err(|error| error.error)
            .context("installing candidate fixture in private compilation")?;
        Ok(())
    })();
    let restore_result = fs::set_permissions(parent, directory_permissions)
        .context("resealing private compilation after candidate staging");
    staged_result?;
    restore_result
}

fn patch_fixture(original: &[u8], record: &FixtureFactRecord) -> Result<Vec<u8>> {
    let original = std::str::from_utf8(original).context("fixture is not UTF-8")?;
    let document = registry_platform_yaml::Reader::new("fixture").read(
        original.as_bytes(),
        &registry_platform_yaml::Expect::one(&fixtures::FIXTURE_FORMAT),
    )?;
    let value = document.to_json_value();
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("fixture cases are unavailable"))?;
    let mut case_ids = BTreeSet::new();
    for case in cases {
        let id = case
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("fixture case identifier is invalid"))?;
        case_ids.insert(id.to_owned());
    }
    if record.evaluated_cases != case_ids.len() {
        bail!("the Evidence fact record did not evaluate every fixture case");
    }
    if record
        .matched_facts
        .keys()
        .any(|case| !case_ids.contains(case))
    {
        bail!("the Evidence fact record names an unknown fixture case");
    }

    let mut edits = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"]
            .as_str()
            .ok_or_else(|| anyhow!("fixture case identifier is invalid"))?;
        let pointer = format!("/cases/{index}/expectedFacts");
        let existing = case.get("expectedFacts");
        let replacement = record.matched_facts.get(id);
        let replacement_value = replacement.map(|facts| Value::Object(facts.clone()));
        if existing == replacement_value.as_ref() {
            continue;
        }
        match (
            document.key_span_of(&pointer),
            document.span_of(&pointer),
            replacement,
        ) {
            (Some(key), Some(value), Some(facts)) => {
                let indent = key.start.column.saturating_sub(1);
                if key.start.line == value.start.line {
                    edits.push((
                        byte_offset(original, key.start)?,
                        byte_offset(original, value.end)?,
                        render_member(facts, indent, false)?,
                    ));
                } else {
                    let start = line_start(original, byte_offset(original, key.start)?);
                    let end = block_member_end(
                        original,
                        &document,
                        case,
                        index,
                        cases.len(),
                        start,
                        indent,
                    )?;
                    edits.push((
                        start,
                        end,
                        render_block_replacement(original, end, facts, indent)?,
                    ));
                }
            }
            (Some(key), Some(value), None) => {
                let key_start = byte_offset(original, key.start)?;
                if key.start.line == value.start.line {
                    edits.push((key_start, byte_offset(original, value.end)?, String::new()));
                } else {
                    let start = line_start(original, key_start);
                    let end = block_member_end(
                        original,
                        &document,
                        case,
                        index,
                        cases.len(),
                        start,
                        key.start.column.saturating_sub(1),
                    )?;
                    edits.push((
                        block_removal_start(original, start, end),
                        end,
                        String::new(),
                    ));
                }
            }
            (None, None, Some(facts)) => {
                let anchor = [
                    "expectedLookup",
                    "expectedValues",
                    "expectedValue",
                    "derivationRuns",
                    "signedSuccess",
                    "source",
                ]
                .into_iter()
                .find_map(|member| document.key_span_of(&format!("/cases/{index}/{member}")))
                .ok_or_else(|| anyhow!("fixture case has no stable fact-record insertion point"))?;
                let key_start = byte_offset(original, anchor.start)?;
                let start = line_start(original, key_start);
                let indent = anchor.start.column.saturating_sub(1);
                edits.push((start, start, render_member(facts, indent, true)?));
            }
            (None, None, None) => {}
            _ => bail!("fixture expectedFacts source span is invalid"),
        }
    }
    edits.sort_by_key(|(start, _, _)| std::cmp::Reverse(*start));
    let mut patched = original.to_owned();
    for (start, end, replacement) in edits {
        patched.replace_range(start..end, &replacement);
    }
    Ok(patched.into_bytes())
}

fn render_member(
    facts: &Map<String, Value>,
    indent: usize,
    include_indent: bool,
) -> Result<String> {
    let facts = crate::authored::to_indented_yaml(facts)?;
    let prefix = " ".repeat(indent);
    let child = " ".repeat(indent.saturating_add(2));
    let mut rendered = String::new();
    if include_indent {
        rendered.push_str(&prefix);
    }
    if facts.trim() == "{}" {
        rendered.push_str("expectedFacts: {}");
    } else {
        rendered.push_str("expectedFacts:\n");
        for (index, line) in facts.trim_end().lines().enumerate() {
            if index > 0 {
                rendered.push('\n');
            }
            rendered.push_str(&child);
            rendered.push_str(line);
        }
    }
    if include_indent {
        rendered.push('\n');
    }
    Ok(rendered)
}

fn render_block_replacement(
    original: &str,
    end: usize,
    facts: &Map<String, Value>,
    indent: usize,
) -> Result<String> {
    let mut rendered = render_member(facts, indent, true)?;
    if end == original.len() && !original.ends_with('\n') {
        rendered.pop();
    }
    Ok(rendered)
}

fn block_removal_start(original: &str, start: usize, end: usize) -> usize {
    if end != original.len() || original.ends_with('\n') {
        return start;
    }
    if original[..start].ends_with("\r\n") {
        start.saturating_sub(2)
    } else if original[..start].ends_with('\n') {
        start.saturating_sub(1)
    } else {
        start
    }
}

fn byte_offset(text: &str, position: registry_platform_yaml::Position) -> Result<usize> {
    let line_start = if position.line == 1 {
        0
    } else {
        text.match_indices('\n')
            .nth(position.line - 2)
            .map(|(offset, _)| offset + 1)
            .context("fixture source span line is outside the document")?
    };
    let line = &text[line_start..];
    let column = position.column.saturating_sub(1);
    let byte_in_line = if column == 0 {
        0
    } else {
        line.char_indices().nth(column).map_or_else(
            || line.find('\n').unwrap_or(line.len()),
            |(offset, _)| offset,
        )
    };
    Ok(line_start + byte_in_line)
}

fn line_start(text: &str, offset: usize) -> usize {
    text[..offset].rfind('\n').map_or(0, |newline| newline + 1)
}

fn block_member_end(
    text: &str,
    document: &registry_platform_yaml::Document,
    case: &Value,
    index: usize,
    case_count: usize,
    start: usize,
    key_indent: usize,
) -> Result<usize> {
    let next_member = case
        .as_object()
        .ok_or_else(|| anyhow!("fixture case is not an object"))?
        .keys()
        .filter(|member| member.as_str() != "expectedFacts")
        .filter_map(|member| {
            document
                .key_span_of(&format!("/cases/{index}/{member}"))
                .and_then(|span| byte_offset(text, span.start).ok())
                .map(|offset| line_start(text, offset))
        })
        .filter(|offset| *offset > start)
        .min();
    let case_end = if index + 1 < case_count {
        let next_case = document
            .key_span_of(&format!("/cases/{}/id", index + 1))
            .ok_or_else(|| anyhow!("next fixture case identifier has no source span"))?;
        line_start(text, byte_offset(text, next_case.start)?)
    } else {
        text.len()
    };
    let next = next_member.unwrap_or(case_end);
    if next <= start {
        bail!("fixture expectedFacts has no safe case or document boundary");
    }
    Ok(trailing_boundary_start(text, start, next, key_indent))
}

fn trailing_boundary_start(text: &str, start: usize, end: usize, key_indent: usize) -> usize {
    let mut boundary = end;
    let mut offset = start;
    let mut lines = Vec::new();
    for line in text[start..end].split_inclusive('\n') {
        lines.push((offset, line));
        offset += line.len();
    }
    for (line_start, line) in lines.into_iter().rev() {
        let body = line.trim_end_matches(['\r', '\n']);
        if body.trim().is_empty() {
            boundary = line_start;
            continue;
        }
        let content = body.trim_start_matches(' ');
        let indent = body.len() - content.len();
        if indent <= key_indent && content.starts_with('#') {
            boundary = line_start;
            continue;
        }
        break;
    }
    boundary
}

fn publish_if_unchanged(path: &Path, original: &[u8], candidate: &[u8]) -> Result<()> {
    let parent = path.parent().context("fixture has no parent directory")?;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    let mut staged = tempfile::Builder::new()
        .prefix(".fixture-facts-")
        .tempfile_in(parent)
        .context("creating staged fixture fact record")?;
    staged
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    staged.write_all(candidate)?;
    staged.as_file_mut().sync_all()?;
    let current = crate::authored::read_authored_file(path, "Evidence fixture")?;
    if current != original {
        return Err(FixtureRecordRefusal::ConcurrentEdit.into());
    }
    staged
        .persist(path)
        .map_err(|error| error.error)
        .context("atomically replacing authored fixture")?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "tests create and inspect isolated fixture files and executable stubs"
)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{symlink, PermissionsExt as _},
        path::Path,
    };

    use serde_json::{json, Map, Value};
    use sha2::Digest as _;

    use super::{
        patch_fixture, publish_if_unchanged, require_only_expected_facts_changed,
        require_plain_fixture_path, require_recordable_fixture, run_private_evidence,
        stage_candidate_fixture, FixtureFactRecord, PrivateFixtureOperation, Sha256,
    };

    const FIXTURE: &str = r#"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1
kind: EvidenceFixture
coequalAcceptanceDefinition: true
syntheticOnly: true
cases:
- id: matched
  display: "หลักฐาน"
  expectedValues:
    urn:example:false-output: false
  expectedFacts: {old: FLOW-FACT-CANARY-a44f} # flow fact comment
  expectedLookup: match
  source:
    responseCanary: RAW-RESPONSE-CANARY-931a
- id: absent
  expectedFacts:
    stale: STALE-FACT-CANARY-63f2
  # block fact trailing comment
  expectedLookup: no_match
  source:
    responseCanary: UNMATCHED-RESPONSE-CANARY-29ad
- id: block-matched
  expectedFacts:
    old: BLOCK-FACT-CANARY-538b
  # block replacement trailing comment
  expectedLookup: match
  source:
    responseCanary: BLOCK-RESPONSE-CANARY-20ba
- id: inserted
  expectedLookup: match
  source:
    responseCanary: INSERTED-RESPONSE-CANARY-d371
"#;

    fn facts(value: Value) -> Map<String, Value> {
        value.as_object().expect("fact object").clone()
    }

    fn record() -> FixtureFactRecord {
        FixtureFactRecord {
            api_version: "id.registrystack.org/internal/evidence/fixture-fact-record/v1alpha1"
                .to_owned(),
            kind: "EvidenceFixtureFactRecord".to_owned(),
            evaluated_cases: 4,
            matched_facts: BTreeMap::from([
                (
                    "matched".to_owned(),
                    facts(json!({
                        "active": false,
                        "structured": {"items": [1, null, "kept"]},
                    })),
                ),
                (
                    "block-matched".to_owned(),
                    facts(json!({"actual-block": [false, null]})),
                ),
                (
                    "inserted".to_owned(),
                    facts(json!({"actual": "pack-match"})),
                ),
            ]),
        }
    }

    fn record_for(case_count: usize, matches: &[(&str, Value)]) -> FixtureFactRecord {
        FixtureFactRecord {
            api_version: "id.registrystack.org/internal/evidence/fixture-fact-record/v1alpha1"
                .to_owned(),
            kind: "EvidenceFixtureFactRecord".to_owned(),
            evaluated_cases: case_count,
            matched_facts: matches
                .iter()
                .map(|(id, value)| ((*id).to_owned(), facts(value.clone())))
                .collect(),
        }
    }

    fn safe_fixture_failure(error: anyhow::Error) -> (String, String, String) {
        const PRIVATE_CANARY: &str = "PRIVATE-FIXTURE-REFUSAL-CANARY-7d3b";
        let error = crate::safe_command(
            Err::<std::process::ExitCode, _>(error.context(PRIVATE_CANARY)),
            "evidence.fixtures-record-facts.failed",
            "fixtures/case.yaml".to_owned(),
            "Evidence could not record the selected fixture facts.",
            "Correct the editable project, target, or fixture and rerun fixtures record-facts.",
        )
        .expect_err("fixture recording is refused");
        let failure = error
            .downcast_ref::<crate::SafeCliFailure>()
            .expect("safe fixture failure");
        let human = crate::safe_failure_human(failure);
        let json = crate::safe_failure_json(failure, "fixtures record-facts").to_string();
        assert!(!human.contains(PRIVATE_CANARY), "{human}");
        assert!(!json.contains(PRIVATE_CANARY), "{json}");
        (failure.code.clone(), failure.suggested_action.clone(), json)
    }

    #[test]
    fn patch_inserts_exact_match_facts_removes_nonmatch_facts_and_preserves_other_text() {
        let patched = patch_fixture(FIXTURE.as_bytes(), &record()).expect("patch fixture");
        if let Err(error) = require_only_expected_facts_changed(FIXTURE.as_bytes(), &patched) {
            panic!(
                "only expectedFacts changed: {error:#}\n{}",
                String::from_utf8_lossy(&patched)
            );
        }
        let patched = String::from_utf8(patched).expect("UTF-8 fixture");

        assert!(
            patched.contains("expectedFacts:\n    active: false"),
            "{patched}"
        );
        assert!(
            patched.contains("items:\n        - 1\n        - null\n        - kept"),
            "{patched}"
        );
        assert!(!patched.contains("STALE-FACT-CANARY-63f2"), "{patched}");
        assert!(!patched.contains("FLOW-FACT-CANARY-a44f"), "{patched}");
        assert!(!patched.contains("BLOCK-FACT-CANARY-538b"), "{patched}");
        for unchanged in [
            "หลักฐาน",
            "# flow fact comment",
            "# block fact trailing comment",
            "# block replacement trailing comment",
            "urn:example:false-output: false",
            "RAW-RESPONSE-CANARY-931a",
            "UNMATCHED-RESPONSE-CANARY-29ad",
            "BLOCK-RESPONSE-CANARY-20ba",
            "INSERTED-RESPONSE-CANARY-d371",
        ] {
            assert!(
                patched.contains(unchanged),
                "missing {unchanged}: {patched}"
            );
        }
    }

    #[test]
    fn patch_is_idempotent() {
        let once = patch_fixture(FIXTURE.as_bytes(), &record()).expect("patch fixture");
        let twice = patch_fixture(&once, &record()).expect("patch again");
        assert_eq!(twice, once);
    }

    #[test]
    fn fixture_record_patch_replaces_and_removes_block_facts_last_before_the_next_case() {
        const SOURCE: &str = r#"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1
kind: EvidenceFixture
coequalAcceptanceDefinition: true
syntheticOnly: true
cases:
- id: replace
  display: "หลักฐาน retained"
  expectedLookup: match
  expectedFacts:
    stale: REPLACE-BLOCK-CANARY-c68a
  # replacement boundary comment retained
- id: remove
  display: retained-remove
  expectedLookup: no_match
  expectedFacts:
    stale: REMOVE-BLOCK-CANARY-aa91
  # removal boundary comment retained
- id: unchanged
  expectedLookup: no_match
"#;
        let patched = patch_fixture(
            SOURCE.as_bytes(),
            &record_for(
                3,
                &[("replace", json!({"actual": [false, null, "pack-match"]}))],
            ),
        )
        .expect("last block members can be patched before the next case");
        require_only_expected_facts_changed(SOURCE.as_bytes(), &patched)
            .expect("only expectedFacts changed");
        let patched = String::from_utf8(patched).expect("UTF-8 fixture");
        assert!(patched.contains("actual:\n      - false\n      - null\n      - pack-match"));
        assert!(!patched.contains("REPLACE-BLOCK-CANARY-c68a"));
        assert!(!patched.contains("REMOVE-BLOCK-CANARY-aa91"));
        for retained in [
            "หลักฐาน retained",
            "# replacement boundary comment retained",
            "# removal boundary comment retained",
            "- id: unchanged",
        ] {
            assert!(patched.contains(retained), "missing {retained}: {patched}");
        }
    }

    #[test]
    fn fixture_record_patch_handles_a_final_block_member_at_eof_without_a_newline() {
        const SOURCE: &str = "apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1\nkind: EvidenceFixture\ncoequalAcceptanceDefinition: true\nsyntheticOnly: true\ncases:\n- id: final\n  display: retained-final\n  expectedLookup: match\n  expectedFacts:\n    stale: FINAL-BLOCK-CANARY-f51d\n  # final comment retained";
        const BARE_EOF_SOURCE: &str = "apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1\nkind: EvidenceFixture\ncoequalAcceptanceDefinition: true\nsyntheticOnly: true\ncases:\n- id: final\n  display: retained-bare-final\n  expectedLookup: match\n  expectedFacts:\n    stale: BARE-FINAL-BLOCK-CANARY-e13c";

        let replacement = patch_fixture(
            SOURCE.as_bytes(),
            &record_for(1, &[("final", json!({"actual": false}))]),
        )
        .expect("final block member can be replaced");
        require_only_expected_facts_changed(SOURCE.as_bytes(), &replacement)
            .expect("replacement changes only expectedFacts");
        assert!(!replacement.ends_with(b"\n"));
        let replacement = String::from_utf8(replacement).expect("UTF-8 replacement");
        assert!(replacement.contains("expectedFacts:\n    actual: false"));
        assert!(replacement.ends_with("# final comment retained"));

        let removal = patch_fixture(SOURCE.as_bytes(), &record_for(1, &[]))
            .expect("final block member can be removed");
        require_only_expected_facts_changed(SOURCE.as_bytes(), &removal)
            .expect("removal changes only expectedFacts");
        assert!(!removal.ends_with(b"\n"));
        let removal = String::from_utf8(removal).expect("UTF-8 removal");
        assert!(!removal.contains("FINAL-BLOCK-CANARY-f51d"));
        assert!(removal.contains("display: retained-final"));
        assert!(removal.ends_with("# final comment retained"));

        let bare_replacement = patch_fixture(
            BARE_EOF_SOURCE.as_bytes(),
            &record_for(1, &[("final", json!({"actual": null}))]),
        )
        .expect("bare final block member can be replaced at the document boundary");
        require_only_expected_facts_changed(BARE_EOF_SOURCE.as_bytes(), &bare_replacement)
            .expect("bare replacement changes only expectedFacts");
        assert!(!bare_replacement.ends_with(b"\n"));
        assert!(String::from_utf8(bare_replacement)
            .expect("UTF-8 bare replacement")
            .ends_with("expectedFacts:\n    actual: null"));

        let bare_removal = patch_fixture(BARE_EOF_SOURCE.as_bytes(), &record_for(1, &[]))
            .expect("bare final block member can be removed at the document boundary");
        require_only_expected_facts_changed(BARE_EOF_SOURCE.as_bytes(), &bare_removal)
            .expect("bare removal changes only expectedFacts");
        assert!(!bare_removal.ends_with(b"\n"));
        assert!(String::from_utf8(bare_removal)
            .expect("UTF-8 bare removal")
            .ends_with("expectedLookup: match"));
    }

    #[test]
    fn fixture_record_refusals_have_distinct_closed_value_free_diagnostics() {
        let not_synthetic = FIXTURE.replace("syntheticOnly: true", "syntheticOnly: false");
        let not_coequal = FIXTURE.replace(
            "coequalAcceptanceDefinition: true",
            "coequalAcceptanceDefinition: false",
        );
        let (synthetic_code, synthetic_action, _) = safe_fixture_failure(
            require_recordable_fixture(not_synthetic.as_bytes())
                .expect_err("non-synthetic fixture is refused"),
        );
        let (coequal_code, coequal_action, _) = safe_fixture_failure(
            require_recordable_fixture(not_coequal.as_bytes())
                .expect_err("non-coequal fixture is refused"),
        );

        let directory = tempfile::tempdir().expect("temporary project");
        let real = directory.path().join("real.yaml");
        fs::write(&real, FIXTURE).expect("write fixture");
        symlink(&real, directory.path().join("linked.yaml")).expect("link fixture");
        let (path_code, path_action, _) = safe_fixture_failure(
            require_plain_fixture_path(directory.path(), Path::new("linked.yaml"))
                .expect_err("symlink is refused"),
        );

        let fixture = directory.path().join("concurrent.yaml");
        fs::write(&fixture, b"independent edit\n").expect("write concurrent fixture");
        let (concurrent_code, concurrent_action, _) = safe_fixture_failure(
            publish_if_unchanged(&fixture, b"original\n", b"candidate\n")
                .expect_err("concurrent edit is refused"),
        );
        let (outside_code, outside_action, _) = safe_fixture_failure(anyhow::Error::new(
            super::FixtureRecordRefusal::FixturePathOutsideProject,
        ));
        let (expectation_code, expectation_action, _) = safe_fixture_failure(anyhow::Error::new(
            super::FixtureRecordRefusal::FixtureExpectationRefused,
        ));
        let (patch_code, patch_action, _) = safe_fixture_failure(anyhow::Error::new(
            super::FixtureRecordRefusal::FixturePatchUnavailable,
        ));

        assert_eq!(
            [
                synthetic_code.as_str(),
                coequal_code.as_str(),
                path_code.as_str(),
                outside_code.as_str(),
                expectation_code.as_str(),
                patch_code.as_str(),
                concurrent_code.as_str(),
            ],
            [
                "evidence.fixtures-record-facts.fixture-not-synthetic",
                "evidence.fixtures-record-facts.fixture-not-coequal",
                "evidence.fixtures-record-facts.fixture-path-not-plain",
                "evidence.fixtures-record-facts.fixture-path-outside-project",
                "evidence.fixtures-record-facts.fixture-expectation-refused",
                "evidence.fixtures-record-facts.fixture-patch-unavailable",
                "evidence.fixtures-record-facts.concurrent-edit",
            ]
        );
        assert!(synthetic_action.contains("syntheticOnly: true"));
        assert!(coequal_action.contains("coequalAcceptanceDefinition: true"));
        assert!(path_action.contains("plain project-relative fixture"));
        assert!(outside_action.contains("plain project-relative fixture"));
        assert!(expectation_action.contains("--explain"));
        assert!(patch_action.contains("expectedFacts"));
        assert!(concurrent_action.contains("rerun fixtures record-facts"));
    }

    #[test]
    fn patch_refuses_a_record_for_an_unknown_case() {
        let mut outside = record();
        outside
            .matched_facts
            .insert("unknown".to_owned(), facts(json!({"unexpected": true})));
        let error = patch_fixture(FIXTURE.as_bytes(), &outside)
            .expect_err("matched record names an unknown case");
        assert_eq!(
            error.to_string(),
            "the Evidence fact record names an unknown fixture case"
        );
    }

    #[test]
    fn private_fact_capture_never_relays_child_values() {
        const CANARY: &str = "PRIVATE-FACT-OUTPUT-CANARY-888c";
        let directory = tempfile::tempdir().expect("temporary directory");
        let binary = directory.path().join("evidence");
        fs::write(
            &binary,
            format!("#!/bin/sh\nprintf '{CANARY}\\n'\nprintf '{CANARY}\\n' >&2\nexit 1\n"),
        )
        .expect("write stub");
        let mut permissions = fs::metadata(&binary).expect("stub metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&binary, permissions).expect("make stub executable");

        for (operation, code, action) in [
            (
                PrivateFixtureOperation::RecordFacts,
                "evidence.fixtures-record-facts.record-run-refused",
                "ordinary fixture test",
            ),
            (
                PrivateFixtureOperation::CandidateEvaluation,
                "evidence.fixtures-record-facts.candidate-evaluation-refused",
                "--explain",
            ),
        ] {
            let error = run_private_evidence(&binary, &[], operation).expect_err("stub refuses");
            let rendered = format!("{error:#}");
            assert!(!rendered.contains(CANARY), "{rendered}");
            let (actual_code, actual_action, json) = safe_fixture_failure(error);
            assert_eq!(actual_code, code);
            assert!(actual_action.contains(action), "{actual_action}");
            assert!(!json.contains(CANARY), "{json}");
        }
    }

    #[test]
    fn publication_refuses_a_concurrent_fixture_edit_without_overwriting_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let fixture = directory.path().join("fixture.yaml");
        fs::write(&fixture, b"original\n").expect("write original");
        fs::write(&fixture, b"independent edit\n").expect("write concurrent edit");

        let error = publish_if_unchanged(&fixture, b"original\n", b"candidate\n")
            .expect_err("concurrent edit is refused");
        assert_eq!(
            error.downcast_ref::<super::FixtureRecordRefusal>(),
            Some(&super::FixtureRecordRefusal::ConcurrentEdit)
        );
        assert_eq!(
            fs::read(&fixture).expect("read retained edit"),
            b"independent edit\n"
        );
    }

    #[test]
    fn fixture_path_refuses_symlink_ancestors_and_leaves() {
        let project = tempfile::tempdir().expect("temporary project");
        let real = project.path().join("fixtures-real");
        fs::create_dir(&real).expect("create fixture directory");
        fs::write(real.join("case.yaml"), FIXTURE).expect("write fixture");

        symlink(&real, project.path().join("fixtures-link")).expect("link fixture directory");
        let ancestor_error =
            require_plain_fixture_path(project.path(), Path::new("fixtures-link/case.yaml"))
                .expect_err("symlink ancestor is refused");
        assert_eq!(
            ancestor_error.downcast_ref::<super::FixtureRecordRefusal>(),
            Some(&super::FixtureRecordRefusal::FixturePathNotPlain)
        );

        fs::create_dir(project.path().join("fixtures")).expect("create plain fixture directory");
        symlink(
            real.join("case.yaml"),
            project.path().join("fixtures/case.yaml"),
        )
        .expect("link fixture file");
        let leaf_error =
            require_plain_fixture_path(project.path(), Path::new("fixtures/case.yaml"))
                .expect_err("symlink leaf is refused");
        assert_eq!(
            leaf_error.downcast_ref::<super::FixtureRecordRefusal>(),
            Some(&super::FixtureRecordRefusal::FixturePathNotPlain)
        );
    }

    #[test]
    fn candidate_staging_reseals_the_private_compilation() {
        let compilation = tempfile::tempdir().expect("temporary compilation");
        let bundle = compilation.path().join("bundle");
        fs::create_dir(&bundle).expect("create bundle");
        let fixtures = bundle.join("fixtures");
        fs::create_dir(&fixtures).expect("create fixture directory");
        let fixture = fixtures.join("case.yaml");
        fs::write(&fixture, b"original\n").expect("write fixture");
        let sum_file = bundle.join(registry_platform_config::SUM_FILE);
        fs::write(
            &sum_file,
            format!(
                "{}  fixtures/case.yaml\n",
                hex::encode(Sha256::digest(b"original\n"))
            ),
        )
        .expect("write checksums");
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o400)).expect("seal fixture");
        fs::set_permissions(&sum_file, fs::Permissions::from_mode(0o400)).expect("seal checksums");
        fs::set_permissions(&fixtures, fs::Permissions::from_mode(0o500))
            .expect("seal fixture directory");
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o500)).expect("seal bundle");

        stage_candidate_fixture(&bundle, Path::new("fixtures/case.yaml"), b"candidate\n")
            .expect("stage candidate fixture");

        assert_eq!(fs::read(&fixture).expect("read candidate"), b"candidate\n");
        assert_eq!(
            fs::read_to_string(&sum_file).expect("read checksums"),
            format!(
                "{}  fixtures/case.yaml\n",
                hex::encode(Sha256::digest(b"candidate\n"))
            )
        );
        assert_eq!(
            fs::metadata(&fixture)
                .expect("fixture metadata")
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        assert_eq!(
            fs::metadata(&fixtures)
                .expect("fixture directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
        assert_eq!(
            fs::metadata(&bundle)
                .expect("bundle metadata")
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
    }
}
