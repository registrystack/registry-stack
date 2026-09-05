//! Closed request preparation for local adopter tutorials.
//!
//! The Evidence runtime supplies trusted local relying-procedure metadata and
//! exact pinned subject bindings without making an authorization decision. The
//! relying-party client owns the request, nonce, and retained verification
//! context. Mint separately supplies the bearer used by the tutorial's curl.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    sync::Arc,
};

use anyhow::{anyhow, bail, Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use registry_evidence_client::{
    AssuranceProfile, AudienceScopedRequest, EvidenceClient, EvidenceClientConfig,
    EvidenceRequestSpec, EvidenceResponseFormat, ExpectedOutputDocument, ExpectedSubjectDocument,
    JwksDocument, SelectorValue, StaticToken, SubjectExpectations, SubjectRequest,
};
use registry_platform_crypto::canonicalize_json;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    access,
    dev::{self, ReadyDevState},
};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
// The selected profile applies its exact per-field and aggregate limits. Keep
// this parser at the published contract envelope so it cannot reject a value
// that the profile legitimately permits.
const MAX_SELECTOR_VALUE_BYTES: usize = 8 * 1024;
const MAX_SUBJECTS_FILE_BYTES: u64 = 16 * 1024;
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: u64 = 256 * 1024;
const LOCAL_PROCEDURE_INPUT_SCHEMA_V1: &str = "registry.evidence.local-relying-procedure-input/v1";
const LOCAL_PROCEDURE_SCHEMA_V1: &str = "registry.evidence.local-relying-procedure/v1";

#[derive(Debug, Subcommand)]
pub enum RequestCommand {
    /// Prepare the request, authorization header, and verification context.
    Prepare(PrepareArgs),
    /// Deprecated alias for `evidencectl verify`.
    ///
    /// `evidencectl verify` is the one verification command, and it takes the
    /// same arguments. This spelling keeps working so a script that already
    /// calls it is not broken by the rename.
    Verify(crate::verify::VerifyArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("subject_input")
        .args(["subject", "subjects_file"])
), group(
    ArgGroup::new("request_source")
        .required(true)
        .args(["question", "profile"])
))]
pub struct PrepareArgs {
    /// Question defined by the active local project.
    question: Option<String>,

    /// Owner-only progressive client profile.
    #[arg(long)]
    profile: Option<PathBuf>,

    /// Stable public requirement handle from the selected contract catalog.
    #[arg(long, requires = "profile")]
    requirement: Option<String>,

    /// Exact purpose declared by the question.
    #[arg(long, requires = "question")]
    purpose: Option<String>,

    /// Subject selector. Repeat role:field=value for multiple roles. JSON booleans and integers keep their types.
    #[arg(long)]
    subject: Vec<String>,

    /// Owner-only JSON file containing typed role, field, and value entries.
    #[arg(long, value_name = "PATH")]
    subjects_file: Option<PathBuf>,

    /// Safe name for this retained request.
    #[arg(long)]
    name: String,

    /// Registered local application used to request authorization.
    #[arg(long)]
    client: Option<String>,

    /// Response format to request and verify.
    #[arg(long, value_enum, default_value_t = PreparedResponseFormat::SignedJws)]
    format: PreparedResponseFormat,

    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,

    #[arg(long, hide = true)]
    evidence_bin: Option<PathBuf>,

    #[arg(long, hide = true)]
    mint_bin: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PreparedResponseFormat {
    SignedJws,
    SdJwtVc,
}

impl From<PreparedResponseFormat> for EvidenceResponseFormat {
    fn from(format: PreparedResponseFormat) -> Self {
        match format {
            PreparedResponseFormat::SignedJws => Self::SignedJws,
            PreparedResponseFormat::SdJwtVc => Self::SdJwtVc,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalProcedureInput<'a> {
    schema: &'static str,
    response_format: PreparedResponseFormat,
    requirement: &'a str,
    purpose: &'a str,
    audience: &'a str,
    subjects: Vec<LocalProcedureSubject<'a>>,
}

#[derive(Serialize)]
struct LocalProcedureSubject<'a> {
    role: &'a str,
    selector: LocalProcedureSelector<'a>,
}

#[derive(Serialize)]
struct LocalProcedureSelector<'a> {
    profile: &'a str,
    values: BTreeMap<&'a str, &'a str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectInputFile {
    subjects: Vec<SubjectInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgressiveSubjectInputFile {
    subjects: Vec<ProgressiveSubjectInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgressiveSubjectInput {
    role: String,
    field: String,
    value: ProgressiveSelectorValue,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ProgressiveSelectorValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl From<ProgressiveSelectorValue> for SelectorValue {
    fn from(value: ProgressiveSelectorValue) -> Self {
        match value {
            ProgressiveSelectorValue::String(value) => Self::String(value),
            ProgressiveSelectorValue::Integer(value) => Self::Integer(value),
            ProgressiveSelectorValue::Boolean(value) => Self::Boolean(value),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectInput {
    role: String,
    field: String,
    value: String,
}

struct ValidatedSubject<'a> {
    definition: &'a dev::ReadySubjectState,
    value: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalRelyingProcedure {
    schema: String,
    response_format: PreparedResponseFormat,
    trusted_jwks: JwksDocument,
    expected_assurance_profile: AssuranceProfile,
    issued_by: String,
    provided_by: String,
    requirement: String,
    evidence_type: String,
    purpose: String,
    audience: String,
    configuration_revision: String,
    expected_subjects: Vec<ExpectedSubjectDocument>,
    expected_outputs: Vec<ExpectedOutputDocument>,
    revoked_key_ids: Vec<String>,
    maximum_assertion_lifetime_seconds: u64,
    clock_skew_seconds: u64,
}

pub fn run(command: RequestCommand) -> Result<ExitCode> {
    match command {
        RequestCommand::Prepare(args) => prepare(args),
        RequestCommand::Verify(args) => crate::verify::run(args),
    }
}

fn prepare(args: PrepareArgs) -> Result<ExitCode> {
    if args.profile.is_some() {
        return prepare_progressive(args);
    }
    prepare_local(args)
}

fn prepare_progressive(args: PrepareArgs) -> Result<ExitCode> {
    validate_request_name(&args.name)?;
    if args.client.is_some() || args.purpose.is_some() {
        bail!("progressive preparation accepts profile, requirement, and subject fields");
    }
    let profile = args
        .profile
        .as_deref()
        .ok_or_else(|| anyhow!("progressive preparation requires a client profile"))?;
    crate::client::validate_owner_only_input(profile)
        .context("progressive request preparation failed")?;
    let requirement = args
        .requirement
        .as_deref()
        .ok_or_else(|| anyhow!("progressive preparation requires a requirement handle"))?;
    let (selectors, subjects) = progressive_subject_inputs(&args)?;
    let client = EvidenceClient::from_profile_path(profile)
        .map_err(|_| anyhow!("progressive request preparation failed"))?;
    let mut request = AudienceScopedRequest::new(requirement, selectors);
    if let Some(subjects) = subjects {
        request = request.with_subjects(subjects);
    }
    let request = request.with_response_format(args.format.into());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("progressive request preparation failed")?;
    let prepared = runtime
        .block_on(client.prepare_progressive(request))
        .map_err(|_| anyhow!("progressive request preparation failed"))?;

    let project =
        fs::canonicalize(&args.project).context("progressive request project is unavailable")?;
    let requests_root = ensure_requests_root(&project)
        .map_err(|_| anyhow!("progressive request preparation failed"))?;
    let destination = requests_root.join(&args.name);
    require_absent(&destination)?;
    let mut staging = StagingDirectory::create(&requests_root)
        .map_err(|_| anyhow!("progressive request preparation failed"))?;
    write_private_bytes(
        &staging.path().join("request.json"),
        prepared.request_json(),
    )
    .map_err(|_| anyhow!("progressive request preparation failed"))?;
    write_private_bytes(
        &staging.path().join("verification.json"),
        prepared.retained_verification(),
    )
    .map_err(|_| anyhow!("progressive request preparation failed"))?;
    let relative_request = Path::new(".evidence/requests")
        .join(&args.name)
        .join("request.json");
    let curl = progressive_curl_config(
        prepared.endpoint(),
        prepared.accept(),
        prepared.authorization(),
        &relative_request,
    )?;
    write_private_bytes(&staging.path().join("curl.config"), curl.as_bytes())
        .map_err(|_| anyhow!("progressive request preparation failed"))?;
    staging
        .publish(&destination)
        .map_err(|_| anyhow!("progressive request preparation failed"))?;

    let relative = Path::new(".evidence/requests").join(&args.name);
    println!(
        "Prepared request: {}",
        relative.join("request.json").display()
    );
    println!(
        "Prepared verification context: {}",
        relative.join("verification.json").display()
    );
    println!(
        "Prepared curl config: {}",
        relative.join("curl.config").display()
    );
    Ok(ExitCode::SUCCESS)
}

type ProgressiveSubjects = BTreeMap<String, BTreeMap<String, SelectorValue>>;

fn progressive_subject_inputs(
    args: &PrepareArgs,
) -> Result<(BTreeMap<String, SelectorValue>, Option<ProgressiveSubjects>)> {
    if let Some(path) = &args.subjects_file {
        let parsed = read_progressive_subject_inputs(path)?;
        let mut subjects = ProgressiveSubjects::new();
        for input in parsed {
            validate_progressive_name(&input.role)?;
            validate_progressive_name(&input.field)?;
            let value = progressive_selector_value(input.value)?;
            if subjects
                .entry(input.role)
                .or_default()
                .insert(input.field, value)
                .is_some()
            {
                bail!("progressive subject role and field pairs must be unique");
            }
        }
        if subjects.is_empty() || subjects.values().any(BTreeMap::is_empty) {
            bail!("progressive subjects file must contain complete role selector fields");
        }
        return Ok((BTreeMap::new(), Some(subjects)));
    }

    let mut selectors = BTreeMap::new();
    let mut subjects = ProgressiveSubjects::new();
    let mut uses_roles = None;
    for input in &args.subject {
        let (binding, value) = input
            .split_once('=')
            .filter(|(_, value)| !value.is_empty() && !value.contains('='))
            .ok_or_else(|| {
                anyhow!("progressive subject must be one field=value or role:field=value pair")
            })?;
        let (role, field) = match binding.split_once(':') {
            Some((role, field)) if !role.contains(':') && !field.contains(':') => {
                (Some(role), field)
            }
            None => (None, binding),
            _ => bail!("progressive subject must be one field=value or role:field=value pair"),
        };
        validate_progressive_name(field)?;
        let value = parse_progressive_selector_value(value)?;
        match (uses_roles, role) {
            (None, Some(role)) | (Some(true), Some(role)) => {
                uses_roles = Some(true);
                validate_progressive_name(role)?;
                if subjects
                    .entry(role.to_owned())
                    .or_default()
                    .insert(field.to_owned(), value)
                    .is_some()
                {
                    bail!("progressive subject role and field pairs must be unique");
                }
            }
            (None, None) | (Some(false), None) => {
                uses_roles = Some(false);
                if selectors.insert(field.to_owned(), value).is_some() {
                    bail!("progressive subject fields must be unique");
                }
            }
            _ => bail!("progressive subject inputs must all include a role or all omit it"),
        }
    }
    if uses_roles == Some(true) {
        Ok((BTreeMap::new(), Some(subjects)))
    } else {
        Ok((selectors, None))
    }
}

fn parse_progressive_selector_value(value: &str) -> Result<SelectorValue> {
    if value.len() > MAX_SELECTOR_VALUE_BYTES || value.chars().any(char::is_control) {
        bail!("progressive selector values must be bounded scalars");
    }
    if value == "true" {
        return Ok(SelectorValue::Boolean(true));
    }
    if value == "false" {
        return Ok(SelectorValue::Boolean(false));
    }
    if let Ok(integer) = value.parse::<i64>() {
        return Ok(SelectorValue::Integer(integer));
    }
    if value.starts_with('"') {
        let parsed: String = serde_json::from_str(value)
            .map_err(|_| anyhow!("progressive selector values must be bounded scalars"))?;
        return progressive_selector_value(ProgressiveSelectorValue::String(parsed));
    }
    progressive_selector_value(ProgressiveSelectorValue::String(value.to_owned()))
}

fn progressive_selector_value(value: ProgressiveSelectorValue) -> Result<SelectorValue> {
    if let ProgressiveSelectorValue::String(value) = &value {
        if value.is_empty()
            || value.len() > MAX_SELECTOR_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            bail!("progressive selector values must be bounded scalars");
        }
    }
    Ok(value.into())
}

fn validate_progressive_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.contains([':', '='])
        || value.chars().any(char::is_control)
    {
        bail!("progressive subject roles and fields must be bounded names");
    }
    Ok(())
}

fn read_progressive_subject_inputs(path: &Path) -> Result<Vec<ProgressiveSubjectInput>> {
    let bytes = read_subject_input_bytes(path)?;
    let parsed: ProgressiveSubjectInputFile = serde_json::from_slice(&bytes).map_err(|_| {
        anyhow!("progressive subjects file must be closed JSON with one subjects array")
    })?;
    if parsed.subjects.is_empty() {
        bail!("progressive subjects file must contain at least one subject");
    }
    Ok(parsed.subjects)
}

fn progressive_curl_config(
    endpoint: &str,
    accept: &str,
    authorization: &str,
    request_path: &Path,
) -> Result<Zeroizing<String>> {
    for value in [endpoint, accept, authorization] {
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\'))
        {
            bail!("progressive request preparation failed");
        }
    }
    let path = request_path
        .to_str()
        .filter(|path| !path.contains(['"', '\\', '\r', '\n']))
        .ok_or_else(|| anyhow!("progressive request preparation failed"))?;
    Ok(Zeroizing::new(format!(
        "url = \"{endpoint}\"\nrequest = \"POST\"\nheader = \"Authorization: {authorization}\"\nheader = \"Content-Type: application/json\"\nheader = \"Accept: {accept}\"\ndata-binary = \"@{path}\"\n"
    )))
}

fn prepare_local(args: PrepareArgs) -> Result<ExitCode> {
    validate_request_name(&args.name)?;
    let ready = dev::load_ready_state(&args.project)?;
    let (question, subjects) = validate_closed_inputs(&ready, &args)?;
    let client = resolve_request_client(&ready, args.client.as_deref())?;
    let evidence = dev::resolve_tool_binary(
        "evidence",
        args.evidence_bin.as_deref(),
        "EVIDENCECTL_TEST_EVIDENCE_BIN",
    )?;
    let mint = dev::resolve_tool_binary(
        "mint",
        args.mint_bin.as_deref(),
        "EVIDENCECTL_TEST_MINT_BIN",
    )?;

    let requests_root = ensure_requests_root(&ready.project)?;
    let destination = requests_root.join(&args.name);
    require_absent(&destination)?;
    let mut staging = StagingDirectory::create(&requests_root)?;

    let procedure_input =
        local_procedure_input(question, &subjects, &client.evidence_audience, args.format);
    let procedure_input_path = staging.path().join("procedure-input.json");
    let procedure_input = canonicalize_json(&serde_json::to_value(procedure_input)?)
        .context("failed to serialize the local relying procedure input")?;
    write_private_bytes(&procedure_input_path, &procedure_input)?;
    let procedure =
        prepare_local_relying_procedure(&evidence, &ready.runtime_path, &procedure_input_path)?;
    fs::remove_file(&procedure_input_path)
        .context("failed to remove the private relying procedure input")?;
    validate_local_relying_procedure(&procedure, question, &client.evidence_audience, args.format)?;

    let token = obtain_token(
        &mint,
        &ready.token_url,
        &client.client_id,
        &client.private_key_path,
        &client.assertion_audience,
    )?;
    let token_provider = Arc::new(
        StaticToken::new(token.as_str().to_owned())
            .context("Registry Mint returned an unusable token")?,
    );
    let evidence_origin =
        url::Url::parse(&ready.evidence_origin).context("the active Evidence origin is invalid")?;
    let client_config = EvidenceClientConfig::new(
        evidence_origin,
        token_provider,
        procedure.trusted_jwks.clone(),
        procedure.revoked_key_ids.clone(),
    );
    let evidence_client =
        EvidenceClient::new(client_config).context("the local Evidence client is invalid")?;
    let spec = evidence_request_spec(procedure, &subjects);
    let prepared = evidence_client
        .prepare(spec)
        .context("Evidence request preparation failed")?;
    let request = prepared
        .request_json()
        .context("Evidence request serialization failed")?;
    let request_path = staging.path().join("request.json");
    write_private_bytes(&request_path, &request)?;

    let context_path = staging.path().join("verification.json");
    let retained = evidence_client.retain_verification(&prepared);
    let mut context = canonicalize_json(&serde_json::to_value(retained)?)
        .context("failed to serialize the retained Evidence verification context")?;
    context.push(b'\n');
    write_private_bytes(&context_path, &context)?;
    let authorization_path = staging.path().join("authorization.curl");
    write_authorization(&authorization_path, &token)?;
    drop(token);

    validate_private_directory(&requests_root)?;
    staging.publish(&destination)?;

    let relative = Path::new(".evidence/requests").join(&args.name);
    println!(
        "Prepared request: {}",
        relative.join("request.json").display()
    );
    println!(
        "Prepared verification context: {}",
        relative.join("verification.json").display()
    );
    println!(
        "Prepared authorization: {}",
        relative.join("authorization.curl").display()
    );
    Ok(ExitCode::SUCCESS)
}

struct RequestClient {
    client_id: String,
    private_key_path: PathBuf,
    assertion_audience: String,
    evidence_audience: String,
}

fn resolve_request_client(ready: &ReadyDevState, client_id: Option<&str>) -> Result<RequestClient> {
    match client_id {
        Some(client_id) => {
            if ready.access_policies.is_empty() {
                bail!("--client requires an active generation with explicit access policies");
            }
            let policy_tags = ready
                .access_policies
                .iter()
                .map(|policy| (policy.id.clone(), policy.requester_tag.clone()))
                .collect::<BTreeMap<_, _>>();
            let client = access::resolve_ready_client(&ready.project, client_id, &policy_tags)?;
            Ok(RequestClient {
                client_id: client.client_id,
                private_key_path: client.private_key_path,
                assertion_audience: ready.token_url.clone(),
                evidence_audience: client.evidence_audience,
            })
        }
        None => {
            let caller = ready.caller.as_ref().ok_or_else(|| {
                anyhow!("the active project requires a registered client selected with --client")
            })?;
            Ok(RequestClient {
                client_id: caller.client_id.clone(),
                private_key_path: caller.private_key_path.clone(),
                assertion_audience: caller.assertion_audience.clone(),
                evidence_audience: caller.evidence_audience.clone(),
            })
        }
    }
}

fn validate_closed_inputs<'a>(
    ready: &'a ReadyDevState,
    args: &PrepareArgs,
) -> Result<(&'a dev::ReadyQuestionState, Vec<ValidatedSubject<'a>>)> {
    let question = ready
        .questions
        .iter()
        .find(|question| args.question.as_deref() == Some(question.alias.as_str()))
        .ok_or_else(|| anyhow!("question does not match the active local project"))?;
    if args.purpose.as_deref() != Some(question.purpose.as_str()) {
        bail!("purpose does not match the active local tutorial question");
    }
    let inputs = load_subject_inputs(args, question)?;
    if inputs.len() != question.subjects.len() {
        bail!("subject inputs must match the question's complete role set");
    }
    let mut values = BTreeMap::new();
    for input in inputs {
        let subject = question
            .subjects
            .iter()
            .find(|subject| subject.role == input.role)
            .ok_or_else(|| anyhow!("subject role does not match the active local question"))?;
        if input.field != subject.selector_field
            || values
                .insert(input.role, Zeroizing::new(input.value))
                .is_some()
        {
            bail!("subject inputs must contain each declared role and selector exactly once");
        }
        let value = values
            .get(subject.role.as_str())
            .expect("the inserted subject value is present");
        if value.is_empty()
            || value.len() > MAX_SELECTOR_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            bail!("subject value must be non-empty, bounded, and contain no control characters");
        }
    }
    let subjects = question
        .subjects
        .iter()
        .map(|subject| {
            values
                .remove(subject.role.as_str())
                .map(|value| ValidatedSubject {
                    definition: subject,
                    value,
                })
                .ok_or_else(|| anyhow!("subject inputs do not cover the complete role set"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((question, subjects))
}

fn load_subject_inputs(
    args: &PrepareArgs,
    question: &dev::ReadyQuestionState,
) -> Result<Vec<SubjectInput>> {
    match (&args.subjects_file, args.subject.is_empty()) {
        (Some(path), true) => read_subject_inputs(path),
        (None, false) => args
            .subject
            .iter()
            .map(|input| parse_subject_argument(input, question))
            .collect(),
        _ => bail!("provide exactly one of --subject or --subjects-file"),
    }
}

fn parse_subject_argument(input: &str, question: &dev::ReadyQuestionState) -> Result<SubjectInput> {
    let (binding, value) = input
        .split_once('=')
        .filter(|(_, value)| !value.contains('='))
        .ok_or_else(|| anyhow!("subject must be one field=value or role:field=value pair"))?;
    let (role, field) = match binding.split_once(':') {
        Some((role, field)) if !role.contains(':') && !field.contains(':') => (role, field),
        None if question.subjects.len() == 1 => (question.subjects[0].role.as_str(), binding),
        _ => bail!("multi-subject inputs must use role:field=value"),
    };
    Ok(SubjectInput {
        role: role.to_owned(),
        field: field.to_owned(),
        value: value.to_owned(),
    })
}

fn read_subject_inputs(path: &Path) -> Result<Vec<SubjectInput>> {
    let bytes = read_subject_input_bytes(path)?;
    let parsed: SubjectInputFile = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("subjects file must be closed JSON with one subjects array"))?;
    if parsed.subjects.is_empty() {
        bail!("subjects file must contain at least one subject");
    }
    Ok(parsed.subjects)
}

fn read_subject_input_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .context("failed to open the private subjects file")?;
    let mut file = File::from(descriptor);
    validate_private_file(path, &file, 1, MAX_SUBJECTS_FILE_BYTES)
        .context("subjects file must be an owner-only regular file")?;
    let expected_bytes = file.metadata()?.len();
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut file)
        .take(MAX_SUBJECTS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read the private subjects file")?;
    if bytes.len() as u64 != expected_bytes || bytes.len() as u64 > MAX_SUBJECTS_FILE_BYTES {
        bail!("subjects file changed while it was read or exceeds its byte limit");
    }
    validate_private_file(path, &file, expected_bytes, expected_bytes)
        .context("subjects file failed its final file-safety check")?;
    Ok(bytes)
}

fn validate_request_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    if !matches!(bytes.first(), Some(b'a'..=b'z'))
        || bytes.len() > 64
        || bytes[1..].iter().any(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        bail!("request name must be a safe lowercase local name");
    }
    Ok(())
}

fn local_procedure_input<'a>(
    question: &'a dev::ReadyQuestionState,
    subjects: &'a [ValidatedSubject<'a>],
    audience: &'a str,
    response_format: PreparedResponseFormat,
) -> LocalProcedureInput<'a> {
    let subjects = subjects
        .iter()
        .map(|subject| LocalProcedureSubject {
            role: &subject.definition.role,
            selector: LocalProcedureSelector {
                profile: &subject.definition.selector_profile,
                values: BTreeMap::from([(
                    subject.definition.selector_field.as_str(),
                    subject.value.as_str(),
                )]),
            },
        })
        .collect::<Vec<_>>();
    LocalProcedureInput {
        schema: LOCAL_PROCEDURE_INPUT_SCHEMA_V1,
        response_format,
        requirement: &question.requirement_uri,
        purpose: &question.purpose,
        audience,
        subjects,
    }
}

fn prepare_local_relying_procedure(
    evidence: &Path,
    runtime: &Path,
    input: &Path,
) -> Result<LocalRelyingProcedure> {
    let mut child = Command::new(evidence)
        .arg("--runtime")
        .arg(runtime)
        .arg("prepare-local-relying-procedure")
        .arg("--input")
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to invoke Evidence relying procedure preparation")?;
    let mut output = Vec::new();
    let read_result = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to open Evidence relying procedure output"))?
        .take(MAX_CONTEXT_BYTES + 1)
        .read_to_end(&mut output);
    if read_result.is_err() || output.is_empty() || output.len() as u64 > MAX_CONTEXT_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        bail!("Evidence relying procedure preparation failed");
    }
    let status = child.wait().context("failed to wait for Evidence")?;
    if !status.success() {
        bail!("Evidence relying procedure preparation failed");
    }
    serde_json::from_slice(&output)
        .map_err(|_| anyhow!("Evidence relying procedure preparation failed"))
}

fn validate_local_relying_procedure(
    procedure: &LocalRelyingProcedure,
    question: &dev::ReadyQuestionState,
    audience: &str,
    response_format: PreparedResponseFormat,
) -> Result<()> {
    if procedure.schema != LOCAL_PROCEDURE_SCHEMA_V1
        || procedure.response_format != response_format
        || procedure.expected_assurance_profile != AssuranceProfile::Local
        || procedure.requirement != question.requirement_uri
        || procedure.purpose != question.purpose
        || procedure.audience != audience
    {
        bail!("Evidence relying procedure preparation failed");
    }
    Ok(())
}

fn evidence_request_spec(
    procedure: LocalRelyingProcedure,
    subjects: &[ValidatedSubject<'_>],
) -> EvidenceRequestSpec {
    let subjects = subjects
        .iter()
        .map(|subject| SubjectRequest {
            role: subject.definition.role.clone(),
            selector_profile: subject.definition.selector_profile.clone(),
            selector_values: Some(vec![(
                subject.definition.selector_field.clone(),
                SelectorValue::String(subject.value.to_string()),
            )]),
        })
        .collect();
    EvidenceRequestSpec {
        response_format: procedure.response_format.into(),
        requirement: procedure.requirement,
        purpose: procedure.purpose,
        audience: procedure.audience,
        evidence_type: procedure.evidence_type,
        issued_by: procedure.issued_by,
        provided_by: procedure.provided_by,
        configuration_revision: procedure.configuration_revision,
        expected_assurance_profile: procedure.expected_assurance_profile,
        subjects,
        // A local relying procedure is audience-scoped by construction: it is
        // prepared ahead of any request, and a holder-bound binding derives
        // from a per-request wallet key that does not exist at preparation
        // time. Supplying none is the mode, not an omission.
        holder_keys: Vec::new(),
        expected_outputs: procedure.expected_outputs,
        maximum_assertion_lifetime_seconds: procedure.maximum_assertion_lifetime_seconds,
        clock_skew_seconds: procedure.clock_skew_seconds,
        subject_expectations: SubjectExpectations::Pinned(procedure.expected_subjects),
    }
}

fn obtain_token(
    mint: &Path,
    token_url: &str,
    client_id: &str,
    private_key_path: &Path,
    assertion_audience: &str,
) -> Result<Zeroizing<String>> {
    let mut child = Command::new(mint)
        .arg("token")
        .arg("--url")
        .arg(token_url)
        .arg("--client-id")
        .arg(client_id)
        .arg("--key")
        .arg(private_key_path)
        .arg("--audience")
        .arg(assertion_audience)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to invoke Mint")?;
    let mut stdout = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_BYTES + 2));
    let read_result = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to open Mint token output"))?
        .take((MAX_TOKEN_BYTES + 3) as u64)
        .read_to_end(&mut stdout);
    if read_result.is_err() || stdout.len() > MAX_TOKEN_BYTES + 2 {
        let _ = child.kill();
        let _ = child.wait();
        bail!("Registry Mint refused a token for client {client_id}");
    }
    let status = child.wait().context("failed to wait for Mint")?;
    if !status.success() {
        bail!("Registry Mint refused a token for client {client_id}");
    }
    if std::str::from_utf8(&stdout).is_err() {
        bail!("Registry Mint refused a token for client {client_id}");
    }
    let mut token = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut stdout)).expect("Mint output was validated as UTF-8"),
    );
    if token.ends_with('\n') {
        token.pop();
        if token.ends_with('\r') {
            token.pop();
        }
    }
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || token
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        bail!("Registry Mint refused a token for client {client_id}");
    }
    Ok(token)
}

fn write_authorization(path: &Path, token: &str) -> Result<()> {
    let mut contents = Zeroizing::new(String::with_capacity(token.len() + 36));
    contents.push_str("header = \"Authorization: Bearer ");
    contents.push_str(token);
    contents.push_str("\"\n");
    write_private_bytes(path, contents.as_bytes())
}

fn ensure_requests_root(project: &Path) -> Result<PathBuf> {
    let generated = project.join(".evidence");
    match fs::symlink_metadata(&generated) {
        Ok(_) => validate_private_directory(&generated)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(&generated)?;
        }
        Err(error) => return Err(error.into()),
    }
    ensure_self_ignored(&generated)?;
    let requests = generated.join("requests");
    match fs::symlink_metadata(&requests) {
        Ok(_) => validate_private_directory(&requests)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(&requests)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(requests)
}

/// Make the generated directory ignore its own contents.
///
/// It holds a live bearer token. The scaffold ignores `.evidence/` from the
/// project root, but `dev start` can create the directory in a repository that
/// never ran the scaffold, and then `git add .` commits the token. A `.gitignore`
/// of `*` inside the directory covers everything in it including itself, so the
/// guarantee travels with the directory instead of depending on how it was made.
/// An existing file is left as the operator wrote it.
fn ensure_self_ignored(directory: &Path) -> Result<()> {
    let path = directory.join(".gitignore");
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_private_bytes(&path, b"*\n")
        }
        Err(error) => Err(error.into()),
    }
}

fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("request name already exists; refusing to replace it"),
        Err(error) => Err(error.into()),
    }
}

struct StagingDirectory {
    path: Option<PathBuf>,
}

impl StagingDirectory {
    fn create(parent: &Path) -> Result<Self> {
        for _ in 0..8 {
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random)?;
            let name = format!(".prepare-{}", URL_SAFE_NO_PAD.encode(random));
            random.zeroize();
            let path = parent.join(name);
            match create_private_directory(&path) {
                Ok(()) => return Ok(Self { path: Some(path) }),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists) => {
                }
                Err(error) => return Err(error),
            }
        }
        bail!("failed to allocate private request staging")
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("staging remains active")
    }

    fn publish(&mut self, destination: &Path) -> Result<()> {
        let path = self.path();
        rename_noreplace(path, destination)
            .with_context(|| format!("failed to publish request `{}`", destination.display()))?;
        self.path = None;
        Ok(())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
                let _ = fs::remove_file(path);
            }
            Ok(metadata) if metadata.is_dir() => {
                let _ = fs::remove_dir_all(path);
            }
            _ => {}
        }
    }
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(PRIVATE_DIRECTORY_MODE);
    builder
        .create(path)
        .with_context(|| format!("failed to create private directory {}", path.display()))?;
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private directory {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        bail!(
            "private directory {} must be owner-only and unsymlinked",
            path.display()
        );
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::from_bits_truncate(PRIVATE_FILE_MODE as rustix::fs::RawMode),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("failed to create private file {}", path.display()))?;
    let file = File::from(fd);
    validate_private_file(path, &file, 0, u64::MAX)?;
    Ok(file)
}

fn write_private_bytes(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = create_private_file(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    validate_private_file(path, &file, contents.len() as u64, contents.len() as u64)
}

fn validate_private_file(
    path: &Path,
    opened: &File,
    minimum_bytes: u64,
    maximum_bytes: u64,
) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path)?;
    let open_metadata = opened.metadata()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.nlink() != 1
        || path_metadata.uid() != rustix::process::getuid().as_raw()
        || path_metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || path_metadata.dev() != open_metadata.dev()
        || path_metadata.ino() != open_metadata.ino()
        || !(minimum_bytes..=maximum_bytes).contains(&open_metadata.len())
    {
        bail!("private request artifact failed its file-safety checks");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn rename_noreplace(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace request publication is unsupported",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progressive_args(subject: Vec<&str>, subjects_file: Option<PathBuf>) -> PrepareArgs {
        PrepareArgs {
            question: None,
            profile: Some(PathBuf::from("client.json")),
            requirement: Some("relationship".to_owned()),
            purpose: None,
            subject: subject.into_iter().map(str::to_owned).collect(),
            subjects_file,
            name: "request".to_owned(),
            client: None,
            format: PreparedResponseFormat::SignedJws,
            project: PathBuf::from("."),
            evidence_bin: None,
            mint_bin: None,
        }
    }

    #[test]
    fn progressive_direct_subjects_preserve_roles_and_scalar_types() {
        let args = progressive_args(
            vec![
                "parent:person_id=person-123",
                "parent:attempt=7",
                "child:confirmed=true",
                "child:literal=\"true\"",
            ],
            None,
        );
        let (selectors, subjects) =
            progressive_subject_inputs(&args).expect("multi-role selectors parse");
        assert!(selectors.is_empty());
        assert_eq!(
            serde_json::to_value(subjects.expect("role map")).expect("subjects serialize"),
            serde_json::json!({
                "parent": {"person_id": "person-123", "attempt": 7},
                "child": {"confirmed": true, "literal": "true"}
            })
        );
    }

    #[test]
    fn progressive_subject_file_preserves_explicit_json_scalar_types() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("subjects.json");
        fs::write(
            &path,
            br#"{"subjects":[{"role":"person","field":"integer_string","value":"7"},{"role":"person","field":"integer","value":7},{"role":"person","field":"flag","value":false}]}"#,
        )
        .expect("subjects file");
        fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("private mode");

        let args = progressive_args(Vec::new(), Some(path));
        let (selectors, subjects) = progressive_subject_inputs(&args).expect("typed file parses");
        assert!(selectors.is_empty());
        assert_eq!(
            serde_json::to_value(subjects.expect("role map")).expect("subjects serialize"),
            serde_json::json!({
                "person": {"integer_string": "7", "integer": 7, "flag": false}
            })
        );
    }

    #[test]
    fn progressive_selector_values_accept_the_contract_wide_maximum() {
        let value = "x".repeat(MAX_SELECTOR_VALUE_BYTES);

        let direct = parse_progressive_selector_value(&value)
            .expect("a direct selector at the contract-wide maximum parses");
        assert_eq!(
            serde_json::to_value(direct).expect("direct selector serializes"),
            serde_json::json!(value)
        );

        let from_file = progressive_selector_value(ProgressiveSelectorValue::String(value.clone()))
            .expect("a file selector at the contract-wide maximum parses");
        assert_eq!(
            serde_json::to_value(from_file).expect("file selector serializes"),
            serde_json::json!(value)
        );
    }

    #[test]
    fn progressive_selector_values_refuse_above_the_contract_wide_maximum() {
        let value = "x".repeat(MAX_SELECTOR_VALUE_BYTES + 1);

        assert!(parse_progressive_selector_value(&value).is_err());
        assert!(progressive_selector_value(ProgressiveSelectorValue::String(value)).is_err());
    }

    #[test]
    fn progressive_subjects_refuse_mixed_role_syntax_and_duplicate_fields() {
        for subject in [
            vec!["person:person_id=person-123", "case_id=case-1"],
            vec!["person:person_id=person-123", "person:person_id=person-456"],
        ] {
            assert!(progressive_subject_inputs(&progressive_args(subject, None)).is_err());
        }
    }

    #[test]
    fn progressive_requests_allow_contracts_with_no_request_origin_selectors() {
        let (selectors, subjects) = progressive_subject_inputs(&progressive_args(Vec::new(), None))
            .expect("selector-free progressive request");
        assert!(selectors.is_empty());
        assert!(subjects.is_none());
    }

    /// `.evidence` holds a live bearer token. The scaffold ignores it from the
    /// project root, but `dev start` can create the directory in a repository
    /// that never ran the scaffold, and then `git add .` commits the token. The
    /// ignore has to travel with the directory rather than depend on how it was
    /// made.
    #[test]
    fn the_generated_directory_ignores_itself_however_it_was_created() {
        let project = tempfile::tempdir().expect("temporary project");
        let generated = project.path().join(".evidence");
        create_private_directory(&generated).expect("the generated directory is created");

        ensure_requests_root(project.path()).expect("the requests root is prepared");

        let ignore = generated.join(".gitignore");
        assert_eq!(
            fs::read_to_string(&ignore).expect("the generated directory ignores itself"),
            "*\n"
        );
    }

    /// An operator who has written their own rules keeps them. Replacing the
    /// file would be the tool overruling the project it is running inside.
    #[test]
    fn an_existing_ignore_file_is_left_alone() {
        let project = tempfile::tempdir().expect("temporary project");
        let generated = project.path().join(".evidence");
        create_private_directory(&generated).expect("the generated directory is created");
        let ignore = generated.join(".gitignore");
        fs::write(&ignore, "*\n!notes.md\n").expect("write an existing ignore file");

        ensure_requests_root(project.path()).expect("the requests root is prepared");

        assert_eq!(
            fs::read_to_string(&ignore).expect("the ignore file is readable"),
            "*\n!notes.md\n"
        );
    }

    #[test]
    fn curl_config_is_closed_and_keeps_authorization_out_of_arguments() {
        let config = progressive_curl_config(
            "https://evidence.example.test/v1/evidence",
            "application/evidence+jws",
            "Bearer token-canary",
            Path::new(".evidence/requests/first/request.json"),
        )
        .expect("safe curl config");
        assert_eq!(
            config.as_str(),
            "url = \"https://evidence.example.test/v1/evidence\"\n\
             request = \"POST\"\n\
             header = \"Authorization: Bearer token-canary\"\n\
             header = \"Content-Type: application/json\"\n\
             header = \"Accept: application/evidence+jws\"\n\
             data-binary = \"@.evidence/requests/first/request.json\"\n"
        );
        assert!(progressive_curl_config(
            "https://evidence.example.test/\nheader = \"Injected: true\"",
            "application/evidence+jws",
            "Bearer token-canary",
            Path::new("request.json"),
        )
        .is_err());
    }
}
