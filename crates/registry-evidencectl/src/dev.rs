//! Minimal private lifecycle for local Evidence tutorials.
//!
//! The final `.evidence/dev` directory is compiled in place because the
//! runtime contains absolute paths. A resident supervisor owns both service
//! children and is the only process allowed to stop them.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::{
        fs::{
            symlink, DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
            PermissionsExt as _,
        },
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{
    access,
    authoring::{
        access_policy_requester_tag, compile_local_project_with_ports, CompiledAccessPolicy,
        CompiledConceptForm, CompiledProject, CompiledQuestion, LocalServicePorts,
    },
    keygen,
};

const STATE_SCHEMA: &str = "registry.evidencectl.dev-state/v5";
const CONTROL_SOCKET_NAME: &str = "control.sock";
const CALLER_ID: &str = "local-tutorial-caller";
const LOCAL_ACCESS_TOKEN_AUDIENCE: &str = "registry-evidence-local";
const LOCAL_CALLER_EVIDENCE_AUDIENCE: &str = "urn:registrystack:evidence:local:caller";
const LOCAL_REQUESTER_TAG: &str = "local-caller";
const MINT_AUDIT_KEY_FILENAME: &str = "mint-audit-hmac-key";
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_HTTP_BODY_BYTES: u64 = 64 * 1024;
const DEFAULT_READY_TIMEOUT_SECONDS: u64 = 45;
const SHUTDOWN_TIMEOUT_SECONDS: u64 = 35;

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct DevArgs {
    #[command(subcommand)]
    action: Option<DevAction>,

    /// Return after Registry Mint and Evidence Gateway are ready on loopback.
    #[arg(long, required = true)]
    detach: bool,

    /// Loopback port for the local Evidence Gateway service.
    #[arg(long, default_value_t = 8080)]
    evidence_port: u16,

    /// Loopback port for the local Mint service.
    #[arg(long, default_value_t = 8081)]
    mint_port: u16,

    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,

    #[arg(long, hide = true)]
    evidence_bin: Option<PathBuf>,

    #[arg(long, hide = true)]
    mint_bin: Option<PathBuf>,

    #[arg(
        long,
        default_value_t = DEFAULT_READY_TIMEOUT_SECONDS,
        value_parser = clap::value_parser!(u64).range(1..=120),
        hide = true
    )]
    ready_timeout_seconds: u64,
}

#[derive(Debug, Subcommand)]
enum DevAction {
    /// Stop the active local Registry Mint and Evidence Gateway pair.
    Stop(StopArgs),
    /// Remove one completed stopped local generation.
    Clean(CleanArgs),
}

#[derive(Debug, Args)]
struct StopArgs {
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,
}

#[derive(Debug, Args)]
struct CleanArgs {
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,
}

#[derive(Debug, Args)]
pub struct SupervisorArgs {
    #[arg(long)]
    dev_root: PathBuf,
    #[arg(long)]
    evidence_bin: PathBuf,
    #[arg(long)]
    mint_bin: PathBuf,
    #[arg(long)]
    ready_timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DevStatus {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FailureKind {
    MintStart,
    MintReadiness,
    EvidenceStart,
    EvidenceReadiness,
    ChildExited,
    Supervisor,
    SupervisorSignal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DevState {
    schema: String,
    status: DevStatus,
    project: PathBuf,
    runtime_path: PathBuf,
    evidence_origin: String,
    mint_origin: String,
    token_url: String,
    access_token_audience: String,
    caller: Option<CallerState>,
    access_policies: Vec<AccessPolicyState>,
    questions: Vec<QuestionState>,
    failure: Option<FailureKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallerState {
    client_id: String,
    private_key_path: PathBuf,
    assertion_audience: String,
    evidence_audience: String,
    requester_tag: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccessPolicyState {
    id: String,
    requester_tag: String,
    questions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuestionState {
    alias: String,
    requirement_uri: String,
    purpose: String,
    subjects: Vec<SubjectState>,
    concepts: Vec<ConceptState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubjectState {
    role: String,
    selector_profile: String,
    selector_field: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConceptState {
    alias: String,
    uri: String,
    form: String,
}

/// Validated active-session inputs for native request preparation.
///
/// Consumers use this seam instead of parsing private state themselves. Every
/// path is absolute and revalidated against the one ready `.evidence/dev`
/// session before it is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadyDevState {
    pub(crate) project: PathBuf,
    pub(crate) runtime_path: PathBuf,
    pub(crate) evidence_origin: String,
    pub(crate) mint_origin: String,
    pub(crate) token_url: String,
    pub(crate) access_token_audience: String,
    pub(crate) caller: Option<ReadyCallerState>,
    pub(crate) access_policies: Vec<ReadyAccessPolicy>,
    pub(crate) questions: Vec<ReadyQuestionState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadyCallerState {
    pub(crate) client_id: String,
    pub(crate) private_key_path: PathBuf,
    pub(crate) assertion_audience: String,
    pub(crate) evidence_audience: String,
    pub(crate) requester_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadyAccessPolicy {
    pub(crate) id: String,
    pub(crate) requester_tag: String,
    pub(crate) questions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadyQuestionState {
    pub(crate) alias: String,
    pub(crate) requirement_uri: String,
    pub(crate) purpose: String,
    pub(crate) subjects: Vec<ReadySubjectState>,
    pub(crate) concepts: Vec<ReadyConceptState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadySubjectState {
    pub(crate) role: String,
    pub(crate) selector_profile: String,
    pub(crate) selector_field: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadyConceptState {
    pub(crate) alias: String,
    pub(crate) uri: String,
    pub(crate) form: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoppedDevState {
    pub(crate) runtime_path: PathBuf,
    pub(crate) questions: Vec<ReadyQuestionState>,
}

pub(crate) struct LifecycleLock {
    _file: File,
}

#[derive(Default)]
struct OwnedChildren {
    evidence: Option<Child>,
    mint: Option<Child>,
}

impl OwnedChildren {
    fn stop(&mut self) {
        stop_children(self.evidence.as_mut(), self.mint.as_mut());
        self.evidence = None;
        self.mint = None;
    }
}

impl Drop for OwnedChildren {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn run(args: DevArgs) -> Result<ExitCode> {
    match args.action {
        Some(DevAction::Stop(stop)) => {
            if args.detach {
                bail!("`dev stop` does not accept `--detach`");
            }
            stop_dev(&stop.project)
        }
        Some(DevAction::Clean(clean)) => {
            if args.detach {
                bail!("`dev clean` does not accept `--detach`");
            }
            clean_dev(&clean.project)
        }
        None => {
            if !args.detach {
                bail!("the local development lifecycle requires `evidencectl dev --detach`");
            }
            let ports = LocalServicePorts::new(args.evidence_port, args.mint_port)?;
            start_detached(
                &args.project,
                args.evidence_bin.as_deref(),
                args.mint_bin.as_deref(),
                args.ready_timeout_seconds,
                ports,
            )
        }
    }
}

pub fn run_supervisor(args: SupervisorArgs) -> Result<ExitCode> {
    let dev_root = args.dev_root.clone();
    let terminate = Arc::new(AtomicBool::new(false));
    let result = (|| {
        // SIGKILL cannot be observed and is intentionally not part of this
        // tutorial lifecycle. Catchable operator signals use owned cleanup.
        for signal in [
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
            signal_hook::consts::SIGINT,
        ] {
            signal_hook::flag::register(signal, Arc::clone(&terminate))
                .context("failed to install the local supervisor signal handler")?;
        }
        injected_supervisor_failure("before-setsid")?;
        rustix::process::setsid().context("failed to detach the local supervisor session")?;
        publish_test_supervisor_pid()?;
        supervise(args, &terminate)
    })();
    if let Err(error) = result {
        let _ = publish_supervisor_failure(&dev_root, FailureKind::Supervisor);
        return Err(error);
    }
    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)] // Crate-private handoff for the immediately following request slice.
pub(crate) fn load_ready_state(project: &Path) -> Result<ReadyDevState> {
    let project = canonical_project(project)?;
    let generated_root = existing_private_generated_root(&project)?;
    let dev_root = generated_root.join("dev");
    validate_private_directory(&dev_root)?;
    let state = read_state(&dev_root.join("state.json"))?;
    if state.status != DevStatus::Ready || state.failure.is_some() {
        bail!("the local development state is not the closed ready session");
    }
    validate_closed_state(&state, &project, &dev_root)?;
    require_owned_regular_file(&state.runtime_path, 0o400)?;
    if let Some(caller) = &state.caller {
        require_owned_regular_file(&caller.private_key_path, PRIVATE_FILE_MODE)?;
    }
    validate_control_socket(&dev_root.join("control.sock"))?;
    Ok(ReadyDevState {
        project,
        runtime_path: state.runtime_path,
        evidence_origin: state.evidence_origin,
        mint_origin: state.mint_origin,
        token_url: state.token_url,
        access_token_audience: state.access_token_audience,
        caller: state.caller.map(|caller| ReadyCallerState {
            client_id: caller.client_id,
            private_key_path: caller.private_key_path,
            assertion_audience: caller.assertion_audience,
            evidence_audience: caller.evidence_audience,
            requester_tag: caller.requester_tag,
        }),
        access_policies: state
            .access_policies
            .into_iter()
            .map(|policy| ReadyAccessPolicy {
                id: policy.id,
                requester_tag: policy.requester_tag,
                questions: policy.questions,
            })
            .collect(),
        questions: state.questions.into_iter().map(ready_question).collect(),
    })
}

#[allow(dead_code)] // Consumed by the access-management CLI slice.
pub(crate) fn try_load_ready_state(project: &Path) -> Result<Option<ReadyDevState>> {
    let project = canonical_project(project)?;
    let generated_root = project.join(".evidence");
    match fs::symlink_metadata(&generated_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(_) => validate_private_directory(&generated_root)?,
        Err(error) => return Err(error.into()),
    }
    let dev_root = generated_root.join("dev");
    match fs::symlink_metadata(&dev_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(_) => validate_private_directory(&dev_root)?,
        Err(error) => return Err(error.into()),
    }
    let state = read_state(&dev_root.join("state.json"))?;
    match state.status {
        DevStatus::Ready if state.failure.is_none() => load_ready_state(&project).map(Some),
        DevStatus::Stopped if state.caller.is_none() && state.failure.is_none() => {
            load_stopped_state(&project)?;
            Ok(None)
        }
        _ => bail!("local development state exists but is neither ready nor cleanly stopped"),
    }
}

#[allow(dead_code)] // Crate-private handoff for the immediately following audit slice.
pub(crate) fn load_stopped_state(project: &Path) -> Result<StoppedDevState> {
    let project = canonical_project(project)?;
    let generated_root = existing_private_generated_root(&project)?;
    let dev_root = generated_root.join("dev");
    validate_private_directory(&dev_root)?;
    let state = read_state(&dev_root.join("state.json"))?;
    if state.status != DevStatus::Stopped || state.caller.is_some() || state.failure.is_some() {
        bail!("the local development state is not the closed stopped session");
    }
    validate_closed_state(&state, &project, &dev_root)?;
    require_owned_regular_file(&state.runtime_path, 0o400)?;
    match fs::symlink_metadata(dev_root.join("control.sock")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("stopped local state still has a control path"),
        Err(error) => return Err(error.into()),
    }
    Ok(StoppedDevState {
        runtime_path: state.runtime_path,
        questions: state.questions.into_iter().map(ready_question).collect(),
    })
}

/// Ask the private local supervisor to make Mint reload its complete client
/// registry. This confirms only that SIGHUP was delivered. The next token
/// request remains the functional proof that Mint accepted the new registry.
#[allow(dead_code)] // Consumed by the access-management CLI slice.
pub(crate) fn request_mint_reload(project: &Path) -> Result<()> {
    let project = canonical_project(project)?;
    let generated_root = existing_private_generated_root(&project)?;
    let dev_root = generated_root.join("dev");
    validate_private_directory(&dev_root)?;
    let state = read_state(&dev_root.join("state.json"))?;
    if state.status != DevStatus::Ready || state.failure.is_some() {
        bail!("the local development state is not ready for a Mint reload");
    }
    validate_closed_state(&state, &project, &dev_root)?;
    let socket = dev_root.join(CONTROL_SOCKET_NAME);
    validate_control_socket(&socket)?;
    send_control_request(&socket, b"reload-mint\n", b"reload-requested\n")
        .context("the local supervisor did not accept the Mint reload request")
}

fn send_control_request(socket: &Path, request: &[u8], expected: &[u8]) -> Result<()> {
    let parent = socket
        .parent()
        .ok_or_else(|| anyhow!("local control socket has no parent"))?;
    let bridge = tempfile::Builder::new()
        .prefix("ec-")
        .tempdir()
        .context("creating a short private control path")?;
    fs::set_permissions(bridge.path(), fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    let link = bridge.path().join("d");
    symlink(parent, &link).context("creating a short private control path")?;
    let mut stream = UnixStream::connect(link.join(CONTROL_SOCKET_NAME))
        .context("the local supervisor is unavailable")?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    (&mut stream).take(64).read_to_end(&mut response)?;
    if response != expected {
        bail!("the local supervisor returned an unexpected control response");
    }
    Ok(())
}

fn validate_closed_state(state: &DevState, project: &Path, dev_root: &Path) -> Result<()> {
    let evidence_port = local_origin_port(&state.evidence_origin);
    let mint_port = local_origin_port(&state.mint_origin);
    let origins_are_closed = matches!((evidence_port, mint_port), (Some(evidence), Some(mint)) if evidence != mint)
        && state.token_url == format!("{}/token", state.mint_origin);
    let questions_are_closed = !state.questions.is_empty()
        && state.questions.len() <= 128
        && state.questions.iter().all(valid_question_state)
        && state
            .questions
            .iter()
            .map(|question| question.alias.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == state.questions.len();
    let question_aliases = state
        .questions
        .iter()
        .map(|question| question.alias.as_str())
        .collect::<BTreeSet<_>>();
    let access_policies_are_closed = state.access_policies.len() <= 128
        && state
            .access_policies
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
        && state
            .access_policies
            .iter()
            .all(|policy| valid_access_policy_state(policy, &question_aliases))
        && state
            .access_policies
            .iter()
            .map(|policy| policy.requester_tag.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == state.access_policies.len()
        && state_matches_sealed_bundle(&state.questions, &state.access_policies, dev_root)
            .unwrap_or(false);
    let caller_is_closed = match state.status {
        DevStatus::Starting | DevStatus::Ready => {
            state.access_policies.is_empty() == state.caller.is_some()
        }
        DevStatus::Stopped => state.caller.is_none(),
        DevStatus::Stopping | DevStatus::Failed => true,
    } && state
        .caller
        .as_ref()
        .is_none_or(|caller| validate_closed_caller(caller, dev_root, &state.token_url).is_ok());
    if state.project != project
        || state.runtime_path != dev_root.join("runtime.yaml")
        || !origins_are_closed
        || state.access_token_audience != LOCAL_ACCESS_TOKEN_AUDIENCE
        || !questions_are_closed
        || !access_policies_are_closed
        || !caller_is_closed
    {
        bail!("the local development state contains values outside the closed lifecycle profile");
    }
    Ok(())
}

fn valid_access_policy_state(
    policy: &AccessPolicyState,
    question_aliases: &BTreeSet<&str>,
) -> bool {
    valid_local_identifier(&policy.id)
        && !policy.questions.is_empty()
        && policy.questions.len() <= 128
        && policy.questions.windows(2).all(|pair| pair[0] < pair[1])
        && policy
            .questions
            .iter()
            .all(|question| question_aliases.contains(question.as_str()))
        && access_policy_requester_tag(&policy.id, &policy.questions)
            .is_ok_and(|tag| tag == policy.requester_tag)
}

fn valid_question_state(question: &QuestionState) -> bool {
    let identifiers_are_closed = [question.alias.as_str(), question.purpose.as_str()]
        .into_iter()
        .all(valid_local_identifier);
    let concepts_are_closed = !question.concepts.is_empty()
        && question.concepts.len() <= 16
        && question.concepts.iter().all(valid_concept_state)
        && question
            .concepts
            .iter()
            .map(|concept| concept.alias.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == question.concepts.len();
    let subject_count = question.subjects.len();
    let subjects_are_closed = !question.subjects.is_empty()
        && question.subjects.len() <= 8
        && question.subjects.iter().all(|subject| {
            valid_local_identifier(&subject.role)
                && valid_local_identifier(&subject.selector_profile)
                && valid_local_identifier(&subject.selector_field)
                && (!subject.selector_profile.starts_with("local-subject-")
                    || subject.selector_profile
                        == if subject_count == 1 {
                            format!("local-subject-{}-v1", question.alias)
                        } else {
                            format!("local-subject-{}-{}-v1", question.alias, subject.role)
                        })
        })
        && question
            .subjects
            .iter()
            .map(|subject| subject.role.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == question.subjects.len();
    identifiers_are_closed
        && valid_uri(&question.requirement_uri)
        && subjects_are_closed
        && concepts_are_closed
}

fn valid_concept_state(concept: &ConceptState) -> bool {
    valid_local_identifier(&concept.alias)
        && valid_uri(&concept.uri)
        && matches!(
            concept.form.as_str(),
            "boolean" | "controlled-category" | "bounded-integer" | "reviewed-structured-value"
        )
}

fn valid_uri(value: &str) -> bool {
    value.len() <= 512 && url::Url::parse(value).is_ok()
}

fn state_matches_sealed_bundle(
    questions: &[QuestionState],
    access_policies: &[AccessPolicyState],
    dev_root: &Path,
) -> Result<bool> {
    let path = dev_root.join("bundle/evidence.yaml");
    require_owned_regular_file(&path, 0o400)?;
    let bytes = fs::read(&path).context("failed to read the sealed local bundle")?;
    if bytes.len() > 1024 * 1024 {
        return Ok(false);
    }
    let bundle: Value =
        serde_norway::from_slice(&bytes).context("the sealed local bundle is invalid")?;
    let requirements = bundle
        .get("requirements")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("the sealed local bundle has no requirements"))?;
    if requirements.len() != questions.len() {
        return Ok(false);
    }
    let selector_profiles = bundle
        .get("selectorProfiles")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("the sealed local bundle has no selector profiles"))?;
    for question in questions {
        let Some(requirement) = requirements.iter().find(|requirement| {
            requirement.get("id").and_then(Value::as_str) == Some(question.requirement_uri.as_str())
        }) else {
            return Ok(false);
        };
        if !requirement
            .get("purposes")
            .and_then(Value::as_array)
            .is_some_and(|purposes| *purposes == [Value::String(question.purpose.clone())])
        {
            return Ok(false);
        }
        let concepts = requirement
            .get("concepts")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("a sealed local requirement has no concepts"))?;
        if concepts.len() != question.concepts.len()
            || question.concepts.iter().any(|concept| {
                !concepts.iter().any(|configured| {
                    configured.get("id").and_then(Value::as_str) == Some(concept.uri.as_str())
                        && configured.get("form").and_then(Value::as_str)
                            == Some(concept.form.as_str())
                })
            })
        {
            return Ok(false);
        }
        let roles = requirement
            .get("subjectRoles")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("a sealed local requirement has no subject roles"))?;
        if roles.len() != question.subjects.len()
            || question.subjects.iter().any(|subject| {
                !roles.iter().any(|role| {
                    role.get("role").and_then(Value::as_str) == Some(subject.role.as_str())
                        && role
                            .get("selectorProfiles")
                            .and_then(Value::as_array)
                            .is_some_and(|profiles| {
                                profiles.iter().any(|profile| {
                                    profile.as_str() == Some(subject.selector_profile.as_str())
                                })
                            })
                }) || !selector_profiles
                    .get(&subject.selector_profile)
                    .and_then(|profile| profile.get("fields"))
                    .and_then(Value::as_object)
                    .is_some_and(|fields| fields.contains_key(&subject.selector_field))
            })
        {
            return Ok(false);
        }
    }
    let authority_profiles = bundle
        .get("authorityProfiles")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("the sealed local bundle has no authority profiles"))?;
    if access_policies.is_empty() {
        let Some(profile) = authority_profiles.get(LOCAL_REQUESTER_TAG) else {
            return Ok(false);
        };
        return Ok(authority_profiles.len() == 1
            && authority_profile_matches(
                profile,
                LOCAL_REQUESTER_TAG,
                &questions.iter().collect::<Vec<_>>(),
            ));
    }
    if authority_profiles.len() != access_policies.len() {
        return Ok(false);
    }
    for policy in access_policies {
        let Some(profile) = authority_profiles.get(&policy.requester_tag) else {
            return Ok(false);
        };
        let governed_questions = policy
            .questions
            .iter()
            .filter_map(|alias| questions.iter().find(|question| question.alias == *alias))
            .collect::<Vec<_>>();
        if governed_questions.len() != policy.questions.len()
            || !authority_profile_matches(profile, &policy.requester_tag, &governed_questions)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn authority_profile_matches(
    profile: &Value,
    requester_tag: &str,
    questions: &[&QuestionState],
) -> bool {
    if profile.get("kind").and_then(Value::as_str) != Some("explicit-request")
        || profile
            .get("requesterTags")
            .and_then(Value::as_array)
            .is_none_or(|tags| tags.as_slice() != [Value::String(requester_tag.to_owned())])
    {
        return false;
    }
    profile
        .get("grants")
        .and_then(Value::as_array)
        .is_some_and(|grants| {
            grants.len() == questions.len()
                && grants
                    .iter()
                    .zip(questions)
                    .all(|(grant, question)| grant_matches_question(grant, question))
        })
}

fn grant_matches_question(grant: &Value, question: &QuestionState) -> bool {
    if grant.get("requirement").and_then(Value::as_str) != Some(question.requirement_uri.as_str())
        || grant.get("purpose").and_then(Value::as_str) != Some(question.purpose.as_str())
        || grant.get("audienceFrom").and_then(Value::as_str) != Some("authenticated-requester")
    {
        return false;
    }
    grant
        .get("subjects")
        .and_then(Value::as_array)
        .is_some_and(|subjects| {
            subjects.len() == question.subjects.len()
                && subjects
                    .iter()
                    .zip(&question.subjects)
                    .all(|(configured, expected)| {
                        configured.get("role").and_then(Value::as_str)
                            == Some(expected.role.as_str())
                            && configured.get("selectorProfile").and_then(Value::as_str)
                                == Some(expected.selector_profile.as_str())
                            && configured.get("valueOrigin").and_then(Value::as_str)
                                == Some("request")
                    })
        })
}

fn validate_closed_caller(caller: &CallerState, dev_root: &Path, token_url: &str) -> Result<()> {
    if caller.client_id != CALLER_ID
        || caller.private_key_path != dev_root.join("generated/keys/caller-private.jwk")
        || caller.assertion_audience != token_url
        || caller.evidence_audience != LOCAL_CALLER_EVIDENCE_AUDIENCE
        || caller.requester_tag != LOCAL_REQUESTER_TAG
    {
        bail!("the local development caller is outside the closed lifecycle profile");
    }
    Ok(())
}

fn local_origin_port(origin: &str) -> Option<u16> {
    let port = origin.strip_prefix("http://127.0.0.1:")?.parse().ok()?;
    (port != 0 && origin == format!("http://127.0.0.1:{port}")).then_some(port)
}

fn local_origin(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn valid_local_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 64
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn start_detached(
    project: &Path,
    evidence_override: Option<&Path>,
    mint_override: Option<&Path>,
    ready_timeout_seconds: u64,
    ports: LocalServicePorts,
) -> Result<ExitCode> {
    let project = canonical_project(project)?;
    let generated_root = ensure_private_generated_root(&project)?;
    let _lifecycle = lock_lifecycle(&generated_root)?;
    let dev_root = generated_root.join("dev");

    match fs::symlink_metadata(&dev_root) {
        Ok(metadata) => {
            validate_private_directory_metadata(&dev_root, &metadata)?;
            remove_completed_dev_root(&project, &dev_root)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect local development state"),
    }

    create_private_directory(&dev_root)?;
    let result = prepare_and_start(
        &project,
        &dev_root,
        evidence_override,
        mint_override,
        ready_timeout_seconds,
        ports,
    );
    if let Err(error) = result {
        if let Err(cleanup) = cleanup_new_dev_root(&dev_root) {
            return Err(error.context(format!(
                "failed to roll back the incomplete local session: {cleanup:#}"
            )));
        }
        return Err(error);
    }
    result
}

fn remove_completed_dev_root(project: &Path, dev_root: &Path) -> Result<()> {
    let state = read_state(&dev_root.join("state.json"))?;
    if state.status != DevStatus::Stopped || state.caller.is_some() || state.failure.is_some() {
        bail!("local development state already exists and is not a completed stopped session");
    }
    validate_closed_state(&state, project, dev_root)?;
    require_owned_regular_file(&state.runtime_path, 0o400)?;
    match fs::symlink_metadata(dev_root.join(CONTROL_SOCKET_NAME)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("stopped local state still has a control path"),
        Err(error) => return Err(error.into()),
    }
    make_tree_removable(dev_root)?;
    fs::remove_dir_all(dev_root).context("failed to replace the completed local session")
}

fn clean_dev(project: &Path) -> Result<ExitCode> {
    let project = canonical_project(project)?;
    let generated_root = existing_private_generated_root(&project)?;
    let _lifecycle = lock_lifecycle(&generated_root)?;
    let dev_root = generated_root.join("dev");
    validate_private_directory(&dev_root)?;
    remove_completed_dev_root(&project, &dev_root)?;
    println!("Removed stopped local Evidence state");
    Ok(ExitCode::SUCCESS)
}

fn prepare_and_start(
    project: &Path,
    dev_root: &Path,
    evidence_override: Option<&Path>,
    mint_override: Option<&Path>,
    ready_timeout_seconds: u64,
    ports: LocalServicePorts,
) -> Result<ExitCode> {
    let evidence_bin = canonical_tool_binary(resolve_tool_binary(
        "evidence",
        evidence_override,
        "EVIDENCECTL_TEST_EVIDENCE_BIN",
    )?)?;
    let mint_bin = canonical_tool_binary(resolve_tool_binary(
        "mint",
        mint_override,
        "EVIDENCECTL_TEST_MINT_BIN",
    )?)?;
    let compiled = compile_local_project_with_ports(project, dev_root, &evidence_bin, ports)?;
    let evidence_origin = local_origin(ports.evidence);
    let mint_origin = local_origin(ports.mint);
    let token_url = format!("{mint_origin}/token");

    let generated = dev_root.join("generated");
    let keys = generated.join("keys");
    let clients = generated.join("clients");
    let mint_audit = generated.join("audit");
    let logs = dev_root.join("logs");
    for directory in [&generated, &keys, &clients, &mint_audit, &logs] {
        create_private_directory(directory)?;
    }

    let mint_public = generate_service_and_holder_keys(&keys)?;
    let mint_audit_key = keys.join(MINT_AUDIT_KEY_FILENAME);
    generate_mint_audit_key(&mint_audit_key)?;
    let mint_config = mint_config(&compiled, &mint_public, &keys, ports);
    let mint_config_path = generated.join("mint.yaml");
    write_private_yaml(&mint_config_path, &mint_config)?;
    let caller = if compiled.access_policies.is_empty() {
        let (caller_private, caller_public) =
            keygen::generate_dev_keypair(&keys, "caller-private.jwk", "caller-public.jwk.json")?;
        let caller_public = read_owner_json(&caller_public, 16 * 1024)?;
        write_private_yaml(
            &clients.join("caller.yaml"),
            &local_caller_registration(&compiled, caller_public),
        )?;
        Some(CallerState {
            client_id: CALLER_ID.to_owned(),
            private_key_path: caller_private,
            assertion_audience: token_url.clone(),
            evidence_audience: compiled.caller_evidence_audience.clone(),
            requester_tag: compiled.requester_tag.clone(),
        })
    } else {
        let policy_tags = compiled
            .access_policies
            .iter()
            .map(|policy| (policy.id.clone(), policy.requester_tag.clone()))
            .collect::<BTreeMap<_, _>>();
        let registrations = access::load_active_clients(project, &policy_tags)?;
        if registrations.is_empty() {
            bail!("explicit access policies require at least one active client");
        }
        for registration in registrations {
            write_private_yaml(
                &clients.join(format!("{}.yaml", registration.client_id)),
                &registration.registration,
            )?;
        }
        None
    };
    run_check(&mint_bin, &["check", "--config"], &mint_config_path, "Mint")?;

    let state = DevState {
        schema: STATE_SCHEMA.to_owned(),
        status: DevStatus::Starting,
        project: project.to_path_buf(),
        runtime_path: compiled.runtime_path.clone(),
        evidence_origin: evidence_origin.clone(),
        mint_origin: mint_origin.clone(),
        token_url: token_url.clone(),
        access_token_audience: compiled.local_audience.clone(),
        caller,
        access_policies: compiled
            .access_policies
            .iter()
            .map(AccessPolicyState::from)
            .collect(),
        questions: compiled.questions.iter().map(QuestionState::from).collect(),
        failure: None,
    };
    write_new_state(&dev_root.join("state.json"), &state)?;

    let supervisor_log = create_private_file(&logs.join("supervisor.log"))?;
    let supervisor_error = supervisor_log.try_clone()?;
    let executable = supervisor_executable()?;
    let mut supervisor = match Command::new(executable)
        .arg("__dev-supervisor")
        .arg("--dev-root")
        .arg(dev_root)
        .arg("--evidence-bin")
        .arg(&evidence_bin)
        .arg("--mint-bin")
        .arg(&mint_bin)
        .arg("--ready-timeout-seconds")
        .arg(ready_timeout_seconds.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(supervisor_log))
        .stderr(Stdio::from(supervisor_error))
        .spawn()
    {
        Ok(supervisor) => supervisor,
        Err(error) => {
            publish_supervisor_failure(dev_root, FailureKind::Supervisor)?;
            return Err(error).context("failed to start the local supervisor");
        }
    };

    if let Err(error) = wait_for_supervisor_ready(dev_root, &mut supervisor, ready_timeout_seconds)
    {
        abort_start(&mut supervisor)?;
        publish_supervisor_failure(dev_root, FailureKind::Supervisor)?;
        return Err(error);
    }
    println!("Evidence ready at {evidence_origin}");
    println!("Mint ready at {mint_origin}");
    Ok(ExitCode::SUCCESS)
}

fn generate_service_and_holder_keys(keys: &Path) -> Result<PathBuf> {
    for name in [
        "mint-private.jwk",
        "mint-public.jwk.json",
        "holder-private.jwk",
        "holder-public.jwk.json",
    ] {
        match fs::symlink_metadata(keys.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!("refusing to replace existing private dev key material"),
            Err(error) => return Err(error).context("inspecting private dev key material"),
        }
    }
    let (_mint_private, staged_mint_public) =
        keygen::generate_dev_keypair(keys, "mint-private.jwk", "mint-public.jwk.json")?;
    let mint_public = publish_thumbprint_named_public_jwk(&staged_mint_public)?;
    // Keep one disposable holder pair beside the other private local session
    // keys so wallet-binding examples need no extra setup. Evidence does not
    // consume the private half and neither half leaves supervised dev state.
    let _holder =
        keygen::generate_dev_keypair(keys, "holder-private.jwk", "holder-public.jwk.json")?;
    Ok(mint_public)
}

fn publish_thumbprint_named_public_jwk(staged: &Path) -> Result<PathBuf> {
    let bytes = read_owner_file(staged, 16 * 1024)?;
    let encoded = std::str::from_utf8(&bytes).context("generated public JWK is not UTF-8")?;
    let public = registry_platform_crypto::PublicJwk::parse(encoded)
        .context("generated public JWK failed validation")?;
    let kid = public
        .kid
        .as_deref()
        .ok_or_else(|| anyhow!("generated public JWK has no key id"))?;
    if public
        .jkt()
        .context("generated public JWK has no thumbprint")?
        != kid
    {
        bail!("generated public JWK key id is not its RFC 7638 thumbprint");
    }
    let published = staged
        .parent()
        .ok_or_else(|| anyhow!("generated public JWK has no parent directory"))?
        .join(format!("{kid}.jwk.json"));
    let mut file = create_private_file(&published)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::remove_file(staged).context("failed to remove the staged public JWK")?;
    Ok(published)
}

fn stop_dev(project: &Path) -> Result<ExitCode> {
    let project = canonical_project(project)?;
    let generated_root = or_inactive_session(existing_private_generated_root(&project))?;
    let _lifecycle = lock_lifecycle(&generated_root)?;
    let dev_root = generated_root.join("dev");
    or_inactive_session(validate_private_directory(&dev_root))?;
    let state = or_inactive_session(read_state(&dev_root.join("state.json")))?;
    if state.project != project || !matches!(state.status, DevStatus::Starting | DevStatus::Ready) {
        bail!("local development state is not an active session");
    }
    let socket = dev_root.join(CONTROL_SOCKET_NAME);
    validate_control_socket(&socket)?;
    std::env::set_current_dir(&dev_root)
        .context("failed to enter the private local development directory")?;
    let mut stream = UnixStream::connect(CONTROL_SOCKET_NAME)
        .context("the recorded local supervisor is unavailable; refusing PID-based recovery")?;
    stream.set_read_timeout(Some(Duration::from_secs(SHUTDOWN_TIMEOUT_SECONDS + 5)))?;
    stream.write_all(b"stop\n")?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    (&mut stream).take(64).read_to_end(&mut response)?;
    if response != b"stopped\n" {
        bail!("the local supervisor did not confirm a clean stop");
    }
    let stopped = read_state(&dev_root.join("state.json"))?;
    if stopped.status != DevStatus::Stopped || stopped.caller.is_some() {
        bail!("the local supervisor did not publish the closed stopped state");
    }
    println!("Local Evidence stopped");
    Ok(ExitCode::SUCCESS)
}

/// Report the same refusal as a recorded but inactive session when the
/// generated root, dev directory, or dev state file is simply missing,
/// instead of letting the raw filesystem error reach the caller.
fn or_inactive_session<T>(result: Result<T>) -> Result<T> {
    match result {
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            bail!("local development state is not an active session")
        }
        other => other,
    }
}

fn supervisor_executable() -> Result<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("EVIDENCECTL_TEST_SUPERVISOR_BIN") {
        return Ok(PathBuf::from(path));
    }
    std::env::current_exe().context("failed to resolve evidencectl")
}

fn injected_supervisor_failure(stage: &str) -> Result<()> {
    #[cfg(debug_assertions)]
    if std::env::var("EVIDENCECTL_TEST_SUPERVISOR_FAIL_STAGE").as_deref() == Ok(stage) {
        bail!("injected local supervisor failure at {stage}");
    }
    let _ = stage;
    Ok(())
}

fn publish_test_supervisor_pid() -> Result<()> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("EVIDENCECTL_TEST_SUPERVISOR_PID_FILE") {
        let path = PathBuf::from(path);
        let mut file = create_private_file(&path)?;
        writeln!(file, "{}", std::process::id())?;
        file.sync_all()?;
    }
    Ok(())
}

fn publish_test_service_pid(name: &str, child: &Child) -> Result<()> {
    #[cfg(debug_assertions)]
    if let Some(directory) = std::env::var_os("EVIDENCECTL_TEST_SERVICE_PID_DIRECTORY") {
        let directory = PathBuf::from(directory);
        validate_private_directory(&directory)?;
        let mut file = create_private_file(&directory.join(format!("{name}.pid")))?;
        writeln!(file, "{}", child.id())?;
        file.sync_all()?;
    }
    let _ = (name, child);
    Ok(())
}

fn publish_supervisor_failure(dev_root: &Path, kind: FailureKind) -> Result<()> {
    let state_path = dev_root.join("state.json");
    let mut state = read_state(&state_path)?;
    if !matches!(state.status, DevStatus::Failed | DevStatus::Stopped) {
        state.status = DevStatus::Failed;
        state.failure = Some(kind);
        replace_state(&state_path, &state)?;
    }
    let socket = dev_root.join(CONTROL_SOCKET_NAME);
    match fs::symlink_metadata(&socket) {
        Ok(_) => remove_control_socket(&socket),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn supervise(args: SupervisorArgs, terminate: &AtomicBool) -> Result<()> {
    ensure_supervisor_active(terminate)?;
    validate_private_directory(&args.dev_root)?;
    let dev_root = fs::canonicalize(&args.dev_root)?;
    let state_path = dev_root.join("state.json");
    let mut state = read_state(&state_path)?;
    if state.status != DevStatus::Starting || state.runtime_path != dev_root.join("runtime.yaml") {
        bail!("supervisor state is not a fresh compiled local session");
    }
    let project = dev_root
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow!("local development root is outside a project"))?;
    validate_closed_state(&state, project, &dev_root)?;

    std::env::set_current_dir(&dev_root)
        .context("failed to enter the private local development directory")?;
    let socket_path = dev_root.join(CONTROL_SOCKET_NAME);
    injected_supervisor_failure("before-socket")?;
    let listener = UnixListener::bind(CONTROL_SOCKET_NAME)
        .context("failed to bind the private local control socket")?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    validate_control_socket(&socket_path)?;
    listener.set_nonblocking(true)?;
    injected_supervisor_failure("after-socket")?;

    let mut children = OwnedChildren::default();
    children.mint = Some(
        match spawn_service(
            &args.mint_bin,
            &["serve", "--config"],
            &dev_root.join("generated/mint.yaml"),
            &dev_root.join("logs/mint.log"),
        ) {
            Ok(child) => child,
            Err(error) => {
                eprintln!("Mint start failed before child ownership: {error:#}");
                return fail_before_evidence(&state_path, &mut state, FailureKind::MintStart);
            }
        },
    );
    publish_test_service_pid(
        "mint",
        children.mint.as_ref().expect("Mint child was assigned"),
    )?;
    if wait_for_http(
        &format!("{}/.well-known/jwks.json", state.mint_origin),
        children.mint.as_mut().expect("Mint child was assigned"),
        HttpProof::MintEs256Key,
        args.ready_timeout_seconds,
        terminate,
    )
    .is_err()
    {
        eprintln!("Mint did not reach its fixed local JWKS readiness proof");
        return fail_before_evidence(&state_path, &mut state, FailureKind::MintReadiness);
    }

    children.evidence = Some(
        match spawn_evidence(
            &args.evidence_bin,
            &state.runtime_path,
            &dev_root.join("logs/evidence.log"),
        ) {
            Ok(child) => child,
            Err(error) => {
                eprintln!("Evidence start failed: {error:#}");
                return fail_before_evidence(&state_path, &mut state, FailureKind::EvidenceStart);
            }
        },
    );
    publish_test_service_pid(
        "evidence",
        children
            .evidence
            .as_ref()
            .expect("Evidence child was assigned"),
    )?;
    if wait_for_http(
        &format!("{}/ready", state.evidence_origin),
        children
            .evidence
            .as_mut()
            .expect("Evidence child was assigned"),
        HttpProof::EvidenceReady,
        args.ready_timeout_seconds,
        terminate,
    )
    .is_err()
    {
        eprintln!("Evidence did not reach its fixed local readiness proof");
        return fail_before_evidence(&state_path, &mut state, FailureKind::EvidenceReadiness);
    }

    state.status = DevStatus::Ready;
    injected_supervisor_failure("before-ready-state")?;
    replace_state(&state_path, &state)?;
    let outcome = supervisor_loop(
        &listener,
        children
            .evidence
            .as_mut()
            .expect("Evidence child was assigned"),
        children.mint.as_mut().expect("Mint child was assigned"),
        terminate,
    )
    .unwrap_or(SupervisorOutcome::Failed(FailureKind::Supervisor));
    state.status = DevStatus::Stopping;
    let stopping_state = replace_state(&state_path, &state);
    children.stop();
    stopping_state?;

    match outcome {
        SupervisorOutcome::Stop(mut stream) => {
            remove_control_socket(&socket_path)?;
            remove_private_tree(&dev_root.join("generated"))?;
            remove_private_tree(&dev_root.join("logs"))?;
            state.status = DevStatus::Stopped;
            state.caller = None;
            state.failure = None;
            replace_state(&state_path, &state)?;
            stream.write_all(b"stopped\n")?;
            Ok(())
        }
        SupervisorOutcome::Failed(kind) => {
            remove_control_socket(&socket_path)?;
            state.status = DevStatus::Failed;
            state.failure = Some(kind);
            replace_state(&state_path, &state)
        }
    }
}

fn fail_before_evidence(state_path: &Path, state: &mut DevState, kind: FailureKind) -> Result<()> {
    state.status = DevStatus::Failed;
    state.failure = Some(kind);
    replace_state(state_path, state)
}

enum SupervisorOutcome {
    Stop(UnixStream),
    Failed(FailureKind),
}

fn supervisor_loop(
    listener: &UnixListener,
    evidence: &mut Child,
    mint: &mut Child,
    terminate: &AtomicBool,
) -> Result<SupervisorOutcome> {
    loop {
        if terminate.load(Ordering::Relaxed) {
            return Ok(SupervisorOutcome::Failed(FailureKind::SupervisorSignal));
        }
        if evidence.try_wait()?.is_some() || mint.try_wait()?.is_some() {
            return Ok(SupervisorOutcome::Failed(FailureKind::ChildExited));
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                let mut request = Vec::new();
                (&mut stream).take(16).read_to_end(&mut request)?;
                if request == b"stop\n" {
                    return Ok(SupervisorOutcome::Stop(stream));
                }
                if request == b"reload-mint\n" {
                    signal_child_with(mint, rustix::process::Signal::HUP)?;
                    stream.write_all(b"reload-requested\n")?;
                    continue;
                }
                let _ = stream.write_all(b"invalid\n");
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return Ok(SupervisorOutcome::Failed(FailureKind::Supervisor)),
        }
    }
}

fn spawn_service(binary: &Path, prefix: &[&str], value: &Path, log: &Path) -> Result<Child> {
    let stdout = create_private_file(log)?;
    let stderr = stdout.try_clone()?;
    Command::new(binary)
        .args(prefix)
        .arg(value)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to start {}", binary.display()))
}

fn spawn_evidence(binary: &Path, runtime: &Path, log: &Path) -> Result<Child> {
    let stdout = create_private_file(log)?;
    let stderr = stdout.try_clone()?;
    Command::new(binary)
        .arg("--runtime")
        .arg(runtime)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to start {}", binary.display()))
}

enum HttpProof {
    MintEs256Key,
    EvidenceReady,
}

fn wait_for_http(
    url: &str,
    child: &mut Child,
    proof: HttpProof,
    seconds: u64,
    terminate: &AtomicBool,
) -> Result<()> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(250))
        .timeout_read(Duration::from_secs(2))
        .timeout_write(Duration::from_millis(500))
        .redirects(0)
        .build();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        ensure_supervisor_active(terminate)?;
        if child.try_wait()?.is_some() {
            bail!("service exited before readiness");
        }
        if let Ok(response) = agent.get(url).call() {
            let mut bytes = Vec::new();
            response
                .into_reader()
                .take(MAX_HTTP_BODY_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 <= MAX_HTTP_BODY_BYTES {
                let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                let matches = match proof {
                    HttpProof::MintEs256Key => value["keys"].as_array().is_some_and(|keys| {
                        keys.iter().any(|key| {
                            key["kty"] == "EC"
                                && key["crv"] == "P-256"
                                && key["alg"] == "ES256"
                                && key["kid"].as_str().is_some_and(|kid| kid.len() == 43)
                        })
                    }),
                    HttpProof::EvidenceReady => value == json!({"status": "ready"}),
                };
                if matches && child.try_wait()?.is_none() {
                    return Ok(());
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("service readiness timed out")
}

fn ensure_supervisor_active(terminate: &AtomicBool) -> Result<()> {
    if terminate.load(Ordering::Relaxed) {
        bail!("local supervisor received a termination signal");
    }
    Ok(())
}

fn stop_children(evidence: Option<&mut Child>, mint: Option<&mut Child>) {
    let mut evidence = evidence;
    let mut mint = mint;
    if let Some(child) = evidence.as_deref_mut() {
        let _ = signal_child(child);
    }
    if let Some(child) = mint.as_deref_mut() {
        let _ = signal_child(child);
    }
    let deadline = Instant::now() + Duration::from_secs(SHUTDOWN_TIMEOUT_SECONDS);
    loop {
        let evidence_done = evidence
            .as_deref_mut()
            .is_none_or(|child| child.try_wait().ok().flatten().is_some());
        let mint_done = mint
            .as_deref_mut()
            .is_none_or(|child| child.try_wait().ok().flatten().is_some());
        if evidence_done && mint_done {
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    for child in [evidence, mint].into_iter().flatten() {
        // A child that ignores TERM is killed only after the bounded graceful
        // deadline. Child::kill is SIGKILL on Unix and cannot run child cleanup.
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn signal_child(child: &Child) -> Result<()> {
    signal_child_with(child, rustix::process::Signal::TERM)
}

fn signal_child_with(child: &Child, signal: rustix::process::Signal) -> Result<()> {
    let raw = i32::try_from(child.id()).context("child identifier is not a process id")?;
    let pid =
        rustix::process::Pid::from_raw(raw).ok_or_else(|| anyhow!("invalid child process"))?;
    rustix::process::kill_process(pid, signal)?;
    Ok(())
}

fn wait_for_supervisor_ready(dev_root: &Path, child: &mut Child, seconds: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(seconds + 5);
    loop {
        let state = read_state(&dev_root.join("state.json"))?;
        match state.status {
            DevStatus::Ready => return Ok(()),
            DevStatus::Failed => {
                let _ = child.wait();
                let diagnostic = read_owner_file(&dev_root.join("logs/supervisor.log"), 4096)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .unwrap_or_default();
                bail!(
                    "local services failed during startup ({:?}){}{}",
                    state.failure,
                    if diagnostic.is_empty() { "" } else { ": " },
                    diagnostic.trim()
                );
            }
            DevStatus::Starting if Instant::now() < deadline => {}
            _ => bail!("local supervisor did not publish readiness"),
        }
        if child.try_wait()?.is_some() {
            bail!("local supervisor exited before readiness");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn abort_start(supervisor: &mut Child) -> Result<()> {
    if supervisor.try_wait()?.is_some() {
        return Ok(());
    }
    signal_child(supervisor).context("failed to terminate the local supervisor after startup")?;
    // SIGKILL is deliberately outside this tutorial lifecycle because it
    // cannot run the supervisor's child cleanup. TERM is bounded by the
    // supervisor's own child shutdown deadline, and the creating command
    // waits for that cleanup instead of abandoning the owner process.
    supervisor.wait()?;
    Ok(())
}

fn mint_config(
    compiled: &CompiledProject,
    mint_public: &Path,
    secret_root: &Path,
    ports: LocalServicePorts,
) -> Value {
    let mint_origin = ports.mint_origin();
    let token_url = format!("{mint_origin}/token");
    json!({
        "version": 1,
        "validationMode": "supervised-local-development",
        "issuer": mint_origin,
        "listener": {
            "address": "127.0.0.1",
            "port": ports.mint,
            "maximumRequestBytes": 16384,
            "requestTimeoutMilliseconds": 5000,
        },
        "signing": {
            "algorithm": "ES256",
            "activePublicJwkFile": mint_public,
            "publishedPublicJwkFiles": [],
            "revokedKeyIds": [],
            "jwksPath": "/.well-known/jwks.json",
        },
        "signer": {
            "kind": "local-jwk",
            "privateKeyRef": "secret:file/mint-private.jwk",
        },
        "secretProviders": {"file": {"root": secret_root}},
        "audit": {
            "path": "audit/mint.jsonl",
            // Mint rotates a sealed segment at this threshold. A local
            // tutorial session never reaches it, and the value matches the
            // documented deployment example.
            "maximumFileBytes": 1_073_741_824u64,
            "hashKeyRef": "secret:file/mint-audit-hmac-key",
            "hashKeyVersion": 1,
        },
        "accessTokens": {
            "audiences": [compiled.local_audience],
            "lifetimeSeconds": 300,
            "claims": {
                "principal": "sub",
                "requesterTags": "evidence_tags",
                "evidenceAudience": "evidence_audience",
                "grantId": "evidence_grant_id",
                "grantAuthority": "evidence_authority",
            },
        },
        "clientAssertion": {
            "audience": token_url,
            "maximumLifetimeSeconds": 120,
            "algorithms": ["ES256"],
            "replayCacheEntries": 256,
        },
        "clients": {"directory": "clients"},
    })
}

fn generate_mint_audit_key(path: &Path) -> Result<()> {
    let mut entropy = Zeroizing::new([0_u8; 32]);
    getrandom::fill(entropy.as_mut_slice())
        .context("failed to generate local Mint audit key material")?;
    let key = Zeroizing::new(URL_SAFE_NO_PAD.encode(entropy.as_slice()));
    let mut file = create_private_file(path)?;
    file.write_all(key.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn local_caller_registration(compiled: &CompiledProject, caller_public: Value) -> Value {
    json!({
        "clientId": CALLER_ID,
        "principal": "urn:registrystack:evidence:local:caller",
        "evidenceAudience": compiled.caller_evidence_audience,
        "requesterTags": [compiled.requester_tag],
        "keys": [caller_public],
    })
}

impl From<&CompiledAccessPolicy> for AccessPolicyState {
    fn from(compiled: &CompiledAccessPolicy) -> Self {
        Self {
            id: compiled.id.clone(),
            requester_tag: compiled.requester_tag.clone(),
            questions: compiled.questions.clone(),
        }
    }
}

impl From<&CompiledQuestion> for QuestionState {
    fn from(compiled: &CompiledQuestion) -> Self {
        Self {
            alias: compiled.question_alias.clone(),
            requirement_uri: compiled.requirement_uri.clone(),
            purpose: compiled.purpose.clone(),
            subjects: compiled
                .subjects
                .iter()
                .map(|subject| SubjectState {
                    role: subject.role.clone(),
                    selector_profile: subject.selector_profile.clone(),
                    selector_field: subject.selector_field.clone(),
                })
                .collect(),
            concepts: compiled
                .concepts
                .iter()
                .map(|concept| ConceptState {
                    alias: concept.concept_alias.clone(),
                    uri: concept.concept_uri.clone(),
                    form: match concept.concept_form {
                        CompiledConceptForm::Boolean => "boolean".to_owned(),
                        CompiledConceptForm::ControlledCategory => "controlled-category".to_owned(),
                        CompiledConceptForm::BoundedInteger => "bounded-integer".to_owned(),
                        CompiledConceptForm::Structured => "reviewed-structured-value".to_owned(),
                    },
                })
                .collect(),
        }
    }
}

fn run_check(binary: &Path, prefix: &[&str], config: &Path, name: &str) -> Result<()> {
    let status = Command::new(binary)
        .args(prefix)
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to run {name} check"))?;
    if !status.success() {
        bail!("{name} rejected the generated local configuration");
    }
    Ok(())
}

#[allow(dead_code)] // Shared by the immediately following request and audit slices.
pub(crate) fn resolve_tool_binary(
    name: &str,
    explicit: Option<&Path>,
    test_env: &str,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let current = std::env::current_exe().context("failed to resolve evidencectl")?;
    if let Some(sibling) = current.parent().map(|parent| parent.join(name)) {
        if sibling.is_file() {
            return Ok(sibling);
        }
    }
    if let Some(path) = std::env::var_os(test_env) {
        return Ok(PathBuf::from(path));
    }
    Ok(PathBuf::from(name))
}

fn canonical_tool_binary(path: PathBuf) -> Result<PathBuf> {
    fs::canonicalize(&path)
        .with_context(|| format!("failed to resolve tool binary {}", path.display()))
}

fn canonical_project(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("project {} is unavailable", path.display()))?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("project is not a real directory");
    }
    require_owner(&metadata, "project directory")?;
    Ok(canonical)
}

fn ensure_private_generated_root(project: &Path) -> Result<PathBuf> {
    let root = project.join(".evidence");
    match fs::symlink_metadata(&root) {
        Ok(metadata) => validate_private_directory_metadata(&root, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(&root)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn existing_private_generated_root(project: &Path) -> Result<PathBuf> {
    let root = project.join(".evidence");
    validate_private_directory(&root)?;
    Ok(root)
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(PRIVATE_DIR_MODE);
    builder
        .create(path)
        .with_context(|| format!("failed to create private directory {}", path.display()))?;
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private directory {}", path.display()))?;
    validate_private_directory_metadata(path, &metadata)
}

fn validate_private_directory_metadata(path: &Path, metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("private state {} is not a real directory", path.display());
    }
    require_owner(metadata, "private directory")?;
    if metadata.mode() & 0o777 != PRIVATE_DIR_MODE {
        bail!("private state {} must have mode 0700", path.display());
    }
    Ok(())
}

fn lock_lifecycle(root: &Path) -> Result<LifecycleLock> {
    let path = root.join("lifecycle.lock");
    let file = match create_private_rw_file(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => open_owner_rw(&path)?,
        Err(error) => return Err(error.into()),
    };
    require_owner_file(&path)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .context("another local lifecycle operation is already active")?;
    Ok(LifecycleLock { _file: file })
}

#[allow(dead_code)] // Consumed by the access-management CLI slice.
pub(crate) fn lock_project_lifecycle(project: &Path) -> Result<LifecycleLock> {
    let project = canonical_project(project)?;
    let generated_root = ensure_private_generated_root(&project)?;
    lock_lifecycle(&generated_root)
}

fn create_private_rw_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
}

fn open_owner_rw(path: &Path) -> Result<File> {
    require_owner_file(path)?;
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(fd);
    require_owner_metadata(&file.metadata()?, "lifecycle lock")?;
    Ok(file)
}

fn require_owner_file(path: &Path) -> Result<Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        bail!("owner-only state is not a single-link regular file");
    }
    require_owner_metadata(&metadata, "owner-only state")?;
    Ok(metadata)
}

#[allow(dead_code)]
fn require_owned_regular_file(path: &Path, mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        bail!("ready session path is not a single-link regular file");
    }
    require_owner(&metadata, "ready session file")?;
    if metadata.mode() & 0o777 != mode {
        bail!("ready session file has the wrong private mode");
    }
    Ok(())
}

fn require_owner_metadata(metadata: &Metadata, label: &str) -> Result<()> {
    require_owner(metadata, label)?;
    if metadata.mode() & 0o777 != PRIVATE_FILE_MODE {
        bail!("{label} must have mode 0600");
    }
    Ok(())
}

fn require_owner(metadata: &Metadata, label: &str) -> Result<()> {
    if metadata.uid() != rustix::process::getuid().as_raw() {
        bail!("{label} is not owned by the current user");
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    require_owner_file(path)?;
    Ok(file)
}

fn write_private_yaml(path: &Path, value: &Value) -> Result<()> {
    let mut text = serde_norway::to_string(value)?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let mut file = create_private_file(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn read_owner_json(path: &Path, maximum: u64) -> Result<Value> {
    let bytes = read_owner_file(path, maximum)?;
    serde_json::from_slice(&bytes).context("owner-only JSON is invalid")
}

fn read_owner_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let before = require_owner_file(path)?;
    if before.len() > maximum {
        bail!("owner-only state exceeds its size bound");
    }
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    let mut file = File::from(fd);
    let opened = file.metadata()?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        bail!("owner-only state changed while opening");
    }
    let mut bytes = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("owner-only state exceeds its size bound");
    }
    Ok(bytes)
}

fn write_new_state(path: &Path, state: &DevState) -> Result<()> {
    let bytes = serde_json::to_vec(state)?;
    let mut file = create_private_file(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn replace_state(path: &Path, state: &DevState) -> Result<()> {
    require_owner_file(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("state has no parent"))?;
    validate_private_directory(parent)?;
    let mut random = [0_u8; 9];
    getrandom::fill(&mut random)?;
    let temporary = parent.join(format!(".state-{}", URL_SAFE_NO_PAD.encode(random)));
    write_new_state(&temporary, state)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn read_state(path: &Path) -> Result<DevState> {
    let bytes = read_owner_file(path, MAX_STATE_BYTES)?;
    let state: DevState = serde_json::from_slice(&bytes).context("local state is invalid")?;
    if state.schema != STATE_SCHEMA {
        bail!("local state schema is unsupported");
    }
    Ok(state)
}

fn validate_control_socket(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        bail!("local control path is not a Unix socket");
    }
    require_owner_metadata(&metadata, "local control socket")
}

fn remove_control_socket(path: &Path) -> Result<()> {
    validate_control_socket(path)?;
    fs::remove_file(path)?;
    Ok(())
}

fn remove_private_tree(path: &Path) -> Result<()> {
    validate_private_directory(path)?;
    fs::remove_dir_all(path).with_context(|| format!("failed to remove {}", path.display()))
}

fn cleanup_new_dev_root(dev_root: &Path) -> Result<()> {
    validate_private_directory(dev_root)?;
    let socket = dev_root.join("control.sock");
    match fs::symlink_metadata(&socket) {
        Ok(_) => remove_control_socket(&socket)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    make_tree_removable(dev_root)?;
    fs::remove_dir_all(dev_root).context("failed to clean incomplete local development state")
}

fn make_tree_removable(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        require_owner(&metadata, "incomplete local state")?;
        if metadata.file_type().is_symlink() {
            bail!("incomplete local state contains a symlink");
        }
        if metadata.is_dir() {
            make_tree_removable(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
        } else if metadata.is_file() {
            fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
        } else {
            bail!("incomplete local state contains an unexpected entry");
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    Ok(())
}

fn ready_question(question: QuestionState) -> ReadyQuestionState {
    ReadyQuestionState {
        alias: question.alias,
        requirement_uri: question.requirement_uri,
        purpose: question.purpose,
        subjects: question
            .subjects
            .into_iter()
            .map(|subject| ReadySubjectState {
                role: subject.role,
                selector_profile: subject.selector_profile,
                selector_field: subject.selector_field,
            })
            .collect(),
        concepts: question
            .concepts
            .into_iter()
            .map(|concept| ReadyConceptState {
                alias: concept.alias,
                uri: concept.uri,
                form: concept.form,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled(runtime: &Path) -> CompiledProject {
        CompiledProject {
            runtime_path: runtime.to_path_buf(),
            questions: vec![CompiledQuestion {
                question_alias: "adult-status".to_owned(),
                requirement_uri: "urn:registrystack:evidence:local:requirement:adult-status"
                    .to_owned(),
                purpose: "age-check".to_owned(),
                subjects: vec![crate::authoring::CompiledSubject {
                    role: "person".to_owned(),
                    selector_profile: "local-subject-adult-status-v1".to_owned(),
                    selector_field: "person_id".to_owned(),
                }],
                concepts: vec![crate::authoring::CompiledConcept {
                    concept_alias: "is_adult".to_owned(),
                    concept_uri: "urn:registrystack:evidence:local:concept:adult-status:is_adult"
                        .to_owned(),
                    concept_form: CompiledConceptForm::Boolean,
                }],
            }],
            local_audience: "registry-evidence-local".to_owned(),
            requester_tag: "local-caller".to_owned(),
            caller_evidence_audience: LOCAL_CALLER_EVIDENCE_AUDIENCE.to_owned(),
            access_policies: Vec::new(),
        }
    }

    #[test]
    fn mint_documents_are_closed_and_derive_authority_from_the_compiler() {
        let compiled = compiled(Path::new("/private/runtime.yaml"));
        let config = mint_config(
            &compiled,
            Path::new("/private/mint-public.jwk.json"),
            Path::new("/private"),
            LocalServicePorts::default(),
        );
        let caller = local_caller_registration(
            &compiled,
            json!({"kty":"EC","crv":"P-256","kid":"caller","alg":"ES256","x":"public","y":"public"}),
        );
        assert_eq!(config["validationMode"], "supervised-local-development");
        assert_eq!(config["issuer"], "http://127.0.0.1:8081");
        assert_eq!(
            config["listener"],
            json!({
                "address": "127.0.0.1", "port": 8081,
                "maximumRequestBytes": 16384, "requestTimeoutMilliseconds": 5000
            })
        );
        assert_eq!(
            config["accessTokens"]["audiences"],
            json!([compiled.local_audience])
        );
        assert_eq!(
            config["audit"],
            json!({
                "path": "audit/mint.jsonl",
                "maximumFileBytes": 1_073_741_824u64,
                "hashKeyRef": "secret:file/mint-audit-hmac-key",
                "hashKeyVersion": 1,
            })
        );
        assert_eq!(caller["requesterTags"], json!([compiled.requester_tag]));
        assert_eq!(
            caller["evidenceAudience"],
            compiled.caller_evidence_audience
        );
        assert!(caller.to_string().find("private").is_none());
    }

    #[test]
    fn supervised_dev_generates_create_only_private_p256_mint_and_holder_pairs() {
        let root = tempfile::tempdir().expect("tempdir");
        let keys = root.path().join("keys");
        let mint_public = generate_service_and_holder_keys(&keys).expect("generate dev keys");

        for name in ["mint", "holder"] {
            let private_path = keys.join(format!("{name}-private.jwk"));
            let private = registry_platform_crypto::PrivateJwk::parse(
                &fs::read_to_string(&private_path).expect("private JWK"),
            )
            .expect("private JWK parses");
            let public_path = if name == "mint" {
                assert_eq!(
                    mint_public.file_name().and_then(|value| value.to_str()),
                    private
                        .kid
                        .as_deref()
                        .map(|kid| format!("{kid}.jwk.json"))
                        .as_deref()
                );
                mint_public.clone()
            } else {
                keys.join("holder-public.jwk.json")
            };
            let public = registry_platform_crypto::PublicJwk::parse(
                &fs::read_to_string(&public_path).expect("public JWK"),
            )
            .expect("public JWK parses");
            assert_eq!(private.kty, "EC");
            assert_eq!(private.crv.as_deref(), Some("P-256"));
            assert_eq!(private.alg.as_deref(), Some("ES256"));
            assert_eq!(private.kid, public.kid);
            assert_eq!(
                fs::metadata(private_path)
                    .expect("private JWK metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                PRIVATE_FILE_MODE
            );
            assert_eq!(
                fs::metadata(public_path)
                    .expect("public JWK metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                PRIVATE_FILE_MODE
            );
        }
        assert!(!keys.join("mint-public.jwk.json").exists());

        let before = fs::read(keys.join("holder-private.jwk")).expect("holder private JWK");
        assert!(generate_service_and_holder_keys(&keys).is_err());
        assert_eq!(
            fs::read(keys.join("holder-private.jwk")).expect("holder private JWK"),
            before,
            "a repeated dev setup must not replace disposable keys"
        );
    }

    #[test]
    fn structured_concepts_use_the_runtime_value_form_in_lifecycle_state() {
        let mut compiled = compiled(Path::new("/private/runtime.yaml"));
        compiled.questions[0].concepts[0].concept_form = CompiledConceptForm::Structured;

        let state = QuestionState::from(&compiled.questions[0]);

        assert_eq!(state.concepts[0].form, "reviewed-structured-value");
        assert!(valid_question_state(&state));
    }

    #[test]
    fn private_state_rejects_public_directories_files_and_symlinks() {
        let root = tempfile::tempdir().expect("tempdir");
        let public = root.path().join("public");
        fs::create_dir(&public).expect("directory");
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).expect("mode");
        assert!(validate_private_directory(&public).is_err());

        let private = root.path().join("private");
        create_private_directory(&private).expect("private directory");
        let state = private.join("state.json");
        fs::write(&state, b"{}").expect("state");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(read_state(&state).is_err());

        let link = root.path().join("link");
        symlink(&private, &link).expect("symlink");
        assert!(validate_private_directory(&link).is_err());
    }

    #[test]
    fn ready_and_stopped_handoffs_validate_the_closed_lifecycle_state() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let project = temporary.path().join("project");
        fs::create_dir(&project).expect("project");
        let project = fs::canonicalize(project).expect("canonical project");
        let generated = project.join(".evidence");
        create_private_directory(&generated).expect("generated root");
        let dev = generated.join("dev");
        create_private_directory(&dev).expect("dev root");
        create_private_directory(&dev.join("generated")).expect("generated");
        create_private_directory(&dev.join("generated/keys")).expect("keys");

        let runtime = dev.join("runtime.yaml");
        drop(create_private_file(&runtime).expect("runtime"));
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o400)).expect("seal runtime");
        let caller_key = dev.join("generated/keys/caller-private.jwk");
        drop(create_private_file(&caller_key).expect("caller key"));
        let socket = dev.join("control.sock");
        let listener = UnixListener::bind(&socket).expect("control socket");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("socket mode");

        let compiled = compiled(&runtime);
        let bundle = dev.join("bundle");
        create_private_directory(&bundle).expect("bundle");
        let bundle_path = bundle.join("evidence.yaml");
        fs::write(
            &bundle_path,
            br#"selectorProfiles:
  local-subject-adult-status-v1:
    fields:
      person_id: {type: string}
authorityProfiles:
  local-caller:
    kind: explicit-request
    requesterTags: [local-caller]
    grants:
      - requirement: urn:registrystack:evidence:local:requirement:adult-status
        purpose: age-check
        audienceFrom: authenticated-requester
        responseFormats: [signed-jws]
        subjects:
          - role: person
            selectorProfile: local-subject-adult-status-v1
            valueOrigin: request
requirements:
  - id: urn:registrystack:evidence:local:requirement:adult-status
    purposes: [age-check]
    subjectRoles:
      - role: person
        selectorProfiles: [local-subject-adult-status-v1]
    concepts:
      - id: urn:registrystack:evidence:local:concept:adult-status:is_adult
        form: boolean
"#,
        )
        .expect("bundle config");
        fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o400))
            .expect("seal bundle config");
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o500)).expect("seal bundle");
        let mut state = DevState {
            schema: STATE_SCHEMA.to_owned(),
            status: DevStatus::Ready,
            project: project.clone(),
            runtime_path: runtime.clone(),
            evidence_origin: local_origin(8080),
            mint_origin: local_origin(8081),
            token_url: format!("{}/token", local_origin(8081)),
            access_token_audience: compiled.local_audience.clone(),
            caller: Some(CallerState {
                client_id: CALLER_ID.to_owned(),
                private_key_path: caller_key,
                assertion_audience: format!("{}/token", local_origin(8081)),
                evidence_audience: compiled.caller_evidence_audience.clone(),
                requester_tag: compiled.requester_tag.clone(),
            }),
            access_policies: Vec::new(),
            questions: compiled.questions.iter().map(QuestionState::from).collect(),
            failure: None,
        };
        write_new_state(&dev.join("state.json"), &state).expect("ready state");
        let ready = load_ready_state(&project).expect("ready handoff");
        assert_eq!(ready.runtime_path, runtime);
        assert_eq!(ready.questions[0].alias, "adult-status");
        assert!(ready.caller.is_some());
        assert!(ready.access_policies.is_empty());
        assert!(
            clean_dev(&project).is_err(),
            "active state is never removed"
        );
        assert!(dev.is_dir(), "refused cleanup preserves active state");

        let valid_ready = state.clone();
        state.access_token_audience = "tampered-audience".to_owned();
        replace_state(&dev.join("state.json"), &state).expect("tampered state");
        assert!(load_ready_state(&project).is_err());
        state = valid_ready.clone();
        state.questions[0].requirement_uri = "urn:tampered".to_owned();
        replace_state(&dev.join("state.json"), &state).expect("tampered canonical value");
        assert!(load_ready_state(&project).is_err());
        state = valid_ready.clone();
        state.questions[0].concepts[0].uri = "urn:tampered".to_owned();
        replace_state(&dev.join("state.json"), &state).expect("tampered concept");
        assert!(load_ready_state(&project).is_err());
        state = valid_ready;
        replace_state(&dev.join("state.json"), &state).expect("restore ready state");

        let policy_questions = vec!["adult-status".to_owned()];
        let policy_tag =
            access_policy_requester_tag("age-checks", &policy_questions).expect("policy tag");
        let mut explicit_bundle: Value =
            serde_norway::from_slice(&fs::read(&bundle_path).expect("read implicit bundle"))
                .expect("parse implicit bundle");
        explicit_bundle["authorityProfiles"] = Value::Object(serde_json::Map::from_iter([(
            policy_tag.clone(),
            json!({
                "kind": "explicit-request",
                "requesterTags": [policy_tag],
                "grants": [{
                    "requirement": "urn:registrystack:evidence:local:requirement:adult-status",
                    "purpose": "age-check",
                    "audienceFrom": "authenticated-requester",
                    "responseFormats": ["signed-jws"],
                    "subjects": [{
                        "role": "person",
                        "selectorProfile": "local-subject-adult-status-v1",
                        "valueOrigin": "request",
                    }],
                }],
            }),
        )]));
        fs::set_permissions(&bundle_path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("unseal bundle config for test update");
        fs::write(
            &bundle_path,
            serde_norway::to_string(&explicit_bundle).expect("explicit bundle YAML"),
        )
        .expect("write explicit bundle");
        fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o400))
            .expect("reseal bundle config");
        state.caller = None;
        state.access_policies = vec![AccessPolicyState {
            id: "age-checks".to_owned(),
            requester_tag: policy_tag.clone(),
            questions: policy_questions,
        }];
        replace_state(&dev.join("state.json"), &state).expect("explicit policy state");
        let explicit = load_ready_state(&project).expect("explicit ready handoff");
        assert!(explicit.caller.is_none());
        assert_eq!(explicit.access_policies[0].requester_tag, policy_tag);
        assert!(try_load_ready_state(&project)
            .expect("optional ready handoff")
            .is_some());
        let valid_explicit = state.clone();
        state.access_policies[0].id = "other-age-checks".to_owned();
        state.access_policies[0].requester_tag = access_policy_requester_tag(
            &state.access_policies[0].id,
            &state.access_policies[0].questions,
        )
        .expect("internally valid but unsealed policy tag");
        replace_state(&dev.join("state.json"), &state).expect("unsealed policy state");
        assert!(load_ready_state(&project).is_err());
        state = valid_explicit.clone();
        state.access_policies[0].requester_tag = "policy-v1-tampered".to_owned();
        replace_state(&dev.join("state.json"), &state).expect("tampered policy state");
        assert!(load_ready_state(&project).is_err());
        state = valid_explicit;
        replace_state(&dev.join("state.json"), &state).expect("restore explicit state");

        drop(listener);
        remove_control_socket(&socket).expect("remove socket");
        remove_private_tree(&dev.join("generated")).expect("remove generated");
        state.status = DevStatus::Stopped;
        state.caller = None;
        replace_state(&dev.join("state.json"), &state).expect("stopped state");
        let stopped = load_stopped_state(&project).expect("stopped handoff");
        assert!(try_load_ready_state(&project)
            .expect("stopped optional handoff")
            .is_none());
        assert_eq!(stopped.runtime_path, runtime);
        assert_eq!(stopped.questions[0].concepts[0].alias, "is_adult");

        clean_dev(&project).expect("clean stopped session");
        assert!(!dev.exists());
    }

    #[test]
    fn lifecycle_lock_is_nonblocking_and_owner_only() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().join("generated");
        create_private_directory(&root).expect("root");
        let _held = lock_lifecycle(&root).expect("first lock");
        assert!(lock_lifecycle(&root).is_err(), "second operation must fail");
        require_owner_file(&root.join("lifecycle.lock")).expect("private sentinel");
    }

    #[test]
    fn supervisor_reload_control_signals_only_mint_and_keeps_serving() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let socket = temporary.path().join("control.sock");
        let listener = UnixListener::bind(&socket).expect("control listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");

        let mint_script = temporary.path().join("mint-child");
        let mint_ready = temporary.path().join("mint-ready");
        fs::write(
            &mint_script,
            "#!/bin/sh\ntrap ':' HUP\nprintf ready > \"$MINT_READY\"\nwhile :; do sleep 1; done\n",
        )
        .expect("mint script");
        fs::set_permissions(&mint_script, fs::Permissions::from_mode(0o700)).expect("script mode");
        let mut mint = Command::new(&mint_script)
            .env("MINT_READY", &mint_ready)
            .spawn()
            .expect("mint child");
        let mut evidence = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("evidence child");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !mint_ready.is_file() {
            if let Some(status) = mint.try_wait().expect("mint child status") {
                panic!("mint child exited before installing its HUP handler: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "mint child did not install its HUP handler within 10 seconds"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let client_socket = socket.clone();
        let client = thread::spawn(move || {
            send_control_request(&client_socket, b"reload-mint\n", b"reload-requested\n")
                .expect("reload response");
            send_control_request(&client_socket, b"stop\n", b"stopped\n").expect("stop response");
        });
        let outcome = supervisor_loop(&listener, &mut evidence, &mut mint, &AtomicBool::new(false))
            .expect("supervisor loop");
        match outcome {
            SupervisorOutcome::Stop(mut stream) => {
                stream.write_all(b"stopped\n").expect("stop confirmation");
            }
            SupervisorOutcome::Failed(kind) => panic!("unexpected supervisor failure: {kind:?}"),
        }
        client.join().expect("control client");
        assert!(evidence.try_wait().expect("evidence status").is_none());
        assert!(mint.try_wait().expect("mint status").is_none());
        signal_child(&evidence).expect("stop evidence");
        signal_child(&mint).expect("stop mint");
        evidence.wait().expect("wait evidence");
        mint.wait().expect("wait mint");
    }

    #[test]
    fn control_requests_bridge_paths_longer_than_sockaddr_un() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let short = temporary.path().join("short");
        fs::create_dir(&short).expect("short directory");
        let socket = short.join(CONTROL_SOCKET_NAME);
        let listener = UnixListener::bind(&socket).expect("listener");

        let mut long_parent = temporary.path().join("long");
        fs::create_dir(&long_parent).expect("long root");
        for _ in 0..6 {
            long_parent = long_parent.join("component-with-a-deliberately-long-name");
            fs::create_dir(&long_parent).expect("long component");
        }
        let alias = long_parent.join("target");
        symlink(&short, &alias).expect("short target alias");
        let long_socket = alias.join(CONTROL_SOCKET_NAME);
        assert!(long_socket.as_os_str().as_encoded_bytes().len() > 104);
        assert!(UnixStream::connect(&long_socket).is_err());

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            (&mut stream)
                .take(16)
                .read_to_end(&mut request)
                .expect("request");
            assert_eq!(request, b"reload-mint\n");
            stream.write_all(b"reload-requested\n").expect("response");
        });
        send_control_request(&long_socket, b"reload-mint\n", b"reload-requested\n")
            .expect("long control path");
        server.join().expect("server");
    }

    #[test]
    fn stop_dev_reports_a_friendly_refusal_when_no_generated_root_exists() {
        let project = tempfile::tempdir().expect("tempdir");
        let error =
            stop_dev(project.path()).expect_err("stop must refuse a project with no dev session");
        let diagnostic = format!("{error:#}");
        assert_eq!(
            diagnostic,
            "local development state is not an active session"
        );
    }

    #[test]
    fn stop_dev_reports_a_friendly_refusal_when_dev_state_is_missing() {
        let project = tempfile::tempdir().expect("tempdir");
        let generated_root = project.path().join(".evidence");
        fs::create_dir(&generated_root).expect("create generated root");
        fs::set_permissions(
            &generated_root,
            fs::Permissions::from_mode(PRIVATE_DIR_MODE),
        )
        .expect("mode generated root");
        let dev_root = generated_root.join("dev");
        fs::create_dir(&dev_root).expect("create dev root");
        fs::set_permissions(&dev_root, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
            .expect("mode dev root");

        let error =
            stop_dev(project.path()).expect_err("stop must refuse a project with no dev state");
        let diagnostic = format!("{error:#}");
        assert_eq!(
            diagnostic,
            "local development state is not an active session"
        );
    }
}
