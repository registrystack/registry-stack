// SPDX-License-Identifier: Apache-2.0

/// The pre-1.0 project authoring contract. Runtime artifacts may still lower
/// this concise model into product-owned structures, but authored files never
/// expose those structures.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredIntegrationDocument {
    version: u8,
    id: String,
    revision: u32,
    #[serde(default)]
    source: Option<AuthoredSourceDeclaration>,
    input: BTreeMap<String, AuthoredInputDeclaration>,
    capability: AuthoredCapabilityDeclaration,
    outputs: AuthoredOutputsDeclaration,
    #[serde(default)]
    limits: Option<AuthoredLimitsDeclaration>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSourceDeclaration {
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    versions: AuthoredSourceVersions,
    auth: CredentialInterface,
    #[serde(default)]
    allow: Vec<AuthoredSourceAllowRule>,
    #[serde(default)]
    response: Option<AuthoredSourceResponse>,
    #[serde(default)]
    request_headers: Vec<String>,
    #[serde(default)]
    response_headers: Vec<String>,
    #[serde(default)]
    protocol: Option<AuthoredProtocolDeclaration>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSourceVersions {
    #[serde(default)]
    tested: Vec<String>,
    #[serde(default)]
    unverified: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredProtocolDeclaration {
    #[serde(default)]
    signed_dci: Option<AuthoredSignedDciDeclaration>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSignedDciDeclaration {
    profile: String,
    path: String,
    jwks_profile: String,
    sender: String,
    receiver: String,
    registry_type: String,
    record_type: String,
    locale: String,
    selectors: BTreeMap<String, AuthoredDciSelectorBinding>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredDciSelectorBinding {
    field: String,
    response_pointer: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSourceAllowRule {
    method: ReadMethod,
    path: String,
    #[serde(default)]
    semantics: Option<AuthoredRequestSemantics>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthoredRequestSemantics {
    ReadOnly,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSourceResponse {
    #[serde(default = "default_authored_response_format")]
    format: AuthoredResponseFormat,
    #[serde(default)]
    max_bytes: Option<AuthoredByteSize>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthoredResponseFormat {
    Json,
    Text,
}

fn default_authored_response_format() -> AuthoredResponseFormat {
    AuthoredResponseFormat::Json
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredInputDeclaration {
    role: AuthoredInputRole,
    #[serde(rename = "type")]
    input_type: AuthoredSchemaType,
    #[serde(default)]
    format: Option<AuthoredStringFormat>,
    #[serde(default, rename = "maxLength")]
    max_length: Option<u32>,
    #[serde(default, rename = "minLength")]
    min_length: Option<u32>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default, rename = "enum")]
    enum_values: Option<Vec<Value>>,
    #[serde(default, rename = "const")]
    const_value: Option<Value>,
    #[serde(default)]
    minimum: Option<i64>,
    #[serde(default)]
    maximum: Option<i64>,
    #[serde(default)]
    canonicalization: Option<Canonicalization>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthoredInputRole {
    Selector,
    Parameter,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
enum AuthoredSchemaType {
    Single(AuthoredScalarType),
    Union(Vec<AuthoredScalarType>),
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthoredScalarType {
    String,
    Boolean,
    Integer,
    Null,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthoredStringFormat {
    Date,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum AuthoredCapabilityDeclaration {
    Http {
        http: AuthoredHttpDeclaration,
    },
    Script {
        script: AuthoredScriptDeclaration,
    },
    Snapshot {
        snapshot: AuthoredSnapshotDeclaration,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredHttpDeclaration {
    request: AuthoredHttpRequest,
    #[serde(default)]
    response: AuthoredHttpResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredHttpRequest {
    method: ReadMethod,
    path: String,
    #[serde(default)]
    semantics: Option<AuthoredRequestSemantics>,
    #[serde(default)]
    query: BTreeMap<String, Value>,
    #[serde(default)]
    headers: BTreeMap<String, Value>,
    #[serde(default)]
    body: Option<Value>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredHttpResponse {
    #[serde(default)]
    no_match: Vec<u16>,
    #[serde(default)]
    ambiguous: Vec<u16>,
    #[serde(default)]
    shape: Option<AuthoredHttpShape>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum AuthoredHttpShape {
    Singleton(AuthoredSingletonShape),
    Collection {
        records: String,
        cardinality: CardinalityMode,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthoredSingletonShape {
    Singleton,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredScriptDeclaration {
    file: PathBuf,
    #[serde(default)]
    modules: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSnapshotDeclaration {
    entity: String,
    exact: BTreeMap<String, AuthoredInputReference>,
    freshness: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredInputReference {
    input: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum AuthoredOutputsDeclaration {
    Schemas(BTreeMap<String, AuthoredOutputDeclaration>),
    EntityFields(Vec<String>),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredOutputDeclaration {
    #[serde(rename = "type")]
    output_type: AuthoredSchemaType,
    #[serde(default)]
    format: Option<AuthoredStringFormat>,
    #[serde(default, rename = "maxLength")]
    max_length: Option<u32>,
    #[serde(default)]
    minimum: Option<i64>,
    #[serde(default)]
    maximum: Option<i64>,
    #[serde(default, rename = "x-registry-source")]
    source: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredLimitsDeclaration {
    #[serde(default)]
    calls: Option<u8>,
    #[serde(default)]
    request_bytes: Option<AuthoredByteSize>,
    #[serde(default)]
    source_bytes: Option<AuthoredByteSize>,
    #[serde(default)]
    deadline: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum AuthoredByteSize {
    Bytes(u64),
    Human(String),
}

impl AuthoredByteSize {
    fn bytes(&self, field: &str) -> Result<u64> {
        match self {
            Self::Bytes(bytes) => Ok(*bytes),
            Self::Human(value) => {
                let (digits, multiplier) = if let Some(digits) = value.strip_suffix("KiB") {
                    (digits, 1024_u64)
                } else if let Some(digits) = value.strip_suffix("MiB") {
                    (digits, 1024_u64 * 1024)
                } else {
                    bail!("{field} must be bytes or a positive KiB/MiB value");
                };
                let amount = digits
                    .parse::<u64>()
                    .with_context(|| format!("{field} has an invalid byte quantity"))?;
                if amount == 0 {
                    bail!("{field} must be positive");
                }
                amount
                    .checked_mul(multiplier)
                    .ok_or_else(|| anyhow!("{field} exceeds the platform integer range"))
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredFixtureDocument {
    name: String,
    classification: AuthoredFixtureClassification,
    input: BTreeMap<String, Value>,
    #[serde(default)]
    variables: BTreeMap<String, Value>,
    #[serde(default)]
    interactions: Vec<AuthoredFixtureInteraction>,
    expect: FixtureExpectation,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthoredFixtureClassification {
    Synthetic,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredFixtureInteraction {
    expect: AuthoredFixtureRequest,
    respond: AuthoredFixtureResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredFixtureRequest {
    method: ReadMethod,
    path: String,
    #[serde(default)]
    query: BTreeMap<String, Value>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<AuthoredFixtureBody>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum AuthoredFixtureResponse {
    Http {
        status: u16,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        body: Option<AuthoredFixtureBody>,
    },
    Timeout {
        timeout: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum AuthoredFixtureBody {
    File { file: PathBuf },
    Inline(Value),
}

const DEFAULT_SOURCE_RESPONSE_BYTES: u64 = 512 * 1024;
const MAX_DECLARATIVE_HTTP_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_REQUEST_BYTES: u64 = 64 * 1024;
const DEFAULT_SCRIPT_CALLS: u8 = 5;
const DEFAULT_DEADLINE: &str = "15s";

fn lower_authored_integration(
    authored: &AuthoredIntegrationDocument,
) -> Result<IntegrationDocument> {
    validate_authored_integration_contract(authored)?;
    let source = authored.source.as_ref();
    let source_metadata = SourceDeclaration {
        product: source.and_then(|source| source.product.clone()),
        versions: source
            .map(|source| SourceVersions {
                tested: source.versions.tested.clone(),
                unverified: source.versions.unverified.clone(),
            })
            .unwrap_or_default(),
    };
    let input = authored
        .input
        .iter()
        .map(|(name, declaration)| {
            let schema = lower_input_schema(name, declaration)?;
            Ok((
                name.clone(),
                InputDeclaration {
                    role: declaration.role,
                    input_type: schema.input_type,
                    nullable: schema.nullable,
                    max_length: schema.max_length,
                    min_length: schema.min_length,
                    bytes: schema.max_bytes,
                    pattern: schema.pattern,
                    enum_values: schema.enum_values,
                    const_value: schema.const_value,
                    canonicalization: declaration
                        .canonicalization
                        .clone()
                        .unwrap_or(Canonicalization::Identity),
                    minimum: schema.minimum,
                    maximum: schema.maximum,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let limits = authored.limits.as_ref();
    let bounds = BoundsDeclaration {
        calls: limits
            .and_then(|limits| limits.calls)
            .unwrap_or(DEFAULT_SCRIPT_CALLS),
        calls_authored: limits.is_some_and(|limits| limits.calls.is_some()),
        source_bytes: limits
            .and_then(|limits| limits.source_bytes.as_ref())
            .map(|size| size.bytes("limits.source_bytes"))
            .transpose()?
            .unwrap_or(DEFAULT_SOURCE_BYTES),
        source_bytes_authored: limits.is_some_and(|limits| limits.source_bytes.is_some()),
        request_bytes: u32::try_from(
            limits
                .and_then(|limits| limits.request_bytes.as_ref())
                .map(|size| size.bytes("limits.request_bytes"))
                .transpose()?
                .unwrap_or(DEFAULT_REQUEST_BYTES),
        )
        .map_err(|_| anyhow!("limits.request_bytes exceeds the platform integer range"))?,
        request_bytes_authored: limits.is_some_and(|limits| limits.request_bytes.is_some()),
        deadline: limits
            .and_then(|limits| limits.deadline.clone())
            .unwrap_or_else(|| DEFAULT_DEADLINE.to_string()),
        deadline_authored: limits.is_some_and(|limits| limits.deadline.is_some()),
        concurrency: 8,
    };
    let (capability, outputs) = match (&authored.capability, &authored.outputs) {
        (
            AuthoredCapabilityDeclaration::Http { http },
            AuthoredOutputsDeclaration::Schemas(outputs),
        ) => lower_http_capability(source, http, outputs)?,
        (
            AuthoredCapabilityDeclaration::Script { script },
            AuthoredOutputsDeclaration::Schemas(outputs),
        ) => lower_script_capability(source, script, outputs)?,
        (
            AuthoredCapabilityDeclaration::Snapshot { .. },
            AuthoredOutputsDeclaration::EntityFields(_),
        ) => bail!("snapshot entity output lowering requires the loaded entity contract"),
        (AuthoredCapabilityDeclaration::Snapshot { .. }, _) => {
            bail!("snapshot outputs must be a non-empty list of entity fields")
        }
        (_, AuthoredOutputsDeclaration::EntityFields(_)) => {
            bail!("http and script outputs must be a map of scalar schemas")
        }
    };
    Ok(IntegrationDocument {
        version: authored.version,
        id: authored.id.clone(),
        revision: authored.revision,
        source: source_metadata,
        input,
        capability,
        outputs,
        bounds: BoundsDeclaration {
            calls: if matches!(
                &authored.capability,
                AuthoredCapabilityDeclaration::Http { .. }
            ) || authored
                .source
                .as_ref()
                .and_then(|source| source.protocol.as_ref())
                .and_then(|protocol| protocol.signed_dci.as_ref())
                .is_some()
            {
                1
            } else {
                bounds.calls
            },
            ..bounds
        },
        fixtures: PathBuf::from("fixtures"),
    })
}

fn validate_authored_integration_contract(authored: &AuthoredIntegrationDocument) -> Result<()> {
    if authored.version != 1 || authored.revision == 0 {
        bail!("integration version must be 1 and revision must be positive");
    }
    validate_stable_id(&authored.id, "integration id")?;
    if authored.input.is_empty() || authored.input.len() > 16 {
        bail!("integration input must contain between one and sixteen entries");
    }
    let selector_count = authored
        .input
        .values()
        .filter(|input| input.role == AuthoredInputRole::Selector)
        .count();
    if !(1..=8).contains(&selector_count) {
        bail!("integration input must contain between one and eight selectors");
    }
    let mut selector_bytes = 0_u32;
    for (name, input) in &authored.input {
        validate_input_name(name).with_context(|| format!("input.{name}.name"))?;
        let schema = lower_input_schema(name, input)?;
        if schema.max_bytes > 4096 {
            bail!("input.{name} worst-case canonical value exceeds 4096 bytes");
        }
        if input.role == AuthoredInputRole::Selector {
            selector_bytes = selector_bytes
                .checked_add(u32::from(schema.max_bytes))
                .ok_or_else(|| anyhow!("selector byte bound overflow"))?;
        }
    }
    if selector_bytes > 4096 {
        bail!("canonical selector inputs exceed the fixed 4096-byte aggregate ceiling");
    }
    if let AuthoredOutputsDeclaration::Schemas(outputs) = &authored.outputs {
        if outputs.is_empty() || outputs.len() > MAX_OUTPUTS {
            bail!("outputs must contain between one and {MAX_OUTPUTS} fields");
        }
        for (name, output) in outputs {
            validate_input_name(name).with_context(|| format!("outputs.{name}"))?;
            if matches!(name.as_str(), "matched" | "outcome") {
                bail!("outputs.{name} is reserved consultation vocabulary");
            }
            validate_authored_output(name, output)?;
        }
    }
    if let Some(source) = &authored.source {
        validate_authored_source(source)?;
        if let Some(signed_dci) = source
            .protocol
            .as_ref()
            .and_then(|protocol| protocol.signed_dci.as_ref())
        {
            let selectors = authored
                .input
                .iter()
                .filter(|(_, input)| input.role == AuthoredInputRole::Selector)
                .map(|(name, _)| name.as_str())
                .collect::<BTreeSet<_>>();
            if signed_dci
                .selectors
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != selectors
            {
                bail!("source.protocol.signed_dci.selectors must bind every selector exactly once");
            }
            if authored
                .limits
                .as_ref()
                .and_then(|limits| limits.calls)
                .is_some_and(|calls| calls != 1)
            {
                bail!("source.protocol.signed_dci supports exactly one high-level Script call");
            }
        }
    }
    if let Some(limits) = &authored.limits {
        if limits.calls.is_some_and(|calls| !(1..=16).contains(&calls))
            || limits
                .request_bytes
                .as_ref()
                .map(|bytes| bytes.bytes("limits.request_bytes"))
                .transpose()?
                .is_some_and(|bytes| bytes == 0 || bytes > 1024 * 1024)
            || limits
                .source_bytes
                .as_ref()
                .map(|bytes| bytes.bytes("limits.source_bytes"))
                .transpose()?
                .is_some_and(|bytes| bytes == 0 || bytes > 16 * 1024 * 1024)
        {
            bail!("authored limits exceed the v1 hard ceilings");
        }
        if let Some(deadline) = &limits.deadline {
            let milliseconds = parse_duration_ms(deadline)?;
            if milliseconds == 0 || milliseconds > 60_000 {
                bail!("limits.deadline must be between 1ms and 60s");
            }
        }
    }
    match &authored.capability {
        AuthoredCapabilityDeclaration::Http { .. } => {
            if authored
                .limits
                .as_ref()
                .and_then(|limits| limits.calls)
                .is_some()
            {
                bail!("http performs exactly one call and does not accept limits.calls");
            }
        }
        AuthoredCapabilityDeclaration::Script { .. } => {
            let source = authored
                .source
                .as_ref()
                .ok_or_else(|| anyhow!("script integrations require source"))?;
            if source.allow.is_empty() || source.allow.len() > 16 {
                bail!("script source.allow must contain between one and sixteen rules");
            }
        }
        AuthoredCapabilityDeclaration::Snapshot { .. } => {
            if authored.source.is_some() || authored.limits.is_some() {
                bail!("snapshot does not declare remote source or HTTP execution limits");
            }
        }
    }
    Ok(())
}

fn validate_authored_source(source: &AuthoredSourceDeclaration) -> Result<()> {
    if source.versions.tested.is_empty()
        && source.versions.unverified.is_empty()
        && source.product.is_some()
    {
        bail!("source.versions must classify at least one product version label");
    }
    if source
        .response
        .as_ref()
        .and_then(|response| response.max_bytes.as_ref())
        .map(|size| size.bytes("source.response.max_bytes"))
        .transpose()?
        .is_some_and(|bytes| bytes == 0 || bytes > 8 * 1024 * 1024)
    {
        bail!("source.response.max_bytes exceeds the 8MiB v1 hard ceiling");
    }
    if source.request_headers.len() > 32 || source.response_headers.len() > 32 {
        bail!("source request and response header allow-lists contain at most 32 names");
    }
    validate_authored_credential_interface(&source.auth)?;
    if let Some(protocol) = &source.protocol {
        let signed_dci = protocol
            .signed_dci
            .as_ref()
            .ok_or_else(|| anyhow!("source.protocol must enable one supported helper"))?;
        if signed_dci.profile != "dci-search-v1" || signed_dci.jwks_profile != "rsa-signing-jwks-v1"
        {
            bail!("source.protocol.signed_dci uses an unsupported protocol profile");
        }
        if source.auth.credential_type != CredentialType::Oauth2ClientCredentials {
            bail!("signed DCI requires oauth2_client_credentials source authentication");
        }
        validate_exact_private_path(&signed_dci.path, "source.protocol.signed_dci.path")?;
        for (name, binding) in &signed_dci.selectors {
            validate_input_name(name)
                .with_context(|| format!("source.protocol.signed_dci.selectors.{name}"))?;
            validate_token(
                &binding.field,
                "source.protocol.signed_dci selector field",
                160,
            )?;
            signed_dci_pointer_segments(&binding.response_pointer).with_context(|| {
                format!("source.protocol.signed_dci.selectors.{name}.response_pointer")
            })?;
        }
    }
    Ok(())
}

fn signed_dci_pointer_segments(pointer: &str) -> Result<Vec<String>> {
    let pointer = pointer
        .strip_prefix('/')
        .ok_or_else(|| anyhow!("signed DCI selector response pointer must be absolute"))?;
    if pointer.is_empty() || pointer.contains('~') {
        bail!("signed DCI selector response pointer must be canonical");
    }
    let segments = pointer.split('/').map(str::to_string).collect::<Vec<_>>();
    if segments.iter().any(String::is_empty) {
        bail!("signed DCI selector response pointer must be canonical");
    }
    if segments.first().is_some_and(|segment| segment == "identifier") {
        let valid = matches!(
            segments.as_slice(),
            [_, index, field]
                if index.bytes().all(|byte| byte.is_ascii_digit())
                    && (index == "0" || !index.starts_with('0'))
                    && index.parse::<usize>().is_ok_and(|index| index < 64)
                    && matches!(field.as_str(), "identifier_type" | "identifier_value")
        );
        if !valid {
            if segments.get(1).is_some_and(|index| {
                index.bytes().all(|byte| byte.is_ascii_digit())
                    && index != "0"
                    && index.starts_with('0')
            }) {
                bail!("signed DCI selector response pointer must use a canonical array index");
            }
            bail!("signed DCI selector response pointer is outside the signed record schema");
        }
    }
    Ok(segments)
}

fn validate_authored_credential_interface(interface: &CredentialInterface) -> Result<()> {
    let oauth_fields_absent = interface.request.is_none()
        && interface.response_profile.is_none()
        && interface.scope.is_none()
        && interface.audience.is_none()
        && interface.refresh_skew.is_none();
    match interface.credential_type {
        CredentialType::Oauth2ClientCredentials => {
            if interface.name.is_some()
                || interface.max_value_bytes.is_some()
                || interface.request.is_none()
                || interface.response_profile != Some(OAuthResponseProfile::Oauth2Bearer)
            {
                bail!("source.auth OAuth fields do not form the oauth2_bearer profile");
            }
            if let Some(scope) = &interface.scope {
                let scopes = scope.split_ascii_whitespace().collect::<Vec<_>>();
                if scopes.is_empty()
                    || scopes.len() > 32
                    || scopes.iter().any(|scope| {
                        scope.is_empty()
                            || scope.len() > 128
                            || scope.bytes().any(|byte| byte.is_ascii_control())
                    })
                {
                    bail!("source.auth.scope is outside the bounded OAuth token grammar");
                }
            }
            if let Some(audience) = &interface.audience {
                validate_token(audience, "source.auth.audience", 2048)?;
            }
            if interface
                .refresh_skew
                .as_deref()
                .map(parse_duration_ms)
                .transpose()?
                .is_some_and(|skew| skew == 0 || skew >= 3_600_000)
            {
                bail!("source.auth.refresh_skew must be positive and below one hour");
            }
        }
        CredentialType::ApiKeyHeader | CredentialType::ApiKeyQuery => {
            if !oauth_fields_absent {
                bail!("API-key source.auth cannot declare OAuth fields");
            }
            if interface.name.as_deref().is_none_or(str::is_empty)
                || interface
                    .max_value_bytes
                    .is_none_or(|bound| bound == 0 || bound > 4096)
            {
                bail!("API-key source.auth requires one bounded fixed name");
            }
        }
        CredentialType::None | CredentialType::Basic | CredentialType::StaticBearer => {
            if !oauth_fields_absent
                || interface.name.is_some()
                || interface.max_value_bytes.is_some()
            {
                bail!("source.auth contains fields that do not apply to its type");
            }
        }
    }
    Ok(())
}

fn validate_authored_output(name: &str, output: &AuthoredOutputDeclaration) -> Result<()> {
    let (scalar, _) = schema_type_parts(&output.output_type)?;
    match scalar {
        AuthoredScalarType::String => {
            let max = output
                .max_length
                .ok_or_else(|| anyhow!("outputs.{name}.maxLength is required for String"))?;
            if max == 0 || max > 16_384 {
                bail!("outputs.{name}.maxLength is outside the v1 bounds");
            }
            if output.minimum.is_some() || output.maximum.is_some() {
                bail!("outputs.{name} String schemas cannot declare minimum or maximum");
            }
            if output.format == Some(AuthoredStringFormat::Date) && max != 10 {
                bail!("outputs.{name} date format requires maxLength: 10");
            }
        }
        AuthoredScalarType::Boolean => {
            if output.format.is_some()
                || output.max_length.is_some()
                || output.minimum.is_some()
                || output.maximum.is_some()
            {
                bail!("outputs.{name} Boolean schema has incompatible constraints");
            }
        }
        AuthoredScalarType::Integer => {
            let minimum = output
                .minimum
                .ok_or_else(|| anyhow!("outputs.{name}.minimum is required for Integer"))?;
            let maximum = output
                .maximum
                .ok_or_else(|| anyhow!("outputs.{name}.maximum is required for Integer"))?;
            if minimum > maximum || output.format.is_some() || output.max_length.is_some() {
                bail!("outputs.{name} Integer schema has invalid constraints");
            }
        }
        AuthoredScalarType::Null => bail!("outputs.{name} cannot have only null type"),
    }
    Ok(())
}

struct LoweredInputSchema {
    input_type: InputType,
    nullable: bool,
    max_length: Option<u16>,
    min_length: Option<u16>,
    max_bytes: u16,
    pattern: Option<String>,
    enum_values: Option<Vec<Value>>,
    const_value: Option<Value>,
    minimum: Option<i64>,
    maximum: Option<i64>,
}

fn lower_input_schema(
    name: &str,
    declaration: &AuthoredInputDeclaration,
) -> Result<LoweredInputSchema> {
    let nullable = schema_type_parts(&declaration.input_type)?.1;
    if declaration.role == AuthoredInputRole::Selector && nullable {
        bail!("input.{name}: selector inputs cannot be nullable");
    }
    let scalar = schema_type_parts(&declaration.input_type)?.0;
    match scalar {
        AuthoredScalarType::String => {
            let max_length = declaration
                .max_length
                .ok_or_else(|| anyhow!("input.{name}.maxLength is required for String inputs"))?;
            if max_length == 0
                || declaration
                    .min_length
                    .is_some_and(|minimum| minimum > max_length)
                || declaration.minimum.is_some()
                || declaration.maximum.is_some()
            {
                bail!("input.{name}: String schema has incompatible constraints");
            }
            let conservative_bytes = max_length
                .checked_mul(4)
                .and_then(|bytes| u16::try_from(bytes).ok())
                .ok_or_else(|| {
                    anyhow!("input.{name} worst-case UTF-8 bytes exceed the input budget")
                })?;
            let (input_type, max_bytes, pattern) =
                if declaration.format == Some(AuthoredStringFormat::Date) {
                    if max_length != 10
                        || declaration.min_length.is_some_and(|minimum| minimum != 10)
                        || declaration.pattern.is_some()
                        || !matches!(
                            declaration
                                .canonicalization
                                .as_ref()
                                .unwrap_or(&Canonicalization::Identity),
                            Canonicalization::Identity
                        )
                    {
                        bail!(
                        "input.{name}: format date requires the exact RFC 3339 full-date contract"
                    );
                    }
                    (InputType::FullDate, 10, None)
                } else {
                    (
                        InputType::String,
                        conservative_bytes,
                        declaration.pattern.clone(),
                    )
                };
            validate_input_enum_and_const(name, declaration, nullable)?;
            Ok(LoweredInputSchema {
                input_type,
                nullable,
                max_length: Some(
                    u16::try_from(max_length)
                        .map_err(|_| anyhow!("input.{name}.maxLength exceeds the product range"))?,
                ),
                min_length: declaration
                    .min_length
                    .map(u16::try_from)
                    .transpose()
                    .map_err(|_| anyhow!("input.{name}.minLength exceeds the product range"))?,
                max_bytes: max_bytes.max(if nullable { 4 } else { 0 }),
                pattern,
                enum_values: declaration.enum_values.clone(),
                const_value: declaration.const_value.clone(),
                minimum: None,
                maximum: None,
            })
        }
        AuthoredScalarType::Boolean => {
            if declaration.format.is_some()
                || declaration.max_length.is_some()
                || declaration.min_length.is_some()
                || declaration.pattern.is_some()
                || declaration.minimum.is_some()
                || declaration.maximum.is_some()
                || !matches!(
                    declaration
                        .canonicalization
                        .as_ref()
                        .unwrap_or(&Canonicalization::Identity),
                    Canonicalization::Identity
                )
            {
                bail!("input.{name}: Boolean schema has incompatible constraints");
            }
            validate_input_enum_and_const(name, declaration, nullable)?;
            Ok(LoweredInputSchema {
                input_type: InputType::Boolean,
                nullable,
                max_length: None,
                min_length: None,
                max_bytes: 5,
                pattern: None,
                enum_values: declaration.enum_values.clone(),
                const_value: declaration.const_value.clone(),
                minimum: None,
                maximum: None,
            })
        }
        AuthoredScalarType::Integer => {
            const JSON_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
            let minimum = declaration
                .minimum
                .ok_or_else(|| anyhow!("input.{name}.minimum is required for Integer inputs"))?;
            let maximum = declaration
                .maximum
                .ok_or_else(|| anyhow!("input.{name}.maximum is required for Integer inputs"))?;
            if minimum > maximum
                || minimum < -JSON_SAFE_INTEGER
                || maximum > JSON_SAFE_INTEGER
                || declaration.format.is_some()
                || declaration.max_length.is_some()
                || declaration.min_length.is_some()
                || declaration.pattern.is_some()
                || !matches!(
                    declaration
                        .canonicalization
                        .as_ref()
                        .unwrap_or(&Canonicalization::Identity),
                    Canonicalization::Identity
                )
            {
                bail!("input.{name}: Integer schema has incompatible constraints");
            }
            validate_input_enum_and_const(name, declaration, nullable)?;
            let max_bytes = minimum
                .to_string()
                .len()
                .max(maximum.to_string().len())
                .max(if nullable { 4 } else { 0 });
            Ok(LoweredInputSchema {
                input_type: InputType::Integer,
                nullable,
                max_length: None,
                min_length: None,
                max_bytes: u16::try_from(max_bytes)
                    .map_err(|_| anyhow!("input.{name} integer byte bound overflows"))?,
                pattern: None,
                enum_values: declaration.enum_values.clone(),
                const_value: declaration.const_value.clone(),
                minimum: Some(minimum),
                maximum: Some(maximum),
            })
        }
        AuthoredScalarType::Null => bail!("input.{name}: null cannot be the only input type"),
    }
}

fn validate_input_enum_and_const(
    name: &str,
    declaration: &AuthoredInputDeclaration,
    nullable: bool,
) -> Result<()> {
    if declaration.enum_values.as_ref().is_some_and(Vec::is_empty) {
        bail!("input.{name}.enum must not be empty");
    }
    if let (Some(values), Some(constant)) = (&declaration.enum_values, &declaration.const_value) {
        if !values.contains(constant) {
            bail!("input.{name}.const must be a member of input.{name}.enum");
        }
    }
    let (scalar, _) = schema_type_parts(&declaration.input_type)?;
    for value in declaration
        .enum_values
        .iter()
        .flatten()
        .chain(declaration.const_value.iter())
    {
        if value.is_null() {
            if !nullable {
                bail!("input.{name}: null enum/const value requires a nullable parameter");
            }
            continue;
        }
        match scalar {
            AuthoredScalarType::String => {
                let value = value
                    .as_str()
                    .ok_or_else(|| anyhow!("input.{name} enum/const value must be a String"))?;
                let characters = u32::try_from(value.chars().count())
                    .map_err(|_| anyhow!("input.{name} enum/const String is too long"))?;
                if declaration
                    .min_length
                    .is_some_and(|minimum| characters < minimum)
                    || declaration
                        .max_length
                        .is_some_and(|maximum| characters > maximum)
                    || declaration.pattern.as_ref().is_some_and(|pattern| {
                        regex::Regex::new(pattern)
                            .map_or(true, |compiled| !compiled.is_match(value))
                    })
                    || declaration.format == Some(AuthoredStringFormat::Date)
                        && time::Date::parse(
                            value,
                            &time::macros::format_description!("[year]-[month]-[day]"),
                        )
                        .is_err()
                {
                    bail!("input.{name} enum/const String violates its base schema");
                }
            }
            AuthoredScalarType::Boolean if !value.is_boolean() => {
                bail!("input.{name} enum/const value must be a Boolean");
            }
            AuthoredScalarType::Integer => {
                let value = value
                    .as_i64()
                    .ok_or_else(|| anyhow!("input.{name} enum/const value must be an Integer"))?;
                if declaration.minimum.is_some_and(|minimum| value < minimum)
                    || declaration.maximum.is_some_and(|maximum| value > maximum)
                {
                    bail!("input.{name} enum/const Integer violates its base schema");
                }
            }
            AuthoredScalarType::Boolean => {}
            AuthoredScalarType::Null => unreachable!("schema_type_parts rejects null-only input"),
        }
    }
    Ok(())
}

fn schema_type_parts(schema_type: &AuthoredSchemaType) -> Result<(AuthoredScalarType, bool)> {
    match schema_type {
        AuthoredSchemaType::Single(scalar) if *scalar != AuthoredScalarType::Null => {
            Ok((*scalar, false))
        }
        AuthoredSchemaType::Union(items) if items.len() == 2 => {
            let scalar = items
                .iter()
                .copied()
                .find(|item| *item != AuthoredScalarType::Null)
                .ok_or_else(|| anyhow!("nullable type union must contain one scalar and null"))?;
            if !items.contains(&AuthoredScalarType::Null) {
                bail!("type unions are limited to one scalar plus null");
            }
            Ok((scalar, true))
        }
        _ => bail!("type must be one scalar or a two-member scalar/null union"),
    }
}

fn lower_http_capability(
    source: Option<&AuthoredSourceDeclaration>,
    http: &AuthoredHttpDeclaration,
    authored_outputs: &BTreeMap<String, AuthoredOutputDeclaration>,
) -> Result<(CapabilityDeclaration, BTreeMap<String, OutputDeclaration>)> {
    let source = source.ok_or_else(|| anyhow!("http integrations require source"))?;
    if http.request.method == ReadMethod::Post
        && http.request.semantics != Some(AuthoredRequestSemantics::ReadOnly)
    {
        bail!("http POST requires semantics: read_only");
    }
    validate_status_mappings(&http.response)?;
    let mut accepted_statuses = vec![200];
    accepted_statuses.extend(http.response.no_match.iter().copied());
    accepted_statuses.extend(http.response.ambiguous.iter().copied());
    accepted_statuses.sort_unstable();
    accepted_statuses.dedup();
    let outputs = lower_output_map(authored_outputs, "request", true)?;
    let schema = response_schema_for_outputs(authored_outputs)?;
    let (records, mode) = match &http.response.shape {
        None | Some(AuthoredHttpShape::Singleton(AuthoredSingletonShape::Singleton)) => {
            (None, CardinalityMode::Singleton)
        }
        Some(AuthoredHttpShape::Collection {
            records,
            cardinality,
        }) => (Some(pointer_to_path(records)?), *cardinality),
    };
    let mut path_parameters = BTreeMap::new();
    let path = lower_http_path(&http.request.path, &mut path_parameters)?;
    let credential = lower_oauth_credential_operation(&source.auth)?;
    let response_bytes = source
        .response
        .as_ref()
        .and_then(|response| response.max_bytes.as_ref())
        .map(|size| size.bytes("source.response.max_bytes"))
        .transpose()?
        .unwrap_or(DEFAULT_SOURCE_RESPONSE_BYTES);
    if response_bytes > MAX_DECLARATIVE_HTTP_RESPONSE_BYTES {
        bail!("http source.response.max_bytes exceeds the 8MiB platform ceiling");
    }
    let operation = OperationDeclaration {
        depends_on: credential
            .as_ref()
            .map(|(id, _)| vec![id.clone()])
            .unwrap_or_default(),
        role: OperationRole::Data,
        primitive: None,
        request: RequestDeclaration {
            method: http.request.method,
            destination: "data".to_string(),
            path,
            path_parameters,
            query: lower_http_value_map(&http.request.query)?,
            headers: lower_http_value_map(&http.request.headers)?,
            body: http.request.body.clone().map(lower_http_body).transpose()?,
            primitive: None,
            codec: match http.request.method {
                ReadMethod::Get => None,
                ReadMethod::Post => Some("strict_json_v1".to_string()),
            },
            authorization: None,
        },
        response: ResponseDeclaration {
            statuses: accepted_statuses,
            max_bytes: u32::try_from(response_bytes)
                .map_err(|_| anyhow!("source.response.max_bytes exceeds the product range"))?,
            schema,
            codec: Some("json_v1".to_string()),
            cardinality: Some(CardinalityDeclaration { records, mode }),
            status_semantics: Some(StatusSemanticsDeclaration {
                no_match: http.response.no_match.clone(),
                ambiguous: http.response.ambiguous.clone(),
            }),
        },
        verification: None,
        when: None,
    };
    let mut operations = BTreeMap::from([("request".to_string(), operation)]);
    if let Some((id, operation)) = credential {
        operations.insert(id, operation);
    }
    Ok((
        CapabilityDeclaration::Http {
            http: HttpDeclaration {
                credential: source.auth.clone(),
                operations,
                response_max_bytes_authored: source
                    .response
                    .as_ref()
                    .is_some_and(|response| response.max_bytes.is_some()),
            },
        },
        outputs,
    ))
}

fn validate_status_mappings(response: &AuthoredHttpResponse) -> Result<()> {
    let mut seen = BTreeSet::new();
    for (field, statuses) in [
        ("no_match", response.no_match.as_slice()),
        ("ambiguous", response.ambiguous.as_slice()),
    ] {
        for status in statuses {
            if !(100..=599).contains(status) {
                bail!("capability.http.response.{field} contains an invalid HTTP status");
            }
            if !seen.insert(*status) {
                bail!("capability.http.response status mappings must be disjoint");
            }
        }
    }
    Ok(())
}

fn lower_script_capability(
    source: Option<&AuthoredSourceDeclaration>,
    script: &AuthoredScriptDeclaration,
    authored_outputs: &BTreeMap<String, AuthoredOutputDeclaration>,
) -> Result<(CapabilityDeclaration, BTreeMap<String, OutputDeclaration>)> {
    if script.file.extension().and_then(std::ffi::OsStr::to_str) != Some("rhai") {
        bail!("capability.script.file must use the .rhai extension");
    }
    if script.modules.len() > 32 {
        bail!("capability.script.modules may contain at most 32 local modules");
    }
    let mut unique_modules = BTreeSet::new();
    for module in &script.modules {
        if module.extension().and_then(std::ffi::OsStr::to_str) != Some("rhai") {
            bail!("capability.script.modules must use the .rhai extension");
        }
        if module == &script.file || !unique_modules.insert(module) {
            bail!("capability.script.modules must be unique and exclude the entrypoint file");
        }
    }
    let source = source.ok_or_else(|| anyhow!("script integrations require source"))?;
    if source.allow.is_empty() {
        bail!("script integrations require at least one source.allow rule");
    }
    let outputs = lower_output_map(authored_outputs, "source", false)?;
    for (index, rule) in source.allow.iter().enumerate() {
        if rule.method == ReadMethod::Post
            && rule.semantics != Some(AuthoredRequestSemantics::ReadOnly)
        {
            bail!("source.allow[{index}] POST requires semantics: read_only");
        }
    }
    let signed_dci = source
        .protocol
        .as_ref()
        .and_then(|protocol| protocol.signed_dci.as_ref());
    if let Some(protocol) = signed_dci {
        if source.allow.len() != 1
            || source.allow[0].method != ReadMethod::Post
            || source.allow[0].path != protocol.path
            || source.allow[0].semantics != Some(AuthoredRequestSemantics::ReadOnly)
        {
            bail!("signed DCI source.allow must contain only its exact read-only POST path");
        }
    }
    let response = source.response.as_ref();
    let max_bytes = u32::try_from(
        response
            .and_then(|response| response.max_bytes.as_ref())
            .map(|size| size.bytes("source.response.max_bytes"))
            .transpose()?
            .unwrap_or(DEFAULT_SOURCE_RESPONSE_BYTES),
    )
    .map_err(|_| anyhow!("source.response.max_bytes exceeds the product range"))?;
    Ok((
        CapabilityDeclaration::Script {
            script: Box::new(ScriptDeclaration {
                runtime: ScriptRuntime::RhaiV1,
                credential: source.auth.clone(),
                allow: source
                    .allow
                    .iter()
                    .map(|rule| ScriptAllowRule {
                        method: rule.method,
                        path: rule.path.clone(),
                        semantics: rule.semantics,
                    })
                    .collect(),
                request_headers: source.request_headers.clone(),
                response_headers: source.response_headers.clone(),
                response: ScriptResponseDeclaration {
                    format: response.map_or(AuthoredResponseFormat::Json, |response| {
                        response.format
                    }),
                    max_bytes,
                    max_bytes_authored: response.is_some_and(|response| response.max_bytes.is_some()),
                },
                signed_dci: signed_dci.cloned(),
                script: script.file.clone(),
                modules: script.modules.clone(),
            }),
        },
        outputs,
    ))
}

fn lower_oauth_credential_operation(
    interface: &CredentialInterface,
) -> Result<Option<(String, OperationDeclaration)>> {
    if interface.credential_type != CredentialType::Oauth2ClientCredentials {
        return Ok(None);
    }
    let codec = match interface
        .request
        .ok_or_else(|| anyhow!("OAuth request format is absent"))?
    {
        OAuthRequestFormat::Form => "oauth2_client_credentials_form_v1",
        OAuthRequestFormat::Json => "oauth2_client_credentials_json_v1",
    };
    Ok(Some((
        "oauth".to_string(),
        OperationDeclaration {
            depends_on: Vec::new(),
            role: OperationRole::Credential,
            primitive: Some("oauth2_client_credentials".to_string()),
            request: RequestDeclaration {
                method: ReadMethod::Post,
                destination: "credential".to_string(),
                path: "/".to_string(),
                path_parameters: BTreeMap::new(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                body: None,
                primitive: None,
                codec: Some(codec.to_string()),
                authorization: None,
            },
            response: ResponseDeclaration {
                statuses: vec![200],
                max_bytes: 8 * 1024,
                schema: SchemaNode::Object {
                    additional_fields: AdditionalFields::Reject,
                    fields: BTreeMap::from([
                        (
                            "access_token".to_string(),
                            SchemaField {
                                required: true,
                                schema: SchemaNode::String { max_bytes: 4096 },
                            },
                        ),
                        (
                            "token_type".to_string(),
                            SchemaField {
                                required: true,
                                schema: SchemaNode::String { max_bytes: 16 },
                            },
                        ),
                        (
                            "expires_in".to_string(),
                            SchemaField {
                                required: true,
                                schema: SchemaNode::Integer {
                                    min: 60,
                                    max: 3_600,
                                },
                            },
                        ),
                    ]),
                },
                codec: Some("oauth2_token_v1".to_string()),
                cardinality: None,
                status_semantics: None,
            },
            verification: None,
            when: None,
        },
    )))
}

fn lower_output_map(
    authored: &BTreeMap<String, AuthoredOutputDeclaration>,
    step: &str,
    require_source: bool,
) -> Result<BTreeMap<String, OutputDeclaration>> {
    if authored.is_empty() || authored.len() > MAX_OUTPUTS {
        bail!("outputs must contain between one and {MAX_OUTPUTS} fields");
    }
    authored
        .iter()
        .map(|(name, declaration)| {
            let (scalar, nullable) = schema_type_parts(&declaration.output_type)?;
            let output_type = match (scalar, declaration.format) {
                (AuthoredScalarType::String, Some(AuthoredStringFormat::Date)) => OutputType::Date,
                (AuthoredScalarType::String, None) => OutputType::String,
                (AuthoredScalarType::Boolean, None) => OutputType::Boolean,
                (AuthoredScalarType::Integer, None) => OutputType::Integer,
                (AuthoredScalarType::Null, _) => {
                    bail!("outputs.{name}: null cannot be the only output type")
                }
                (_, Some(_)) => bail!("outputs.{name}: format is valid only for String"),
            };
            let pointer = match (&declaration.source, require_source) {
                (Some(pointer), true) => {
                    pointer_segments(pointer)?;
                    Some(pointer.clone())
                }
                (Some(_), false) => None,
                (None, true) => {
                    bail!("outputs.{name}.x-registry-source is required for http")
                }
                (None, false) => None,
            };
            let max_bytes = if output_type == OutputType::String {
                Some(
                    declaration
                        .max_length
                        .ok_or_else(|| anyhow!("outputs.{name}.maxLength is required"))?
                        .checked_mul(4)
                        .ok_or_else(|| anyhow!("outputs.{name}.maxLength exceeds byte limits"))?,
                )
            } else if output_type == OutputType::Date {
                Some(10)
            } else {
                None
            };
            Ok((
                name.clone(),
                OutputDeclaration {
                    output_type,
                    nullable,
                    max_bytes,
                    minimum: (output_type == OutputType::Integer)
                        .then_some(declaration.minimum)
                        .flatten(),
                    maximum: (output_type == OutputType::Integer)
                        .then_some(declaration.maximum)
                        .flatten(),
                    from: pointer.as_ref().map(|_| format!("{step}.record.{name}")),
                    source_pointer: pointer,
                },
            ))
        })
        .collect()
}

fn response_schema_for_outputs(
    outputs: &BTreeMap<String, AuthoredOutputDeclaration>,
) -> Result<SchemaNode> {
    let mut root = SchemaNode::Object {
        additional_fields: AdditionalFields::Ignore,
        fields: BTreeMap::new(),
    };
    for (name, output) in outputs {
        let source = output.source.as_deref().unwrap_or(name.as_str());
        let path = pointer_segments(source)?;
        insert_output_schema(&mut root, &path, output, name)?;
    }
    Ok(root)
}

fn insert_output_schema(
    node: &mut SchemaNode,
    path: &[String],
    output: &AuthoredOutputDeclaration,
    output_name: &str,
) -> Result<()> {
    let (head, tail) = path
        .split_first()
        .ok_or_else(|| anyhow!("outputs.{output_name}: source pointer cannot select the root"))?;
    let SchemaNode::Object { fields, .. } = node else {
        bail!("outputs.{output_name}: source pointers overlap incompatibly");
    };
    if tail.is_empty() {
        if fields.contains_key(head) {
            bail!("outputs.{output_name}: duplicate or overlapping source pointer");
        }
        fields.insert(
            head.clone(),
            SchemaField {
                required: !schema_type_parts(&output.output_type)?.1,
                schema: output_schema_node(output, output_name)?,
            },
        );
        return Ok(());
    }
    let field = fields.entry(head.clone()).or_insert_with(|| SchemaField {
        required: true,
        schema: SchemaNode::Object {
            additional_fields: AdditionalFields::Ignore,
            fields: BTreeMap::new(),
        },
    });
    insert_output_schema(&mut field.schema, tail, output, output_name)
}

fn output_schema_node(output: &AuthoredOutputDeclaration, name: &str) -> Result<SchemaNode> {
    let (scalar, _) = schema_type_parts(&output.output_type)?;
    match (scalar, output.format) {
        (AuthoredScalarType::String, Some(AuthoredStringFormat::Date)) => Ok(SchemaNode::Date),
        (AuthoredScalarType::String, None) => Ok(SchemaNode::String {
            max_bytes: output
                .max_length
                .ok_or_else(|| anyhow!("outputs.{name}.maxLength is required"))?
                .checked_mul(4)
                .ok_or_else(|| anyhow!("outputs.{name}.maxLength exceeds byte limits"))?,
        }),
        (AuthoredScalarType::Boolean, None) => Ok(SchemaNode::Boolean),
        (AuthoredScalarType::Integer, None) => Ok(SchemaNode::Integer {
            min: output
                .minimum
                .ok_or_else(|| anyhow!("outputs.{name}.minimum is required"))?,
            max: output
                .maximum
                .ok_or_else(|| anyhow!("outputs.{name}.maximum is required"))?,
        }),
        _ => bail!("outputs.{name}: unsupported scalar schema"),
    }
}

fn lower_http_path(path: &str, parameters: &mut BTreeMap<String, ValueSource>) -> Result<String> {
    let mut rendered = Vec::new();
    for segment in path.split('/') {
        if let Some(name) = segment
            .strip_prefix("{input.")
            .and_then(|segment| segment.strip_suffix('}'))
        {
            if name.is_empty() {
                bail!("http request path contains an empty input placeholder");
            }
            parameters.insert(
                name.to_string(),
                ValueSource::Input {
                    input: name.to_string(),
                },
            );
            rendered.push(format!("{{{name}}}"));
        } else {
            if segment.contains('{') || segment.contains('}') {
                bail!("http path placeholders must occupy one complete segment");
            }
            rendered.push(segment.to_string());
        }
    }
    Ok(rendered.join("/"))
}

fn lower_http_value_map(values: &BTreeMap<String, Value>) -> Result<BTreeMap<String, ValueSource>> {
    values
        .iter()
        .map(|(name, value)| Ok((name.clone(), lower_http_value(value)?)))
        .collect()
}

fn lower_http_value(value: &Value) -> Result<ValueSource> {
    if let Some(object) = value.as_object() {
        if object.len() == 1 {
            if let Some(input) = object.get("input").and_then(Value::as_str) {
                return Ok(ValueSource::Input {
                    input: input.to_string(),
                });
            }
        }
    }
    Ok(ValueSource::Value {
        value: value.clone(),
    })
}

fn lower_http_body(value: Value) -> Result<Value> {
    match value {
        Value::Object(object) => object
            .into_iter()
            .map(|(name, value)| {
                let value = match lower_http_value(&value)? {
                    ValueSource::Input { input } => {
                        json!({ "source": "consultation_input", "name": input })
                    }
                    ValueSource::Value { value } => lower_http_body(value)?,
                    ValueSource::Prior { .. } => unreachable!("authored http has no prior values"),
                };
                Ok((name, value))
            })
            .collect::<Result<Map<_, _>>>()
            .map(Value::Object),
        Value::Array(values) => values
            .into_iter()
            .map(lower_http_body)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        value => Ok(value),
    }
}

fn pointer_to_path(pointer: &str) -> Result<String> {
    Ok(pointer_segments(pointer)?.join("."))
}

fn pointer_segments(pointer: &str) -> Result<Vec<String>> {
    let pointer = pointer.strip_prefix('/').unwrap_or(pointer);
    if pointer.is_empty() {
        bail!("source pointer must select a field");
    }
    pointer
        .split('/')
        .map(|segment| {
            let decoded = segment.replace("~1", "/").replace("~0", "~");
            if decoded.is_empty() {
                bail!("source pointer contains an unsupported field token");
            }
            Ok(decoded)
        })
        .collect()
}
