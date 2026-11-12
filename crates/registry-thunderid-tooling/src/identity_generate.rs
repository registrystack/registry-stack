//! The identity generator: ThunderID deployment configuration derived from
//! the products' identity facts and one operator deployment file.
//!
//! [`generate`] is pure: it takes the bytes of its inputs and returns the
//! bytes of its outputs, opens no file, reads no environment variable and
//! resolves no secret. [`generate_to_directory`] is the file-system front
//! end: it reads only the deployment file, the facts files and the public key
//! files the deployment names, and writes a new directory.
//!
//! Identifiers are [`crate::local::derived_uuid`] of
//! `{seed}:{kind}:{id}` (kinds: `machine`, `application`, `user`, `user-type`,
//! `connection`, `organization-unit`, and `role:{kind}`), where the seed
//! comes from the issuer, so each kind has its own namespace and a
//! principal's `sub` is reproducible from the receipt alone. The scope tree
//! is that of [`crate::local::declare_resource`].

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use registry_platform_yaml::{Diagnostic, Document, Severity};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::description::{
    ExchangeAttributeKind, ExchangeIssuer, ExchangeMapping, InteractiveApplication, MachineClient,
    OrganizationUnit, Profile, Role, SessionIdentity, SyntheticUser, TokenExchangeClient,
    DEFAULT_OU_HANDLE, DEFAULT_OU_ID, PRIVATE_JWK_MEMBERS,
};
use crate::identity_deployment::{
    self as deployment_file, relative_path, ClaimValue, Grant, IdentityDeployment,
};
use crate::identity_facts::{
    self as facts_file, https_url, AccessProfile, ActorKind, Admission, AssertionMapping,
    ClaimType, MergedFacts, ProductFacts, ACTOR_KIND_CLAIM,
};
use crate::render::{Area, DeploymentExtras, ExtensionUserType, Mode};
use crate::version::ThunderIdPin;
use crate::{local, ToolingError};

pub const RECEIPT_API_VERSION: &str = "id.registrystack.org/formats/platform/identity-receipt/v1";
pub const RECEIPT_KIND: &str = "PlatformIdentityReceipt";
/// The receipt's file name; it is the last entry published.
const RECEIPT_FILE: &str = "identity-receipt.json";

/// The largest input file the generator reads, in bytes.
pub const MAXIMUM_INPUT_BYTES: u64 = 1024 * 1024;

/// One input's bytes and the name diagnostics call it.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    pub label: &'a str,
    pub bytes: &'a [u8],
}

/// Everything [`generate`] reads.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    pub deployment: Source<'a>,
    pub facts: &'a [Source<'a>],
    /// The bytes of each public key file, by the path the deployment writes.
    pub public_jwks: &'a BTreeMap<String, Vec<u8>>,
}

/// What a run produced, in words a command can print: counts, names and
/// relative paths, never a value read from an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub issuer: String,
    /// Relative paths of the generated files, sorted.
    pub files: Vec<String>,
    pub resource_servers: usize,
    pub machine_clients: usize,
    pub browser_apps: usize,
    pub users: usize,
    /// The environment variables the placeholders name, sorted. The
    /// operator must provide each to ThunderID.
    pub required_environment: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Generated {
    /// File bytes by path relative to the output directory.
    pub files: BTreeMap<String, Vec<u8>>,
    pub summary: Summary,
}

/// The identifier seed for one issuer. It is stable for an issuer and never
/// the URL itself, which can exceed the seed's bound.
pub(crate) fn deployment_session_id(issuer: &str) -> String {
    let digest = Sha256::digest(format!("registry-identity-deployment:{issuer}").as_bytes());
    hex(&digest)[..32].to_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

/// Diagnostics about the deployment file, positioned in it.
struct Findings<'a> {
    document: &'a Document,
    found: Vec<Diagnostic>,
}

impl Findings<'_> {
    fn error(&mut self, pointer: &str, code: &str, message: &str, action: &str) {
        self.found.push(self.document.diagnostic_at_value(
            Severity::Error,
            code,
            pointer,
            message,
            action,
        ));
    }
}

/// A principal's resolved grants: the profile and the product it belongs to.
type Granted<'a> = Vec<(&'a str, &'a AccessProfile)>;

fn requester_allows(profile: &AccessProfile, client: &str) -> bool {
    profile
        .requester_clients
        .as_ref()
        .is_none_or(|clients| clients.iter().any(|allowed| allowed == client))
}

/// Whether a token from one of `clients` can reach `profile`: the product
/// admits the client and the profile's requester clients name it. A product
/// that restricts neither admits every principal, including one no listed
/// client reaches.
fn admits_any(product: &ProductFacts, profile: &AccessProfile, clients: &[String]) -> bool {
    let unrestricted = matches!(product.allowed_clients, Admission::Unrestricted)
        && profile.requester_clients.is_none();
    unrestricted
        || clients.iter().any(|client| {
            product.allowed_clients.admits(client) && requester_allows(profile, client)
        })
}

/// Resolve grants against the merged facts. `reaching` returns the client ids
/// whose tokens reach one product profile for this principal: the client
/// itself, or for a user every browser application authorized to carry that
/// profile and sign them in.
fn resolve_grants<'a>(
    findings: &mut Findings<'_>,
    facts: &'a MergedFacts,
    pointer: &str,
    grants: &'a [Grant],
    reaching: &dyn Fn(&str, &str) -> Vec<String>,
) -> Granted<'a> {
    let mut resolved = Vec::new();
    for (index, grant) in grants.iter().enumerate() {
        let at = format!("{pointer}/grants/{index}");
        let Some((product, product_facts)) = facts.products.get_key_value(&grant.product) else {
            findings.error(
                &format!("{at}/product"),
                "identity.deployment.unknown-product",
                "the grant names a product no identity facts document describes",
                "Supply the product's identity facts, or name another product.",
            );
            continue;
        };
        for (position, id) in grant.access_profiles.iter().enumerate() {
            let Some(profile) = product_facts.access_profiles.get(id) else {
                findings.error(
                    &format!("{at}/accessProfiles/{position}"),
                    "identity.deployment.unknown-profile",
                    "the product declares no access profile with this id",
                    "Name an access profile the product's identity facts declare. A product leaves out a profile that only a delegated or task-grant token reaches; its facts command names each one.",
                );
                continue;
            };
            let reachable = reaching(product, &profile.id);
            if !reachable.iter().any(|client| {
                product_facts.allowed_clients.admits(client) && requester_allows(profile, client)
            }) {
                findings.error(
                    &format!("{at}/accessProfiles/{position}"),
                    "identity.deployment.client-not-admitted",
                    "the product does not admit the client that would present this profile",
                    "Admit the client in the product's configuration and regenerate its facts. For a user, list its type on a browser application and grant that application the same profile outside its default product. Otherwise remove the grant.",
                );
                continue;
            }
            resolved.push((product.as_str(), profile));
        }
    }
    resolved
}

/// Permissions grouped by resource server id, scopes sorted and distinct.
fn permissions(
    description: &crate::description::IssuerDescription,
    facts: &MergedFacts,
    granted: &Granted<'_>,
) -> Vec<(String, Vec<String>)> {
    let mut by_server: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (product, profile) in granted {
        if profile.exchange.is_some() {
            continue;
        }
        if let Some(server) = description
            .resource_servers
            .iter()
            .find(|server| server.identifier == facts.products[*product].audience)
        {
            by_server
                .entry(server.id.clone())
                .or_default()
                .extend(profile.scopes.iter().cloned());
        }
    }
    by_server
        .into_iter()
        .map(|(server, scopes)| (server, scopes.into_iter().collect()))
        .collect()
}

/// The claim that says what kind of principal a token represents.
const ACTOR_KIND: &str = ACTOR_KIND_CLAIM;
const HUMAN: &str = "human";
/// The claim that says for which purpose a token is used.
const PURPOSE: &str = "registry_purpose";
/// The most token attributes a browser application may carry, as the
/// deployment file and the description both bound them.
const MAXIMUM_TOKEN_ATTRIBUTES: usize = 16;

/// Whether `claims` carry every value `selected_by` requires: a string claim
/// equals the single required value, and a string-array claim contains every
/// required value. A claim the principal lacks, or of another shape, selects
/// nothing. An empty `selected_by` is always satisfied.
pub fn selects(
    selected_by: &BTreeMap<String, Vec<String>>,
    claims: &BTreeMap<String, Value>,
) -> bool {
    selected_by
        .iter()
        .all(|(name, required)| match claims.get(name) {
            Some(Value::String(one)) => required.len() == 1 && required[0] == *one,
            Some(Value::Array(many)) => required
                .iter()
                .all(|value| many.iter().any(|carried| carried.as_str() == Some(value))),
            _ => false,
        })
}

/// The actor kinds a profile asks of the principal that holds it: the values
/// that select it by `registry_actor_kind`, and the kind it requires of
/// whoever holds it. An exchange profile selects on the exchanged token,
/// whose claims come from the assertion, so only the kind it requires of the
/// client's own bootstrap token counts.
fn named_kinds(profile: &AccessProfile) -> impl Iterator<Item = &str> {
    profile
        .selected_by
        .get(ACTOR_KIND)
        .filter(|_| profile.exchange.is_none())
        .into_iter()
        .flatten()
        .map(String::as_str)
        .chain(profile.actor_kind.map(ActorKind::as_str))
}

/// The actor kind a machine client's granted profiles require, when they
/// agree on one; machine clients are services otherwise. `Err` names the
/// product and profile that require `human`, which no machine client is.
fn machine_actor_kind(granted: &Granted<'_>) -> Result<String, String> {
    let required: BTreeSet<&str> = granted
        .iter()
        .flat_map(|(_, profile)| named_kinds(profile))
        .collect();
    let kind = match required.iter().next() {
        Some(kind) if required.len() == 1 => (*kind).to_owned(),
        _ => "service".to_owned(),
    };
    if kind != HUMAN {
        return Ok(kind);
    }
    let (product, profile) = granted
        .iter()
        .find(|(_, profile)| named_kinds(profile).any(|kind| kind == HUMAN))
        .expect("a human kind was required by some granted profile");
    Err(format!("{product}/{}", profile.id))
}

/// Every granted profile that requires an actor kind must get it, and every
/// granted profile that admits only some kinds must get one of them: a
/// product that resolves a profile and then checks the kind refuses a token
/// of any other kind. An exchange profile's kind is required of the
/// client's own bootstrap token. Run after the kind is settled.
fn check_required_actor_kind(
    findings: &mut Findings<'_>,
    pointer: &str,
    granted: &Granted<'_>,
    claims: &BTreeMap<String, Value>,
) {
    let carried = claims.get(ACTOR_KIND).and_then(Value::as_str);
    for (product, profile) in granted {
        let at = format!("{pointer}/grants/{product}/{}", profile.id);
        if let Some(required) = profile.actor_kind {
            if carried != Some(required.as_str()) {
                findings.error(
                    &at,
                    "identity.deployment.profile-requires-actor-kind",
                    "the access profile requires a registry_actor_kind this principal does not carry",
                    "Grant the profile to a principal of the kind it requires, or state that kind in the principal's claims.",
                );
            }
        }
        if !profile.admitted_actor_kinds.is_empty()
            && !profile
                .admitted_actor_kinds
                .iter()
                .any(|kind| carried == Some(kind.as_str()))
        {
            findings.error(
                &at,
                "identity.deployment.profile-refuses-actor-kind",
                "the access profile does not admit this principal's registry_actor_kind, so the product would refuse its tokens",
                "Grant the profile to a principal of a kind it admits, or remove the grant.",
            );
        }
    }
}

/// The claims a principal's granted profiles require of every token.
/// Exchange profiles require nothing of the
/// principal: their token's claims come from the exchanged assertion.
fn required_claims<'a>(granted: &Granted<'a>) -> BTreeSet<&'a str> {
    granted
        .iter()
        .filter(|(_, profile)| profile.exchange.is_none())
        .flat_map(|(_, profile)| profile.required_claims.iter().map(String::as_str))
        .collect()
}

/// A principal must carry every claim its granted profiles require: the
/// product refuses a token without one at authentication, after generation
/// would otherwise have passed it. Run after the actor kind and purpose are
/// settled, so a claim the generator derives counts as carried.
fn check_required_claims(
    findings: &mut Findings<'_>,
    pointer: &str,
    granted: &Granted<'_>,
    claims: &BTreeMap<String, Value>,
) {
    if required_claims(granted)
        .iter()
        .any(|name| !claims.contains_key(*name))
    {
        findings.error(
            &format!("{pointer}/claims"),
            "identity.deployment.required-claim-missing",
            "a granted access profile requires a claim this principal does not carry, so the product would refuse its tokens",
            "State the claim in the principal's claims, or remove the grant.",
        );
    }
}

/// A principal must carry no claim its granted profiles refuse: the product
/// never selects such a profile for its tokens. Exchange profiles refuse
/// nothing of the principal: their token's claims come from the exchanged
/// assertion.
fn check_refused_claims(
    findings: &mut Findings<'_>,
    pointer: &str,
    granted: &Granted<'_>,
    claims: &BTreeMap<String, Value>,
) {
    if granted
        .iter()
        .filter(|(_, profile)| profile.exchange.is_none())
        .flat_map(|(_, profile)| &profile.refused_claims)
        .any(|name| claims.contains_key(name))
    {
        findings.error(
            &format!("{pointer}/claims"),
            "identity.deployment.profile-refuses-claim",
            "the principal carries a claim a granted access profile refuses, so the product would refuse its tokens",
            "Remove the claim from the principal, or remove the grant.",
        );
    }
}

/// Settle `registry_purpose` from the principal's grants, for a user as for
/// a machine client: an explicit purpose must be one a granted profile
/// lists, and when none is stated the one purpose the grants list is
/// derived. Several purposes and no explicit choice are refused. Only the
/// profiles of products that read the claim count: Evidence, for one, takes
/// its purpose from the request. Declares nothing when no product reads the
/// claim.
fn settle_purpose(
    findings: &mut Findings<'_>,
    facts: &MergedFacts,
    pointer: &str,
    granted: &Granted<'_>,
    claims: &mut BTreeMap<String, Value>,
) {
    let purposes: BTreeSet<&String> = granted
        .iter()
        .filter(|(product, profile)| {
            profile.exchange.is_none() && reads_purpose(&facts.products[*product])
        })
        .flat_map(|(_, profile)| &profile.purposes)
        .collect();
    match claims.get(PURPOSE).and_then(Value::as_str) {
        Some(explicit) if !purposes.is_empty() && !purposes.iter().any(|p| p.as_str() == explicit) => {
            findings.error(
                &format!("{pointer}/claims"),
                "identity.deployment.purpose-not-granted",
                "the registry_purpose claim names a purpose none of the granted profiles carries",
                "Choose one of the purposes the granted access profiles list.",
            );
        }
        Some(_) => {}
        None => match purposes.len() {
            0 => {}
            1 => {
                claims.insert(
                    PURPOSE.to_owned(),
                    json!(purposes.iter().next().expect("one purpose")),
                );
            }
            _ => findings.error(
                &format!("{pointer}/claims"),
                "identity.deployment.ambiguous-purpose",
                "the granted profiles carry several purposes and no registry_purpose claim chooses one",
                "State the registry_purpose claim, or grant profiles of one purpose.",
            ),
        },
    }
}

/// Whether `product` reads `registry_purpose` from its tokens.
fn reads_purpose(product: &ProductFacts) -> bool {
    product.claims.get(PURPOSE) == Some(&ClaimType::String)
}

/// Settle `registry_actor_kind` from the principal: a user is human, a
/// machine client is not, and an operator value that contradicts either is
/// refused. Declares nothing when no product reads the claim. `false` means
/// no kind could be derived, so the selection check would only repeat it.
fn settle_actor_kind(
    findings: &mut Findings<'_>,
    facts: &MergedFacts,
    pointer: &str,
    human: bool,
    granted: &Granted<'_>,
    claims: &mut BTreeMap<String, Value>,
) -> bool {
    if facts.claims.get(ACTOR_KIND) != Some(&ClaimType::String) {
        return true;
    }
    match claims.get(ACTOR_KIND).and_then(Value::as_str) {
        Some(stated) if (stated == HUMAN) != human => findings.error(
            &format!("{pointer}/claims"),
            "identity.deployment.actor-kind-mismatch",
            "registry_actor_kind contradicts the kind of principal: users are human, machine clients are not",
            "Remove the claim so it follows the principal, or state a kind that fits it.",
        ),
        Some(_) => {}
        None => {
            let kind = if human {
                HUMAN.to_owned()
            } else {
                match machine_actor_kind(granted) {
                    Ok(kind) => kind,
                    Err(profile) => {
                        findings.error(
                            &format!("{pointer}/grants/{profile}"),
                            "identity.deployment.machine-requires-human",
                            "a machine client is granted an access profile that only human principals can be selected for",
                            "Grant this profile to a user, or remove it from the machine client.",
                        );
                        return false;
                    }
                }
            };
            claims.insert(ACTOR_KIND.to_owned(), json!(kind));
        }
    }
    check_required_actor_kind(findings, pointer, granted, claims);
    true
}

/// A principal's claims must select exactly the profiles it is granted
/// among those the products select by claim values. A profile that states
/// no selector is not checked: the facts do not determine its selection.
///
/// A profile none of the principal's `reaching` clients can present is
/// never selected for it, whatever its claims: Messaging resolves a profile
/// by client id before it reads a scope, so two profiles may require the
/// same scopes for disjoint requester clients. A user's native client reaches
/// every profile the product admits once an eligible browser application names
/// it as the default or carries any grant for it. The API sees the client and
/// claims, not which declaration made that application eligible.
///
/// That skip is safe only while every product that selects by claims states a
/// selector on each such profile. Evidence does: it requires at least one
/// requester tag on every profile, so its writer always emits a selector. A
/// writer that meant "any principal" by an empty selector would pass here
/// unchecked, so each writer must state a selector for every profile it
/// selects by claims.
fn check_selection(
    findings: &mut Findings<'_>,
    facts: &MergedFacts,
    pointer: &str,
    claims: &BTreeMap<String, Value>,
    granted: &Granted<'_>,
    user: bool,
    reaching: &dyn Fn(&str) -> Vec<String>,
) {
    for (product, product_facts) in &facts.products {
        let clients = reaching(product);
        for profile in product_facts.access_profiles.values() {
            if profile.selected_by.is_empty()
                || profile.exchange.is_some()
                || !admits_any(product_facts, profile, &clients)
            {
                continue;
            }
            let is_granted = granted
                .iter()
                .any(|(name, held)| name == product && held.id == profile.id);
            let selected = selects(&profile.selected_by, claims);
            if selected && !is_granted {
                findings.error(
                    &format!("{pointer}/claims"),
                    "identity.deployment.claims-select-ungranted-profile",
                    "the claims select an access profile the principal was not granted",
                    "Change the claim values so they select only granted profiles, or grant the profile.",
                );
            } else if !selected && is_granted {
                // User claims are single strings, so a selector that needs a
                // string-array claim can only be met by a machine client.
                let array_claim = profile
                    .selected_by
                    .keys()
                    .find(|name| facts.claims.get(*name) == Some(&ClaimType::StringArray));
                if let (true, Some(name)) = (user, array_claim) {
                    findings.error(
                        &format!("{pointer}/claims/{name}"),
                        "identity.deployment.user-claim-needs-array",
                        "this claim must hold a list to select a granted profile, and user claims are single strings",
                        "Use the default scope claim so the profile states no selector, or grant the profile to a machine client.",
                    );
                    continue;
                }
                findings.error(
                    &format!("{pointer}/grants"),
                    "identity.deployment.profile-not-selectable",
                    "the claims cannot select a granted access profile",
                    "State the claim values the profile requires, or remove the grant.",
                );
            }
        }
    }
}

/// The claims products read as their scopes, under whatever names they
/// renamed them to, with the products that read each: a claim whose selector
/// value, in some profile, is that profile's scopes.
fn scope_claims(facts: &MergedFacts) -> BTreeMap<&str, BTreeSet<&str>> {
    let mut claims: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (product, product_facts) in &facts.products {
        for profile in product_facts.access_profiles.values() {
            for (name, values) in &profile.selected_by {
                if same_members(values, &profile.scopes) {
                    claims.entry(name).or_default().insert(product);
                }
            }
        }
    }
    claims
}

fn same_members(left: &[String], right: &[String]) -> bool {
    left.iter().collect::<BTreeSet<_>>() == right.iter().collect::<BTreeSet<_>>()
}

/// A scope claim's static values must be scopes the principal's grants give
/// for the products that read that claim; anything more would let the token
/// carry a scope nothing granted. Exchange profiles give none: their token
/// is exchanged, not selected by claim.
fn check_scope_claims(
    findings: &mut Findings<'_>,
    facts: &MergedFacts,
    pointer: &str,
    claims: &BTreeMap<String, Value>,
    granted: &Granted<'_>,
) {
    for (name, products) in scope_claims(facts) {
        let Some(Value::Array(carried)) = claims.get(name) else {
            continue;
        };
        let given: BTreeSet<&str> = granted
            .iter()
            .filter(|(product, profile)| products.contains(*product) && profile.exchange.is_none())
            .flat_map(|(_, profile)| profile.scopes.iter().map(String::as_str))
            .collect();
        if carried
            .iter()
            .any(|scope| scope.as_str().is_none_or(|scope| !given.contains(scope)))
        {
            findings.error(
                &format!("{pointer}/claims"),
                "identity.deployment.scope-claim-exceeds-grants",
                "a scope claim carries a scope the principal's grants do not give",
                "Remove the extra scopes, or grant the access profile that gives them.",
            );
        }
    }
}

fn claim_kind(value: &ClaimValue) -> ClaimType {
    match value {
        ClaimValue::One(_) => ClaimType::String,
        ClaimValue::Many(_) => ClaimType::StringArray,
    }
}

fn claim_value(value: &ClaimValue) -> Value {
    match value {
        ClaimValue::One(one) => json!(one),
        ClaimValue::Many(many) => json!(many),
    }
}

/// A claim must be one a product declares, with the type it declares.
fn check_claim(
    findings: &mut Findings<'_>,
    facts: &MergedFacts,
    pointer: &str,
    name: &str,
    kind: ClaimType,
) {
    match facts.claims.get(name) {
        None => findings.error(
            pointer,
            "identity.deployment.unknown-claim",
            "no product declares a claim with this name",
            "Declare the claim in the product's configuration, or remove it.",
        ),
        Some(declared) if *declared != kind => findings.error(
            pointer,
            "identity.deployment.claim-type",
            "the claim's value type differs from the type the products declare",
            "Write the value in the declared type: a string or a list of strings.",
        ),
        Some(_) => {}
    }
}

/// A key file's refusal: code, message and fix. Repeats no value read.
pub(crate) type KeyFileRefusal = (&'static str, &'static str, &'static str);

/// Why a public key file is unusable, if it is. `None` means the file is a
/// JWKS of 1 to 8 public keys.
pub(crate) fn key_file_refusal(bytes: Option<&[u8]>) -> Option<KeyFileRefusal> {
    const MISSING: KeyFileRefusal = (
        "identity.deployment.missing-key-file",
        "the key file was not supplied or could not be read",
        "Provide the public JWKS file at this path.",
    );
    const PRIVATE: KeyFileRefusal = (
        "identity.deployment.private-key-material",
        "the key file carries private key material",
        "Publish the public key only: remove d, p, q, dp, dq, qi, k and oth, and keep the private key with its workload.",
    );
    const INVALID: KeyFileRefusal = (
        "identity.deployment.invalid-key-file",
        "the key file is not a JWKS with 1 to 8 keys",
        "Provide a JSON object with a `keys` array of public JWKs.",
    );
    let Some(bytes) = bytes else {
        return Some(MISSING);
    };
    let parsed: Option<Value> = serde_json::from_slice(bytes).ok();
    let keys = parsed
        .as_ref()
        .and_then(|jwks| jwks.get("keys"))
        .and_then(Value::as_array);
    let Some(keys) = keys.filter(|keys| !keys.is_empty() && keys.len() <= 8) else {
        return Some(INVALID);
    };
    if unexpected_member(parsed.as_ref()).is_some() {
        return Some((
            "identity.deployment.unexpected-key-file-member",
            "the key file holds a top-level member other than `keys`",
            "Publish a JSON object whose only member is the `keys` array.",
        ));
    }
    if keys.iter().any(|key| !key.is_object()) {
        return Some((
            INVALID.0,
            "a key in the key file is not a JSON object",
            INVALID.2,
        ));
    }
    if keys.iter().any(|key| {
        PRIVATE_JWK_MEMBERS
            .iter()
            .any(|member| key.get(member).is_some())
    }) {
        return Some(PRIVATE);
    }
    if keys.iter().any(carries_template_syntax) {
        return Some((
            "identity.deployment.template-syntax-in-key-file",
            "a key file member holds the delimiters reserved for generated placeholders",
            "Remove `{{` and `}}` from every key member name and value.",
        ));
    }
    if keys.iter().any(|key| !is_public_jwk(key)) {
        return Some((
            INVALID.0,
            "a key in the key file is not a public RSA, EC or OKP key of a length ThunderID accepts",
            "Publish each key with its type (kty RSA, EC or OKP), a curve ThunderID verifies (P-256, P-384, P-521 or Ed25519) and exactly its public members, written as base64url. EC coordinates are 32, 48 or 66 bytes, an Ed25519 x is 32 bytes, an RSA modulus is 256 to 1024 bytes and its exponent is odd.",
        ));
    }
    let mut kids = BTreeSet::new();
    if !keys.iter().all(|key| {
        key.get("kid")
            .and_then(Value::as_str)
            .is_some_and(|kid| !kid.is_empty() && kids.insert(kid))
    }) {
        return Some((
            INVALID.0,
            "a key in the key file has no non-empty `kid` string, or two keys share one",
            "Give every key a distinct, non-empty `kid`: ThunderID matches a client assertion's `kid` header against it.",
        ));
    }
    None
}

/// The first top-level member of a JWKS other than `keys`, if any. A plain
/// name is returned as written so the finding can place it; any other name is
/// reported as `other`, since a key file's text is never repeated.
fn unexpected_member(jwks: Option<&Value>) -> Option<String> {
    let name = jwks?.as_object()?.keys().find(|name| *name != "keys")?;
    let plain = name.len() <= 32
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    Some(if plain {
        name.clone()
    } else {
        "other".to_owned()
    })
}

/// Whether any member name or string value in `value`, at any depth, holds
/// the delimiters reserved for generated placeholders. It reads the parsed
/// JSON, so an escaped delimiter is found too.
fn carries_template_syntax(value: &Value) -> bool {
    match value {
        Value::String(text) => facts_file::has_template_syntax(text),
        Value::Array(items) => items.iter().any(carries_template_syntax),
        Value::Object(members) => members.iter().any(|(name, member)| {
            facts_file::has_template_syntax(name) || carries_template_syntax(member)
        }),
        _ => false,
    }
}

/// Whether `key` is a public key ThunderID can verify with: a known type
/// with exactly its public members, each a non-empty unpadded base64url
/// string, an EC or OKP curve on the allowlist, and metadata of the
/// registered JWK types (`kid`, `use` and `alg` strings, `key_ops` a list of
/// strings). Lengths follow ThunderID's runtime key parsing: EC coordinates
/// of 32, 48 or 66 bytes by curve, an Ed25519 `x` of 32 bytes, an RSA
/// modulus of 256 to 1024 bytes and an odd exponent of 1 to 4 bytes that is
/// at least 3, each without a leading zero. Whether a point lies on its curve is
/// left to ThunderID.
fn is_public_jwk(key: &Value) -> bool {
    let Some(members) = key.as_object() else {
        return false;
    };
    let (required, curves): (&[&str], &[&str]) = match key.get("kty").and_then(Value::as_str) {
        Some("RSA") => (&["n", "e"], &[]),
        Some("EC") => (&["x", "y"], &["P-256", "P-384", "P-521"]),
        Some("OKP") => (&["x"], &["Ed25519"]),
        _ => return false,
    };
    let curve_fits = match members.get("crv") {
        None => curves.is_empty(),
        Some(curve) => curve.as_str().is_some_and(|curve| curves.contains(&curve)),
    };
    let decoded = |name: &str| {
        members
            .get(name)
            .and_then(Value::as_str)
            .and_then(decode_base64url)
    };
    let public_members_fit = required.iter().all(|name| decoded(name).is_some())
        && match (
            key.get("kty").and_then(Value::as_str),
            key.get("crv").and_then(Value::as_str),
        ) {
            (Some("EC"), Some(curve)) => {
                let length = match curve {
                    "P-256" => 32,
                    "P-384" => 48,
                    _ => 66,
                };
                ["x", "y"]
                    .iter()
                    .all(|name| decoded(name).is_some_and(|bytes| bytes.len() == length))
            }
            (Some("OKP"), _) => decoded("x").is_some_and(|bytes| bytes.len() == 32),
            _ => {
                decoded("n")
                    .is_some_and(|modulus| (256..=1024).contains(&modulus.len()) && modulus[0] != 0)
                    && decoded("e").is_some_and(|exponent| {
                        (1..=4).contains(&exponent.len())
                            && exponent[0] != 0
                            && exponent
                                .iter()
                                .fold(0u32, |value, byte| value << 8 | u32::from(*byte))
                                >= 3
                            && exponent[exponent.len() - 1] % 2 == 1
                    })
            }
        };
    let every_member_known = members.iter().all(|(name, value)| match name.as_str() {
        "kty" | "crv" => true,
        "kid" | "use" | "alg" => value.is_string(),
        "key_ops" => value
            .as_array()
            .is_some_and(|operations| operations.iter().all(Value::is_string)),
        name => required.contains(&name),
    });
    curve_fits && public_members_fit && every_member_known
}

/// The bytes of non-empty unpadded base64url with no stray bits.
fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    if text.is_empty() {
        return None;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
}

/// Read a public JWKS and re-serialize it canonically.
fn read_jwks(
    findings: &mut Findings<'_>,
    pointer: &str,
    bytes: Option<&Vec<u8>>,
) -> Option<String> {
    if let Some((code, message, action)) = key_file_refusal(bytes.map(Vec::as_slice)) {
        let member = bytes
            .filter(|_| code == "identity.deployment.unexpected-key-file-member")
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            .and_then(|jwks| unexpected_member(Some(&jwks)));
        match member {
            Some(member) => findings.error(&format!("{pointer}/{member}"), code, message, action),
            None => findings.error(pointer, code, message, action),
        }
        return None;
    }
    serde_json::to_string(&serde_json::from_slice::<Value>(bytes?).ok()?).ok()
}

fn refused(document: &Document, found: Vec<Diagnostic>) -> ToolingError {
    let mut report = document.warnings();
    for diagnostic in found {
        report.push(diagnostic);
    }
    ToolingError::FileRefused {
        what: "the identity deployment file",
        fix: "Correct the reported members, or the products' facts they are checked against.",
        report: Box::new(report),
    }
}

/// Every `{{` the output holds opens either a secret placeholder this run
/// emitted or one of the renderer's fixed Gate expressions. Each appears at
/// its exact expected multiplicity, and the output holds no other template
/// opener or closer. An input string that slipped through would add one,
/// including a verbatim copy of an expected expression.
fn assert_only_known_placeholders(
    files: &BTreeMap<String, Vec<u8>>,
    environment: &[String],
    browser_applications: usize,
) -> Result<(), ToolingError> {
    let count = |needle: &str| -> usize {
        files
            .values()
            .map(|bytes| String::from_utf8_lossy(bytes).matches(needle).count())
            .sum()
    };
    let names: BTreeSet<&String> = environment.iter().collect();
    let each_once = names
        .iter()
        .all(|name| count(&format!("{{{{.{name}}}}}")) == 1);
    let gate = crate::render::gate_template_expression_counts(browser_applications);
    let fixed = gate.iter().map(|(_, expected)| expected).sum::<usize>();
    let exact_gate = gate
        .iter()
        .all(|(expression, expected)| count(expression) == *expected);
    let expected = names.len() + fixed;
    if !each_once || !exact_gate || count("{{") != expected || count("}}") != expected {
        return Err(ToolingError::InvalidRender {
            reason: "the output holds template syntax that is not a generated placeholder",
        });
    }
    Ok(())
}

/// The issuer, the merged facts, and the operator file, turned into
/// ThunderID configuration. Pure: see the module documentation.
pub fn generate(inputs: &Inputs<'_>) -> Result<Generated, ToolingError> {
    let pin = ThunderIdPin::load()?;
    let documents = inputs
        .facts
        .iter()
        .map(|source| facts_file::read(source.label, source.bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let facts = facts_file::merge(documents)?;
    if !https_url(&facts.issuer) {
        return Err(ToolingError::IdentityRefused {
            code: "identity.facts.issuer-not-https",
            message: "a deployment's issuer must be an https URL",
            location: "facts/issuer".to_owned(),
        });
    }
    let (deployment, document) =
        deployment_file::read(inputs.deployment.label, inputs.deployment.bytes)?;
    let mut findings = Findings {
        document: &document,
        found: Vec::new(),
    };
    let sid = deployment_session_id(&facts.issuer);

    let unit = &deployment.organization_unit;
    let default_unit = unit.handle == DEFAULT_OU_HANDLE;
    let mut description = crate::description::IssuerDescription {
        session: SessionIdentity {
            label: "identity-deployment".to_owned(),
            id: sid.clone(),
        },
        port: 0,
        state_root: PathBuf::new(),
        organization_unit: OrganizationUnit {
            id: if default_unit {
                DEFAULT_OU_ID.to_owned()
            } else {
                local::derived_uuid(&format!("{sid}:organization-unit:{}", unit.handle))
            },
            handle: unit.handle.clone(),
            name: unit.name.clone(),
            description: unit
                .description
                .clone()
                .unwrap_or_else(|| unit.name.clone()),
        },
        resource_servers: Vec::new(),
        roles: Vec::new(),
        machine_clients: Vec::new(),
        compatibility_clients: Vec::new(),
        interactive_applications: Vec::new(),
        synthetic_users: Vec::new(),
        exchange_issuers: Vec::new(),
        schema_attributes: Vec::new(),
    };

    // Every product audience is a resource server holding the exact scopes
    // its access profiles name. Declaring a scope grants nothing.
    for product in facts.products.values() {
        let scopes: BTreeSet<String> = product
            .access_profiles
            .values()
            .flat_map(|profile| profile.scopes.iter().cloned())
            .collect();
        if !scopes.is_empty() {
            local::declare_resource_as(
                &mut description,
                &product.audience,
                &scopes.into_iter().collect::<Vec<_>>(),
                local::Wording::Deployment,
            )?;
        }
    }
    let bootstrap_scopes: BTreeSet<(String, String)> = facts
        .products
        .values()
        .flat_map(|product| product.access_profiles.values())
        .filter_map(|profile| profile.exchange.as_ref())
        .map(|exchange| {
            (
                exchange.bootstrap_audience.clone(),
                exchange.bootstrap_scope.clone(),
            )
        })
        .collect();
    for (audience, scope) in bootstrap_scopes {
        local::declare_resource_as(
            &mut description,
            &audience,
            &[scope],
            local::Wording::Deployment,
        )?;
    }
    let server_id = |description: &crate::description::IssuerDescription, audience: &str| {
        description
            .resource_servers
            .iter()
            .find(|server| server.identifier == audience)
            .map(|server| server.id.clone())
    };

    // A user reaches the application's default product as before. A different
    // product is reachable only where the application explicitly grants that
    // same profile. In both cases the application must sign in the user's
    // type: every application admits `RegistryPerson`, and an extension type
    // only where its `userTypes` lists it.
    let user_reaching = |user_type: Option<&str>, product: &str, profile: &str| {
        deployment
            .browser_apps
            .iter()
            .filter(|app| {
                let product_reachable = app.product == product
                    || app.grants.iter().any(|grant| {
                        grant.product == product
                            && grant
                                .access_profiles
                                .iter()
                                .any(|granted| granted == profile)
                    });
                product_reachable
                    && user_type.is_none_or(|wanted| app.user_types.iter().any(|id| id == wanted))
            })
            .map(|app| app.id.clone())
            .collect::<Vec<_>>()
    };
    let user_native_reaching = |user_type: Option<&str>, product: &str| {
        deployment
            .browser_apps
            .iter()
            .filter(|app| {
                let product_reachable = app.product == product
                    || app.grants.iter().any(|grant| grant.product == product);
                product_reachable
                    && user_type.is_none_or(|wanted| app.user_types.iter().any(|id| id == wanted))
            })
            .map(|app| app.id.clone())
            .collect::<Vec<_>>()
    };

    let mut extras = DeploymentExtras::default();
    let mut schema_attributes = BTreeSet::new();
    let mut used_issuers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut identities: BTreeMap<String, Value> = BTreeMap::new();
    // Users have their own namespace, so a user and a client may share an id.
    let mut user_identities: BTreeMap<String, Value> = BTreeMap::new();
    let mut jwks_digests: BTreeMap<String, String> = BTreeMap::new();
    // For each browser application, the claims the profiles reached through
    // it require: its own grants' and those of every user it signs in.
    let mut projected_requirements: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for (index, client) in deployment.clients.iter().enumerate() {
        let pointer = format!("/clients/{index}");
        let reaching = |_: &str, _: &str| vec![client.id.clone()];
        let found_before = findings.found.len();
        let granted = resolve_grants(&mut findings, &facts, &pointer, &client.grants, &reaching);
        let resolved = findings.found.len() == found_before;
        let jwks_bytes = inputs.public_jwks.get(&client.public_jwks_file);
        let jwks = read_jwks(
            &mut findings,
            &format!("{pointer}/publicJwksFile"),
            jwks_bytes,
        );
        if let Some(bytes) = jwks_bytes {
            jwks_digests.insert(client.id.clone(), digest_of(bytes));
        }
        let mut attributes: BTreeMap<String, Value> = BTreeMap::new();
        for (name, value) in &client.claims {
            check_claim(
                &mut findings,
                &facts,
                &format!("{pointer}/claims"),
                name,
                claim_kind(value),
            );
            attributes.insert(name.clone(), claim_value(value));
        }
        settle_purpose(&mut findings, &facts, &pointer, &granted, &mut attributes);
        let settled = settle_actor_kind(
            &mut findings,
            &facts,
            &pointer,
            false,
            &granted,
            &mut attributes,
        );
        if settled {
            check_required_claims(&mut findings, &pointer, &granted, &attributes);
            check_refused_claims(&mut findings, &pointer, &granted, &attributes);
        }
        if resolved && settled {
            let selection_reaching = |_: &str| vec![client.id.clone()];
            check_selection(
                &mut findings,
                &facts,
                &pointer,
                &attributes,
                &granted,
                false,
                &selection_reaching,
            );
            check_scope_claims(&mut findings, &facts, &pointer, &attributes, &granted);
        }
        schema_attributes.extend(attributes.keys().cloned());

        // A client granted an exchange profile presents an assertion; its
        // only direct permission is the bootstrap scope.
        let exchanges: BTreeSet<_> = granted
            .iter()
            .filter_map(|(_, profile)| profile.exchange.as_ref())
            .collect();
        let agent_id = local::derived_uuid(&format!("{sid}:machine:{}", client.id));
        let mut role_permissions = permissions(&description, &facts, &granted);
        let mut token_exchange = None;
        if let Some(exchange) = exchanges.iter().next() {
            if exchanges.len() > 1 {
                findings.error(
                    &format!("{pointer}/grants"),
                    "identity.deployment.conflicting-exchange",
                    "the granted exchange profiles name different assertion issuers or bootstrap permissions",
                    "Grant exchange profiles that share one assertion issuer and bootstrap scope, or split the client.",
                );
            }
            let bootstrap = server_id(&description, &exchange.bootstrap_audience)
                .expect("bootstrap resources are declared above");
            if role_permissions
                .iter()
                .any(|(server, _)| *server == bootstrap)
            {
                findings.error(
                    &format!("{pointer}/grants"),
                    "identity.deployment.exchange-bootstrap-overlap",
                    "a directly granted profile shares the bootstrap resource of an exchange profile",
                    "Remove the overlapping grant; an exchange client holds only its bootstrap permission there.",
                );
            }
            token_exchange = Some(TokenExchangeClient {
                assertion_resource_server_id: bootstrap.clone(),
                assertion_scope: exchange.bootstrap_scope.clone(),
                ordinary_resource_permissions: role_permissions.clone(),
            });
            role_permissions.insert(0, (bootstrap, vec![exchange.bootstrap_scope.clone()]));
            used_issuers
                .entry(exchange.assertion_issuer_id.clone())
                .or_default()
                .push(client.id.clone());
        }
        let Some(public_jwks) = jwks else { continue };
        description.roles.push(Role {
            id: local::derived_uuid(&format!("{sid}:role:machine:{}", client.id)),
            name: format!("Deployment {}", client.id),
            description: "Explicit deployment client permissions".to_owned(),
            permissions: role_permissions,
            assigned_agents: vec![agent_id.clone()],
            assigned_users: vec![],
            assigned_applications: vec![],
        });
        description.machine_clients.push(MachineClient {
            agent_id: agent_id.clone(),
            name: format!("Client {}", client.id),
            description: "Deployment machine client".to_owned(),
            client_id: client.id.clone(),
            public_jwks,
            token_attributes: attributes.keys().cloned().collect(),
            attributes,
            access_token_lifetime_seconds: 300,
            token_exchange,
        });
        identities.insert(
            client.id.clone(),
            json!({"kind": "machine", "sub": agent_id}),
        );
    }

    for user_type in &deployment.user_types {
        extras.user_types.push(ExtensionUserType {
            id: local::derived_uuid(&format!("{sid}:user-type:{}", user_type.id)),
            name: user_type.name.clone(),
            attributes: user_type.attributes.clone(),
        });
    }
    let type_name = |id: &str| {
        deployment
            .user_types
            .iter()
            .find(|user_type| user_type.id == id)
            .map(|user_type| user_type.name.clone())
    };

    for (index, app) in deployment.browser_apps.iter().enumerate() {
        let pointer = format!("/browserApps/{index}");
        let reaching = |_: &str, _: &str| vec![app.id.clone()];
        let granted = resolve_grants(&mut findings, &facts, &pointer, &app.grants, &reaching);
        if granted
            .iter()
            .any(|(_, profile)| profile.exchange.is_some())
        {
            findings.error(
                &format!("{pointer}/grants"),
                "identity.deployment.exchange-not-interactive",
                "an exchange profile cannot be granted to a browser application",
                "Grant exchange profiles to a machine client.",
            );
        }
        let Some(product) = facts.products.get(&app.product) else {
            findings.error(
                &format!("{pointer}/product"),
                "identity.deployment.unknown-product",
                "the application names a product no identity facts document describes",
                "Supply the product's identity facts, or name another product.",
            );
            continue;
        };
        for name in &app.token_attributes {
            check_claim(
                &mut findings,
                &facts,
                &format!("{pointer}/tokenAttributes"),
                name,
                ClaimType::String,
            );
        }
        // Every user is given registry_actor_kind when a product reads it
        // (BReg refuses a non-delegated token without it), and the purpose
        // their grants give when any product reachable through the application
        // requires one (BReg refuses a token for such a profile without it). The
        // application's tokens carry both as a machine client's do, listed
        // or not.
        let default_reads_purpose = reads_purpose(product)
            && product
                .access_profiles
                .values()
                .any(|profile| profile.exchange.is_none() && !profile.purposes.is_empty());
        let granted_reads_purpose = granted.iter().any(|(granted_product, profile)| {
            *granted_product != app.product
                && profile.exchange.is_none()
                && !profile.purposes.is_empty()
                && reads_purpose(&facts.products[*granted_product])
        });
        let projects_purpose = default_reads_purpose || granted_reads_purpose;
        let required = [
            (
                ACTOR_KIND,
                facts.claims.get(ACTOR_KIND) == Some(&ClaimType::String),
                "identity.deployment.actor-kind-not-projected",
                "the application lists the most token attributes it may carry, so its tokens cannot also carry registry_actor_kind, which the products require",
                "List registry_actor_kind among the token attributes, or remove one so the generator can add it.",
            ),
            (
                PURPOSE,
                projects_purpose,
                "identity.deployment.purpose-not-projected",
                "the application lists the most token attributes it may carry, so its tokens cannot also carry registry_purpose, which a reachable product requires",
                "List registry_purpose among the token attributes, or remove one so the generator can add it.",
            ),
        ];
        let mut token_attributes = app.token_attributes.clone();
        for (name, read, code, message, remedy) in required {
            if !read || token_attributes.iter().any(|listed| listed == name) {
                continue;
            }
            if token_attributes.len() >= MAXIMUM_TOKEN_ATTRIBUTES {
                findings.error(&format!("{pointer}/tokenAttributes"), code, message, remedy);
                continue;
            }
            token_attributes.push(name.to_owned());
        }
        projected_requirements
            .entry(app.id.clone())
            .or_default()
            .extend(required_claims(&granted).into_iter().map(str::to_owned));
        let app_id = local::derived_uuid(&format!("{sid}:application:{}", app.id));
        description
            .interactive_applications
            .push(InteractiveApplication {
                id: app_id.clone(),
                client_id: app.id.clone(),
                client_secret_file: Path::new("env").join(app.client_secret_ref.name()),
                origin: app.origin.clone(),
                redirect_uris: app.redirect_uris.clone(),
                audience: product.audience.clone(),
                token_attributes,
            });
        description.roles.push(Role {
            id: local::derived_uuid(&format!("{sid}:role:application:{}", app.id)),
            name: format!("Browser {}", app.id),
            description: "Explicit deployment browser application permissions".to_owned(),
            permissions: permissions(&description, &facts, &granted),
            assigned_agents: vec![],
            assigned_users: vec![],
            assigned_applications: vec![app_id.clone()],
        });
        extras.app_user_types.insert(
            app_id.clone(),
            app.user_types
                .iter()
                .filter_map(|id| type_name(id))
                .collect(),
        );
        if let Some(logo) = &app.logo_url {
            extras.app_logo_urls.insert(app_id.clone(), logo.clone());
        }
        identities.insert(app.id.clone(), json!({"kind": "browser", "sub": app_id}));
    }

    for (index, user) in deployment.users.iter().enumerate() {
        let pointer = format!("/users/{index}");
        let reaching = |product: &str, profile: &str| {
            user_reaching(user.user_type.as_deref(), product, profile)
        };
        let found_before = findings.found.len();
        let granted = resolve_grants(&mut findings, &facts, &pointer, &user.grants, &reaching);
        let resolved = findings.found.len() == found_before;
        if granted
            .iter()
            .any(|(_, profile)| profile.exchange.is_some())
        {
            findings.error(
                &format!("{pointer}/grants"),
                "identity.deployment.exchange-not-interactive",
                "an exchange profile cannot be granted to a user",
                "Grant exchange profiles to a machine client.",
            );
        }
        for name in user.claims.keys() {
            check_claim(
                &mut findings,
                &facts,
                &format!("{pointer}/claims"),
                name,
                ClaimType::String,
            );
        }
        let mut user_claims: BTreeMap<String, Value> = user
            .claims
            .iter()
            .map(|(name, value)| (name.clone(), json!(value)))
            .collect();
        settle_purpose(&mut findings, &facts, &pointer, &granted, &mut user_claims);
        // A user is always human, so settling a user's kind cannot fail.
        let _ = settle_actor_kind(
            &mut findings,
            &facts,
            &pointer,
            true,
            &granted,
            &mut user_claims,
        );
        check_required_claims(&mut findings, &pointer, &granted, &user_claims);
        check_refused_claims(&mut findings, &pointer, &granted, &user_claims);
        // The applications that sign this user in carry its tokens, so they
        // must project what its granted profiles require.
        for (product, profile) in &granted {
            if profile.exchange.is_some() {
                continue;
            }
            for app in user_reaching(user.user_type.as_deref(), product, &profile.id) {
                projected_requirements
                    .entry(app)
                    .or_default()
                    .extend(profile.required_claims.iter().cloned());
            }
        }
        if resolved {
            let selection_reaching =
                |product: &str| user_native_reaching(user.user_type.as_deref(), product);
            check_selection(
                &mut findings,
                &facts,
                &pointer,
                &user_claims,
                &granted,
                true,
                &selection_reaching,
            );
            check_scope_claims(&mut findings, &facts, &pointer, &user_claims, &granted);
        }
        let user_id = local::derived_uuid(&format!("{sid}:user:{}", user.id));
        user_identities.insert(user.id.clone(), json!({"kind": "user", "sub": user_id}));
        description.synthetic_users.push(SyntheticUser {
            id: user_id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            password_file: Path::new("env").join(user.password_ref.name()),
            attributes: user_claims
                .iter()
                .filter_map(|(name, value)| Some((name.clone(), value.as_str()?.to_owned())))
                .collect(),
        });
        description.roles.push(Role {
            id: local::derived_uuid(&format!("{sid}:role:user:{}", user.id)),
            name: format!("User {}", user.id),
            description: "Explicit deployment user permissions".to_owned(),
            permissions: permissions(&description, &facts, &granted),
            assigned_agents: vec![],
            assigned_users: vec![user_id.clone()],
            assigned_applications: vec![],
        });
        if let Some(name) = user.user_type.as_deref().and_then(type_name) {
            extras.user_type_of.insert(user_id, name);
        }
    }

    // An application's tokens carry only the attributes it projects, so a
    // claim a profile reached through it requires must be among them; the
    // actor kind and purpose it is given were added above.
    for (index, app) in deployment.browser_apps.iter().enumerate() {
        let Some(projected) = description
            .interactive_applications
            .iter()
            .find(|projected| projected.client_id == app.id)
        else {
            continue;
        };
        if projected_requirements
            .get(&app.id)
            .into_iter()
            .flatten()
            .any(|name| !projected.token_attributes.contains(name))
        {
            findings.error(
                &format!("/browserApps/{index}/tokenAttributes"),
                "identity.deployment.required-claim-not-projected",
                "the application's tokens do not carry a claim that an access profile reached through it requires, so the product would refuse them",
                "List the claim among the application's token attributes.",
            );
        }
    }

    // Trust only the assertion authorities a client actually exchanges for.
    for (id, clients) in &used_issuers {
        let issuer = &facts.assertion_issuers[id];
        description.exchange_issuers.push(ExchangeIssuer {
            id: local::derived_uuid(&format!("{sid}:connection:{id}")),
            name: format!("Assertion authority {id}"),
            issuer: issuer.issuer.clone(),
            jwks_endpoint: issuer.jwks_url.clone(),
            mapping: match issuer.mapping {
                AssertionMapping::InstitutionalGrant => ExchangeMapping::InstitutionalGrant,
                AssertionMapping::FirstParty => ExchangeMapping::FirstParty,
            },
            clients: match issuer.mapping {
                AssertionMapping::InstitutionalGrant => Vec::new(),
                AssertionMapping::FirstParty => clients.clone(),
            },
            token_attributes: issuer
                .projected_claims
                .iter()
                .map(|(name, kind)| {
                    (
                        name.clone(),
                        match kind {
                            ClaimType::String => ExchangeAttributeKind::String,
                            ClaimType::StringArray => ExchangeAttributeKind::StringArray,
                        },
                    )
                })
                .collect(),
        });
    }
    description.schema_attributes = schema_attributes.into_iter().collect();

    if !findings.found.is_empty() {
        let Findings { found, .. } = findings;
        return Err(refused(&document, found));
    }
    description.validate_for(Profile::Deployment {
        issuer: &facts.issuer,
    })?;
    // The extension user types are derived beside the description; every
    // derived identifier must be distinct across all of them.
    if !crate::description::all_distinct(
        description.derived_ids().into_iter().chain(
            extras
                .user_types
                .iter()
                .map(|user_type| user_type.id.clone()),
        ),
    ) {
        return Err(ToolingError::InvalidDescription {
            reason: "two derived identifiers are the same",
        });
    }

    let built = crate::render::build(&description, &Mode::Deployment { extras: &extras })?;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut resources = Vec::new();
    for output in built.outputs {
        match output.area {
            Area::Resources => {
                resources.extend_from_slice(b"---\n");
                resources.extend_from_slice(&output.bytes);
            }
            Area::Bootstrap => {
                files.insert(
                    format!("{}/{}", crate::render::BOOTSTRAP_DIR, output.path.display()),
                    output.bytes,
                );
            }
            Area::Assets => {}
        }
    }
    files.insert(
        format!("{}/resources.yaml", crate::render::RESOURCES_DIR),
        resources,
    );
    files.insert(
        "deployment.yaml".to_owned(),
        deployment_yaml(&facts.issuer, &pin).into_bytes(),
    );

    let required_environment = deployment.required_environment();
    let mut inputs_receipt = json!({
        "deployment": {"digest": digest_of(inputs.deployment.bytes)},
        "facts": {},
        "publicJwks": {},
    });
    for source in inputs.facts {
        // The product name is the key; the label (often a path) is never recorded.
        let product = facts_file::read(source.label, source.bytes)?.product;
        inputs_receipt["facts"][product] = json!({"digest": digest_of(source.bytes)});
    }
    for (client, digest) in &jwks_digests {
        inputs_receipt["publicJwks"][client] = json!({"digest": digest});
    }
    let receipt = json!({
        "apiVersion": RECEIPT_API_VERSION,
        "kind": RECEIPT_KIND,
        "issuer": facts.issuer,
        "thunderid": {"version": pin.version, "image": pin.image},
        "inputs": inputs_receipt,
        "clients": identities,
        "users": user_identities,
        "requiredEnvironment": required_environment,
    });
    let mut receipt_text =
        serde_json::to_string_pretty(&receipt).map_err(|_| ToolingError::InvalidRender {
            reason: "the identity receipt did not serialize",
        })?;
    receipt_text.push('\n');
    files.insert(RECEIPT_FILE.to_owned(), receipt_text.into_bytes());

    assert_only_known_placeholders(
        &files,
        &required_environment,
        description.interactive_applications.len(),
    )?;

    let summary = Summary {
        issuer: facts.issuer.clone(),
        files: files.keys().cloned().collect(),
        resource_servers: description.resource_servers.len(),
        machine_clients: description.machine_clients.len(),
        browser_apps: description.interactive_applications.len(),
        users: description.synthetic_users.len(),
        required_environment,
    };
    Ok(Generated { files, summary })
}

/// The server members this generator owns, to merge into the environment's
/// own `deployment.yaml`; the database, TLS and signing material stay with
/// the environment.
fn deployment_yaml(issuer: &str, pin: &ThunderIdPin) -> String {
    format!(
        "# Generated for ThunderID {} by the Registry Stack identity generator.\n\
         # Merge these members into the environment's deployment.yaml; the\n\
         # database, TLS and signing material stay with the environment.\n\
         server:\n  public_url: {issuer}\n\
         resource:\n  store: composite\n\
         role:\n  store: composite\n\
         theme:\n  store: composite\n\
         layout:\n  store: composite\n\
         identity_provider:\n  store: composite\n",
        pin.version
    )
}

/// The public key files a deployment names, by the path it writes. A path
/// outside the deployment directory is refused by the reader; a file that
/// cannot be read is left out and reported with its member.
pub(crate) fn read_public_jwks(
    base: &Path,
    deployment: &IdentityDeployment,
) -> BTreeMap<String, Vec<u8>> {
    let mut public_jwks = BTreeMap::new();
    for file in deployment.jwks_files() {
        if relative_path(file) {
            if let Ok(bytes) = read_bounded(&base.join(file)) {
                public_jwks.insert(file.to_owned(), bytes);
            }
        }
    }
    public_jwks
}

pub(crate) fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAXIMUM_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAXIMUM_INPUT_BYTES {
        return Err(std::io::Error::other("input too large"));
    }
    Ok(bytes)
}

/// Read the deployment file, the facts files and the public key files the
/// deployment names, and write the generated tree into `output`, which must
/// not exist. Opens no other file; a secret is never read.
pub fn generate_to_directory(
    deployment: &Path,
    facts: &[PathBuf],
    output: &Path,
) -> Result<Summary, ToolingError> {
    if fs::symlink_metadata(output).is_ok() {
        return Err(ToolingError::OutputExists);
    }
    let unreadable = |_| ToolingError::Filesystem {
        reason: "an input file could not be read",
    };
    let deployment_bytes = read_bounded(deployment).map_err(unreadable)?;
    let deployment_label = deployment.display().to_string();
    let (parsed, _): (IdentityDeployment, _) =
        deployment_file::read(&deployment_label, &deployment_bytes)?;
    let base = deployment.parent().unwrap_or_else(|| Path::new("."));
    let public_jwks = read_public_jwks(base, &parsed);
    let labels: Vec<String> = facts
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let fact_bytes = facts
        .iter()
        .map(|path| read_bounded(path).map_err(unreadable))
        .collect::<Result<Vec<_>, _>>()?;
    let sources: Vec<Source<'_>> = labels
        .iter()
        .zip(&fact_bytes)
        .map(|(label, bytes)| Source { label, bytes })
        .collect();
    let generated = generate(&Inputs {
        deployment: Source {
            label: &deployment_label,
            bytes: &deployment_bytes,
        },
        facts: &sources,
        public_jwks: &public_jwks,
    })?;
    write_private_tree(output, &generated.files)?;
    Ok(generated.summary)
}

/// Write the files into a private sibling directory (0700 directories, 0600
/// files), then create `output` exclusively and move the finished entries
/// into it. The exclusive create refuses atomically if anything, even an empty
/// directory, took the output's place meanwhile; the output is private from
/// the moment it exists.
fn write_private_tree(
    output: &Path,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), ToolingError> {
    write_private_tree_with(output, files, || {})
}

/// The order top-level entries move into the output: by name, with the
/// receipt last, so the receipt's presence marks a complete output.
fn in_publication_order(mut names: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    names.sort_by_key(|name| (name == RECEIPT_FILE, name.clone()));
    names
}

/// `write_private_tree`, calling `before_publish` once the staging directory
/// is complete and just before the output is created.
fn write_private_tree_with(
    output: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    before_publish: impl FnOnce(),
) -> Result<(), ToolingError> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let name = output
        .file_name()
        .ok_or(ToolingError::Filesystem {
            reason: "the output path must name a new directory",
        })?
        .to_string_lossy();
    let staging = output.with_file_name(format!(
        ".{name}.staging-{}",
        crate::container::random_urlsafe(12).map_err(|_| ToolingError::Filesystem {
            reason: "a staging directory name could not be generated",
        })?
    ));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&staging)
        .map_err(|_| ToolingError::Filesystem {
            reason: "the output directory could not be created; its parent must exist",
        })?;
    // Best effort on every failure below: the staging directory is this
    // call's own and holds only generated output. The refusal is what reports.
    let discard_staging = || {
        let _ = fs::remove_dir_all(&staging);
    };
    let written = (|| -> std::io::Result<()> {
        builder.recursive(true);
        for (relative, bytes) in files {
            let target = staging.join(relative);
            if let Some(parent) = target.parent() {
                builder.create(parent)?;
            }
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&target)?
                .write_all(bytes)?;
        }
        Ok(())
    })();
    if written.is_err() {
        discard_staging();
        return Err(ToolingError::Filesystem {
            reason: "the output could not be written; the output directory was not created",
        });
    }
    before_publish();
    builder.recursive(false);
    if let Err(error) = builder.create(output) {
        discard_staging();
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            ToolingError::OutputExists
        } else {
            ToolingError::Filesystem {
                reason: "the output directory could not be created; check its parent's permissions",
            }
        });
    }
    let moved = (|| -> std::io::Result<()> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&staging)? {
            names.push(entry?.file_name());
        }
        for name in in_publication_order(names) {
            fs::rename(staging.join(&name), output.join(&name))?;
        }
        fs::remove_dir(&staging)
    })();
    if moved.is_err() {
        // The output was created by this call a moment ago, so it holds only
        // this run's entries.
        let _ = fs::remove_dir_all(output);
        discard_staging();
        return Err(ToolingError::Filesystem {
            reason: "the output could not be written; the output directory was removed",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    include!("identity_generate_tests.rs");
}
