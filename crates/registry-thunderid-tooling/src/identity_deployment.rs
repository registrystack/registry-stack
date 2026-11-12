//! The identity deployment file (`PlatformIdentityDeployment`): the part of a
//! hosted issuer's configuration that no product knows.
//!
//! The operator writes the organization unit, each client's public key file
//! and grants, the browser applications, the users, and the environment
//! variable that holds each secret. Everything a product knows (issuer,
//! audience, admitted clients, claims, access profiles, assertion
//! authorities) comes from the products' identity facts instead, and the
//! generator checks this file against it.
//!
//! The file names no secret: a secret is a `secret:env/NAME` reference
//! (CFG-SEC-1), and the generator renders it as a `{{.NAME}}` placeholder
//! without reading the environment.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_yaml::{
    ApiVersion, Decoded, Diagnostic, Document, EnvelopeRule, Expect, FormatSpec, LocalId, Reader,
    SecretProvider, SecretReference, Severity,
};
use serde::{Deserialize, Serialize};

use crate::description::protected_attribute;
use crate::identity_facts::{set, valid_claim_name, valid_client_id, ActorKind, ACTOR_KIND_CLAIM};
use crate::ToolingError;

pub const API_VERSION: &str = "id.registrystack.org/formats/platform/identity-deployment/v1";
pub const KIND: &str = "PlatformIdentityDeployment";

/// The most clients, browser applications or users one file states.
pub const MAXIMUM_PRINCIPALS: usize = 256;
/// The most grants one principal holds.
pub const MAXIMUM_GRANTS: usize = 16;

pub const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The organization unit every generated resource belongs to. The handle
/// `default` builds on the unit the bootstrap bundle creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OrganizationUnit {
    pub handle: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Access profiles of one product, granted to one principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Grant {
    /// The `product` of a facts document.
    pub product: String,
    /// Ids of that product's access profiles.
    #[serde(deserialize_with = "set")]
    pub access_profiles: Vec<String>,
}

/// A static claim value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
#[serde(untagged)]
pub enum ClaimValue {
    One(String),
    Many(Vec<String>),
}

registry_platform_yaml::shape_union!(ClaimValue { scalar => One, list => Many });

/// A machine client: authenticates with `private_key_jwt` against its own
/// public key set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Client {
    /// The OAuth client id.
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    /// A JWKS file holding public keys only, relative to this file.
    pub public_jwks_file: String,
    pub grants: Vec<Grant>,
    /// Static claims the issuer puts in the client's tokens; each name and
    /// type must be one a product declares.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, ClaimValue>,
}

/// A browser application: an authorization-code client with PKCE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BrowserApp {
    /// The OAuth client id.
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub client_secret_ref: SecretReference,
    pub origin: String,
    #[serde(deserialize_with = "set")]
    pub redirect_uris: Vec<String>,
    /// The `product` whose audience tokens carry by default. A request still
    /// produces a token for one audience.
    pub product: String,
    /// Claims the application's tokens carry from the signed-in user. Each
    /// is declared by a product or by an extension user type this application
    /// explicitly admits. A product declaration remains authoritative.
    #[serde(deserialize_with = "set")]
    pub token_attributes: Vec<String>,
    /// Profiles granted to the application. A grant outside `product` also
    /// lets an eligible signed-in user's matching profile reach that product;
    /// it does not change the default audience.
    pub grants: Vec<Grant>,
    /// Extension user types (ids of `userTypes`) that may sign in, beside
    /// the generated `RegistryPerson`.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "set"
    )]
    pub user_types: Vec<String>,
    /// A public logo URL, shown on the sign-in page; omitted shows none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::Url>")
    )]
    pub logo_url: Option<String>,
}

/// A user, with the claims their tokens carry stated explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct User {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_ref: SecretReference,
    /// An extension user type (id of `userTypes`); omitted is `RegistryPerson`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_type: Option<String>,
    /// Product claims, plus scalar issuer-owned attributes declared by this
    /// user's exact extension type. `RegistryPerson` has no such extension.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, String>,
    pub grants: Vec<Grant>,
}

/// An extension user type: an additional ThunderID user schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UserType {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    /// The ThunderID type name users of this type carry.
    pub name: String,
    /// Optional issuer-owned string attributes beyond username, email and
    /// password. They grant no product authority. A user may carry one only
    /// through this exact type, and an application may project one only when
    /// it explicitly admits a type that declares it. Product claim types and
    /// selectors remain authoritative where a product declares the same name.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "set"
    )]
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdentityDeployment {
    pub api_version: String,
    pub kind: String,
    pub organization_unit: OrganizationUnit,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<Client>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub browser_apps: Vec<BrowserApp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<User>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_types: Vec<UserType>,
}

impl IdentityDeployment {
    /// The public key files this deployment names, in client order. These
    /// are the only files the generator reads besides the deployment itself
    /// and the facts documents.
    pub fn jwks_files(&self) -> Vec<&str> {
        self.clients
            .iter()
            .map(|client| client.public_jwks_file.as_str())
            .collect()
    }

    /// The environment variables the rendered placeholders name, sorted.
    pub fn required_environment(&self) -> Vec<String> {
        self.secret_references()
            .into_iter()
            .map(|reference| reference.name().to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn secret_references(&self) -> Vec<&SecretReference> {
        self.browser_apps
            .iter()
            .map(|app| &app.client_secret_ref)
            .chain(self.users.iter().map(|user| &user.password_ref))
            .collect()
    }
}

/// A path relative to the deployment file: `/` separators, no empty,
/// `.` or `..` segment, and not absolute.
pub(crate) fn relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Read one deployment file through the shared reader and check what its
/// types do not. Resolves no secret and opens no file it names.
pub fn read(file: &str, bytes: &[u8]) -> Result<(IdentityDeployment, Document), ToolingError> {
    let refused = |report| ToolingError::FileRefused {
        what: "the identity deployment file",
        fix: "Correct the reported members; see the identity deployment format.",
        report: Box::new(report),
    };
    let mut hook = registry_platform_config::AuthoredExpressions;
    let Decoded { value, document } = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<IdentityDeployment>(bytes, &Expect::one(&FORMAT))
        .map_err(refused)?;
    let mut found = check(&document, &value);
    found.extend(crate::identity_facts::template_findings(&document));
    if found.is_empty() {
        return Ok((value, document));
    }
    let mut report = document.warnings();
    for diagnostic in found {
        report.push(diagnostic);
    }
    Err(refused(report))
}

/// Refuse an explicit `registry_actor_kind` the products' runtimes do not
/// parse: each refuses a token whose kind is not `human`, `agent` or
/// `service`, whatever profile it is granted.
fn unknown_actor_kind(pointer: &str, error: &mut dyn FnMut(&str, &str, &str, &str)) {
    error(
        &format!("{pointer}/claims/{ACTOR_KIND_CLAIM}"),
        "identity.deployment.unknown-actor-kind",
        "registry_actor_kind is not human, agent or service, so every product would refuse the principal's tokens",
        "State human, agent or service, or remove the claim so the generator derives it.",
    );
}

fn check(document: &Document, deployment: &IdentityDeployment) -> Vec<Diagnostic> {
    let mut found = Vec::new();
    let mut error = |pointer: &str, code: &str, message: &str, action: &str| {
        found.push(document.diagnostic_at_value(Severity::Error, code, pointer, message, action));
    };
    let unit = &deployment.organization_unit;
    if LocalId::new(unit.handle.clone()).is_err() || unit.name.is_empty() || unit.name.len() > 128 {
        error(
            "/organizationUnit",
            "identity.deployment.invalid-organization-unit",
            "the organization unit handle is not a local identifier, or its name is empty or too long",
            "Write a handle of lowercase letters, digits, `-` and `_`, and a name of at most 128 bytes.",
        );
    }
    if deployment.clients.is_empty() && deployment.browser_apps.is_empty() {
        error(
            "/clients",
            "identity.deployment.no-principals",
            "the file states no client and no browser application",
            "State at least one client or browser application.",
        );
    }
    if deployment.clients.len() > MAXIMUM_PRINCIPALS
        || deployment.browser_apps.len() > MAXIMUM_PRINCIPALS
        || deployment.users.len() > MAXIMUM_PRINCIPALS
    {
        error(
            "/clients",
            "identity.deployment.too-many",
            "more than 256 clients, browser applications or users are stated",
            "State at most 256 of each.",
        );
    }
    if !deployment.users.is_empty() && deployment.browser_apps.is_empty() {
        error(
            "/users",
            "identity.deployment.users-need-an-app",
            "users are stated but no browser application lets them sign in",
            "State a browser application, or remove the users.",
        );
    }

    let mut client_ids = BTreeSet::new();
    let check_grants = |pointer: &str,
                        grants: &[Grant],
                        found: &mut dyn FnMut(&str, &str, &str, &str)| {
        if grants.is_empty() || grants.len() > MAXIMUM_GRANTS {
            found(
                &format!("{pointer}/grants"),
                "identity.deployment.no-grants",
                "a principal holds no grant, or more than 16",
                "Grant 1 to 16 products' access profiles; an unlisted principal has no access.",
            );
        }
        for (index, grant) in grants.iter().enumerate() {
            if LocalId::new(grant.product.clone()).is_err()
                || grant.access_profiles.is_empty()
                || grant.access_profiles.len() > crate::identity_facts::MAXIMUM_PROFILES
                || grant.access_profiles.iter().collect::<BTreeSet<_>>().len()
                    != grant.access_profiles.len()
                || grant
                    .access_profiles
                    .iter()
                    .any(|profile| LocalId::new(profile.clone()).is_err())
            {
                found(
                    &format!("{pointer}/grants/{index}"),
                    "identity.deployment.invalid-grant",
                    "a grant names no product, or its profiles are empty, repeated, or not local identifiers",
                    "Name one product and list its access profiles once each.",
                );
            }
        }
    };
    for (index, client) in deployment.clients.iter().enumerate() {
        let pointer = format!("/clients/{index}");
        if LocalId::new(client.id.clone()).is_err()
            || !valid_client_id(&client.id)
            || !client_ids.insert(client.id.as_str())
        {
            error(
                &format!("{pointer}/id"),
                "identity.deployment.duplicate-client",
                "a client id is not a client id, or repeats an earlier client or browser application",
                "Give each client and browser application its own id.",
            );
        }
        if !relative_path(&client.public_jwks_file) {
            error(
                &format!("{pointer}/publicJwksFile"),
                "identity.deployment.invalid-path",
                "the key file path is not a relative path inside the deployment directory",
                "Write a path relative to this file, with `/` separators and no `..`.",
            );
        }
        check_grants(&pointer, &client.grants, &mut error);
        if let Some(kind) = client.claims.get(ACTOR_KIND_CLAIM) {
            if !matches!(kind, ClaimValue::One(kind) if ActorKind::parse(kind).is_some()) {
                unknown_actor_kind(&pointer, &mut error);
            }
        }
        for name in client.claims.keys() {
            if !valid_claim_name(name) || protected_attribute(name) {
                error(
                    &format!("{pointer}/claims"),
                    "identity.deployment.invalid-claim",
                    "a claim name is invalid or names the protected grant namespace",
                    "Use letters, digits and `_`, and not a registry_grant_ name.",
                );
            }
        }
    }
    let mut secret_names = BTreeSet::new();
    for (index, app) in deployment.browser_apps.iter().enumerate() {
        let pointer = format!("/browserApps/{index}");
        if LocalId::new(app.id.clone()).is_err()
            || !valid_client_id(&app.id)
            || !client_ids.insert(app.id.as_str())
        {
            error(
                &format!("{pointer}/id"),
                "identity.deployment.duplicate-client",
                "a client id is not a client id, or repeats an earlier client or browser application",
                "Give each client and browser application its own id.",
            );
        }
        if app.client_secret_ref.provider() != SecretProvider::Environment
            || !secret_names.insert(app.client_secret_ref.name().to_owned())
        {
            let (code, message) = if app.client_secret_ref.provider() != SecretProvider::Environment
            {
                (
                    "identity.deployment.environment-secret-only",
                    "the secret reference does not name an environment variable",
                )
            } else {
                (
                    "identity.deployment.duplicate-secret",
                    "the secret reference repeats another secret's environment variable",
                )
            };
            error(
                &format!("{pointer}/clientSecretRef"),
                code,
                message,
                "Write secret:env/NAME with a variable no other secret uses.",
            );
        }
        let https = |value: &str| {
            url::Url::parse(value).is_ok_and(|url| {
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none()
            })
        };
        if !https(&app.origin)
            || app.redirect_uris.is_empty()
            || app.redirect_uris.len() > 8
            || app.redirect_uris.iter().any(|uri| !https(uri))
            || app.logo_url.as_deref().is_some_and(|logo| !https(logo))
        {
            error(
                &pointer,
                "identity.deployment.invalid-origin",
                "the origin, a redirect URI or the logo is not https, or 1 to 8 redirect URIs are not stated",
                "Use https URLs without user information or a fragment.",
            );
        }
        if app.token_attributes.is_empty()
            || app.token_attributes.len() > 16
            || app
                .token_attributes
                .iter()
                .any(|name| !valid_claim_name(name) || protected_attribute(name))
            || app.token_attributes.iter().collect::<BTreeSet<_>>().len()
                != app.token_attributes.len()
        {
            error(
                &format!("{pointer}/tokenAttributes"),
                "identity.deployment.invalid-claim",
                "the token attributes are empty, more than 16, repeated, invalid, or protected",
                "List 1 to 16 distinct claim names.",
            );
        }
        check_grants(&pointer, &app.grants, &mut error);
    }
    let mut usernames = BTreeSet::new();
    let mut emails = BTreeSet::new();
    let mut user_ids = BTreeSet::new();
    for (index, user) in deployment.users.iter().enumerate() {
        let pointer = format!("/users/{index}");
        if LocalId::new(user.id.clone()).is_err() || !user_ids.insert(user.id.as_str()) {
            error(
                &format!("{pointer}/id"),
                "identity.deployment.invalid-user",
                "the user id is not a local identifier, or repeats an earlier user",
                "Give each user its own id of lowercase letters, digits, `-` and `_`.",
            );
        }
        if user.username.is_empty()
            || user.username.len() > 64
            || !user
                .username
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !usernames.insert(user.username.as_str())
        {
            error(
                &format!("{pointer}/username"),
                "identity.deployment.invalid-user",
                "the username is not 1 to 64 lowercase letters, digits or `-`, or repeats an earlier user",
                "Give each user its own username.",
            );
        }
        let valid_email = user.email.len() <= 128
            && user.email.split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty()
                    && !domain.contains('@')
                    && domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
            })
            && !user.email.bytes().any(|byte| byte.is_ascii_whitespace());
        if !valid_email || !emails.insert(user.email.as_str()) {
            error(
                &format!("{pointer}/email"),
                "identity.deployment.invalid-email",
                "the email is not an address, or repeats an earlier user's",
                "Give each user their own address.",
            );
        }
        if user.password_ref.provider() != SecretProvider::Environment
            || !secret_names.insert(user.password_ref.name().to_owned())
        {
            let (code, message) = if user.password_ref.provider() != SecretProvider::Environment {
                (
                    "identity.deployment.environment-secret-only",
                    "the secret reference does not name an environment variable",
                )
            } else {
                (
                    "identity.deployment.duplicate-secret",
                    "the secret reference repeats another secret's environment variable",
                )
            };
            error(
                &format!("{pointer}/passwordRef"),
                code,
                message,
                "Write secret:env/NAME with a variable no other secret uses.",
            );
        }
        if user.claims.len() > 16
            || user.claims.iter().any(|(name, value)| {
                !valid_claim_name(name)
                    || protected_attribute(name)
                    || value.is_empty()
                    || value.len() > 512
            })
        {
            error(
                &format!("{pointer}/claims"),
                "identity.deployment.invalid-claim",
                "a user claim name is invalid or protected, a value is empty or too long, or more than 16 are stated",
                "State at most 16 claims with bounded string values.",
            );
        }
        if user
            .claims
            .get(ACTOR_KIND_CLAIM)
            .is_some_and(|kind| ActorKind::parse(kind).is_none())
        {
            unknown_actor_kind(&pointer, &mut error);
        }
        check_grants(&pointer, &user.grants, &mut error);
    }
    let mut type_ids = BTreeSet::new();
    let mut type_names = BTreeSet::from(["RegistryPerson"]);
    for (index, user_type) in deployment.user_types.iter().enumerate() {
        let pointer = format!("/userTypes/{index}");
        if LocalId::new(user_type.id.clone()).is_err()
            || !type_ids.insert(user_type.id.as_str())
            || user_type.name.is_empty()
            || user_type.name.len() > 64
            || !user_type
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
            || !type_names.insert(user_type.name.as_str())
            || user_type.attributes.len() > 16
            || user_type
                .attributes
                .iter()
                .any(|name| !valid_claim_name(name) || protected_attribute(name))
        {
            error(
                &pointer,
                "identity.deployment.invalid-user-type",
                "a user type id or name is invalid or repeated, or its attributes are invalid",
                "Give each type a local id and a distinct alphanumeric name, with at most 16 attributes.",
            );
        }
    }
    for (index, app) in deployment.browser_apps.iter().enumerate() {
        if app
            .user_types
            .iter()
            .any(|id| !type_ids.contains(id.as_str()))
        {
            error(
                &format!("/browserApps/{index}/userTypes"),
                "identity.deployment.unknown-user-type",
                "an application admits a user type that userTypes does not state",
                "Name the id of an entry of userTypes.",
            );
        }
    }
    for (index, user) in deployment.users.iter().enumerate() {
        if user
            .user_type
            .as_deref()
            .is_some_and(|id| !type_ids.contains(id))
        {
            error(
                &format!("/users/{index}/userType"),
                "identity.deployment.unknown-user-type",
                "a user has a type that userTypes does not state",
                "Name the id of an entry of userTypes.",
            );
        }
    }
    found
}

#[cfg(test)]
pub(crate) mod tests {
    include!("identity_deployment_tests.rs");
}
