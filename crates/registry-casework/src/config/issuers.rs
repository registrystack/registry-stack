//! The issuers Casework accepts access tokens from.
//!
//! `authentication.oidc.issuers` maps an issuer id to one entry. Each entry
//! holds the shared core (issuer, audience, key source, access-token type,
//! scope claim, client rule and declared actor kinds) beside the members that
//! describe that issuer: the assertion issuers each client may exchange from,
//! the key identifiers Casework refuses, and the longest token lifetime it
//! accepts.

use std::collections::BTreeMap;

use registry_platform_config::{
    Admitted, CallerIssuerCore, CallerIssuerEntry, ClientList, ClientRule, DevelopmentClass,
    DevelopmentSetting,
};
use serde::{Deserialize, Deserializer};

use super::RevokedKeyIds;

/// The JSON pointer of the issuer set in a Casework runtime file.
pub const ISSUERS_POINTER: &str = "/authentication/oidc/issuers";

/// `allowedClients: unrestricted`: every client the issuer signs for is
/// admitted.
pub static UNRESTRICTED_CLIENTS: DevelopmentSetting = DevelopmentSetting {
    code: "casework.posture.unrestricted-clients",
    key: "allowedClients",
    summary: "admits a token from every client this issuer signs for",
    production: "List the OAuth clients whose access tokens this issuer entry admits.",
};

/// One entry of `authentication.oidc.issuers`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkIssuer {
    /// The issuer, its audience and key source, the access-token type, the
    /// scope claim, the clients admitted and any declared actor kind.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer-core"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub core: CallerIssuerCore<CaseworkAllowedClients>,
    /// The assertion authorities each client may exchange a subject token
    /// from, keyed by client identifier. Omitted, no assertion-issuer rule
    /// applies. Written, it lists at least one client, each with at least one
    /// authority, and a client that is not listed may exchange from no
    /// authority.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "registry_platform_config::non_empty_assertion_issuers"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "registry_platform_config::assertion_issuers_schema")
    )]
    pub assertion_issuers: BTreeMap<String, Vec<String>>,
    /// Signing-key identifiers Casework refuses for this issuer, even while
    /// the issuer still publishes them. Listing a key does not revoke it at
    /// the issuer. Omitted, no key is refused. Written, the list is non-empty.
    #[serde(default, deserialize_with = "super::present_revoked_key_ids")]
    pub revoked_key_ids: Option<RevokedKeyIds>,
    /// The longest lifetime, in seconds, an access token from this issuer may
    /// declare, independently of the issuer's own policy.
    #[serde(
        default,
        deserialize_with = "registry_casework_core::typed::optional_bounded_u64::<_, 1, 7_200>"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 7_200)))]
    pub maximum_token_lifetime_seconds: Option<u64>,
}

impl CallerIssuerEntry for CaseworkIssuer {
    type Clients = CaseworkAllowedClients;

    fn core(&self) -> &CallerIssuerCore<CaseworkAllowedClients> {
        &self.core
    }
}

impl CaseworkIssuer {
    /// The clients this entry lists, or `None` when it admits every client.
    #[must_use]
    pub fn listed_clients(&self) -> Option<&[String]> {
        match self.core.allowed_clients.admitted() {
            Admitted::Listed(clients) => Some(clients),
            Admitted::Unrestricted | Admitted::FromPackage | Admitted::FromPolicies => None,
        }
    }

    /// Whether this entry lists `client`.
    #[must_use]
    pub fn lists_client(&self, client: &str) -> bool {
        self.listed_clients()
            .is_some_and(|clients| clients.iter().any(|listed| listed == client))
    }
}

/// `allowedClients` of a Casework issuer entry: a list of at least one
/// client, or `unrestricted`, which selects the development-only setting
/// `casework.posture.unrestricted-clients`. The value is held plainly and is
/// readable in every posture. Decoding records no posture setting for it. The
/// runtime records the setting for each entry that states `unrestricted` when
/// it loads or checks the file, so production refuses it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseworkAllowedClients {
    /// Admit a token only from a listed client.
    Listed(Vec<String>),
    /// Admit a token from every client the issuer verifies.
    Unrestricted,
}

impl ClientRule for CaseworkAllowedClients {
    fn admitted(&self) -> Admitted<'_> {
        match self {
            Self::Listed(clients) => Admitted::Listed(clients),
            Self::Unrestricted => Admitted::Unrestricted,
        }
    }
}

impl DevelopmentClass for CaseworkAllowedClients {
    const SETTINGS: &'static [&'static DevelopmentSetting] = &[&UNRESTRICTED_CLIENTS];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        match self {
            Self::Listed(_) => None,
            Self::Unrestricted => Some(&UNRESTRICTED_CLIENTS),
        }
    }
}

impl<'de> Deserialize<'de> for CaseworkAllowedClients {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match AuthoredClients::deserialize(deserializer)? {
            AuthoredClients::Unrestricted(UnrestrictedKeyword) => Self::Unrestricted,
            AuthoredClients::Listed(clients) => match clients.admitted() {
                Admitted::Listed(listed) => Self::Listed(listed.to_vec()),
                Admitted::Unrestricted | Admitted::FromPackage | Admitted::FromPolicies => {
                    return Err(allowed_clients_refused());
                }
            },
        })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for CaseworkAllowedClients {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CaseworkAllowedClients".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = <AuthoredClients as schemars::JsonSchema>::json_schema(generator);
        let codes: Vec<&str> = Self::SETTINGS.iter().map(|setting| setting.code).collect();
        schema.insert("x-registry-development-only".to_owned(), codes.into());
        schema
    }
}

/// How `allowedClients` is written: the keyword `unrestricted`, or a list of
/// at least one distinct client.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
enum AuthoredClients {
    Unrestricted(UnrestrictedKeyword),
    Listed(ClientList),
}

registry_platform_yaml::shape_union!(AuthoredClients { scalar => Unrestricted, list => Listed });

const UNRESTRICTED: &str = "unrestricted";

fn allowed_clients_refused<E: serde::de::Error>() -> E {
    registry_platform_yaml::Invalid::expected(
        "unrestricted, or a list of at least one OAuth client",
        "List the OAuth clients whose access tokens are admitted, or write unrestricted to admit every client the issuer verifies.",
    )
    .into_error()
}

/// The keyword `unrestricted`.
struct UnrestrictedKeyword;

impl<'de> Deserialize<'de> for UnrestrictedKeyword {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == UNRESTRICTED {
            Ok(Self)
        } else {
            Err(allowed_clients_refused())
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for UnrestrictedKeyword {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CaseworkUnrestrictedClients".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type": "string", "const": UNRESTRICTED})
    }
}
