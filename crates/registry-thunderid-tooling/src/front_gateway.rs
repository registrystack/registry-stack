//! The front gateway: a static Envoy configuration that is the only way in to
//! ThunderID.
//!
//! Browsers and pages reach the identity provider through it, and it forwards
//! to the provider's internal address. People cannot change their own user
//! record through the identity provider's self-service API; administrators
//! manage it. The gateway answers `PUT`, `PATCH` and `DELETE` on `/users/me`
//! and every path under it with a fixed `403` problem, and refuses any request
//! that carries a method-override header.
//!
//! Only the paths a sign-in and a relying party need are routed; every other
//! path answers `404`. They are taken from the pinned release's source: its
//! unauthenticated paths (`publicPaths` in
//! `backend/internal/system/security/permissions.go`) that the sign-in page
//! and the OAuth 2.0 and OpenID Connect endpoints use, and the self-service
//! routes that read the record or change a password
//! (`backend/internal/user/init.go`). The sign-in page runs before any token
//! exists, so every call it makes is to one of those unauthenticated paths.
//! The admin API, the console, the health checks, the Direct API, the
//! wallet endpoints, the MCP server and dynamic client registration are not
//! routed: operators reach them on the provider's internal name.
//!
//! The provider's router matches paths case-sensitively and takes no
//! configurable path prefix, so the routes below are the provider's own
//! paths, matched as written. The refusals also match in any letter case.

/// The generated file, relative to the output directory.
pub const FILE: &str = "front-gateway/envoy.yaml";
/// The port the gateway listens on, on every interface.
pub const LISTEN_PORT: u16 = 8080;
/// The provider's name on the private network the gateway shares with it.
pub const PROVIDER_HOST: &str = "thunderid";
/// The provider's plain HTTP port on that network (`http_only: true`).
pub const PROVIDER_PORT: u16 = 8090;
const PROVIDER_CLUSTER: &str = "thunderid";

/// The prefix of every problem `type` URI the gateway answers with.
const PROBLEM_TYPE_PREFIX: &str =
    "https://id.registrystack.org/problems/registry-platform/identity/";

/// The self-service path whose changes are refused.
const SELF_SERVICE_PATH: &str = "/users/me";
/// The methods that change a resource, refused on the self-service path.
const REFUSED_METHODS: [&str; 3] = ["PUT", "PATCH", "DELETE"];
/// The request headers some frameworks read to replace the method. The
/// pinned release reads none of them; they are refused all the same.
const OVERRIDE_HEADERS: [&str; 3] = [
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
];

/// Every problem the gateway answers with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProblemKind {
    SelfServiceEditRefused,
    MethodOverrideRefused,
}

impl ProblemKind {
    /// Every kind, for the identifier catalog and for tests.
    pub const ALL: [Self; 2] = [Self::SelfServiceEditRefused, Self::MethodOverrideRefused];

    /// The suffix of the code and of the `type` URI.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::SelfServiceEditRefused => "self-service-edit-refused",
            Self::MethodOverrideRefused => "method-override-refused",
        }
    }

    /// The problem's `code` member.
    #[must_use]
    pub fn code(self) -> String {
        format!("identity.{}", self.suffix())
    }

    /// The problem's `type` URI.
    #[must_use]
    pub fn type_uri(self) -> String {
        format!("{PROBLEM_TYPE_PREFIX}{}", self.suffix())
    }

    /// The problem's `title` member.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::SelfServiceEditRefused => "User record changes are managed by administrators",
            Self::MethodOverrideRefused => "Method override not accepted",
        }
    }

    /// Value-free documentation of the refusal, for the identifier catalog.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::SelfServiceEditRefused => "People cannot change their own user record through the identity provider's self-service API; administrators manage it. Reading the record and changing a password remain available.",
            Self::MethodOverrideRefused => "The identity provider's front gateway does not accept a request that carries a header asking to replace its HTTP method.",
        }
    }

    /// The HTTP status of the answer.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::SelfServiceEditRefused | Self::MethodOverrideRefused => 403,
        }
    }

    /// The fixed answer body. Nothing from the request is echoed.
    fn body(self) -> String {
        format!(
            r#"{{"type":"{}","title":"{}","status":{},"code":"{}"}}"#,
            self.type_uri(),
            self.title(),
            self.http_status(),
            self.code()
        )
    }
}

/// How a route matches the path.
enum PathMatch {
    Exact(&'static str),
    Prefix(&'static str),
    Regex(&'static str),
}

/// What a route does with a matching request.
enum Action {
    Refuse(ProblemKind),
    NotRouted,
    Forward,
}

struct Route {
    name: String,
    path: PathMatch,
    /// Matches the path in any letter case.
    any_case: bool,
    method: Option<&'static str>,
    header_present: Option<&'static str>,
    action: Action,
}

impl Route {
    fn forward(name: &str, path: PathMatch, method: Option<&'static str>) -> Self {
        Self {
            name: name.to_owned(),
            path,
            any_case: false,
            method,
            header_present: None,
            action: Action::Forward,
        }
    }
}

/// The routes, in the order the gateway tries them: the refusals first, then
/// the paths that are not routed under a forwarded prefix, then the paths
/// that pass. A request no route matches answers `404`.
fn routes() -> Vec<Route> {
    let mut routes = Vec::new();
    for header in OVERRIDE_HEADERS {
        routes.push(Route {
            name: format!("refuse-{header}"),
            path: PathMatch::Prefix("/"),
            any_case: false,
            method: None,
            header_present: Some(header),
            action: Action::Refuse(ProblemKind::MethodOverrideRefused),
        });
    }
    for method in REFUSED_METHODS {
        let lower = method.to_ascii_lowercase();
        for (shape, path) in [
            ("record", PathMatch::Exact(SELF_SERVICE_PATH)),
            ("under-record", PathMatch::Prefix("/users/me/")),
        ] {
            routes.push(Route {
                name: format!("refuse-{lower}-self-service-{shape}"),
                path,
                any_case: true,
                method: Some(method),
                header_present: None,
                action: Action::Refuse(ProblemKind::SelfServiceEditRefused),
            });
        }
    }
    // Dynamic client registration creates applications, which administrators
    // manage on the provider's internal name.
    routes.push(Route {
        name: "not-routed-client-registration".to_owned(),
        path: PathMatch::Prefix("/oauth2/dcr"),
        any_case: false,
        method: None,
        header_present: None,
        action: Action::NotRouted,
    });
    routes.push(Route::forward(
        "oauth2",
        PathMatch::Prefix("/oauth2/"),
        None,
    ));
    routes.push(Route::forward(
        "well-known",
        PathMatch::Prefix("/.well-known/"),
        None,
    ));
    routes.push(Route::forward("flow", PathMatch::Prefix("/flow/"), None));
    routes.push(Route::forward(
        "sign-in-page",
        PathMatch::Prefix("/gate/"),
        None,
    ));
    routes.push(Route::forward(
        "sign-in-design",
        PathMatch::Exact("/design/resolve"),
        None,
    ));
    routes.push(Route::forward(
        "sign-in-text",
        PathMatch::Regex("^/i18n/languages(/[^/]+/translations(/ns/[^/]+/keys/[^/]+)?/resolve)?$"),
        None,
    ));
    for (name, path, methods) in [
        ("self-service-record", SELF_SERVICE_PATH, ["GET", "OPTIONS"]),
        ("self-service-meta", "/users/me/meta", ["GET", "OPTIONS"]),
        (
            "self-service-password",
            "/users/me/update-credentials",
            ["POST", "OPTIONS"],
        ),
    ] {
        for method in methods {
            routes.push(Route::forward(
                &format!("{name}-{}", method.to_ascii_lowercase()),
                PathMatch::Exact(path),
                Some(method),
            ));
        }
    }
    routes
}

/// YAML for one route, as a sequence entry at the left margin; the caller
/// indents it under `routes:`.
fn route_yaml(route: &Route) -> String {
    let mut lines = vec![format!("- name: {}", route.name), "  match:".to_owned()];
    match route.path {
        PathMatch::Exact(path) => lines.push(format!("    path: \"{path}\"")),
        PathMatch::Prefix(prefix) => lines.push(format!("    prefix: \"{prefix}\"")),
        PathMatch::Regex(regex) => {
            lines.push("    safe_regex:".to_owned());
            lines.push(format!("      regex: '{regex}'"));
        }
    }
    if route.any_case {
        lines.push("    case_sensitive: false".to_owned());
    }
    if let Some(method) = route.method {
        lines.push("    headers:".to_owned());
        lines.push("    - name: \":method\"".to_owned());
        lines.push("      string_match:".to_owned());
        lines.push(format!("        exact: {method}"));
    }
    if let Some(header) = route.header_present {
        lines.push("    headers:".to_owned());
        lines.push(format!("    - name: {header}"));
        lines.push("      present_match: true".to_owned());
    }
    match route.action {
        Action::Forward => {
            lines.push("  route:".to_owned());
            lines.push(format!("    cluster: {PROVIDER_CLUSTER}"));
        }
        Action::NotRouted => {
            lines.push("  direct_response:".to_owned());
            lines.push("    status: 404".to_owned());
        }
        Action::Refuse(kind) => {
            lines.push("  direct_response:".to_owned());
            lines.push(format!("    status: {}", kind.http_status()));
            lines.push("    body:".to_owned());
            lines.push(format!("      inline_string: '{}'", kind.body()));
            lines.push("  response_headers_to_add:".to_owned());
            for (key, value) in [
                ("content-type", "application/problem+json"),
                ("cache-control", "no-store"),
            ] {
                lines.push("  - header:".to_owned());
                lines.push(format!("      key: {key}"));
                lines.push(format!("      value: {value}"));
                lines.push("    append_action: OVERWRITE_IF_EXISTS_OR_ADD".to_owned());
            }
        }
    }
    lines
        .into_iter()
        .map(|line| format!("{ROUTE_INDENT}{line}\n"))
        .collect()
}

/// The indentation of a route entry under `routes:`.
const ROUTE_INDENT: &str = "              ";

/// The front gateway file for the pinned release `version`.
#[must_use]
pub fn render(version: &str) -> String {
    let routes: String = routes().iter().map(route_yaml).collect();
    format!(
        "# Generated for ThunderID {version} by the Registry Stack identity generator.\n\
         #\n\
         # The front gateway is the only way in to the identity provider. Browsers\n\
         # and pages reach it on port {LISTEN_PORT}; it forwards to the provider at\n\
         # {PROVIDER_HOST}:{PROVIDER_PORT} on the private network they share. The provider\n\
         # must publish no host port: run it with no published port, and put any\n\
         # TLS terminator or shared address in front of this gateway, not of the\n\
         # provider.\n\
         #\n\
         # People cannot change their own user record through the identity\n\
         # provider's self-service API; administrators manage it. PUT, PATCH and\n\
         # DELETE on /users/me and every path under it answer a fixed 403 problem.\n\
         # Reading the record and changing a password pass.\n\
         #\n\
         # Only the sign-in page, its flow, design and text, the OAuth 2.0 and\n\
         # OpenID Connect endpoints and the self-service reads are routed. The\n\
         # admin API and the console are not: operators reach them on the\n\
         # provider's internal name. Every other path answers 404.\n\
         static_resources:\n\
         \x20 listeners:\n\
         \x20 - name: thunderid_front\n\
         \x20   address:\n\
         \x20     socket_address:\n\
         \x20       address: 0.0.0.0\n\
         \x20       port_value: {LISTEN_PORT}\n\
         \x20   filter_chains:\n\
         \x20   - filters:\n\
         \x20     - name: envoy.filters.network.http_connection_manager\n\
         \x20       typed_config:\n\
         \x20         \"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager\n\
         \x20         stat_prefix: thunderid_front\n\
         \x20         normalize_path: true\n\
         \x20         merge_slashes: true\n\
         \x20         path_with_escaped_slashes_action: REJECT_REQUEST\n\
         \x20         route_config:\n\
         \x20           name: thunderid_front\n\
         \x20           virtual_hosts:\n\
         \x20           - name: thunderid\n\
         \x20             domains: [\"*\"]\n\
         \x20             routes:\n\
         {routes}\
         \x20         http_filters:\n\
         \x20         - name: envoy.filters.http.router\n\
         \x20           typed_config:\n\
         \x20             \"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\n\
         \x20 clusters:\n\
         \x20 - name: {PROVIDER_CLUSTER}\n\
         \x20   type: STRICT_DNS\n\
         \x20   connect_timeout: 5s\n\
         \x20   load_assignment:\n\
         \x20     cluster_name: {PROVIDER_CLUSTER}\n\
         \x20     endpoints:\n\
         \x20     - lb_endpoints:\n\
         \x20       - endpoint:\n\
         \x20           address:\n\
         \x20             socket_address:\n\
         \x20               address: {PROVIDER_HOST}\n\
         \x20               port_value: {PROVIDER_PORT}\n"
    )
}

#[cfg(test)]
mod tests {
    include!("front_gateway_tests.rs");
}
