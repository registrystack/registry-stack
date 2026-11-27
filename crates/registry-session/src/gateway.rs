// SPDX-License-Identifier: Apache-2.0

//! The gateway's part of the session service, generated from the runtime file.
//!
//! The gateway asks the service, on each call to a signed-in route, which
//! bearer token to attach. Which routes run that check, their order, the cookie
//! strip, and the cross-site defence must match the service's own route table,
//! so the Envoy fragments are written from the same file and never by hand.
//! The output is deterministic: a stable order and no timestamps. Generating
//! reads no environment variable and no secret.

use std::{fmt, fs, io, path::Path};

use registry_platform_yaml::Reader;
use serde_json::Value;

use crate::{
    check::CHECK_PREFIX,
    config::{
        clean_prefix, RuntimeConfig, RuntimeConfigError, UpstreamConfig, DEVELOPMENT_FLOW_COOKIE,
        DEVELOPMENT_SESSION_COOKIE, FLOW_COOKIE, SESSION_COOKIE, SESSION_PREFIX,
    },
    wire::{ProblemKind, ANSWER_MARKER_HEADER, ANSWER_MARKER_VALUE, CHECK_REQUEST_HEADERS},
};

/// Why the fragments were not written or did not match.
#[derive(Debug)]
pub enum GatewayError {
    /// The runtime file was refused or could not be read.
    Config(RuntimeConfigError),
    /// The runtime file has no `gateway` block.
    NoGatewayBlock,
    /// The runtime file cannot be rendered as fragments: one finding each.
    Refused(Vec<String>),
    /// A generated file could not be read or written.
    Io { path: String, kind: io::ErrorKind },
    /// The named files differ from what the runtime file generates.
    Differs(Vec<&'static str>),
    /// An assembled configuration does not meet the gateway's rules: one
    /// finding each.
    Assembled(Vec<String>),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::NoGatewayBlock => formatter.write_str(
                "the runtime configuration has no gateway block, which the gateway fragments need",
            ),
            Self::Refused(findings) => write!(
                formatter,
                "the runtime configuration cannot be rendered as gateway fragments:\n{}",
                findings.join("\n")
            ),
            Self::Io { path, kind } => write!(formatter, "{path}: {kind}"),
            Self::Differs(names) => write!(
                formatter,
                "the generated files differ from the runtime configuration: {}",
                names.join(", ")
            ),
            Self::Assembled(findings) => write!(
                formatter,
                "the assembled configuration is refused:\n{}",
                findings.join("\n")
            ),
        }
    }
}

impl std::error::Error for GatewayError {}

/// The public routes the service serves itself, each matched exactly.
pub const PUBLIC_PATHS: [&str; 5] = [
    "/session/sign-in",
    "/session/callback",
    "/session/sign-out",
    "/session/me",
    "/session/signed-out",
];

/// The check's answer headers the gateway passes on to the browser.
pub const CHECK_CLIENT_HEADERS: [&str; 3] = ["content-type", "cache-control", "location"];

/// The header the check's allow answer fills in with the bearer token.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// The header that carries the session cookie.
const COOKIE_HEADER: &str = "cookie";

/// The clusters that reach the service's two listeners.
const PUBLIC_CLUSTER: &str = "registry-session-public";
const CHECK_CLUSTER: &str = "registry-session-check";

/// The names of the filters the service adds to the host's chain. Every
/// per-route switch is keyed by these names, never by a filter's type name: a
/// host chain may hold several filters of one type.
const CSRF_FILTER: &str = "registry-session.csrf";
const CHECK_FILTER: &str = "registry-session.check";
const STRIP_FILTER: &str = "registry-session.strip-cookies";

/// The prefix of the names of the routes the service generates, and of its
/// filters. A host's own route or filter never carries it.
const OWN_PREFIX: &str = "registry-session.";

const FILTER_CONFIG_TYPE: &str = "type.googleapis.com/envoy.config.route.v3.FilterConfig";

/// One generated file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedFile {
    pub name: &'static str,
    pub content: String,
}

/// What `gateway envoy` does with the generated files.
#[derive(Clone, Copy, Debug)]
pub enum Mode<'a> {
    /// Write the files into the directory.
    Write(&'a Path),
    /// Compare the files with the ones in the directory.
    Check(&'a Path),
}

/// The fragments for `config`.
///
/// Every guarded route, and the `/session/` catch-all, removes the answer
/// marker from its upstream answer, so a product cannot pass its own answer
/// off as the service's. A removal made higher, on the virtual host or the
/// route configuration, would strip the public routes too and cannot be opted
/// out of, so the host's own routes get theirs when the recipe assembles the
/// configuration, and [`verify_assembled`] checks it.
pub fn generate(config: &RuntimeConfig) -> Result<Vec<GeneratedFile>, GatewayError> {
    let gateway = config
        .gateway
        .as_ref()
        .ok_or(GatewayError::NoGatewayBlock)?;
    let authority = config
        .gateway_authority()
        .ok_or(GatewayError::NoGatewayBlock)?;
    let guarded = guarded_routes(config)?;
    Ok(vec![
        GeneratedFile {
            name: "http-filters.yaml",
            content: http_filters(gateway.check_timeout_milliseconds.get()),
        },
        GeneratedFile {
            name: "routes.yaml",
            content: routes(config, &authority, &guarded),
        },
        GeneratedFile {
            name: "clusters.yaml",
            content: clusters(config),
        },
        GeneratedFile {
            name: "local-reply.yaml",
            content: local_reply(),
        },
    ])
}

/// Load the runtime file for the gateway commands. The output must not depend
/// on the environment they run in, so no `${NAME}` expression is filled in and
/// a member the fragments are written from may not hold one. No secret is
/// read: the file's secret references are checked by syntax only.
fn load_for_gateway(runtime_config: &Path) -> Result<RuntimeConfig, GatewayError> {
    let (config, _) =
        RuntimeConfig::load_without_substitution(runtime_config).map_err(GatewayError::Config)?;
    let bytes = fs::read(runtime_config).map_err(|error| io_error(runtime_config, &error))?;
    let document = Reader::new(runtime_config.display().to_string())
        .scan(&bytes)
        .map_err(|report| GatewayError::Refused(vec![report.render_human()]))?
        .ok_or_else(|| {
            GatewayError::Refused(vec!["the runtime configuration is empty".to_owned()])
        })?
        .to_json_value();
    let unresolved = unresolved_members(&document);
    if unresolved.is_empty() {
        Ok(config)
    } else {
        Err(GatewayError::Refused(unresolved))
    }
}

/// The members the fragments are written from that hold a `${NAME}`
/// expression, one finding each.
fn unresolved_members(document: &Value) -> Vec<String> {
    fn holds_expression(value: &Value) -> bool {
        match value {
            Value::String(text) => text.contains("${"),
            Value::Array(items) => items.iter().any(holds_expression),
            Value::Object(map) => map.values().any(holds_expression),
            _ => false,
        }
    }
    let mut found = Vec::new();
    let mut check = |pointer: String, value: Option<&Value>| {
        if value.is_some_and(holds_expression) {
            found.push(format!(
                "{pointer} holds a ${{NAME}} expression, which the gateway fragments never \
                 resolve: write the value out"
            ));
        }
    };
    check("/publicOrigin".to_owned(), document.get("publicOrigin"));
    check("/gateway".to_owned(), document.get("gateway"));
    for list in ["modules", "pages"] {
        let items = document
            .get(list)
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        for (index, item) in items.iter().enumerate() {
            for member in ["id", "prefix", "upstream"] {
                check(format!("/{list}/{index}/{member}"), item.get(member));
            }
        }
    }
    found
}

/// Load the runtime file and write or compare its fragments.
pub fn run_envoy(runtime_config: &Path, mode: Mode<'_>) -> Result<(), GatewayError> {
    let config = load_for_gateway(runtime_config)?;
    let files = generate(&config)?;
    match mode {
        Mode::Write(directory) => {
            fs::create_dir_all(directory).map_err(|error| io_error(directory, &error))?;
            for file in &files {
                let path = directory.join(file.name);
                fs::write(&path, &file.content).map_err(|error| io_error(&path, &error))?;
            }
            Ok(())
        }
        Mode::Check(directory) => {
            let mut differing = Vec::new();
            for file in &files {
                let path = directory.join(file.name);
                match fs::read_to_string(&path) {
                    Ok(existing) if existing == file.content => {}
                    Ok(_) => differing.push(file.name),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        differing.push(file.name);
                    }
                    Err(error) => return Err(io_error(&path, &error)),
                }
            }
            if differing.is_empty() {
                Ok(())
            } else {
                Err(GatewayError::Differs(differing))
            }
        }
    }
}

fn io_error(path: &Path, error: &io::Error) -> GatewayError {
    GatewayError::Io {
        path: path.display().to_string(),
        kind: error.kind(),
    }
}

/// A scalar as a double-quoted YAML string.
fn quoted(text: &str) -> String {
    serde_json::to_string(text).expect("a string serializes")
}

/// A duration as Envoy's protobuf JSON form: seconds with an optional
/// fraction.
fn duration_milliseconds(milliseconds: u64) -> String {
    let (seconds, fraction) = (milliseconds / 1000, milliseconds % 1000);
    if fraction == 0 {
        return format!("{seconds}s");
    }
    let fraction = format!("{fraction:03}");
    format!("{seconds}.{}s", fraction.trim_end_matches('0'))
}

fn header(kind: &str) -> String {
    format!(
        "# Generated by `registry-session gateway envoy` from the runtime configuration.\n\
         # Do not edit: regenerate it. This is the {kind}.\n"
    )
}

/// The cookies the service sets, under their production and development names.
fn own_cookies() -> [&'static str; 4] {
    [
        SESSION_COOKIE,
        DEVELOPMENT_SESSION_COOKIE,
        FLOW_COOKIE,
        DEVELOPMENT_FLOW_COOKIE,
    ]
}

/// The strip's Lua after the table of the service's cookies.
///
/// The cookie name is matched in one linear pass. A lazy pattern anchored at
/// the end of the string backtracks quadratically over a long run of spaces,
/// and one request can carry tens of thousands.
const LUA_BODY: &str = r#"
-- Removes the service's own cookies from the request and keeps the rest.
function envoy_on_request(handle)
  local headers = handle:headers()
  local cookie = headers:get("cookie")
  if cookie == nil then
    return
  end
  local kept = {}
  for pair in string.gmatch(cookie, "[^;]+") do
    local first = string.find(pair, "%S")
    if first ~= nil then
      local name = string.match(pair, "^%s*([^=]*)")
      if not own_cookies[name] then
        local last = #pair
        while string.find(string.sub(pair, last, last), "%s") do
          last = last - 1
        end
        table.insert(kept, string.sub(pair, first, last))
      end
    end
  end
  if #kept == 0 then
    headers:remove("cookie")
  else
    headers:replace("cookie", table.concat(kept, "; "))
  end
end
"#;

fn lua_source() -> String {
    let cookies = own_cookies()
        .iter()
        .map(|name| format!("  [{}] = true,\n", quoted(name)))
        .collect::<String>();
    format!("local own_cookies = {{\n{cookies}}}\n{LUA_BODY}")
}

fn http_filters(check_timeout_milliseconds: u64) -> String {
    let mut out = header(
        "HTTP filters, to splice at the head of the host's chain, in this order, ahead of the \
         host's own filters and its router",
    );
    out.push_str(&format!(
        "- name: {csrf}\n\
         \x20 disabled: true\n\
         \x20 typed_config:\n\
         \x20   \"@type\": type.googleapis.com/envoy.extensions.filters.http.csrf.v3.CsrfPolicy\n\
         \x20   filter_enabled:\n\
         \x20     default_value:\n\
         \x20       numerator: 100\n\
         \x20       denominator: HUNDRED\n\
         - name: {check}\n\
         \x20 disabled: true\n\
         \x20 typed_config:\n\
         \x20   \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz\n\
         \x20   failure_mode_allow: false\n\
         \x20   status_on_error:\n\
         \x20     code: ServiceUnavailable\n\
         \x20   http_service:\n\
         \x20     server_uri:\n\
         \x20       uri: {uri}\n\
         \x20       cluster: {cluster}\n\
         \x20       timeout: {timeout}\n\
         \x20     path_prefix: {prefix}\n\
         \x20     authorization_response:\n\
         \x20       allowed_upstream_headers:\n\
         \x20         patterns:\n\
         \x20           - exact: {authorization}\n\
         \x20       allowed_client_headers:\n\
         \x20         patterns:\n",
        csrf = quoted(CSRF_FILTER),
        check = quoted(CHECK_FILTER),
        uri = quoted(&format!("http://{CHECK_CLUSTER}")),
        cluster = quoted(CHECK_CLUSTER),
        timeout = quoted(&duration_milliseconds(check_timeout_milliseconds)),
        prefix = quoted(CHECK_PREFIX),
        authorization = quoted(AUTHORIZATION_HEADER),
    ));
    for name in CHECK_CLIENT_HEADERS
        .iter()
        .copied()
        .chain([ANSWER_MARKER_HEADER])
    {
        out.push_str(&format!("            - exact: {}\n", quoted(name)));
    }
    out.push_str("    allowed_headers:\n      patterns:\n");
    for name in CHECK_REQUEST_HEADERS {
        out.push_str(&format!("        - exact: {}\n", quoted(name)));
    }
    out.push_str(&format!(
        "- name: {}\n\
         \x20 typed_config:\n\
         \x20   \"@type\": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua\n\
         \x20   default_source_code:\n\
         \x20     inline_string: |\n",
        quoted(STRIP_FILTER)
    ));
    for line in lua_source().lines() {
        if line.is_empty() {
            out.push('\n');
        } else {
            out.push_str(&format!("        {line}\n"));
        }
    }
    out
}

/// A route to a host cluster: a module or a page.
struct GuardedRoute<'a> {
    name: String,
    prefix: &'a str,
    upstream: &'a UpstreamConfig,
    page: bool,
}

/// The guarded routes in the order the service resolves them: the longest
/// prefix first across modules and pages, equal lengths by prefix. A prefix
/// outside the path grammar the service accepts, or a name two routes would
/// share, is refused.
fn guarded_routes(config: &RuntimeConfig) -> Result<Vec<GuardedRoute<'_>>, GatewayError> {
    let modules = config.modules.iter().filter_map(|module| {
        Some(GuardedRoute {
            name: format!("module-{}", module.id.as_str()),
            prefix: &module.prefix,
            upstream: module.upstream.as_ref()?,
            page: false,
        })
    });
    let pages = config.pages.iter().filter_map(|page| {
        Some(GuardedRoute {
            name: format!("page-{}", page.prefix.trim_matches('/').replace('/', "-")),
            prefix: &page.prefix,
            upstream: page.upstream.as_ref()?,
            page: true,
        })
    });
    let mut routes: Vec<GuardedRoute<'_>> = modules.chain(pages).collect();
    routes.sort_by(|left, right| {
        right
            .prefix
            .len()
            .cmp(&left.prefix.len())
            .then_with(|| left.prefix.cmp(right.prefix))
    });
    let mut findings = Vec::new();
    for (index, route) in routes.iter().enumerate() {
        if !clean_prefix(route.prefix) {
            findings.push(format!(
                "the prefix {} is not a path the service accepts",
                quoted(route.prefix)
            ));
        }
        if let Some(earlier) = routes[..index]
            .iter()
            .find(|earlier| earlier.name == route.name)
        {
            findings.push(format!(
                "the prefixes {} and {} would give two routes the name {}",
                quoted(earlier.prefix),
                quoted(route.prefix),
                quoted(&route.name)
            ));
        }
    }
    if findings.is_empty() {
        Ok(routes)
    } else {
        Err(GatewayError::Refused(findings))
    }
}

fn match_lines(out: &mut String, matcher: &str, authority: &str) {
    out.push_str(&format!(
        "  match:\n\
         \x20   {matcher}\n\
         \x20   headers:\n\
         \x20     - name: \":authority\"\n\
         \x20       string_match:\n\
         \x20         exact: {}\n",
        quoted(authority)
    ));
}

fn response_header_lines(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!(
        "  response_headers_to_add:\n\
         \x20   - header:\n\
         \x20       key: {}\n\
         \x20       value: {}\n\
         \x20     append_action: OVERWRITE_IF_EXISTS_OR_ADD\n",
        quoted(key),
        quoted(value)
    ));
}

fn marker_removal_lines(out: &mut String) {
    out.push_str(&format!(
        "  response_headers_to_remove:\n    - {}\n",
        quoted(ANSWER_MARKER_HEADER)
    ));
}

fn switch_off(out: &mut String, filter: &str) {
    out.push_str(&format!(
        "    {}:\n      \"@type\": {FILTER_CONFIG_TYPE}\n      disabled: true\n",
        quoted(filter)
    ));
}

fn csrf_on(out: &mut String) {
    out.push_str(&format!(
        "    {}:\n\
         \x20     \"@type\": type.googleapis.com/envoy.extensions.filters.http.csrf.v3.CsrfPolicy\n\
         \x20     filter_enabled:\n\
         \x20       default_value:\n\
         \x20         numerator: 100\n\
         \x20         denominator: HUNDRED\n",
        quoted(CSRF_FILTER)
    ));
}

fn check_on(out: &mut String) {
    out.push_str(&format!(
        "    {}:\n\
         \x20     \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute\n\
         \x20     check_settings: {{}}\n",
        quoted(CHECK_FILTER)
    ));
}

fn strip_off(out: &mut String) {
    out.push_str(&format!(
        "    {}:\n\
         \x20     \"@type\": type.googleapis.com/envoy.extensions.filters.http.lua.v3.LuaPerRoute\n\
         \x20     disabled: true\n",
        quoted(STRIP_FILTER)
    ));
}

fn routes(config: &RuntimeConfig, authority: &str, guarded: &[GuardedRoute<'_>]) -> String {
    let host_filters: Vec<&str> = config
        .gateway
        .iter()
        .flat_map(|gateway| gateway.host_filters.iter())
        .map(|filter| filter.as_str())
        .collect();
    let mut out = header("routes, to splice into the host's virtual host before its own routes");
    for path in PUBLIC_PATHS {
        let name = path.trim_start_matches(SESSION_PREFIX);
        out.push_str(&format!(
            "- name: {}\n",
            quoted(&format!("{OWN_PREFIX}{name}"))
        ));
        match_lines(&mut out, &format!("path: {}", quoted(path)), authority);
        out.push_str(&format!(
            "  route:\n    cluster: {}\n",
            quoted(PUBLIC_CLUSTER)
        ));
        response_header_lines(&mut out, "cache-control", "no-store");
        out.push_str("  typed_per_filter_config:\n");
        csrf_on(&mut out);
        strip_off(&mut out);
        for filter in &host_filters {
            switch_off(&mut out, filter);
        }
    }
    out.push_str(&format!(
        "- name: {}\n",
        quoted(&format!("{OWN_PREFIX}reserved"))
    ));
    match_lines(
        &mut out,
        &format!("prefix: {}", quoted(SESSION_PREFIX)),
        authority,
    );
    out.push_str("  direct_response:\n    status: 404\n");
    marker_removal_lines(&mut out);
    // A host filter must never refuse or alter an answer under the service's
    // own prefix, the 404 included.
    if !host_filters.is_empty() {
        out.push_str("  typed_per_filter_config:\n");
        for filter in &host_filters {
            switch_off(&mut out, filter);
        }
    }
    for route in guarded {
        out.push_str(&format!("- name: {}\n", quoted(&route.name)));
        match_lines(
            &mut out,
            &format!("prefix: {}", quoted(route.prefix)),
            authority,
        );
        out.push_str(&format!(
            "  route:\n    cluster: {}\n",
            quoted(route.upstream.cluster.as_str())
        ));
        if let Some(rewrite) = &route.upstream.prefix_rewrite {
            out.push_str(&format!(
                "    prefix_rewrite: {}\n",
                quoted(rewrite.as_str())
            ));
        }
        out.push_str(&format!(
            "    timeout: {}s\n  request_headers_to_remove:\n    - {}\n",
            route.upstream.timeout_seconds.get(),
            quoted(COOKIE_HEADER)
        ));
        if route.page {
            // The check adds no bearer for a page, so a browser-sent one would
            // reach the page's upstream unless the route removes it.
            out.push_str(&format!("    - {}\n", quoted(AUTHORIZATION_HEADER)));
            response_header_lines(&mut out, "cache-control", "no-cache");
        }
        marker_removal_lines(&mut out);
        out.push_str("  typed_per_filter_config:\n");
        csrf_on(&mut out);
        check_on(&mut out);
        for filter in &host_filters {
            if !route
                .upstream
                .keep_host_filters
                .iter()
                .any(|kept| kept.as_str() == *filter)
            {
                switch_off(&mut out, filter);
            }
        }
    }
    out
}

fn cluster(out: &mut String, name: &str, host: &str, port: u32) {
    out.push_str(&format!(
        "- name: {name}\n\
         \x20 type: STRICT_DNS\n\
         \x20 connect_timeout: 1s\n\
         \x20 load_assignment:\n\
         \x20   cluster_name: {name}\n\
         \x20   endpoints:\n\
         \x20     - lb_endpoints:\n\
         \x20         - endpoint:\n\
         \x20             address:\n\
         \x20               socket_address:\n\
         \x20                 address: {host}\n\
         \x20                 port_value: {port}\n",
        name = quoted(name),
        host = quoted(host),
    ));
}

fn clusters(config: &RuntimeConfig) -> String {
    let mut out = header("clusters, to splice into the host's cluster list");
    if let Some(gateway) = &config.gateway {
        let service = &gateway.service;
        cluster(
            &mut out,
            PUBLIC_CLUSTER,
            service.host.as_str(),
            service.public_port.get(),
        );
        cluster(
            &mut out,
            CHECK_CLUSTER,
            service.host.as_str(),
            service.check_port.get(),
        );
    }
    out
}

fn local_reply() -> String {
    let unavailable = ProblemKind::Unavailable;
    let mut out = header(
        "local reply configuration, to splice into the host's HTTP connection manager as its \
         first mapper: the answer when the check itself fails",
    );
    out.push_str(&format!(
        "local_reply_config:\n\
         \x20 mappers:\n\
         \x20   - filter:\n\
         \x20       and_filter:\n\
         \x20         filters:\n\
         \x20           - status_code_filter:\n\
         \x20               comparison:\n\
         \x20                 op: EQ\n\
         \x20                 value:\n\
         \x20                   default_value: 503\n\
         \x20                   runtime_key: registry-session.local-reply.status\n\
         \x20           - response_flag_filter:\n\
         \x20               flags:\n\
         \x20                 - UAEX\n\
         \x20     headers_to_add:\n\
         \x20       - header:\n\
         \x20           key: {marker}\n\
         \x20           value: {marker_value}\n\
         \x20         append_action: OVERWRITE_IF_EXISTS_OR_ADD\n\
         \x20       - header:\n\
         \x20           key: cache-control\n\
         \x20           value: no-store\n\
         \x20         append_action: OVERWRITE_IF_EXISTS_OR_ADD\n\
         \x20     body_format_override:\n\
         \x20       json_format:\n\
         \x20         type: {problem_type}\n\
         \x20         title: {title}\n\
         \x20         status: 503\n\
         \x20         code: {code}\n\
         \x20       content_type: application/problem+json\n",
        marker = quoted(ANSWER_MARKER_HEADER),
        marker_value = quoted(ANSWER_MARKER_VALUE),
        problem_type = quoted(&unavailable.type_uri()),
        title = quoted(unavailable.title()),
        code = quoted(&unavailable.code()),
    ));
    out
}

/// The most bytes of an assembled configuration `--verify-assembled` reads.
const MAXIMUM_ASSEMBLED_BYTES: u64 = 16 * 1024 * 1024;

/// What the runtime file generates, parsed, for comparison with an assembled
/// configuration.
struct Expected {
    authority: String,
    /// The service's three filters, in chain order.
    filters: Vec<Value>,
    /// Every generated route in order. The first [`PUBLIC_PATHS`] entries are
    /// the service's public routes.
    routes: Vec<Value>,
    /// The first local reply mapper.
    mapper: Value,
    /// The host's own filters the generated routes switch off.
    host_filters: Vec<String>,
}

fn parse_fragment(file: &GeneratedFile) -> Result<Value, GatewayError> {
    Reader::new(file.name)
        .scan(file.content.as_bytes())
        .map_err(|report| GatewayError::Refused(vec![report.render_human()]))?
        .map(|node| node.to_json_value())
        .ok_or_else(|| GatewayError::Refused(vec![format!("{} is empty", file.name)]))
}

impl Expected {
    fn new(config: &RuntimeConfig) -> Result<Self, GatewayError> {
        let files = generate(config)?;
        let fragment = |name: &str| {
            files
                .iter()
                .find(|file| file.name == name)
                .ok_or_else(|| GatewayError::Refused(vec![format!("{name} is not generated")]))
                .and_then(parse_fragment)
        };
        let items = |value: Value| match value {
            Value::Array(items) => items,
            _ => Vec::new(),
        };
        let mapper = fragment("local-reply.yaml")?
            .pointer("/local_reply_config/mappers/0")
            .cloned()
            .ok_or_else(|| {
                GatewayError::Refused(vec!["local-reply.yaml has no mapper".to_owned()])
            })?;
        Ok(Self {
            authority: config
                .gateway_authority()
                .ok_or(GatewayError::NoGatewayBlock)?,
            filters: items(fragment("http-filters.yaml")?),
            routes: items(fragment("routes.yaml")?),
            mapper,
            host_filters: config
                .gateway
                .iter()
                .flat_map(|gateway| gateway.host_filters.iter())
                .map(|name| name.as_str().to_owned())
                .collect(),
        })
    }

    fn public_routes(&self) -> &[Value] {
        &self.routes[..PUBLIC_PATHS.len().min(self.routes.len())]
    }
}

/// Check an assembled Envoy configuration offline against what the runtime
/// file generates now.
///
/// Every connection manager that carries any of the service's filters or
/// routes must hold the three filters, as generated, at the head of its chain
/// and the generated mapper first among its local reply mappers, and serve
/// every generated route, as generated and in order, from the virtual host
/// that Envoy picks for the public authority, ahead of any host route that
/// could match the same paths. Every other route removes the answer marker,
/// nothing adds it above a route, and no route in the file redirects.
pub fn verify_assembled(runtime_config: &Path, assembled: &Path) -> Result<(), GatewayError> {
    let config = load_for_gateway(runtime_config)?;
    let expected = Expected::new(&config)?;
    let metadata = fs::metadata(assembled).map_err(|error| io_error(assembled, &error))?;
    if metadata.len() > MAXIMUM_ASSEMBLED_BYTES {
        return Err(GatewayError::Assembled(vec![
            "the assembled configuration is larger than 16 MiB".to_owned(),
        ]));
    }
    let bytes = fs::read(assembled).map_err(|error| io_error(assembled, &error))?;
    let document = Reader::new(assembled.display().to_string())
        .scan(&bytes)
        .map_err(|report| GatewayError::Assembled(vec![report.render_human()]))?
        .ok_or_else(|| {
            GatewayError::Assembled(vec!["the assembled configuration is empty".to_owned()])
        })?
        .to_json_value();
    let mut findings = Vec::new();
    let mut managers = Vec::new();
    collect_managers(&document, &mut managers);
    let carriers: Vec<&Value> = managers
        .into_iter()
        .filter(|manager| carries_session(manager))
        .collect();
    if carriers.is_empty() {
        findings
            .push("no HTTP connection manager carries the service's filters or routes".to_owned());
    }
    for manager in carriers {
        verify_manager(&expected, manager, &mut findings);
    }
    redirects_in(&document, &mut findings);
    if findings.is_empty() {
        Ok(())
    } else {
        Err(GatewayError::Assembled(findings))
    }
}

/// Every object that holds an HTTP filter chain, the connection managers'
/// configuration.
fn collect_managers<'a>(value: &'a Value, out: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if map.get("http_filters").is_some_and(Value::is_array) {
                out.push(value);
            }
            for child in map.values() {
                collect_managers(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_managers(item, out);
            }
        }
        _ => {}
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

fn virtual_hosts(manager: &Value) -> &[Value] {
    manager
        .get("route_config")
        .map_or(&[][..], |config| array(config, "virtual_hosts"))
}

/// Whether the connection manager holds one of the service's filters or
/// routes, by name.
fn carries_session(manager: &Value) -> bool {
    let own = |value: &Value| text(value, "name").is_some_and(|name| name.starts_with(OWN_PREFIX));
    array(manager, "http_filters").iter().any(own)
        || virtual_hosts(manager)
            .iter()
            .any(|host| array(host, "routes").iter().any(own))
}

fn name_of(value: &Value) -> &str {
    text(value, "name").unwrap_or("(unnamed)")
}

fn names_marker(value: Option<&Value>) -> bool {
    value.and_then(Value::as_array).is_some_and(|names| {
        names.iter().any(|name| {
            name.as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(ANSWER_MARKER_HEADER))
        })
    })
}

fn adds_marker(value: &Value) -> bool {
    array(value, "response_headers_to_add").iter().any(|entry| {
        entry
            .get("header")
            .and_then(|header| text(header, "key"))
            .is_some_and(|key| key.eq_ignore_ascii_case(ANSWER_MARKER_HEADER))
    })
}

fn truthy(value: Option<&Value>) -> bool {
    value.and_then(Value::as_bool) == Some(true)
}

/// How well one of a virtual host's domains matches `authority`, in Envoy's
/// order: exact, then `*.suffix`, then `prefix.*`, then `*`. Lower is better.
fn domain_rank(domain: &str, authority: &str) -> Option<u8> {
    let domain = domain.to_ascii_lowercase();
    if domain == authority {
        Some(0)
    } else if domain == "*" {
        Some(3)
    } else if let Some(suffix) = domain.strip_prefix('*') {
        authority.ends_with(suffix).then_some(1)
    } else if let Some(prefix) = domain.strip_suffix('*') {
        authority.starts_with(prefix).then_some(2)
    } else {
        None
    }
}

/// The index of the virtual host Envoy serves `authority` from.
fn serving_host(hosts: &[Value], authority: &str) -> Option<usize> {
    hosts
        .iter()
        .enumerate()
        .filter_map(|(index, host)| {
            array(host, "domains")
                .iter()
                .filter_map(|domain| domain.as_str())
                .filter_map(|domain| domain_rank(domain, authority))
                .min()
                .map(|rank| (rank, index))
        })
        .min()
        .map(|(_, index)| index)
}

/// Whether a route can only match requests for an authority other than
/// `authority`: it matches one exact `:authority` or `host` value.
fn other_authority_only(route: &Value, authority: &str) -> bool {
    route
        .get("match")
        .map_or(&[][..], |matcher| array(matcher, "headers"))
        .iter()
        .any(|header| {
            matches!(text(header, "name"), Some(":authority" | "host"))
                && header
                    .pointer("/string_match/exact")
                    .and_then(Value::as_str)
                    .is_some_and(|exact| !exact.eq_ignore_ascii_case(authority))
        })
}

/// Whether a route's path match reaches under `/session/`.
fn matches_session_path(route: &Value) -> bool {
    let Some(matcher) = route.get("match") else {
        return false;
    };
    ["path", "prefix", "path_separated_prefix"]
        .iter()
        .filter_map(|key| text(matcher, key))
        .any(|path| path.starts_with("/session/") || path == "/session")
}

fn verify_manager(expected: &Expected, manager: &Value, findings: &mut Vec<String>) {
    let chain = array(manager, "http_filters");
    for (index, want) in expected.filters.iter().enumerate() {
        if chain.get(index) == Some(want) {
            continue;
        }
        let name = name_of(want);
        match chain
            .iter()
            .position(|filter| text(filter, "name") == Some(name))
        {
            None => findings.push(format!(
                "the {name} filter is missing from the filter chain"
            )),
            Some(at) if chain[at] == *want => findings.push(format!(
                "the {name} filter is at position {at} of the filter chain and must be at \
                 position {index}: the service's filters run before the host's"
            )),
            Some(_) => findings.push(format!(
                "the {name} filter differs from the generated one: its enabled state, failure \
                 mode, address, timeout, allowed headers or code"
            )),
        }
    }
    for name in &expected.host_filters {
        if !chain
            .iter()
            .any(|filter| text(filter, "name") == Some(name.as_str()))
        {
            findings.push(format!(
                "the host filter {name}, which the generated routes switch off, is not in the \
                 filter chain"
            ));
        }
    }
    let first_mapper = manager
        .pointer("/local_reply_config/mappers/0")
        .filter(|mapper| mapper.is_object());
    if first_mapper != Some(&expected.mapper) {
        findings.push(
            "the first local reply mapper is not the generated one for a failed check (a mapper \
             ahead of it that matches status 503 would answer instead)"
                .to_owned(),
        );
    }
    if expected.authority.contains(':')
        && (truthy(manager.get("strip_any_host_port"))
            || truthy(manager.get("strip_matching_host_port")))
    {
        findings.push(format!(
            "the connection manager strips the port from the host before routing, but the \
             authority {} carries one, so no generated route would match",
            quoted(&expected.authority)
        ));
    }
    if manager.get("rds").is_some() || manager.get("scoped_routes").is_some() {
        findings.push(
            "the routes are delivered by RDS or scoped routes, which this check cannot see: \
             write the route configuration inline"
                .to_owned(),
        );
        return;
    }
    let Some(configuration) = manager.get("route_config") else {
        findings.push("the connection manager has no route configuration".to_owned());
        return;
    };
    let configuration_name = name_of(configuration);
    if adds_marker(configuration) {
        findings.push(format!(
            "the route configuration {configuration_name} adds the answer marker to its answers"
        ));
    }
    let configuration_removes = names_marker(configuration.get("response_headers_to_remove"));
    let hosts = array(configuration, "virtual_hosts");
    for (host_index, host) in hosts.iter().enumerate() {
        let host_name = text(host, "name").map_or_else(|| format!("#{host_index}"), str::to_owned);
        if adds_marker(host) {
            findings.push(format!(
                "virtual host {host_name} adds the answer marker to its answers"
            ));
        }
        let higher_removes =
            configuration_removes || names_marker(host.get("response_headers_to_remove"));
        for route in array(host, "routes") {
            let place = format!(
                "route {} of virtual host {host_name} in {configuration_name}",
                name_of(route)
            );
            if expected.public_routes().contains(route) {
                if higher_removes {
                    findings.push(format!(
                        "{place} is a public session route and removes the answer marker"
                    ));
                }
            } else if !expected.routes.contains(route) {
                if !higher_removes && !names_marker(route.get("response_headers_to_remove")) {
                    findings.push(format!(
                        "{place} does not remove the answer marker from its answers"
                    ));
                }
                if adds_marker(route) {
                    findings.push(format!("{place} adds the answer marker to its answers"));
                }
                let own_switch = route
                    .get("typed_per_filter_config")
                    .and_then(Value::as_object)
                    .is_some_and(|switches| switches.keys().any(|key| key.starts_with(OWN_PREFIX)));
                if own_switch {
                    findings.push(format!(
                        "{place} configures one of the service's filters, which only the \
                         generated routes may do"
                    ));
                }
            }
        }
    }
    let Some(serving) = serving_host(hosts, &expected.authority) else {
        findings.push(format!(
            "no virtual host serves the authority {}",
            quoted(&expected.authority)
        ));
        return;
    };
    let served = array(&hosts[serving], "routes");
    let mut last: Option<usize> = None;
    for want in &expected.routes {
        let name = name_of(want);
        match served.iter().position(|route| route == want) {
            None => findings.push(format!(
                "the generated route {name} is missing from the virtual host that serves the \
                 authority {}, or differs from the generated one",
                quoted(&expected.authority)
            )),
            Some(at) => {
                if last.is_some_and(|previous| at <= previous) {
                    findings.push(format!(
                        "the generated route {name} is out of order in the virtual host that \
                         serves the authority"
                    ));
                }
                last = Some(last.map_or(at, |previous| previous.max(at)));
            }
        }
    }
    for (index, route) in served.iter().enumerate() {
        if expected.routes.contains(route) {
            continue;
        }
        if matches_session_path(route) {
            findings.push(format!(
                "route {} of the virtual host that serves the authority matches a path under \
                 /session/, which the service keeps for its own routes",
                name_of(route)
            ));
        }
        if last.is_some_and(|last| index < last)
            && !other_authority_only(route, &expected.authority)
        {
            findings.push(format!(
                "route {} comes before the generated routes in the virtual host that serves the \
                 authority and could match the same paths",
                name_of(route)
            ));
        }
    }
}

/// A status as a number, whether written as one or as a string.
fn status_value(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

/// Whether a route redirects: a `redirect` action, an internal redirect
/// policy, or a direct reply with a 3xx status.
fn redirects(route: &Value) -> bool {
    route.get("redirect").is_some()
        || route
            .get("route")
            .is_some_and(|action| action.get("internal_redirect_policy").is_some())
        || route
            .get("direct_response")
            .and_then(|reply| reply.get("status"))
            .and_then(status_value)
            .is_some_and(|status| (300..400).contains(&status))
}

/// Whether a virtual host redirects plain-text requests to TLS.
fn requires_tls(host: &Value) -> bool {
    match host.get("require_tls") {
        None => false,
        Some(Value::String(level)) => level != "NONE",
        Some(Value::Number(level)) => level.as_u64() != Some(0),
        Some(_) => true,
    }
}

/// A finding for every redirect in any route configuration of the file.
fn redirects_in(value: &Value, findings: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(hosts) = map.get("virtual_hosts").and_then(Value::as_array) {
                for host in hosts {
                    let host_name = name_of(host);
                    if requires_tls(host) {
                        findings.push(format!(
                            "virtual host {host_name} redirects plain-text requests (require_tls)"
                        ));
                    }
                    for route in array(host, "routes") {
                        if redirects(route) {
                            findings.push(format!(
                                "route {} of virtual host {host_name} redirects",
                                name_of(route)
                            ));
                        }
                    }
                }
            }
            for child in map.values() {
                redirects_in(child, findings);
            }
        }
        Value::Array(items) => {
            for item in items {
                redirects_in(item, findings);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;

    const FIXTURE: &str = include_str!("../tests/gateway/runtime.yaml");

    fn golden_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gateway/golden")
    }

    fn fixture() -> RuntimeConfig {
        crate::config::tests::load(FIXTURE).expect("the fixture loads")
    }

    fn files(config: &RuntimeConfig) -> Vec<GeneratedFile> {
        generate(config).expect("fragments are generated")
    }

    fn file<'a>(files: &'a [GeneratedFile], name: &str) -> &'a str {
        &files
            .iter()
            .find(|file| file.name == name)
            .unwrap_or_else(|| panic!("{name} is generated"))
            .content
    }

    /// The route blocks of `routes.yaml`, each starting at its `- name:` line.
    fn route_blocks(routes: &str) -> Vec<&str> {
        let mut starts: Vec<usize> = routes
            .match_indices("\n- name:")
            .map(|(index, _)| index + 1)
            .collect();
        starts.push(routes.len());
        starts
            .windows(2)
            .map(|pair| &routes[pair[0]..pair[1]])
            .collect()
    }

    fn route_names(routes: &str) -> Vec<String> {
        route_blocks(routes)
            .iter()
            .map(|block| {
                block
                    .lines()
                    .next()
                    .and_then(|line| line.strip_prefix("- name: "))
                    .expect("a route name")
                    .trim_matches('"')
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn the_fixture_produces_the_committed_files_byte_for_byte() {
        if std::env::var_os("REGISTRY_SESSION_UPDATE_GOLDEN").is_some() {
            fs::create_dir_all(golden_dir()).expect("golden directory");
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory
                .path()
                .canonicalize()
                .expect("canonical directory")
                .join("runtime.yaml");
            fs::write(&path, FIXTURE).expect("fixture copy");
            run_envoy(&path, Mode::Write(&golden_dir())).expect("golden files are written");
        }
        let generated = files(&fixture());
        for file in &generated {
            let committed = fs::read_to_string(golden_dir().join(file.name))
                .unwrap_or_else(|_| panic!("{} is committed", file.name));
            assert_eq!(file.content, committed, "{} differs", file.name);
        }
    }

    #[test]
    fn moving_a_module_to_its_own_audience_changes_no_route() {
        let before = fixture();
        let moved = crate::config::tests::load(&FIXTURE.replacen(
            "    prefix: /api/documents/\n    audience: person",
            "    prefix: /api/documents/\n    audience: https://documents.example/api",
            1,
        ))
        .expect("the moved fixture loads");
        assert_ne!(
            before.audience_set("citizen"),
            moved.audience_set("citizen"),
            "the audience set is what changes"
        );
        assert_eq!(files(&before), files(&moved));
    }

    #[test]
    fn routes_run_in_the_service_order() {
        let generated = files(&fixture());
        let names = route_names(file(&generated, "routes.yaml"));
        assert_eq!(
            names,
            [
                "registry-session.sign-in",
                "registry-session.callback",
                "registry-session.sign-out",
                "registry-session.me",
                "registry-session.signed-out",
                "registry-session.reserved",
                "module-documents",
                "module-functions",
                "module-casework",
                "module-registry",
                "module-data",
                "page-apply",
                "page-staff",
            ]
        );
    }

    #[test]
    fn a_longer_prefix_wins_across_modules_and_pages() {
        let nested = FIXTURE.replacen(
            "  - prefix: /staff/\n    signIn: staff",
            "  - prefix: /api/registry/staff/\n    signIn: staff",
            1,
        );
        let config = crate::config::tests::load(&nested).expect("the nested fixture loads");
        let generated = files(&config);
        let names = route_names(file(&generated, "routes.yaml"));
        let page = names
            .iter()
            .position(|name| name == "page-api-registry-staff")
            .expect("the nested page route");
        let module = names
            .iter()
            .position(|name| name == "module-registry")
            .expect("the module route");
        assert!(page < module, "{names:?}");
    }

    #[test]
    fn check_passes_on_fresh_output_and_fails_naming_the_changed_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let runtime = root.join("runtime.yaml");
        fs::write(&runtime, FIXTURE).expect("fixture copy");
        let out = root.join("out");
        run_envoy(&runtime, Mode::Write(&out)).expect("files are written");
        run_envoy(&runtime, Mode::Check(&out)).expect("fresh output passes the check");

        let path = out.join("routes.yaml");
        let mut bytes = fs::read(&path).expect("routes file");
        bytes.push(b'#');
        fs::write(&path, bytes).expect("changed routes file");
        let error = run_envoy(&runtime, Mode::Check(&out)).expect_err("a changed byte fails");
        let GatewayError::Differs(names) = &error else {
            panic!("expected a difference, got {error:?}");
        };
        assert_eq!(names, &["routes.yaml"]);
        assert!(error.to_string().contains("routes.yaml"));

        fs::remove_file(out.join("clusters.yaml")).expect("remove one file");
        let error = run_envoy(&runtime, Mode::Check(&out)).expect_err("a missing file fails");
        let GatewayError::Differs(names) = &error else {
            panic!("expected a difference, got {error:?}");
        };
        assert_eq!(names, &["routes.yaml", "clusters.yaml"]);
    }

    #[test]
    fn a_file_without_a_gateway_block_is_refused() {
        let start = FIXTURE.find("gateway:\n").expect("gateway block");
        let end = FIXTURE.find("modules:\n").expect("modules");
        let mut without = format!("{}{}", &FIXTURE[..start], &FIXTURE[end..]);
        let mut lines: Vec<&str> = Vec::new();
        let mut skipping = false;
        for line in without.lines() {
            if line.starts_with("    upstream:") {
                skipping = true;
                continue;
            }
            if skipping && line.starts_with("      ") {
                continue;
            }
            skipping = false;
            lines.push(line);
        }
        without = lines.join("\n");
        let config = crate::config::tests::load(&without).expect("a file without a gateway loads");
        assert!(matches!(
            generate(&config),
            Err(GatewayError::NoGatewayBlock)
        ));
    }

    #[test]
    fn every_route_that_runs_the_check_matches_the_authority_and_removes_the_cookie() {
        let generated = files(&fixture());
        let routes = file(&generated, "routes.yaml");
        let mut guarded = 0;
        for block in route_blocks(routes) {
            assert!(
                block.contains("string_match:\n          exact: \"app.example\""),
                "every route matches the authority exactly: {block}"
            );
            if block.contains("\"registry-session.check\":") {
                guarded += 1;
                assert!(
                    block.contains("request_headers_to_remove:\n    - \"cookie\"\n"),
                    "{block}"
                );
                assert!(block.contains("\"registry-session.csrf\":"), "{block}");
            }
        }
        assert_eq!(guarded, 7, "five modules and two pages");
    }

    #[test]
    fn public_routes_keep_their_cookies_and_skip_the_check() {
        let generated = files(&fixture());
        let blocks = route_blocks(file(&generated, "routes.yaml"));
        for block in &blocks[..5] {
            assert!(
                block.contains("cluster: \"registry-session-public\""),
                "{block}"
            );
            assert!(
                block.contains("\"registry-session.strip-cookies\":"),
                "{block}"
            );
            assert!(block.contains("disabled: true"), "{block}");
            assert!(block.contains("\"registry-session.csrf\":"), "{block}");
            assert!(!block.contains("\"registry-session.check\":"), "{block}");
            assert!(block.contains("value: \"no-store\""), "{block}");
            for filter in [
                "\"envoy.filters.http.cors\":",
                "\"envoy.filters.http.basic_auth\":",
                "\"envoy.filters.http.rbac\":",
            ] {
                assert!(block.contains(filter), "{filter} is switched off: {block}");
            }
        }
        let reserved = blocks[5];
        assert!(reserved.contains("prefix: \"/session/\""), "{reserved}");
        assert!(reserved.contains("status: 404"), "{reserved}");
        assert!(!reserved.contains("cluster:"), "{reserved}");
        for filter in [
            "\"envoy.filters.http.cors\":",
            "\"envoy.filters.http.basic_auth\":",
            "\"envoy.filters.http.rbac\":",
        ] {
            assert!(
                reserved.contains(filter),
                "{filter} is switched off on the catch-all: {reserved}"
            );
        }
    }

    #[test]
    fn host_filters_go_off_except_where_an_upstream_keeps_one() {
        let generated = files(&fixture());
        let blocks = route_blocks(file(&generated, "routes.yaml"));
        let data = blocks
            .iter()
            .find(|block| block.starts_with("- name: \"module-data\"\n"))
            .expect("the data route");
        assert!(data.contains("\"envoy.filters.http.cors\":"));
        assert!(data.contains("\"envoy.filters.http.basic_auth\":"));
        assert!(!data.contains("\"envoy.filters.http.rbac\":"), "{data}");
        let registry = blocks
            .iter()
            .find(|block| block.starts_with("- name: \"module-registry\"\n"))
            .expect("the registry route");
        assert!(registry.contains("\"envoy.filters.http.rbac\":"));
        assert!(registry.contains("prefix_rewrite: \"/\""));
        assert!(registry.contains("timeout: 30s"));
        let pages = blocks
            .iter()
            .find(|block| block.starts_with("- name: \"page-apply\"\n"))
            .expect("the page route");
        assert!(pages.contains("value: \"no-cache\""), "{pages}");
        assert!(!pages.contains("prefix_rewrite"), "{pages}");
    }

    #[test]
    fn the_filters_are_named_and_the_check_forwards_only_what_it_needs() {
        let generated = files(&fixture());
        let filters = file(&generated, "http-filters.yaml");
        let order: Vec<&str> = filters
            .lines()
            .filter_map(|line| line.strip_prefix("- name: "))
            .collect();
        assert_eq!(
            order,
            [
                "\"registry-session.csrf\"",
                "\"registry-session.check\"",
                "\"registry-session.strip-cookies\""
            ]
        );
        assert!(filters.contains("path_prefix: \"/check\""));
        assert!(filters.contains("failure_mode_allow: false"));
        assert!(filters.contains("timeout: \"3s\""));
        for header in ["cookie", "origin", "sec-fetch-site", "registry-client"] {
            assert!(
                filters.contains(&format!("- exact: \"{header}\"\n")),
                "{header}"
            );
        }
        for cookie in [
            "__Host-registry-session",
            "registry-session",
            "__Host-registry-signin",
            "registry-signin",
        ] {
            assert!(
                filters.contains(&format!("[\"{cookie}\"] = true")),
                "{cookie}"
            );
        }
    }

    #[test]
    fn the_check_lets_the_marker_through_to_the_browser_and_never_to_the_upstream() {
        let generated = files(&fixture());
        let filters = file(&generated, "http-filters.yaml");
        let (upstream, client) = filters
            .split_once("allowed_client_headers:")
            .expect("both header lists");
        let upstream = upstream
            .split_once("allowed_upstream_headers:")
            .expect("the upstream list")
            .1;
        let client = client.split_once("- name:").expect("the next filter").0;
        assert!(client.contains("- exact: \"registry-session-answer\""));
        for header in ["content-type", "cache-control", "location"] {
            assert!(
                client.contains(&format!("- exact: \"{header}\"")),
                "{header}"
            );
        }
        assert!(!upstream.contains("registry-session-answer"));
        assert!(upstream.contains("- exact: \"authorization\""));
    }

    #[test]
    fn the_local_reply_adds_the_marker_to_the_failed_check_answer() {
        let generated = files(&fixture());
        let reply = file(&generated, "local-reply.yaml");
        assert!(reply.contains("local_reply_config:"));
        assert!(reply.contains("UAEX"));
        assert!(reply.contains("and_filter:"), "status and flag together");
        assert!(reply.contains("status_code_filter:"));
        assert!(reply.contains("response_flag_filter:"));
        assert!(reply.contains("default_value: 503"));
        assert!(reply.contains("key: \"registry-session-answer\""));
        assert!(reply.contains("value: \"1\""));
        assert!(reply.contains("content_type: application/problem+json"));
        assert!(reply.contains("code: \"session.unavailable\""));
        assert!(reply.contains("status: 503"));
        assert_eq!(reply.matches("- filter:").count(), 1, "one mapper");
    }

    #[test]
    fn every_route_but_the_public_ones_removes_the_marker() {
        let generated = files(&fixture());
        assert!(!file(&generated, "http-filters.yaml").contains("envoy_on_response"));
        assert!(generated
            .iter()
            .all(|file| file.name != "route-config.yaml"));
        let blocks = route_blocks(file(&generated, "routes.yaml"));
        assert_eq!(blocks.len(), 13);
        for (index, block) in blocks.iter().enumerate() {
            let removes =
                block.contains("response_headers_to_remove:\n    - \"registry-session-answer\"\n");
            assert_eq!(removes, index >= 5, "{block}");
        }
    }

    #[test]
    fn clusters_reach_both_listeners() {
        let generated = files(&fixture());
        let clusters = file(&generated, "clusters.yaml");
        assert!(clusters.contains("- name: \"registry-session-public\""));
        assert!(clusters.contains("- name: \"registry-session-check\""));
        assert_eq!(clusters.matches("type: STRICT_DNS").count(), 2);
        assert_eq!(clusters.matches("connect_timeout: 1s").count(), 2);
        assert!(clusters.contains("port_value: 8120"));
        assert!(clusters.contains("port_value: 8121"));
        assert_eq!(
            clusters.matches("address: \"registry-session\"\n").count(),
            2
        );
    }

    #[test]
    fn every_file_says_it_is_generated() {
        for file in files(&fixture()) {
            assert!(
                file.content
                    .starts_with("# Generated by `registry-session gateway envoy`"),
                "{}",
                file.name
            );
            assert!(
                !file.content.contains(" \n"),
                "{} has trailing spaces",
                file.name
            );
            assert!(file.content.ends_with('\n'), "{}", file.name);
        }
    }

    /// The codes of the findings the check reports for `text`.
    fn codes(text: &str) -> Vec<String> {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory
            .path()
            .canonicalize()
            .expect("canonical directory")
            .join("runtime.yaml");
        fs::write(&path, text).expect("runtime file");
        crate::config::check_runtime(&path, true)
            .diagnostics
            .into_iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    #[test]
    fn the_fixture_has_no_findings() {
        assert_eq!(codes(FIXTURE), Vec::<String>::new());
    }

    #[test]
    fn the_gateway_block_is_refused_where_it_is_wrong() {
        let wrong = |from: &str, to: &str| FIXTURE.replacen(from, to, 1);
        for (text, code) in [
            (
                wrong("checkPort: 8121", "checkPort: 8120"),
                "platform.session-runtime.gateway-ports-equal",
            ),
            (
                wrong(
                    "        - envoy.filters.http.rbac\n",
                    "        - envoy.filters.http.lua\n",
                ),
                "platform.session-runtime.unknown-host-filter",
            ),
            (wrong("      cluster: registry\n", ""), "config.missing-key"),
            (
                wrong(
                    "    upstream:\n      cluster: pages\n      timeoutSeconds: 15\n",
                    "",
                ),
                "platform.session-runtime.upstream-missing",
            ),
        ] {
            let found = codes(&text);
            assert!(found.iter().any(|found| found == code), "{code}: {found:?}");
        }
        for (from, to) in [
            (
                "hostFilters:",
                "checkTimeoutMilliseconds: 499\n  hostFilters:",
            ),
            (
                "hostFilters:",
                "checkTimeoutMilliseconds: 10001\n  hostFilters:",
            ),
            ("timeoutSeconds: 60", "timeoutSeconds: 0"),
            ("publicPort: 8120", "publicPort: 70000"),
        ] {
            let found = codes(&wrong(from, to));
            assert!(
                found.iter().any(|found| found == "config.out-of-range"),
                "{to}: {found:?}"
            );
        }
        // The issuer's timeout stays below the shortest check timeout.
        let timeout = FIXTURE
            .replacen(
                "hostFilters:",
                "checkTimeoutMilliseconds: 500\n  hostFilters:",
                1,
            )
            .replacen(
                "  jwks: https://id.example/oauth2/jwks\n",
                "  jwks: https://id.example/oauth2/jwks\n  timeoutMilliseconds: 400\n",
                1,
            );
        assert_eq!(codes(&timeout), Vec::<String>::new());
    }

    #[test]
    fn an_upstream_without_a_gateway_block_is_refused() {
        let start = FIXTURE.find("gateway:\n").expect("gateway block");
        let end = FIXTURE.find("modules:\n").expect("modules");
        let without = format!("{}{}", &FIXTURE[..start], &FIXTURE[end..]);
        let found = codes(&without);
        assert!(
            found
                .iter()
                .any(|code| code == "platform.session-runtime.upstream-without-gateway"),
            "{found:?}"
        );
    }

    #[test]
    fn the_authority_defaults_to_the_public_origin_and_can_be_set() {
        assert_eq!(
            fixture().gateway_authority().as_deref(),
            Some("app.example")
        );
        let with_port = crate::config::tests::load(&FIXTURE.replacen(
            "publicOrigin: https://app.example",
            "publicOrigin: https://app.example:8443",
            1,
        ))
        .expect("loads");
        assert_eq!(
            with_port.gateway_authority().as_deref(),
            Some("app.example:8443")
        );
        let written = crate::config::tests::load(&FIXTURE.replacen(
            "gateway:\n",
            "gateway:\n  authority: web.example\n",
            1,
        ))
        .expect("loads");
        assert_eq!(written.gateway_authority().as_deref(), Some("web.example"));
        let generated = files(&written);
        assert!(file(&generated, "routes.yaml").contains("exact: \"web.example\""));
    }

    /// Whether any route in `routes` redirects: a `redirect` action, an
    /// internal redirect policy, or a direct reply with a 3xx status.
    fn redirects(routes: &str) -> bool {
        routes.lines().any(|line| {
            let line = line.trim();
            line.starts_with("redirect:")
                || line.starts_with("internal_redirect_policy:")
                || line
                    .strip_prefix("status: ")
                    .and_then(|status| status.parse::<u16>().ok())
                    .is_some_and(|status| (300..400).contains(&status))
        })
    }

    #[test]
    fn no_generated_route_redirects() {
        let generated = files(&fixture());
        assert!(!redirects(file(&generated, "routes.yaml")));
    }

    #[test]
    fn the_redirect_detector_sees_a_redirecting_route() {
        let generated = files(&fixture());
        let routes = file(&generated, "routes.yaml");
        for wrong in [
            routes.replace("status: 404", "status: 302"),
            format!("{routes}  redirect:\n    path_redirect: /x\n"),
            format!("{routes}  route:\n    internal_redirect_policy:\n      max_internal_redirects: 1\n"),
        ] {
            assert!(redirects(&wrong));
        }
    }

    #[test]
    fn the_cookie_strip_matches_the_name_in_one_pass_with_no_lazy_pattern() {
        let generated = files(&fixture());
        let filters = file(&generated, "http-filters.yaml");
        assert!(
            !filters.contains(".-"),
            "a lazy pattern backtracks quadratically over a long run of spaces"
        );
        assert!(filters.contains("string.match(pair, \"^%s*([^=]*)\")"));
    }

    #[test]
    fn page_routes_remove_authorization_with_the_cookie_and_modules_do_not() {
        let generated = files(&fixture());
        for block in route_blocks(file(&generated, "routes.yaml")) {
            if !block.contains("\"registry-session.check\":") {
                continue;
            }
            let page = block.contains("- name: \"page-");
            assert!(block.contains("request_headers_to_remove:\n    - \"cookie\"\n"));
            assert_eq!(block.contains("    - \"authorization\"\n"), page, "{block}");
        }
    }

    #[test]
    fn the_filters_go_at_the_head_of_the_hosts_chain() {
        let generated = files(&fixture());
        let filters = file(&generated, "http-filters.yaml");
        assert!(
            filters.contains("at the head of the host's chain"),
            "{filters}"
        );
        assert!(!filters.contains("before its router"));
    }

    #[test]
    fn every_generated_file_is_valid_yaml_and_quotes_its_names() {
        let hostile = FIXTURE
            .replacen("prefix: /apply/", "prefix: /a:b/", 1)
            .replacen("- envoy.filters.http.cors", "- on", 1);
        let config = crate::config::tests::load(&hostile).expect("the fixture loads");
        for file in files(&config) {
            parse_fragment(&file).unwrap_or_else(|_| panic!("{} is not valid YAML", file.name));
            for line in file.content.lines() {
                if let Some(name) = line.trim_start_matches([' ', '-']).strip_prefix("name: ") {
                    if !name.starts_with('"') {
                        assert!(name.starts_with("\":authority\""), "{line}");
                    }
                }
            }
        }
        let generated = files(&config);
        assert!(file(&generated, "routes.yaml").contains("- name: \"page-a:b\"\n"));
        assert!(file(&generated, "routes.yaml").contains("    \"on\":\n"));
        assert!(file(&generated, "clusters.yaml").contains("address: \"registry-session\"\n"));
    }

    fn refusal(config: &RuntimeConfig) -> Vec<String> {
        match generate(config) {
            Err(GatewayError::Refused(findings)) => findings,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn two_routes_that_would_share_a_name_are_refused_naming_both() {
        let clash = FIXTURE
            .replacen("prefix: /apply/", "prefix: /a/b/", 1)
            .replacen("prefix: /staff/", "prefix: /a-b/", 1);
        let config = crate::config::tests::load(&clash).expect("the clashing fixture loads");
        let found = refusal(&config);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("/a/b/") && found[0].contains("/a-b/"),
            "{found:?}"
        );
        assert!(found[0].contains("page-a-b"), "{found:?}");
    }

    #[test]
    fn a_prefix_outside_the_path_grammar_is_refused() {
        let mut config = fixture();
        config.pages[0].prefix = "/a//b/".to_owned();
        let found = refusal(&config);
        assert!(
            found.iter().any(|finding| finding.contains("/a//b/")),
            "{found:?}"
        );
    }

    #[test]
    fn the_unavailable_answer_and_the_check_headers_come_from_the_wire_module() {
        let generated = files(&fixture());
        let reply = parse_fragment(
            generated
                .iter()
                .find(|file| file.name == "local-reply.yaml")
                .expect("local reply"),
        )
        .expect("parses");
        let body = reply
            .pointer("/local_reply_config/mappers/0/body_format_override/json_format")
            .expect("the body format");
        let kind = ProblemKind::Unavailable;
        assert_eq!(body["type"], kind.type_uri());
        assert_eq!(body["title"], kind.title());
        assert_eq!(body["code"], kind.code());
        let filters = fragment_of(&generated, "http-filters.yaml");
        let forwarded: Vec<&str> = filters
            .pointer("/1/typed_config/allowed_headers/patterns")
            .and_then(Value::as_array)
            .expect("the forwarded headers")
            .iter()
            .filter_map(|pattern| text(pattern, "exact"))
            .collect();
        assert_eq!(forwarded, CHECK_REQUEST_HEADERS);
        assert_eq!(
            CHECK_REQUEST_HEADERS,
            ["cookie", "origin", "sec-fetch-site", "registry-client"],
            "the headers the check reads"
        );
    }

    #[test]
    fn a_nested_page_is_routed_as_a_page_by_the_gateway_and_by_the_service() {
        let nested = FIXTURE.replacen(
            "  - prefix: /staff/\n    signIn: staff",
            "  - prefix: /api/registry/staff/\n    signIn: staff",
            1,
        );
        let config = crate::config::tests::load(&nested).expect("the nested fixture loads");
        assert!(matches!(
            config.route("/api/registry/staff/form"),
            Some(crate::config::Route::Page(_))
        ));
        assert!(matches!(
            config.route("/api/registry/records"),
            Some(crate::config::Route::Module(_))
        ));
    }

    #[test]
    fn the_runtime_file_is_never_read_with_the_environment() {
        for (from, to, pointer) in [
            (
                "host: registry-session",
                "host: ${SESSION_TEST_GATEWAY_HOST}",
                "/gateway",
            ),
            (
                "prefix: /api/registry/",
                "prefix: ${SESSION_TEST_PREFIX}",
                "/modules/0/prefix",
            ),
        ] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let root = directory
                .path()
                .canonicalize()
                .expect("canonical directory");
            let runtime = root.join("runtime.yaml");
            fs::write(&runtime, FIXTURE.replacen(from, to, 1)).expect("runtime file");
            let error = run_envoy(&runtime, Mode::Write(&root.join("out")))
                .expect_err("an expression in a gateway member is refused");
            let GatewayError::Refused(found) = &error else {
                panic!("expected a refusal, got {error:?}");
            };
            assert!(
                found.iter().any(|finding| finding.contains(pointer)),
                "{found:?}"
            );
            assert!(!root.join("out").exists(), "nothing was written");
        }
    }

    #[test]
    fn an_expression_in_a_member_the_fragments_ignore_is_allowed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let runtime = root.join("runtime.yaml");
        fs::write(
            &runtime,
            FIXTURE.replacen(
                "path: /var/lib/session/audit.jsonl",
                "path: ${SESSION_TEST_AUDIT}",
                1,
            ),
        )
        .expect("runtime file");
        run_envoy(&runtime, Mode::Write(&root.join("out"))).expect("the fragments are written");
    }

    #[test]
    fn a_host_filter_may_not_name_the_services_own_filters_or_the_router() {
        for reserved in [
            "registry-session.check",
            "registry-session.csrf",
            "registry-session.strip-cookies",
            "envoy.filters.http.router",
        ] {
            let text = FIXTURE.replacen(
                "    - envoy.filters.http.rbac\n",
                &format!("    - {reserved}\n"),
                1,
            );
            let found = codes(&text);
            assert!(
                found
                    .iter()
                    .any(|code| code == "platform.session-runtime.reserved-host-filter"),
                "{reserved}: {found:?}"
            );
        }
    }

    #[test]
    fn an_upper_case_authority_is_refused() {
        let text = FIXTURE.replacen("gateway:\n", "gateway:\n  authority: App.Example\n", 1);
        assert!(crate::config::tests::load(&text).is_err());
    }

    fn fragment_of(files: &[GeneratedFile], name: &str) -> Value {
        parse_fragment(
            files
                .iter()
                .find(|file| file.name == name)
                .unwrap_or_else(|| panic!("{name} is generated")),
        )
        .expect("the fragment parses")
    }

    fn sequence(value: Value) -> Vec<Value> {
        match value {
            Value::Array(items) => items,
            other => panic!("expected a sequence, got {other:?}"),
        }
    }

    const MANAGER: &str = "/static_resources/listeners/0/filter_chains/0/filters/0/typed_config";

    /// A passing assembled configuration for the runtime file `text`: the
    /// generated fragments in place, the host's filters behind them, and one
    /// host route.
    fn assembled_from(text: &str) -> Value {
        let config = crate::config::tests::load(text).expect("the runtime file loads");
        let authority = config.gateway_authority().expect("an authority");
        let generated = files(&config);
        let mut chain = sequence(fragment_of(&generated, "http-filters.yaml"));
        for name in [
            "envoy.filters.http.cors",
            "envoy.filters.http.basic_auth",
            "envoy.filters.http.rbac",
            "envoy.filters.http.router",
        ] {
            chain.push(json!({ "name": name }));
        }
        let mut routes = sequence(fragment_of(&generated, "routes.yaml"));
        routes.push(json!({
            "name": "host-api",
            "match": { "prefix": "/rest/" },
            "route": { "cluster": "api" },
            "response_headers_to_remove": ["registry-session-answer"],
        }));
        let reply = fragment_of(&generated, "local-reply.yaml");
        json!({"static_resources": {"listeners": [{"name": "main", "filter_chains": [{"filters": [{
            "name": "envoy.filters.network.http_connection_manager",
            "typed_config": {
                "http_filters": chain,
                "local_reply_config": reply["local_reply_config"],
                "route_config": {"name": "local", "virtual_hosts": [
                    {"name": "app", "domains": [authority], "routes": routes}
                ]},
            },
        }]}]}]}})
    }

    fn assembled() -> Value {
        assembled_from(FIXTURE)
    }

    fn manager(document: &mut Value) -> &mut Value {
        document
            .pointer_mut(MANAGER)
            .expect("the connection manager")
    }

    fn chain(document: &mut Value) -> &mut Vec<Value> {
        manager(document)
            .get_mut("http_filters")
            .and_then(Value::as_array_mut)
            .expect("the filter chain")
    }

    fn host_routes(document: &mut Value) -> &mut Vec<Value> {
        manager(document)
            .pointer_mut("/route_config/virtual_hosts/0/routes")
            .and_then(Value::as_array_mut)
            .expect("the virtual host's routes")
    }

    fn route<'a>(document: &'a mut Value, name: &str) -> &'a mut Value {
        host_routes(document)
            .iter_mut()
            .find(|route| text(route, "name") == Some(name))
            .unwrap_or_else(|| panic!("route {name}"))
    }

    fn verified_against(runtime_text: &str, document: &Value) -> Result<(), GatewayError> {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let runtime = root.join("runtime.yaml");
        fs::write(&runtime, runtime_text).expect("runtime file");
        let path = root.join("envoy.yaml");
        fs::write(&path, serde_json::to_string(document).expect("json")).expect("assembled file");
        verify_assembled(&runtime, &path)
    }

    fn findings(document: &Value) -> Vec<String> {
        match verified_against(FIXTURE, document) {
            Err(GatewayError::Assembled(findings)) => findings,
            other => panic!("expected findings, got {other:?}"),
        }
    }

    /// Assert that some finding contains `needle`.
    fn refuses(document: &Value, needle: &str) {
        let found = findings(document);
        assert!(
            found.iter().any(|finding| finding.contains(needle)),
            "no finding mentions {needle:?}: {found:?}"
        );
    }

    fn marker_removing_route(name: &str, matcher: Value) -> Value {
        json!({
            "name": name,
            "match": matcher,
            "route": { "cluster": "api" },
            "response_headers_to_remove": ["registry-session-answer"],
        })
    }

    #[test]
    fn a_complete_assembled_configuration_passes() {
        verified_against(FIXTURE, &assembled()).expect("passes");
    }

    #[test]
    fn a_wildcard_domain_serves_the_authority_when_nothing_is_more_specific() {
        let mut document = assembled();
        manager(&mut document)["route_config"]["virtual_hosts"][0]["domains"] = json!(["*"]);
        verified_against(FIXTURE, &document).expect("passes");
    }

    #[test]
    fn a_session_route_that_leaves_a_host_filter_on_fails() {
        for name in [
            "registry-session.sign-in",
            "registry-session.callback",
            "registry-session.sign-out",
            "registry-session.me",
            "registry-session.signed-out",
            "registry-session.reserved",
        ] {
            let mut document = assembled();
            route(&mut document, name)["typed_per_filter_config"]
                .as_object_mut()
                .expect("per-filter config")
                .remove("envoy.filters.http.rbac")
                .expect("the host filter is switched off in the generated route");
            refuses(&document, name);
        }
    }

    #[test]
    fn a_module_route_with_its_check_switched_off_fails() {
        let mut document = assembled();
        route(&mut document, "module-registry")["typed_per_filter_config"]
            ["registry-session.check"] = json!({
            "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
            "disabled": true,
        });
        refuses(&document, "module-registry");
    }

    #[test]
    fn a_module_route_without_its_check_entry_fails() {
        let mut document = assembled();
        route(&mut document, "module-registry")["typed_per_filter_config"]
            .as_object_mut()
            .expect("per-filter config")
            .remove("registry-session.check");
        refuses(&document, "module-registry");
    }

    #[test]
    fn a_host_route_ahead_of_the_generated_routes_fails() {
        let mut document = assembled();
        host_routes(&mut document)
            .insert(0, marker_removing_route("early", json!({ "prefix": "/" })));
        refuses(&document, "comes before the generated routes");
    }

    #[test]
    fn a_host_route_for_another_authority_may_come_first() {
        let mut document = assembled();
        let mut early = marker_removing_route("early", json!({ "prefix": "/" }));
        early["match"]["headers"] = json!([{
            "name": ":authority",
            "string_match": { "exact": "internal.example" },
        }]);
        host_routes(&mut document).insert(0, early);
        verified_against(FIXTURE, &document).expect("passes");
    }

    #[test]
    fn generated_routes_in_a_wildcard_host_while_another_serves_the_authority_fail() {
        let mut document = assembled();
        let hosts = manager(&mut document)["route_config"]["virtual_hosts"]
            .as_array_mut()
            .expect("virtual hosts");
        hosts[0]["domains"] = json!(["*"]);
        hosts.push(json!({
            "name": "public",
            "domains": ["app.example"],
            "routes": [marker_removing_route("host-api", json!({ "prefix": "/" }))],
        }));
        refuses(
            &document,
            "is missing from the virtual host that serves the authority",
        );
    }

    #[test]
    fn no_virtual_host_for_the_authority_fails() {
        let mut document = assembled();
        manager(&mut document)["route_config"]["virtual_hosts"][0]["domains"] =
            json!(["other.example"]);
        refuses(&document, "no virtual host serves the authority");
    }

    #[test]
    fn generated_routes_out_of_order_fail() {
        let mut document = assembled();
        host_routes(&mut document).swap(0, 1);
        refuses(&document, "out of order");
    }

    #[test]
    fn the_check_filter_with_failure_mode_allow_fails() {
        let mut document = assembled();
        chain(&mut document)[1]["typed_config"]["failure_mode_allow"] = json!(true);
        refuses(&document, "registry-session.check filter differs");
    }

    #[test]
    fn a_changed_check_timeout_address_or_header_list_fails() {
        for (pointer, value) in [
            (
                "/typed_config/http_service/server_uri/timeout",
                json!("30s"),
            ),
            (
                "/typed_config/http_service/server_uri/cluster",
                json!("elsewhere"),
            ),
            (
                "/typed_config/allowed_headers/patterns",
                json!([{ "exact": "cookie" }]),
            ),
        ] {
            let mut document = assembled();
            *chain(&mut document)[1]
                .pointer_mut(pointer)
                .expect("the member") = value;
            refuses(&document, "registry-session.check filter differs");
        }
    }

    #[test]
    fn the_check_filter_after_the_router_or_the_host_filters_fails() {
        let mut document = assembled();
        let check = chain(&mut document).remove(1);
        chain(&mut document).push(check);
        refuses(&document, "registry-session.check filter is at position");
        let mut document = assembled();
        let strip = chain(&mut document).remove(2);
        chain(&mut document).insert(3, strip);
        refuses(
            &document,
            "registry-session.strip-cookies filter is at position",
        );
    }

    #[test]
    fn the_check_filter_in_another_connection_manager_fails() {
        let mut document = assembled();
        let check = chain(&mut document).remove(1);
        document["static_resources"]["listeners"]
            .as_array_mut()
            .expect("listeners")
            .push(json!({"name": "other", "filter_chains": [{"filters": [{
                "name": "envoy.filters.network.http_connection_manager",
                "typed_config": {"http_filters": [check]},
            }]}]}));
        refuses(&document, "registry-session.check filter is missing");
    }

    #[test]
    fn a_missing_csrf_or_cookie_strip_filter_fails() {
        let mut document = assembled();
        chain(&mut document).remove(2);
        refuses(
            &document,
            "registry-session.strip-cookies filter is missing",
        );
        let mut document = assembled();
        chain(&mut document).remove(0);
        refuses(&document, "registry-session.csrf filter");
    }

    #[test]
    fn a_host_route_that_switches_off_the_cookie_strip_fails() {
        let mut document = assembled();
        route(&mut document, "host-api")["typed_per_filter_config"] = json!({
            "registry-session.strip-cookies": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.LuaPerRoute",
                "disabled": true,
            },
        });
        refuses(&document, "configures one of the service's filters");
    }

    #[test]
    fn a_host_mapper_ahead_of_the_generated_one_fails() {
        let mut document = assembled();
        manager(&mut document)["local_reply_config"]["mappers"]
            .as_array_mut()
            .expect("mappers")
            .insert(
                0,
                json!({
                    "filter": {"status_code_filter": {"comparison": {
                        "op": "EQ", "value": {"default_value": 503},
                    }}},
                    "body_format_override": {"text_format": "unavailable"},
                }),
            );
        refuses(&document, "first local reply mapper");
    }

    #[test]
    fn a_missing_local_reply_mapper_fails() {
        let mut document = assembled();
        manager(&mut document)
            .as_object_mut()
            .expect("manager")
            .remove("local_reply_config");
        refuses(&document, "first local reply mapper");
    }

    #[test]
    fn a_host_route_on_a_session_path_without_the_removal_fails_and_so_does_one_with_it() {
        let mut document = assembled();
        let hosts = manager(&mut document)["route_config"]["virtual_hosts"]
            .as_array_mut()
            .expect("virtual hosts");
        hosts.push(
            json!({"name": "internal", "domains": ["internal.example"], "routes": [
                {"name": "x", "match": {"path": "/session/me"}, "route": {"cluster": "api"}},
            ]}),
        );
        refuses(&document, "does not remove the answer marker");
        let mut document = assembled();
        host_routes(&mut document).push(marker_removing_route(
            "late",
            json!({ "path": "/session/me" }),
        ));
        refuses(&document, "matches a path under /session/");
    }

    #[test]
    fn a_marker_added_by_a_virtual_host_or_the_route_configuration_fails() {
        let add = json!([{"header": {"key": "registry-session-answer", "value": "1"}}]);
        let mut document = assembled();
        manager(&mut document)["route_config"]["virtual_hosts"][0]["response_headers_to_add"] =
            add.clone();
        refuses(&document, "virtual host app adds the answer marker");
        let mut document = assembled();
        manager(&mut document)["route_config"]["response_headers_to_add"] = add;
        refuses(
            &document,
            "route configuration local adds the answer marker",
        );
    }

    #[test]
    fn routes_delivered_by_rds_are_refused_because_they_cannot_be_seen() {
        let mut document = assembled();
        let manager = manager(&mut document);
        manager
            .as_object_mut()
            .expect("manager")
            .remove("route_config");
        manager["rds"] = json!({"route_config_name": "local", "config_source": {"ads": {}}});
        refuses(&document, "RDS");
    }

    #[test]
    fn a_redirect_in_any_form_fails() {
        let redirecting = [
            json!({"redirect": {"path_redirect": "/elsewhere"}}),
            json!({"route": {"cluster": "api", "internal_redirect_policy": {"max_internal_redirects": 1}}}),
            json!({"direct_response": {"status": 302}}),
            json!({"direct_response": {"status": "302"}}),
        ];
        for action in redirecting {
            let mut document = assembled();
            let host = route(&mut document, "host-api");
            host.as_object_mut().expect("route").remove("route");
            for (key, value) in action.as_object().expect("action") {
                host[key.as_str()] = value.clone();
            }
            refuses(&document, "host-api");
            assert!(
                findings(&document)
                    .iter()
                    .any(|finding| finding.contains("redirects")),
                "{action}"
            );
        }
        let mut document = assembled();
        manager(&mut document)["route_config"]["virtual_hosts"][0]["require_tls"] = json!("ALL");
        refuses(&document, "require_tls");
    }

    #[test]
    fn a_host_route_without_the_removal_fails_naming_it() {
        let mut document = assembled();
        route(&mut document, "host-api")
            .as_object_mut()
            .expect("route")
            .remove("response_headers_to_remove");
        let found = findings(&document);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("host-api"), "{found:?}");
    }

    #[test]
    fn a_removal_above_the_routes_strips_the_public_routes_and_fails() {
        let mut document = assembled();
        manager(&mut document)["route_config"]["response_headers_to_remove"] =
            json!(["registry-session-answer"]);
        let found = findings(&document);
        assert_eq!(found.len(), 5, "{found:?}");
        assert!(found
            .iter()
            .all(|finding| finding.contains("public session route")));
    }

    #[test]
    fn a_host_filter_the_routes_switch_off_must_be_in_the_chain() {
        let mut document = assembled();
        let rbac = chain(&mut document)
            .iter_mut()
            .find(|filter| text(filter, "name") == Some("envoy.filters.http.rbac"))
            .expect("the rbac filter");
        rbac["name"] = json!("envoy.filters.http.rbak");
        refuses(&document, "host filter envoy.filters.http.rbac");
    }

    #[test]
    fn an_authority_with_a_port_is_refused_when_the_host_strips_ports() {
        let ported = FIXTURE.replacen(
            "publicOrigin: https://app.example",
            "publicOrigin: https://app.example:8443",
            1,
        );
        let mut document = assembled_from(&ported);
        verified_against(&ported, &document).expect("passes without port stripping");
        for member in ["strip_any_host_port", "strip_matching_host_port"] {
            manager(&mut document)[member] = json!(true);
            let Err(GatewayError::Assembled(found)) = verified_against(&ported, &document) else {
                panic!("expected findings for {member}");
            };
            assert!(
                found
                    .iter()
                    .any(|finding| finding.contains("strips the port")),
                "{found:?}"
            );
            manager(&mut document)
                .as_object_mut()
                .expect("manager")
                .remove(member);
        }
        // Without a port in the authority, stripping is harmless.
        let mut plain = assembled();
        manager(&mut plain)["strip_any_host_port"] = json!(true);
        verified_against(FIXTURE, &plain).expect("passes");
    }

    #[test]
    fn a_file_with_no_session_connection_manager_fails() {
        let found = findings(&json!({"static_resources": {"listeners": []}}));
        assert!(found[0].contains("no HTTP connection manager"), "{found:?}");
    }

    #[test]
    fn verifying_reads_the_runtime_file_without_the_environment() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let runtime = root.join("runtime.yaml");
        fs::write(
            &runtime,
            FIXTURE.replacen(
                "prefix: /api/registry/",
                "prefix: ${SESSION_TEST_PREFIX}",
                1,
            ),
        )
        .expect("runtime file");
        let path = root.join("envoy.yaml");
        fs::write(&path, serde_json::to_string(&assembled()).expect("json")).expect("file");
        assert!(matches!(
            verify_assembled(&runtime, &path),
            Err(GatewayError::Refused(_))
        ));
    }
}
