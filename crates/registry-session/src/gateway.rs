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

/// The runtime key the local reply mapper reads its status from.
const LOCAL_REPLY_RUNTIME_KEY: &str = "registry-session.local-reply.status";

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
    if config.gateway_authority().is_none() {
        return Err(GatewayError::NoGatewayBlock);
    }
    let guarded = guarded_routes(config)?;
    Ok(vec![
        GeneratedFile {
            name: "http-filters.yaml",
            content: http_filters(gateway.check_timeout_milliseconds.get()),
        },
        GeneratedFile {
            name: "routes.yaml",
            content: routes(config, &guarded),
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
/// and one request can carry tens of thousands. Pairs are split on `,` as well
/// as `;`: Envoy joins repeated `cookie` fields with `,`, and a cookie value
/// cannot hold one.
const LUA_BODY: &str = r#"
-- Removes the service's own cookies from the request and keeps the rest.
function envoy_on_request(handle)
  local headers = handle:headers()
  local cookie = headers:get("cookie")
  if cookie == nil then
    return
  end
  local kept = {}
  for pair in string.gmatch(cookie, "[^;,]+") do
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

/// A route's path match. No route matches the authority itself: the routes
/// live in a virtual host whose only domain is the authority, and Envoy picks
/// that virtual host in any case of the host name, which an `:authority`
/// header match would not.
fn match_lines(out: &mut String, matcher: &str) {
    out.push_str(&format!("  match:\n    {matcher}\n"));
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

fn routes(config: &RuntimeConfig, guarded: &[GuardedRoute<'_>]) -> String {
    let host_filters: Vec<&str> = config
        .gateway
        .iter()
        .flat_map(|gateway| gateway.host_filters.iter())
        .map(|filter| filter.as_str())
        .collect();
    let mut out = header(
        "routes, to put first, in this order, in a virtual host whose only domain is the public \
         authority, ahead of any host route there",
    );
    for path in PUBLIC_PATHS {
        let name = path.trim_start_matches(SESSION_PREFIX);
        out.push_str(&format!(
            "- name: {}\n",
            quoted(&format!("{OWN_PREFIX}{name}"))
        ));
        match_lines(&mut out, &format!("path: {}", quoted(path)));
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
    match_lines(&mut out, &format!("prefix: {}", quoted(SESSION_PREFIX)));
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
        match_lines(&mut out, &format!("prefix: {}", quoted(route.prefix)));
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
         \x20                   runtime_key: {runtime_key}\n\
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
        runtime_key = LOCAL_REPLY_RUNTIME_KEY,
        marker = quoted(ANSWER_MARKER_HEADER),
        marker_value = quoted(ANSWER_MARKER_VALUE),
        problem_type = quoted(&unavailable.type_uri()),
        title = quoted(unavailable.title()),
        code = quoted(&unavailable.code()),
    ));
    out
}

fn parse_fragment(file: &GeneratedFile) -> Result<Value, GatewayError> {
    Reader::new(file.name)
        .scan(file.content.as_bytes())
        .map_err(|report| GatewayError::Refused(vec![report.render_human()]))?
        .map(|node| node.to_json_value())
        .ok_or_else(|| GatewayError::Refused(vec![format!("{} is empty", file.name)]))
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

mod verify;
pub use verify::verify_assembled;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;

    pub(super) const FIXTURE: &str = include_str!("../tests/gateway/runtime.yaml");

    fn golden_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gateway/golden")
    }

    pub(super) fn fixture() -> RuntimeConfig {
        crate::config::tests::load(FIXTURE).expect("the fixture loads")
    }

    pub(super) fn files(config: &RuntimeConfig) -> Vec<GeneratedFile> {
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
    fn every_route_that_runs_the_check_removes_the_cookie_and_none_matches_the_authority() {
        let generated = files(&fixture());
        let routes = file(&generated, "routes.yaml");
        let mut guarded = 0;
        for block in route_blocks(routes) {
            assert!(
                !block.contains(":authority") && !block.contains("app.example"),
                "the virtual host, not a header match, holds the authority: {block}"
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
        let parsed = sequence(fragment_of(&generated, "routes.yaml"));
        for route in &parsed[..5] {
            let strip = &route["typed_per_filter_config"]["registry-session.strip-cookies"];
            assert_eq!(strip["disabled"], json!(true), "{route}");
            assert_eq!(
                strip["@type"],
                json!("type.googleapis.com/envoy.extensions.filters.http.lua.v3.LuaPerRoute")
            );
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
                "  jwks: https://id.example/oauth2/jwks\n  attemptTimeoutMilliseconds: 400\n",
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
        assert!(!file(&generated, "routes.yaml").contains("web.example"));
    }

    #[test]
    fn no_generated_route_redirects() {
        let generated = files(&fixture());
        let routes = sequence(fragment_of(&generated, "routes.yaml"));
        assert_eq!(routes.len(), 13);
        assert!(!routes.iter().any(verify::redirects));
    }

    #[test]
    fn the_redirect_detector_sees_a_redirecting_route() {
        let generated = files(&fixture());
        let reserved = sequence(fragment_of(&generated, "routes.yaml"))[5].clone();
        assert!(!verify::redirects(&reserved));
        let mut found = reserved.clone();
        found["direct_response"]["status"] = json!(302);
        assert!(verify::redirects(&found));
        let mut found = reserved.clone();
        found["redirect"] = json!({"path_redirect": "/x"});
        assert!(verify::redirects(&found));
        let guarded = sequence(fragment_of(&generated, "routes.yaml"))[6].clone();
        assert!(!verify::redirects(&guarded));
        let mut found = guarded;
        found["route"]["internal_redirect_policy"] = json!({"max_internal_redirects": 1});
        assert!(verify::redirects(&found));
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
        assert!(
            filters.contains("string.gmatch(cookie, \"[^;,]+\")"),
            "repeated cookie fields joined with a comma are split too"
        );
    }

    /// A Lua interpreter on the host, if any: the strip uses only patterns
    /// that read the same in Lua 5.1, LuaJIT and later versions.
    fn lua() -> Option<std::path::PathBuf> {
        ["luajit", "lua5.1", "lua"].iter().find_map(|name| {
            let found = std::process::Command::new(name).arg("-v").output().ok()?;
            found
                .status
                .success()
                .then(|| std::path::PathBuf::from(name))
        })
    }

    #[test]
    fn the_cookie_strip_removes_the_services_cookies_when_run() {
        let Some(lua) = lua() else {
            println!("skipped: no Lua interpreter (luajit, lua5.1 or lua) on this host");
            return;
        };
        let cases = [
            ("a=1; __Host-registry-session=T; b=2", Some("a=1; b=2")),
            ("__Host-registry-session=T", None),
            ("a=1,__Host-registry-session=T", Some("a=1")),
            ("a=1, registry-signin=F,b=2", Some("a=1; b=2")),
            ("  __Host-registry-signin=F ;c=3  ", Some("c=3")),
            (
                "__Host-registry-session2=x",
                Some("__Host-registry-session2=x"),
            ),
            (
                "x__Host-registry-session=T",
                Some("x__Host-registry-session=T"),
            ),
            (";;  ;", None),
        ];
        let mut script = lua_source();
        script.push_str(LUA_BODY_DRIVER);
        for (index, (input, _)) in cases.iter().enumerate() {
            script.push_str(&format!("run({index}, {})\n", quoted(input)));
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("strip.lua");
        fs::write(&path, script).expect("script");
        let output = std::process::Command::new(lua)
            .arg(&path)
            .output()
            .expect("run lua");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let printed = String::from_utf8(output.stdout).expect("utf-8");
        let lines: Vec<&str> = printed.lines().collect();
        assert_eq!(lines.len(), cases.len(), "{printed}");
        for ((input, want), line) in cases.iter().zip(lines) {
            let want = want.map_or_else(|| "removed".to_owned(), |kept| format!("kept {kept}"));
            assert_eq!(
                line.split_once(' ').map(|(_, rest)| rest),
                Some(want.as_str()),
                "{input}"
            );
        }
    }

    /// Runs the strip over one header value with a stand-in for Envoy's
    /// handle, printing what the upstream would receive.
    const LUA_BODY_DRIVER: &str = r#"
function run(index, value)
  local stored = value
  local removed = false
  local headers = {
    get = function(_, _) return stored end,
    remove = function(_, _) removed = true end,
    replace = function(_, _, kept) stored = kept end,
  }
  envoy_on_request({ headers = function(_) return headers end })
  if removed then
    print(index .. " removed")
  else
    print(index .. " kept " .. stored)
  end
end
"#;

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
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory
            .path()
            .canonicalize()
            .expect("canonical directory")
            .join("runtime.yaml");
        fs::write(&path, &text).expect("runtime file");
        let found = crate::config::check_runtime(&path, true).diagnostics;
        assert!(
            found
                .iter()
                .any(|diagnostic| diagnostic.path == "/gateway/authority"
                    && diagnostic.message.contains("lower-case")),
            "{found:?}"
        );
    }

    pub(super) fn sequence(value: Value) -> Vec<Value> {
        match value {
            Value::Array(items) => items,
            other => panic!("expected a sequence, got {other:?}"),
        }
    }

    pub(super) fn fragment_of(files: &[GeneratedFile], name: &str) -> Value {
        parse_fragment(
            files
                .iter()
                .find(|file| file.name == name)
                .unwrap_or_else(|| panic!("{name} is generated")),
        )
        .expect("the fragment parses")
    }
}
