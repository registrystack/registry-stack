// SPDX-License-Identifier: Apache-2.0

//! The gateway's part of the session service, generated from the runtime file.
//!
//! The gateway asks the service, on each call to a signed-in route, which
//! bearer token to attach. Which routes run that check, their order, the cookie
//! strip, and the cross-site defence must match the service's own route table,
//! so the Envoy fragments are written from the same file and never by hand.
//! The output is deterministic: a stable order and no timestamps.

use std::{fmt, fs, io, path::Path};

use registry_platform_yaml::Reader;

use crate::{
    check::CHECK_PREFIX,
    config::{
        RuntimeConfig, RuntimeConfigError, UpstreamConfig, DEVELOPMENT_FLOW_COOKIE,
        DEVELOPMENT_SESSION_COOKIE, FLOW_COOKIE, SESSION_COOKIE, SESSION_PREFIX,
    },
    wire::{ANSWER_MARKER_HEADER, ANSWER_MARKER_VALUE},
};

/// Why the fragments were not written or did not match.
#[derive(Debug)]
pub enum GatewayError {
    /// The runtime file was refused or could not be read.
    Config(RuntimeConfigError),
    /// The runtime file has no `gateway` block.
    NoGatewayBlock,
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

/// The request headers the gateway forwards to the check.
pub const CHECK_REQUEST_HEADERS: [&str; 4] =
    ["cookie", "origin", "sec-fetch-site", "registry-client"];

/// The check's answer headers the gateway passes on to the browser.
pub const CHECK_CLIENT_HEADERS: [&str; 3] = ["content-type", "cache-control", "location"];

/// The header the check's allow answer fills in with the bearer token.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// The clusters that reach the service's two listeners.
const PUBLIC_CLUSTER: &str = "registry-session-public";
const CHECK_CLUSTER: &str = "registry-session-check";

/// The names of the filters the service adds to the host's chain. Every
/// per-route switch is keyed by these names, never by a filter's type name: a
/// host chain may hold several filters of one type.
const CSRF_FILTER: &str = "registry-session.csrf";
const CHECK_FILTER: &str = "registry-session.check";
const STRIP_FILTER: &str = "registry-session.strip-cookies";

/// The base of the problem type of the service's own answers.
const PROBLEM_TYPE_BASE: &str = "https://id.registrystack.org/problems/registry-platform/session";

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
    Ok(vec![
        GeneratedFile {
            name: "http-filters.yaml",
            content: http_filters(gateway.check_timeout_milliseconds.get()),
        },
        GeneratedFile {
            name: "routes.yaml",
            content: routes(config, &authority),
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

/// Load the runtime file and write or compare its fragments. No secret is
/// read: the file's secret references are checked by syntax only.
pub fn run_envoy(runtime_config: &Path, mode: Mode<'_>) -> Result<(), GatewayError> {
    let config = RuntimeConfig::load(runtime_config).map_err(GatewayError::Config)?;
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

fn lua_source() -> String {
    let cookies = own_cookies()
        .iter()
        .map(|name| format!("  [{}] = true,\n", quoted(name)))
        .collect::<String>();
    format!(
        "local own_cookies = {{\n{cookies}}}\n\
         \n\
         -- Removes the service's own cookies from the request and keeps the rest.\n\
         function envoy_on_request(handle)\n\
         \x20 local headers = handle:headers()\n\
         \x20 local cookie = headers:get(\"cookie\")\n\
         \x20 if cookie == nil then\n\
         \x20   return\n\
         \x20 end\n\
         \x20 local kept = {{}}\n\
         \x20 for pair in string.gmatch(cookie, \"[^;]+\") do\n\
         \x20   local trimmed = string.match(pair, \"^%s*(.-)%s*$\")\n\
         \x20   local name = string.match(trimmed, \"^[^=]*\")\n\
         \x20   if trimmed ~= \"\" and not own_cookies[name] then\n\
         \x20     table.insert(kept, trimmed)\n\
         \x20   end\n\
         \x20 end\n\
         \x20 if #kept == 0 then\n\
         \x20   headers:remove(\"cookie\")\n\
         \x20 else\n\
         \x20   headers:replace(\"cookie\", table.concat(kept, \"; \"))\n\
         \x20 end\n\
         end\n"
    )
}

fn http_filters(check_timeout_milliseconds: u64) -> String {
    let mut out = header("HTTP filters, to splice into the host's chain before its router");
    out.push_str(&format!(
        "- name: {CSRF_FILTER}\n\
         \x20 disabled: true\n\
         \x20 typed_config:\n\
         \x20   \"@type\": type.googleapis.com/envoy.extensions.filters.http.csrf.v3.CsrfPolicy\n\
         \x20   filter_enabled:\n\
         \x20     default_value:\n\
         \x20       numerator: 100\n\
         \x20       denominator: HUNDRED\n\
         - name: {CHECK_FILTER}\n\
         \x20 disabled: true\n\
         \x20 typed_config:\n\
         \x20   \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz\n\
         \x20   failure_mode_allow: false\n\
         \x20   status_on_error:\n\
         \x20     code: ServiceUnavailable\n\
         \x20   http_service:\n\
         \x20     server_uri:\n\
         \x20       uri: http://{CHECK_CLUSTER}\n\
         \x20       cluster: {CHECK_CLUSTER}\n\
         \x20       timeout: {timeout}\n\
         \x20     path_prefix: {CHECK_PREFIX}\n\
         \x20     authorization_response:\n\
         \x20       allowed_upstream_headers:\n\
         \x20         patterns:\n\
         \x20           - exact: {AUTHORIZATION_HEADER}\n\
         \x20       allowed_client_headers:\n\
         \x20         patterns:\n",
        timeout = duration_milliseconds(check_timeout_milliseconds),
    ));
    for name in CHECK_CLIENT_HEADERS
        .iter()
        .copied()
        .chain([ANSWER_MARKER_HEADER])
    {
        out.push_str(&format!("            - exact: {name}\n"));
    }
    out.push_str("    allowed_headers:\n      patterns:\n");
    for name in CHECK_REQUEST_HEADERS {
        out.push_str(&format!("        - exact: {name}\n"));
    }
    out.push_str(&format!(
        "- name: {STRIP_FILTER}\n\
         \x20 typed_config:\n\
         \x20   \"@type\": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua\n\
         \x20   default_source_code:\n\
         \x20     inline_string: |\n"
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
/// prefix first across modules and pages, equal lengths by prefix.
fn guarded_routes(config: &RuntimeConfig) -> Vec<GuardedRoute<'_>> {
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
    routes
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
         \x20       key: {key}\n\
         \x20       value: {value}\n\
         \x20     append_action: OVERWRITE_IF_EXISTS_OR_ADD\n"
    ));
}

fn marker_removal_lines(out: &mut String) {
    out.push_str(&format!(
        "  response_headers_to_remove:\n    - {ANSWER_MARKER_HEADER}\n"
    ));
}

fn switch_off(out: &mut String, filter: &str) {
    out.push_str(&format!(
        "    {filter}:\n      \"@type\": {FILTER_CONFIG_TYPE}\n      disabled: true\n"
    ));
}

fn csrf_on(out: &mut String) {
    out.push_str(&format!(
        "    {CSRF_FILTER}:\n\
         \x20     \"@type\": type.googleapis.com/envoy.extensions.filters.http.csrf.v3.CsrfPolicy\n\
         \x20     filter_enabled:\n\
         \x20       default_value:\n\
         \x20         numerator: 100\n\
         \x20         denominator: HUNDRED\n"
    ));
}

fn check_on(out: &mut String) {
    out.push_str(&format!(
        "    {CHECK_FILTER}:\n\
         \x20     \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute\n\
         \x20     check_settings: {{}}\n"
    ));
}

fn strip_off(out: &mut String) {
    out.push_str(&format!(
        "    {STRIP_FILTER}:\n\
         \x20     \"@type\": type.googleapis.com/envoy.extensions.filters.http.lua.v3.LuaPerRoute\n\
         \x20     disabled: true\n"
    ));
}

fn routes(config: &RuntimeConfig, authority: &str) -> String {
    let host_filters: Vec<&str> = config
        .gateway
        .iter()
        .flat_map(|gateway| gateway.host_filters.iter())
        .map(|filter| filter.as_str())
        .collect();
    let mut out = header("routes, to splice into the host's virtual host before its own routes");
    for path in PUBLIC_PATHS {
        let name = path.trim_start_matches(SESSION_PREFIX);
        out.push_str(&format!("- name: registry-session.{name}\n"));
        match_lines(&mut out, &format!("path: {}", quoted(path)), authority);
        out.push_str(&format!("  route:\n    cluster: {PUBLIC_CLUSTER}\n"));
        response_header_lines(&mut out, "cache-control", "no-store");
        out.push_str("  typed_per_filter_config:\n");
        csrf_on(&mut out);
        strip_off(&mut out);
        for filter in &host_filters {
            switch_off(&mut out, filter);
        }
    }
    out.push_str("- name: registry-session.reserved\n");
    match_lines(
        &mut out,
        &format!("prefix: {}", quoted(SESSION_PREFIX)),
        authority,
    );
    out.push_str("  direct_response:\n    status: 404\n");
    marker_removal_lines(&mut out);
    for route in guarded_routes(config) {
        out.push_str(&format!("- name: {}\n", route.name));
        match_lines(
            &mut out,
            &format!("prefix: {}", quoted(route.prefix)),
            authority,
        );
        out.push_str(&format!(
            "  route:\n    cluster: {}\n",
            route.upstream.cluster.as_str()
        ));
        if let Some(rewrite) = &route.upstream.prefix_rewrite {
            out.push_str(&format!(
                "    prefix_rewrite: {}\n",
                quoted(rewrite.as_str())
            ));
        }
        out.push_str(&format!(
            "    timeout: {}s\n  request_headers_to_remove:\n    - cookie\n",
            route.upstream.timeout_seconds.get()
        ));
        if route.page {
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
         \x20                 port_value: {port}\n"
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
    let mut out = header(
        "local reply configuration, to splice into the host's HTTP connection manager: the \
         answer when the check itself fails",
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
         \x20           key: {ANSWER_MARKER_HEADER}\n\
         \x20           value: {}\n\
         \x20         append_action: OVERWRITE_IF_EXISTS_OR_ADD\n\
         \x20       - header:\n\
         \x20           key: cache-control\n\
         \x20           value: no-store\n\
         \x20         append_action: OVERWRITE_IF_EXISTS_OR_ADD\n\
         \x20     body_format_override:\n\
         \x20       json_format:\n\
         \x20         type: {}\n\
         \x20         title: Session service unavailable\n\
         \x20         status: 503\n\
         \x20         code: session.unavailable\n\
         \x20       content_type: application/problem+json\n",
        quoted(ANSWER_MARKER_VALUE),
        quoted(&format!("{PROBLEM_TYPE_BASE}/unavailable")),
    ));
    out
}

/// The most bytes of an assembled configuration `--verify-assembled` reads.
const MAXIMUM_ASSEMBLED_BYTES: u64 = 16 * 1024 * 1024;

/// Check an assembled Envoy configuration offline: every route of every
/// virtual host removes the answer marker except the public session routes,
/// which must not, no route redirects, and the check filter and the local
/// reply mapper are present.
pub fn verify_assembled(path: &Path) -> Result<(), GatewayError> {
    let metadata = fs::metadata(path).map_err(|error| io_error(path, &error))?;
    if metadata.len() > MAXIMUM_ASSEMBLED_BYTES {
        return Err(GatewayError::Assembled(vec![
            "the assembled configuration is larger than 16 MiB".to_owned(),
        ]));
    }
    let bytes = fs::read(path).map_err(|error| io_error(path, &error))?;
    let document = Reader::new(path.display().to_string())
        .scan(&bytes)
        .map_err(|report| GatewayError::Assembled(vec![report.render_human()]))?
        .ok_or_else(|| {
            GatewayError::Assembled(vec!["the assembled configuration is empty".to_owned()])
        })?
        .to_json_value();
    let mut findings = Vec::new();
    let mut walk = Assembled::default();
    walk.visit(&document);
    if !walk.check_filter {
        findings.push(format!("the {CHECK_FILTER} filter is missing"));
    }
    if !walk.local_reply {
        findings.push(
            "the local reply mapper for a failed check (status 503 and response flag UAEX, \
             adding the answer marker) is missing"
                .to_owned(),
        );
    }
    findings.extend(walk.findings);
    if findings.is_empty() {
        Ok(())
    } else {
        Err(GatewayError::Assembled(findings))
    }
}

#[derive(Default)]
struct Assembled {
    check_filter: bool,
    local_reply: bool,
    findings: Vec<String>,
}

fn names_marker(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(serde_json::Value::as_array)
        .is_some_and(|names| {
            names.iter().any(|name| {
                name.as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case(ANSWER_MARKER_HEADER))
            })
        })
}

fn text<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

impl Assembled {
    fn visit(&mut self, value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                if text(value, "name") == Some(CHECK_FILTER) && value.get("typed_config").is_some()
                {
                    self.check_filter = true;
                }
                if let Some(config) = map.get("local_reply_config") {
                    self.local_reply |= has_check_failure_mapper(config);
                }
                if let Some(hosts) = map.get("virtual_hosts").and_then(|hosts| hosts.as_array()) {
                    self.route_configuration(value, hosts);
                }
                for child in map.values() {
                    self.visit(child);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    self.visit(item);
                }
            }
            _ => {}
        }
    }

    fn route_configuration(
        &mut self,
        configuration: &serde_json::Value,
        hosts: &[serde_json::Value],
    ) {
        let configuration_removes = names_marker(configuration.get("response_headers_to_remove"));
        let configuration_name = text(configuration, "name").unwrap_or("(unnamed)");
        for (host_index, host) in hosts.iter().enumerate() {
            let host_name =
                text(host, "name").map_or_else(|| format!("#{host_index}"), str::to_owned);
            let host_removes = names_marker(host.get("response_headers_to_remove"));
            let routes = host
                .get("routes")
                .and_then(serde_json::Value::as_array)
                .map_or(&[][..], Vec::as_slice);
            for (route_index, route) in routes.iter().enumerate() {
                let route_name =
                    text(route, "name").map_or_else(|| format!("#{route_index}"), str::to_owned);
                let place = format!(
                    "route {route_name} of virtual host {host_name} in {configuration_name}"
                );
                let removes = configuration_removes
                    || host_removes
                    || names_marker(route.get("response_headers_to_remove"));
                let public = route
                    .get("match")
                    .and_then(|matcher| text(matcher, "path"))
                    .is_some_and(|path| PUBLIC_PATHS.contains(&path));
                if public && removes {
                    self.findings.push(format!(
                        "{place} is a public session route and removes the answer marker"
                    ));
                } else if !public && !removes {
                    self.findings.push(format!(
                        "{place} does not remove the answer marker from its answers"
                    ));
                }
                if redirects(route) {
                    self.findings.push(format!("{place} redirects"));
                }
            }
        }
    }
}

/// Whether a route redirects: a `redirect` action, an internal redirect
/// policy, or a direct reply with a 3xx status.
fn redirects(route: &serde_json::Value) -> bool {
    route.get("redirect").is_some()
        || route
            .get("route")
            .is_some_and(|action| action.get("internal_redirect_policy").is_some())
        || route
            .get("direct_response")
            .and_then(|reply| reply.get("status"))
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|status| (300..400).contains(&status))
}

/// Whether the local reply configuration has a mapper that matches status 503
/// and the `UAEX` flag together and adds the answer marker.
fn has_check_failure_mapper(config: &serde_json::Value) -> bool {
    let Some(mappers) = config.get("mappers").and_then(serde_json::Value::as_array) else {
        return false;
    };
    mappers.iter().any(|mapper| {
        let filters = mapper
            .get("filter")
            .and_then(|filter| filter.get("and_filter"))
            .and_then(|and| and.get("filters"))
            .and_then(serde_json::Value::as_array);
        let Some(filters) = filters else {
            return false;
        };
        let status_503 = filters.iter().any(|filter| {
            filter
                .get("status_code_filter")
                .and_then(|status| status.get("comparison"))
                .is_some_and(|comparison| {
                    text(comparison, "op") == Some("EQ")
                        && comparison
                            .get("value")
                            .and_then(|value| value.get("default_value"))
                            .and_then(serde_json::Value::as_u64)
                            == Some(503)
                })
        });
        let flag = filters.iter().any(|filter| {
            filter
                .get("response_flag_filter")
                .and_then(|flags| flags.get("flags"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UAEX")))
        });
        let marker = mapper
            .get("headers_to_add")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|headers| {
                headers.iter().any(|entry| {
                    entry
                        .get("header")
                        .is_some_and(|header| text(header, "key") == Some(ANSWER_MARKER_HEADER))
                })
            });
        status_503 && flag && marker
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

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
            if block.contains("registry-session.check:") {
                guarded += 1;
                assert!(
                    block.contains("request_headers_to_remove:\n    - cookie\n"),
                    "{block}"
                );
                assert!(block.contains("registry-session.csrf:"), "{block}");
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
                block.contains("cluster: registry-session-public"),
                "{block}"
            );
            assert!(block.contains("registry-session.strip-cookies:"), "{block}");
            assert!(block.contains("disabled: true"), "{block}");
            assert!(block.contains("registry-session.csrf:"), "{block}");
            assert!(!block.contains("registry-session.check:"), "{block}");
            assert!(block.contains("value: no-store"), "{block}");
            for filter in [
                "envoy.filters.http.cors:",
                "envoy.filters.http.basic_auth:",
                "envoy.filters.http.rbac:",
            ] {
                assert!(block.contains(filter), "{filter} is switched off: {block}");
            }
        }
        let reserved = blocks[5];
        assert!(reserved.contains("prefix: \"/session/\""), "{reserved}");
        assert!(reserved.contains("status: 404"), "{reserved}");
        assert!(!reserved.contains("cluster:"), "{reserved}");
    }

    #[test]
    fn host_filters_go_off_except_where_an_upstream_keeps_one() {
        let generated = files(&fixture());
        let blocks = route_blocks(file(&generated, "routes.yaml"));
        let data = blocks
            .iter()
            .find(|block| block.starts_with("- name: module-data\n"))
            .expect("the data route");
        assert!(data.contains("envoy.filters.http.cors:"));
        assert!(data.contains("envoy.filters.http.basic_auth:"));
        assert!(!data.contains("envoy.filters.http.rbac:"), "{data}");
        let registry = blocks
            .iter()
            .find(|block| block.starts_with("- name: module-registry\n"))
            .expect("the registry route");
        assert!(registry.contains("envoy.filters.http.rbac:"));
        assert!(registry.contains("prefix_rewrite: \"/\""));
        assert!(registry.contains("timeout: 30s"));
        let pages = blocks
            .iter()
            .find(|block| block.starts_with("- name: page-apply\n"))
            .expect("the page route");
        assert!(pages.contains("value: no-cache"), "{pages}");
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
                "registry-session.csrf",
                "registry-session.check",
                "registry-session.strip-cookies"
            ]
        );
        assert!(filters.contains("path_prefix: /check"));
        assert!(filters.contains("failure_mode_allow: false"));
        assert!(filters.contains("timeout: 3s"));
        for header in ["cookie", "origin", "sec-fetch-site", "registry-client"] {
            assert!(
                filters.contains(&format!("- exact: {header}\n")),
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
        assert!(client.contains("- exact: registry-session-answer"));
        for header in ["content-type", "cache-control", "location"] {
            assert!(client.contains(&format!("- exact: {header}")), "{header}");
        }
        assert!(!upstream.contains("registry-session-answer"));
        assert!(upstream.contains("- exact: authorization"));
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
        assert!(reply.contains("key: registry-session-answer"));
        assert!(reply.contains("value: \"1\""));
        assert!(reply.contains("content_type: application/problem+json"));
        assert!(reply.contains("code: session.unavailable"));
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
                block.contains("response_headers_to_remove:\n    - registry-session-answer\n");
            assert_eq!(removes, index >= 5, "{block}");
        }
    }

    #[test]
    fn clusters_reach_both_listeners() {
        let generated = files(&fixture());
        let clusters = file(&generated, "clusters.yaml");
        assert!(clusters.contains("- name: registry-session-public"));
        assert!(clusters.contains("- name: registry-session-check"));
        assert_eq!(clusters.matches("type: STRICT_DNS").count(), 2);
        assert_eq!(clusters.matches("connect_timeout: 1s").count(), 2);
        assert!(clusters.contains("port_value: 8120"));
        assert!(clusters.contains("port_value: 8121"));
        assert_eq!(clusters.matches("address: registry-session\n").count(), 2);
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

    #[test]
    fn the_output_holds_no_secret() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let secrets = root.join("secrets");
        fs::create_dir(&secrets).expect("secrets directory");
        let sentinels = [
            ("citizen-secret", "SENTINEL-CITIZEN-CLIENT-SECRET"),
            ("staff-secret", "SENTINEL-STAFF-CLIENT-SECRET"),
        ];
        for (name, value) in sentinels {
            fs::write(secrets.join(name), value).expect("secret file");
        }
        let text = FIXTURE.replacen(
            "root: /run/secrets",
            &format!("root: {}", secrets.display()),
            1,
        );
        let runtime = root.join("runtime.yaml");
        fs::write(&runtime, text).expect("runtime file");
        let out = root.join("out");
        run_envoy(&runtime, Mode::Write(&out)).expect("files are written");
        for entry in fs::read_dir(&out).expect("output directory") {
            let content = fs::read_to_string(entry.expect("entry").path()).expect("file");
            for (name, value) in sentinels {
                assert!(!content.contains(value), "a secret value is in the output");
                assert!(
                    !content.contains(name),
                    "a secret reference is in the output"
                );
            }
        }
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

    /// A small assembled configuration: one host route, the five public
    /// session routes, the check filter, and the local reply mapper, each
    /// switched by a flag.
    struct Assembled {
        host_route_removes: bool,
        public_route_removes: bool,
        check_filter: bool,
        local_reply: bool,
        mapper_flag_only: bool,
        redirect: bool,
    }

    impl Assembled {
        fn complete() -> Self {
            Self {
                host_route_removes: true,
                public_route_removes: false,
                check_filter: true,
                local_reply: true,
                mapper_flag_only: false,
                redirect: false,
            }
        }

        fn yaml(&self) -> String {
            let removal =
                "          response_headers_to_remove:\n            - registry-session-answer\n";
            let mut out = String::from(
                "static_resources:\n  listeners:\n    - name: main\n      filter_chains:\n        - filters:\n            - name: envoy.filters.network.http_connection_manager\n              typed_config:\n                http_filters:\n",
            );
            if self.check_filter {
                out.push_str("                  - name: registry-session.check\n                    typed_config: {}\n");
            }
            out.push_str("                  - name: envoy.filters.http.router\n");
            if self.local_reply {
                let and = if self.mapper_flag_only {
                    ""
                } else {
                    "                          - status_code_filter:\n                              comparison:\n                                op: EQ\n                                value:\n                                  default_value: 503\n                                  runtime_key: k\n"
                };
                out.push_str(&format!(
                    "                local_reply_config:\n                  mappers:\n                    - filter:\n                        and_filter:\n                          filters:\n{and}                          - response_flag_filter:\n                              flags: [UAEX]\n                      headers_to_add:\n                        - header:\n                            key: registry-session-answer\n                            value: \"1\"\n"
                ));
            }
            out.push_str("                route_config:\n                  name: local\n                  virtual_hosts:\n                    - name: app\n                      domains: [\"*\"]\n                      routes:\n");
            for path in PUBLIC_PATHS {
                out.push_str(&format!(
                    "                        - name: public{path}\n                          match: {{ path: \"{path}\" }}\n                          route: {{ cluster: registry-session-public }}\n"
                ));
                if self.public_route_removes {
                    out.push_str(&removal.replace("          ", "                          "));
                }
            }
            out.push_str("                        - name: host-api\n                          match: { prefix: \"/rest/\" }\n");
            if self.redirect {
                out.push_str("                          redirect: { path_redirect: /elsewhere }\n");
            } else {
                out.push_str("                          route: { cluster: api }\n");
            }
            if self.host_route_removes {
                out.push_str(&removal.replace("          ", "                          "));
            }
            out
        }
    }

    fn verified(assembled: &Assembled) -> Result<(), GatewayError> {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("envoy.yaml");
        fs::write(&path, assembled.yaml()).expect("assembled file");
        verify_assembled(&path)
    }

    fn findings(assembled: &Assembled) -> Vec<String> {
        match verified(assembled) {
            Err(GatewayError::Assembled(findings)) => findings,
            other => panic!("expected findings, got {other:?}"),
        }
    }

    #[test]
    fn a_complete_assembled_configuration_passes() {
        verified(&Assembled::complete()).expect("passes");
    }

    #[test]
    fn a_host_route_without_the_removal_fails_naming_it() {
        let found = findings(&Assembled {
            host_route_removes: false,
            ..Assembled::complete()
        });
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("host-api"), "{found:?}");
    }

    #[test]
    fn a_public_session_route_with_the_removal_fails() {
        let found = findings(&Assembled {
            public_route_removes: true,
            ..Assembled::complete()
        });
        assert_eq!(found.len(), 5, "{found:?}");
        assert!(found
            .iter()
            .all(|finding| finding.contains("public session route")));
    }

    #[test]
    fn a_missing_check_filter_or_local_reply_fails() {
        let found = findings(&Assembled {
            check_filter: false,
            ..Assembled::complete()
        });
        assert!(found
            .iter()
            .any(|finding| finding.contains("registry-session.check")));
        let found = findings(&Assembled {
            local_reply: false,
            ..Assembled::complete()
        });
        assert!(found.iter().any(|finding| finding.contains("local reply")));
    }

    #[test]
    fn a_local_reply_that_matches_the_flag_alone_fails() {
        let found = findings(&Assembled {
            mapper_flag_only: true,
            ..Assembled::complete()
        });
        assert!(found.iter().any(|finding| finding.contains("local reply")));
    }

    #[test]
    fn a_redirecting_route_fails() {
        let found = findings(&Assembled {
            redirect: true,
            ..Assembled::complete()
        });
        assert!(found
            .iter()
            .any(|finding| finding.contains("host-api") && finding.contains("redirects")));
    }

    #[test]
    fn a_removal_higher_up_strips_the_public_routes_and_fails() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("envoy.yaml");
        let text = Assembled::complete().yaml().replace(
            "                  name: local\n",
            "                  name: local\n                  response_headers_to_remove: [registry-session-answer]\n",
        );
        fs::write(&path, text).expect("assembled file");
        let Err(GatewayError::Assembled(found)) = verify_assembled(&path) else {
            panic!("expected findings");
        };
        assert_eq!(found.len(), 5, "{found:?}");
    }

    #[test]
    fn the_generated_fragments_assemble_into_a_passing_configuration() {
        let generated = files(&fixture());
        let indent = |text: &str, by: usize| {
            text.lines()
                .filter(|line| !line.starts_with('#'))
                .map(|line| format!("{}{line}\n", " ".repeat(by)))
                .collect::<String>()
        };
        let host_route = "- name: host-api\n  match:\n    prefix: /rest/\n  route:\n    cluster: api\n  response_headers_to_remove:\n    - registry-session-answer\n";
        let assembled = format!(
            "static_resources:\n  listeners:\n    - name: main\n      filter_chains:\n        - filters:\n            - name: envoy.filters.network.http_connection_manager\n              typed_config:\n{}                http_filters:\n{}                route_config:\n                  name: local\n                  virtual_hosts:\n                    - name: app\n                      domains: [\"*\"]\n                      routes:\n{}{}",
            indent(file(&generated, "local-reply.yaml"), 16),
            indent(file(&generated, "http-filters.yaml"), 18),
            indent(file(&generated, "routes.yaml"), 24),
            indent(host_route, 24),
        );
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("envoy.yaml");
        fs::write(&path, assembled).expect("assembled file");
        verify_assembled(&path).expect("the generated fragments assemble into a passing file");
    }
}
