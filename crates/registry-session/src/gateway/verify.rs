// SPDX-License-Identifier: Apache-2.0

//! `gateway envoy --verify-assembled`: an assembled Envoy configuration checked
//! against what the runtime file generates.
//!
//! The check is an allow-list. It passes only a file it can read exactly as
//! Envoy reads it and whose every path to a request for the public authority
//! it can see: static resources, connection managers with inline routes, the
//! generated routes first in a virtual host of their own. Anything else is
//! refused with a finding that names the member and says why. It does not try
//! to model the rest of Envoy.

use std::{fs, path::Path};

use registry_platform_yaml::{Reader, Refusal, ScalarHook, ScalarSite, ScalarStyle};
use serde_json::Value;

use super::*;

/// The most bytes of an assembled configuration `--verify-assembled` reads.
const MAXIMUM_ASSEMBLED_BYTES: u64 = 16 * 1024 * 1024;

const MANAGER_TYPE: &str =
    "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const ROUTER_TYPE: &str = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router";

/// Members whose contents are free text to Envoy, so their keys may take any
/// case: metadata, a JSON body format and runtime values.
const FREE_FORM: [&str; 5] = [
    "metadata",
    "filter_metadata",
    "typed_filter_metadata",
    "json_format",
    "static_layer",
];

/// Members whose own keys are names (of filters or extensions) and whose
/// values are configuration again.
const NAMED: [&str; 2] = [
    "typed_per_filter_config",
    "typed_extension_protocol_options",
];

/// The plain words YAML 1.1 reads as booleans. Envoy's YAML reader does; the
/// platform reader, which follows YAML 1.2, reads them as text.
const YAML_1_1_BOOLEANS: [&str; 6] = ["y", "n", "yes", "no", "on", "off"];

/// Refuses, while the file is read, what Envoy and this check would read
/// differently: a field spelled other than in snake_case, which Envoy also
/// accepts as lowerCamelCase, and a YAML 1.1 boolean.
struct EnvoyReading;

impl ScalarHook for EnvoyReading {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        let Some((_, ancestors)) = site.keys.split_last() else {
            return Ok(());
        };
        let free = ancestors.iter().any(|key| FREE_FORM.contains(key))
            || ancestors.last().is_some_and(|key| NAMED.contains(key));
        if free || !site.text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Ok(());
        }
        Err(Refusal {
            code: "gateway.assembled.field-name".to_owned(),
            message: "this key holds an upper-case letter: Envoy also reads a field by its \
                      lowerCamelCase name, and this check reads only snake_case names"
                .to_owned(),
            suggested_action: "Write the field's snake_case name.".to_owned(),
        })
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        if site.style == ScalarStyle::Plain
            && YAML_1_1_BOOLEANS
                .iter()
                .any(|word| site.text.eq_ignore_ascii_case(word))
        {
            return Err(Refusal {
                code: "gateway.assembled.yaml-1-1-boolean".to_owned(),
                message: "a plain y, n, yes, no, on or off is a boolean to Envoy's YAML reader \
                          and text to this check: write true or false, or quote the word"
                    .to_owned(),
                suggested_action: "Write true or false, or quote the word if it is text."
                    .to_owned(),
            });
        }
        Ok(None)
    }
}

/// What the runtime file generates, parsed, for comparison with an assembled
/// configuration.
struct Expected {
    authority: String,
    /// The service's three filters, in chain order.
    filters: Vec<Value>,
    /// Every generated route in order. The first [`PUBLIC_PATHS`] entries are
    /// the service's public routes.
    routes: Vec<Value>,
    /// The generated local reply mappers, which come first and in order.
    mappers: Vec<Value>,
    /// The host's own filters the generated routes switch off.
    host_filters: Vec<String>,
    /// The host filters some generated route keeps on.
    kept: Vec<String>,
    /// The path prefixes the generated routes serve, `/session/` included.
    prefixes: Vec<String>,
    /// The clusters only generated routes may reach: every module and page
    /// upstream and the service's own two.
    protected: Vec<String>,
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
        let mappers = fragment("local-reply.yaml")?
            .pointer("/local_reply_config/mappers")
            .cloned()
            .map(items)
            .filter(|mappers| !mappers.is_empty())
            .ok_or_else(|| {
                GatewayError::Refused(vec!["local-reply.yaml has no mapper".to_owned()])
            })?;
        let upstreams = config
            .modules
            .iter()
            .map(|module| (module.prefix.as_str(), module.upstream.as_ref()))
            .chain(
                config
                    .pages
                    .iter()
                    .map(|page| (page.prefix.as_str(), page.upstream.as_ref())),
            );
        let mut kept = Vec::new();
        let mut prefixes = vec![SESSION_PREFIX.to_owned()];
        let mut protected = vec![PUBLIC_CLUSTER.to_owned(), CHECK_CLUSTER.to_owned()];
        for (prefix, upstream) in upstreams {
            prefixes.push(prefix.to_owned());
            if let Some(upstream) = upstream {
                protected.push(upstream.cluster.as_str().to_owned());
                kept.extend(
                    upstream
                        .keep_host_filters
                        .iter()
                        .map(|name| name.as_str().to_owned()),
                );
            }
        }
        Ok(Self {
            authority: config
                .gateway_authority()
                .ok_or(GatewayError::NoGatewayBlock)?,
            filters: items(fragment("http-filters.yaml")?),
            routes: items(fragment("routes.yaml")?),
            mappers,
            host_filters: config
                .gateway
                .iter()
                .flat_map(|gateway| gateway.host_filters.iter())
                .map(|name| name.as_str().to_owned())
                .collect(),
            kept,
            prefixes,
            protected,
        })
    }

    fn public_routes(&self) -> &[Value] {
        &self.routes[..PUBLIC_PATHS.len().min(self.routes.len())]
    }
}

/// Check an assembled Envoy configuration offline against what the runtime
/// file generates now.
///
/// The file is read as Envoy reads it or refused. Listeners, routes and
/// filters must be written inline. Every connection manager that could serve
/// the public authority holds the service's three filters, as generated, at
/// the head of its chain, lists every host filter in `gateway.hostFilters`,
/// takes the generated mapper first, and serves the generated routes, as
/// generated and in order, first in a virtual host whose only domain is the
/// authority. No other route reaches a module, page or service cluster or
/// configures the service's filters, every other route removes the answer
/// marker, nothing adds it, and nothing in the file redirects.
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
    let mut reading = EnvoyReading;
    let document = Reader::new(assembled.display().to_string())
        .with_hook(&mut reading)
        .scan(&bytes)
        .map_err(|report| GatewayError::Assembled(vec![report.render_human()]))?
        .ok_or_else(|| {
            GatewayError::Assembled(vec!["the assembled configuration is empty".to_owned()])
        })?
        .to_json_value();
    let mut findings = Vec::new();
    unseen_members(&document, &mut findings);
    if let Some(dynamic) = document.get("dynamic_resources") {
        for member in ["lds_config", "ads_config"] {
            if dynamic.get(member).is_some() {
                findings.push(format!(
                    "dynamic_resources has {member}, which delivers listeners or routes this \
                     check cannot see: write them under static_resources"
                ));
            }
        }
    }
    runtime_layers(&document, &mut findings);
    let managers = listener_managers(&document, &mut findings);
    stray_managers(&document, &managers, &mut findings);
    let mut served = false;
    for (place, manager) in &managers {
        if !can_serve(manager, &expected.authority) {
            continue;
        }
        served = true;
        let mut found = Vec::new();
        verify_manager(&expected, manager, &mut found);
        findings.extend(
            found
                .into_iter()
                .map(|finding| format!("{place}: {finding}")),
        );
    }
    if !served {
        findings.push(format!(
            "no HTTP connection manager serves the authority {}",
            quoted(&expected.authority)
        ));
    }
    redirects_in(&document, &mut findings);
    if findings.is_empty() {
        Ok(())
    } else {
        Err(GatewayError::Assembled(findings))
    }
}

/// A finding for every member anywhere in the file that delivers
/// configuration this check cannot read: discovery and wrapped configuration.
fn unseen_members(value: &Value, findings: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let finding = match key.as_str() {
                    "rds" | "scoped_routes" => Some(
                        "routes are delivered by RDS or scoped routes, which this check cannot \
                         see: write the route configuration inline",
                    ),
                    "vhds" => Some(
                        "virtual hosts are delivered by VHDS, which this check cannot see: write \
                         them inline",
                    ),
                    "config_discovery" => Some(
                        "a filter is delivered by discovery (config_discovery), which this check \
                         cannot see: write its typed_config inline",
                    ),
                    "per_filter_config" => Some(
                        "per_filter_config is the legacy per-filter form, which this check does \
                         not read: use typed_per_filter_config",
                    ),
                    "@type"
                        if child
                            .as_str()
                            .is_some_and(|kind| kind.ends_with(".TypedStruct")) =>
                    {
                        Some(
                            "a TypedStruct wraps configuration this check cannot read: write the \
                             typed configuration itself",
                        )
                    }
                    _ => None,
                };
                if let Some(finding) = finding {
                    findings.push(finding.to_owned());
                }
                if !FREE_FORM.contains(&key.as_str()) {
                    unseen_members(child, findings);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                unseen_members(item, findings);
            }
        }
        _ => {}
    }
}

/// Whether a runtime key belongs to the service, as the local reply mapper's
/// key does.
fn own_runtime_key(key: &str) -> bool {
    key.starts_with(OWN_PREFIX) || key == OWN_PREFIX.trim_end_matches('.')
}

/// Every key of a runtime layer, nested objects joined with `.` as Envoy
/// joins them.
fn runtime_keys(prefix: &str, value: &Value, out: &mut Vec<String>) {
    if let Value::Object(map) = value {
        for (key, child) in map {
            let joined = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            out.push(joined.clone());
            runtime_keys(&joined, child, out);
        }
    }
}

/// A finding for a runtime layer that sets, or could set from outside the
/// file, a key the service's mapper reads.
fn runtime_layers(document: &Value, findings: &mut Vec<String>) {
    let layers = document
        .get("layered_runtime")
        .map_or(&[][..], |runtime| array(runtime, "layers"));
    for layer in layers {
        let name = name_of(layer);
        if let Some(values) = layer.get("static_layer") {
            let mut keys = Vec::new();
            runtime_keys("", values, &mut keys);
            if keys.iter().any(|key| own_runtime_key(key)) {
                findings.push(format!(
                    "runtime layer {name} sets a key under {OWN_PREFIX}, which the service's \
                     local reply mapper reads"
                ));
            }
        } else if layer.get("admin_layer").is_none() {
            findings.push(format!(
                "runtime layer {name} is read from outside the file (a disk or RTDS layer), so \
                 this check cannot see whether it sets the service's runtime keys"
            ));
        }
    }
}

/// The filter chains of a listener: every `filter_chains` entry and the
/// default one.
fn filter_chains(listener: &Value) -> impl Iterator<Item = &Value> {
    array(listener, "filter_chains")
        .iter()
        .chain(listener.get("default_filter_chain"))
}

/// Every listener's connection managers, named by their listener. A network
/// filter other than a connection manager is refused: this check cannot see
/// where it sends requests.
fn listener_managers<'a>(
    document: &'a Value,
    findings: &mut Vec<String>,
) -> Vec<(String, &'a Value)> {
    let listeners = document
        .get("static_resources")
        .map_or(&[][..], |resources| array(resources, "listeners"));
    let mut managers = Vec::new();
    for listener in listeners {
        let place = format!("listener {}", name_of(listener));
        for chain in filter_chains(listener) {
            for filter in array(chain, "filters") {
                match filter.get("typed_config") {
                    Some(typed) if text(typed, "@type") == Some(MANAGER_TYPE) => {
                        managers.push((place.clone(), typed));
                    }
                    _ => findings.push(format!(
                        "{place}: network filter {} is not an HTTP connection manager, so this \
                         check cannot see where it sends requests",
                        name_of(filter)
                    )),
                }
            }
        }
    }
    managers
}

/// A finding for every connection manager or HTTP filter chain outside a
/// listener's filter chains, where this check does not follow it.
fn stray_managers(value: &Value, managers: &[(String, &Value)], findings: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            let known = managers
                .iter()
                .any(|(_, manager)| std::ptr::eq(*manager, value));
            if !known
                && (text(value, "@type") == Some(MANAGER_TYPE) || map.contains_key("http_filters"))
            {
                findings.push(
                    "an HTTP connection manager or filter chain sits outside a listener's filter \
                     chains, where this check does not follow it"
                        .to_owned(),
                );
            }
            for (key, child) in map {
                if !FREE_FORM.contains(&key.as_str()) {
                    stray_managers(child, managers, findings);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                stray_managers(item, managers, findings);
            }
        }
        _ => {}
    }
}

/// An authority's host, lower case, without its port or a trailing dot.
fn host_part(authority: &str) -> String {
    let lower = authority.to_ascii_lowercase();
    let host = if lower.starts_with('[') {
        lower
            .split_once(']')
            .map_or(lower.as_str(), |(host, _)| host)
    } else {
        lower
            .rsplit_once(':')
            .map_or(lower.as_str(), |(host, _)| host)
    };
    host.trim_end_matches('.').to_owned()
}

fn has_port(authority: &str) -> bool {
    if authority.starts_with('[') {
        authority.contains("]:")
    } else {
        authority.contains(':')
    }
}

/// Whether a connection manager could serve the public authority or one of
/// its variants (another case, a port, a trailing dot): any wildcard domain,
/// or an exact one for the same host. A manager without an inline route
/// configuration counts as one that could.
fn can_serve(manager: &Value, authority: &str) -> bool {
    let Some(configuration) = manager.get("route_config") else {
        return true;
    };
    let host = host_part(authority);
    array(configuration, "virtual_hosts")
        .iter()
        .flat_map(|virtual_host| array(virtual_host, "domains"))
        .filter_map(Value::as_str)
        .any(|domain| domain.contains('*') || host_part(domain) == host)
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

/// The header names an addition list (`response_headers_to_add`,
/// `request_headers_to_add`, a mapper's `headers_to_add`) sets, lower case.
fn added_headers(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .filter_map(|entry| entry.get("header").and_then(|header| text(header, "key")))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn adds_marker(value: &Value) -> bool {
    added_headers(value, "response_headers_to_add")
        .iter()
        .any(|key| key == ANSWER_MARKER_HEADER)
}

fn truthy(value: Option<&Value>) -> bool {
    value.and_then(Value::as_bool) == Some(true)
}

/// Whether any text in `value`, key or string, holds `needle`, in any case.
fn mentions(value: &Value, needle: &str) -> bool {
    let holds = |text: &str| text.to_ascii_lowercase().contains(needle);
    match value {
        Value::String(text) => holds(text),
        Value::Array(items) => items.iter().any(|item| mentions(item, needle)),
        Value::Object(map) => map
            .iter()
            .any(|(key, child)| holds(key) || mentions(child, needle)),
        _ => false,
    }
}

fn is_router(filter: &Value) -> bool {
    filter
        .get("typed_config")
        .and_then(|typed| text(typed, "@type"))
        == Some(ROUTER_TYPE)
}

/// Whether a member configures one of the service's filters per route.
fn configures_own_filter(value: &Value) -> bool {
    value
        .get("typed_per_filter_config")
        .and_then(Value::as_object)
        .is_some_and(|switches| switches.keys().any(|key| key.starts_with(OWN_PREFIX)))
}

/// Whether a path matcher's value lies under `prefix`, in any case. A prefix
/// without a closing `/` holds its own path and the paths below it at a
/// segment boundary, as the generated `path_separated_prefix` match does. A
/// `?` is a boundary too: a host `prefix` match reads the query, so a value
/// that goes on with `?` matches the prefix's own path.
fn lies_under(path: &str, prefix: &str) -> bool {
    path.len() >= prefix.len()
        && path.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
        && (prefix.ends_with('/')
            || matches!(path.as_bytes().get(prefix.len()), None | Some(b'/' | b'?')))
}

fn verify_manager(expected: &Expected, manager: &Value, findings: &mut Vec<String>) {
    verify_chain(expected, manager, findings);
    for upgrade in array(manager, "upgrade_configs") {
        if upgrade.get("filters").is_some() {
            findings.push(format!(
                "the upgrade {} brings its own filter chain, which skips the service's filters: \
                 remove its filters so upgrades use the main chain",
                text(upgrade, "upgrade_type").unwrap_or("(unnamed)")
            ));
        }
    }
    let mappers = manager
        .pointer("/local_reply_config/mappers")
        .map_or(&[][..], |mappers| {
            mappers.as_array().map_or(&[][..], Vec::as_slice)
        });
    if mappers.first() != expected.mappers.first() {
        findings.push(
            "the first local reply mapper is not the generated one for a failed check (a mapper \
             ahead of it that matches status 503 would answer instead)"
                .to_owned(),
        );
    }
    for (index, want) in expected.mappers.iter().enumerate().skip(1) {
        if mappers.get(index) != Some(want) {
            findings.push(format!(
                "local reply mapper {index} is not the generated one for an unreachable session \
                 route: the generated mappers come first, as generated and in order"
            ));
        }
    }
    for (index, mapper) in mappers.iter().enumerate().skip(expected.mappers.len()) {
        if mapper
            .get("status_code")
            .and_then(status_value)
            .is_some_and(|status| (300..400).contains(&status))
        {
            findings.push(format!(
                "local reply mapper {index} answers with a 3xx status, which would turn the \
                 check's refusal into a redirect"
            ));
        }
        if added_headers(mapper, "headers_to_add")
            .iter()
            .any(|key| key == ANSWER_MARKER_HEADER)
        {
            findings.push(format!(
                "local reply mapper {index} adds the answer marker, which only the service's \
                 mapper may add"
            ));
        }
    }
    let Some(configuration) = manager.get("route_config") else {
        findings.push("the connection manager has no inline route configuration".to_owned());
        return;
    };
    if has_port(&expected.authority)
        && (truthy(manager.get("strip_any_host_port"))
            || truthy(manager.get("strip_matching_host_port"))
            || truthy(configuration.get("ignore_port_in_host_matching")))
    {
        findings.push(format!(
            "the connection manager strips the port from the host before routing \
             (strip_any_host_port, strip_matching_host_port or ignore_port_in_host_matching), \
             but the authority {} carries one, so the generated virtual host would not match",
            quoted(&expected.authority)
        ));
    }
    verify_routes(expected, configuration, findings);
}

/// The service's filters first, as generated; every other filter but the
/// router listed as a host filter; the router last.
fn verify_chain(expected: &Expected, manager: &Value, findings: &mut Vec<String>) {
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
    if chain.last().is_none_or(|last| !is_router(last))
        || chain.iter().filter(|filter| is_router(filter)).count() != 1
    {
        findings.push(
            "the filter chain must end with the router (typed as \
             envoy.extensions.filters.http.router.v3.Router) and hold it once"
                .to_owned(),
        );
    }
    for (index, filter) in chain.iter().enumerate().skip(expected.filters.len()) {
        if is_router(filter) {
            continue;
        }
        let name = name_of(filter);
        if name.starts_with(OWN_PREFIX) {
            findings.push(format!(
                "a second {name} filter at position {index}: the service's filters appear once, \
                 at the head of the chain"
            ));
            continue;
        }
        if !expected.host_filters.iter().any(|listed| listed == name) {
            findings.push(format!(
                "the host filter {name} is not listed in gateway.hostFilters, so it would run on \
                 the generated routes: list it there, and keep it on a route with \
                 keepHostFilters only where it must run"
            ));
        }
        let typed = filter.get("typed_config").unwrap_or(&Value::Null);
        if mentions(typed, ANSWER_MARKER_HEADER) {
            findings.push(format!(
                "the host filter {name} names the answer marker, which only the service may set"
            ));
        }
        if expected.kept.iter().any(|kept| kept == name) && mentions(typed, AUTHORIZATION_HEADER) {
            findings.push(format!(
                "the host filter {name}, which a generated route keeps, names authorization: a \
                 kept filter sees the person's bearer token and must not read or change it"
            ));
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
}

/// The rules for a member above the routes, or a route itself: no switch for
/// the service's filters, no marker addition, no mirroring, and above the
/// generated routes no credential header addition.
fn level_rules(value: &Value, place: &str, above_generated: bool, findings: &mut Vec<String>) {
    if configures_own_filter(value) {
        findings.push(format!(
            "{place} configures one of the service's filters, which only the generated routes \
             may do"
        ));
    }
    if adds_marker(value) {
        findings.push(format!("{place} adds the answer marker to its answers"));
    }
    if !array(value, "request_mirror_policies").is_empty() {
        findings.push(format!(
            "{place} mirrors requests (request_mirror_policies), which would copy them, \
             credentials included, to another cluster"
        ));
    }
    if above_generated {
        for header in added_headers(value, "request_headers_to_add") {
            if header == AUTHORIZATION_HEADER || header == COOKIE_HEADER {
                findings.push(format!(
                    "{place} adds the {header} request header above the generated routes, \
                     which would replace or add a credential on them"
                ));
            }
        }
    }
}

fn verify_routes(expected: &Expected, configuration: &Value, findings: &mut Vec<String>) {
    let configuration_name = name_of(configuration);
    level_rules(
        configuration,
        &format!("route configuration {configuration_name}"),
        true,
        findings,
    );
    let configuration_removes = names_marker(configuration.get("response_headers_to_remove"));
    let hosts = array(configuration, "virtual_hosts");
    let owning: Vec<usize> = hosts
        .iter()
        .enumerate()
        .filter(|(_, host)| {
            array(host, "domains").iter().any(|domain| {
                domain
                    .as_str()
                    .is_some_and(|domain| domain.eq_ignore_ascii_case(&expected.authority))
            })
        })
        .map(|(index, _)| index)
        .collect();
    let authority = quoted(&expected.authority);
    let generated_host = match owning.as_slice() {
        [] => {
            findings.push(format!(
                "no virtual host names the authority {authority} exactly: put the generated \
                 routes first in a virtual host whose only domain is the authority"
            ));
            None
        }
        [one] => Some(*one),
        _ => {
            findings.push(format!(
                "more than one virtual host names the authority {authority}"
            ));
            None
        }
    };
    for (host_index, host) in hosts.iter().enumerate() {
        let host_name = text(host, "name").map_or_else(|| format!("#{host_index}"), str::to_owned);
        let generated = generated_host == Some(host_index);
        if generated && array(host, "domains").len() != 1 {
            findings.push(format!(
                "virtual host {host_name} serves the authority {authority} and other domains: \
                 the generated routes need a virtual host of their own, whose only domain is \
                 the authority"
            ));
        }
        level_rules(
            host,
            &format!("virtual host {host_name}"),
            generated,
            findings,
        );
        let above_removes =
            configuration_removes || names_marker(host.get("response_headers_to_remove"));
        let routes = array(host, "routes");
        let mut first_host_route = 0;
        if generated {
            if above_removes {
                for route in expected.public_routes() {
                    findings.push(format!(
                        "route {} is a public session route and loses the answer marker to a \
                         removal on virtual host {host_name} or its route configuration",
                        name_of(route)
                    ));
                }
            }
            for (index, want) in expected.routes.iter().enumerate() {
                if routes.get(index) == Some(want) {
                    continue;
                }
                let name = name_of(want);
                if routes.contains(want) {
                    findings.push(format!(
                        "the generated route {name} is not at position {index} of virtual host \
                         {host_name}: the generated routes come first, as generated and in order"
                    ));
                } else {
                    findings.push(format!(
                        "the generated route {name} is missing from virtual host {host_name}, or \
                         differs from the generated one"
                    ));
                }
            }
            first_host_route = expected.routes.len();
        }
        for (index, route) in routes.iter().enumerate() {
            if generated && index < first_host_route && expected.routes.get(index) == Some(route) {
                continue;
            }
            let place = format!("route {} of virtual host {host_name}", name_of(route));
            if generated && index < first_host_route && !expected.routes.contains(route) {
                findings.push(format!(
                    "{place} comes before the generated routes, which come first"
                ));
            }
            verify_host_route(expected, route, &place, generated, above_removes, findings);
        }
    }
}

/// The rules for a route the service did not generate.
fn verify_host_route(
    expected: &Expected,
    route: &Value,
    place: &str,
    in_generated_host: bool,
    above_removes: bool,
    findings: &mut Vec<String>,
) {
    if !above_removes && !names_marker(route.get("response_headers_to_remove")) {
        findings.push(format!(
            "{place} does not remove the answer marker from its answers"
        ));
    }
    level_rules(route, place, false, findings);
    let matcher = route.get("match").unwrap_or(&Value::Null);
    if array(matcher, "headers").iter().any(|header| {
        text(header, "name").is_some_and(|name| {
            name.eq_ignore_ascii_case(":authority") || name.eq_ignore_ascii_case("host")
        }) && truthy(header.get("invert_match"))
    }) {
        findings.push(format!(
            "{place} matches the authority with invert_match, which matches every other \
             authority, the public one included"
        ));
    }
    if let Some(action) = route.get("route") {
        if !array(action, "request_mirror_policies").is_empty() {
            findings.push(format!(
                "{place} mirrors requests (request_mirror_policies), which would copy them, \
                 credentials included, to another cluster"
            ));
        }
        let mut clusters: Vec<&str> = text(action, "cluster").into_iter().collect();
        if let Some(weighted) = action.get("weighted_clusters") {
            for (index, cluster) in array(weighted, "clusters").iter().enumerate() {
                clusters.extend(text(cluster, "name"));
                level_rules(
                    cluster,
                    &format!("weighted cluster {index} of {place}"),
                    false,
                    findings,
                );
            }
        }
        for cluster in clusters {
            if expected
                .protected
                .iter()
                .any(|protected| protected == cluster)
            {
                findings.push(format!(
                    "{place} reaches the cluster {cluster}, which only the generated routes may \
                     reach"
                ));
            }
        }
        for member in [
            "cluster_header",
            "cluster_specifier_plugin",
            "inline_cluster_specifier_plugin",
        ] {
            if action.get(member).is_some() {
                findings.push(format!(
                    "{place} picks its cluster at request time ({member}), so this check cannot \
                     see whether it reaches a module or page"
                ));
            }
        }
    }
    if !in_generated_host {
        return;
    }
    let Some(path) = ["prefix", "path", "path_separated_prefix"]
        .iter()
        .find_map(|key| text(matcher, key))
    else {
        findings.push(format!(
            "{place} matches paths in a way this check cannot compare with the generated \
             prefixes: only prefix, path and path_separated_prefix are read"
        ));
        return;
    };
    if lies_under(path, SESSION_PREFIX) || path.eq_ignore_ascii_case("/session") {
        findings.push(format!(
            "{place} matches a path under /session/, which the service keeps for its own routes"
        ));
    } else if let Some(prefix) = expected
        .prefixes
        .iter()
        .find(|prefix| lies_under(path, prefix))
    {
        findings.push(format!(
            "{place} matches a path under the generated prefix {}, which only the generated \
             route serves",
            quoted(prefix)
        ));
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
pub(super) fn redirects(route: &Value) -> bool {
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

/// Whether a virtual host redirects plain-text requests to TLS. Envoy reads
/// an enum's name in any case, or its number.
fn requires_tls(host: &Value) -> bool {
    match host.get("require_tls") {
        None => false,
        Some(Value::String(level)) => !level.eq_ignore_ascii_case("NONE"),
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
    use serde_json::json;

    use super::*;
    use crate::gateway::tests::{files, fragment_of, sequence, FIXTURE};

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
        ] {
            chain.push(json!({ "name": name }));
        }
        chain.push(router());
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
                "@type": MANAGER_TYPE,
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

    const MANAGER_TYPE: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";

    fn router() -> Value {
        json!({
            "name": "envoy.filters.http.router",
            "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"},
        })
    }

    /// A listener holding one connection manager with `domains` and `routes`
    /// and only a router in its chain.
    fn listener(name: &str, domains: Value, routes: Value) -> Value {
        json!({"name": name, "filter_chains": [{"filters": [{
            "name": "envoy.filters.network.http_connection_manager",
            "typed_config": {
                "@type": MANAGER_TYPE,
                "http_filters": [router()],
                "route_config": {"name": name, "virtual_hosts": [
                    {"name": name, "domains": domains, "routes": routes}
                ]},
            },
        }]}]})
    }

    fn listeners(document: &mut Value) -> &mut Vec<Value> {
        document["static_resources"]["listeners"]
            .as_array_mut()
            .expect("listeners")
    }

    fn virtual_hosts_of(document: &mut Value) -> &mut Vec<Value> {
        manager(document)["route_config"]["virtual_hosts"]
            .as_array_mut()
            .expect("virtual hosts")
    }

    /// Verify the assembled file `text`, written as given, against the fixture.
    fn verified_text(text: &str) -> Result<(), GatewayError> {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let runtime = root.join("runtime.yaml");
        fs::write(&runtime, FIXTURE).expect("runtime file");
        let path = root.join("envoy.yaml");
        fs::write(&path, text).expect("assembled file");
        verify_assembled(&runtime, &path)
    }

    /// The passing assembled file as text, with `from` replaced by `to` once.
    fn assembled_text(from: &str, to: &str) -> String {
        let text = serde_json::to_string(&assembled()).expect("json");
        assert_eq!(text.matches(from).count(), 1, "{from} occurs once");
        text.replacen(from, to, 1)
    }

    fn refuses_text(text: &str, needle: &str) {
        match verified_text(text) {
            Err(GatewayError::Assembled(found)) => assert!(
                found.iter().any(|finding| finding.contains(needle)),
                "no finding mentions {needle:?}: {found:?}"
            ),
            other => panic!("expected findings mentioning {needle:?}, got {other:?}"),
        }
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
    fn generated_routes_in_a_wildcard_virtual_host_fail() {
        for domains in [json!(["*"]), json!(["app.example*"]), json!(["*.example"])] {
            let mut document = assembled();
            virtual_hosts_of(&mut document)[0]["domains"] = domains;
            refuses(&document, "names the authority");
        }
    }

    #[test]
    fn generated_routes_must_have_their_virtual_host_to_themselves() {
        let mut document = assembled();
        virtual_hosts_of(&mut document)[0]["domains"] = json!(["app.example", "*"]);
        refuses(&document, "of their own");
        let mut document = assembled();
        virtual_hosts_of(&mut document).push(json!({
            "name": "twin",
            "domains": ["APP.example"],
            "routes": [marker_removing_route("twin", json!({"prefix": "/"}))],
        }));
        refuses(&document, "more than one virtual host");
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
    fn a_host_route_for_another_authority_may_not_come_first_either() {
        let mut document = assembled();
        let mut early = marker_removing_route("early", json!({ "prefix": "/" }));
        early["match"]["headers"] = json!([{
            "name": ":authority",
            "string_match": { "exact": "internal.example" },
        }]);
        host_routes(&mut document).insert(0, early);
        refuses(&document, "comes before the generated routes");
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
            "the generated route registry-session.sign-in is missing from virtual host public",
        );
    }

    #[test]
    fn no_virtual_host_for_the_authority_fails() {
        let mut document = assembled();
        manager(&mut document)["route_config"]["virtual_hosts"][0]["domains"] =
            json!(["other.example"]);
        refuses(&document, "no HTTP connection manager serves the authority");
    }

    #[test]
    fn generated_routes_out_of_order_fail() {
        let mut document = assembled();
        host_routes(&mut document).swap(0, 1);
        refuses(&document, "in order");
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
    fn a_session_mapper_without_its_path_condition_fails() {
        let mut document = assembled();
        let mappers = manager(&mut document)["local_reply_config"]["mappers"]
            .as_array_mut()
            .expect("mappers");
        let filters = mappers[1]["filter"]["and_filter"]["filters"]
            .as_array_mut()
            .expect("the session mapper's filters");
        let before = filters.len();
        filters.retain(|filter| filter.get("header_filter").is_none());
        assert_eq!(filters.len(), before - 1, "the path condition was there");
        refuses(&document, "local reply mapper 1");
    }

    #[test]
    fn a_missing_session_mapper_fails() {
        let mut document = assembled();
        manager(&mut document)["local_reply_config"]["mappers"]
            .as_array_mut()
            .expect("mappers")
            .truncate(1);
        refuses(&document, "local reply mapper 1");
    }

    #[test]
    fn an_exact_path_module_passes_and_host_routes_beside_it_are_judged_by_segment() {
        assert!(serde_json::to_string(&assembled())
            .expect("json")
            .contains("\"path_separated_prefix\":\"/api/functions/renew\""));
        assert!(lies_under("/api/functions/renew", "/api/functions/renew"));
        assert!(lies_under("/API/functions/renew/x", "/api/functions/renew"));
        assert!(!lies_under(
            "/api/functions/renewal",
            "/api/functions/renew"
        ));
        assert!(lies_under("/api/functions/renewal", "/api/functions/"));
        assert!(!lies_under("/api/functions", "/api/functions/"));
        for matcher in [
            json!({ "path": "/api/functions/renew" }),
            json!({ "path": "/API/functions/renew" }),
            json!({ "prefix": "/api/functions/renew/x" }),
            json!({ "path_separated_prefix": "/api/functions/renew" }),
        ] {
            let mut document = assembled();
            host_routes(&mut document).push(marker_removing_route("late", matcher.clone()));
            refuses(&document, "matches a path under the generated prefix");
        }
    }

    #[test]
    fn a_host_prefix_that_reaches_an_exact_path_module_through_its_query_fails() {
        // Envoy's `prefix` match reads the query too, so `/API/functions/renew?`
        // matches `/API/functions/renew?x`, the exact path in another case.
        let mut document = assembled();
        host_routes(&mut document).push(marker_removing_route(
            "late",
            json!({ "prefix": "/API/functions/renew?" }),
        ));
        refuses(&document, "matches a path under the generated prefix");
        assert!(lies_under("/API/functions/renew?", "/api/functions/renew"));
        assert!(!lies_under("/api/documents?", "/api/documents/"));
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
        assert!(
            found[0].contains("no HTTP connection manager serves the authority"),
            "{found:?}"
        );
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

    // Reading the file as Envoy reads it.

    #[test]
    fn anchors_aliases_merge_keys_and_tags_are_refused() {
        for (from, to) in [
            ("\"name\":\"main\"", "\"name\": &listener \"main\""),
            (
                "\"name\":\"main\"",
                "\"name\": &listener \"main\", \"stat_prefix\": *listener",
            ),
            (
                "\"name\":\"main\"",
                "\"name\":\"main\", <<: {\"per_connection_buffer_limit_bytes\": 1}",
            ),
            ("\"name\":\"main\"", "\"name\": !ignore \"main\""),
        ] {
            let text = assembled_text(from, to);
            assert!(
                matches!(verified_text(&text), Err(GatewayError::Assembled(found)) if !found.is_empty()),
                "{to}"
            );
        }
    }

    #[test]
    fn a_camel_case_key_is_refused() {
        let text = assembled_text(
            "\"domains\":[\"app.example\"]",
            "\"domains\":[\"app.example\"],\"responseHeadersToAdd\":[{\"header\":{\"key\":\"registry-session-answer\",\"value\":\"1\"}}]",
        );
        refuses_text(&text, "snake_case");
        let text = assembled_text(
            "\"route\":{\"cluster\":\"api\"}",
            "\"route\":{\"cluster\":\"api\"},\"typedPerFilterConfig\":{\"registry-session.strip-cookies\":{\"@type\":\"type.googleapis.com/envoy.extensions.filters.http.lua.v3.LuaPerRoute\",\"disabled\":true}}",
        );
        refuses_text(&text, "snake_case");
    }

    #[test]
    fn upper_case_keys_inside_metadata_pass() {
        let mut document = assembled();
        route(&mut document, "host-api")["metadata"] =
            json!({"filter_metadata": {"Example.Filter": {"SomeKey": "Value"}}});
        verified_against(FIXTURE, &document).expect("passes");
    }

    #[test]
    fn a_yaml_1_1_boolean_is_refused() {
        for word in ["on", "Yes", "OFF", "n", "y"] {
            let text = assembled_text(
                "\"@type\":\"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager\"",
                &format!(
                    "\"@type\":\"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager\",\"strip_any_host_port\": {word}"
                ),
            );
            refuses_text(&text, "true or false");
        }
    }

    #[test]
    fn a_quoted_yaml_1_1_word_is_a_string_and_passes() {
        let mut document = assembled();
        route(&mut document, "host-api")["response_headers_to_add"] =
            json!([{"header": {"key": "x-example", "value": "on"}}]);
        verified_against(FIXTURE, &document).expect("passes");
    }

    #[test]
    fn require_tls_none_passes_in_any_case() {
        for level in ["NONE", "none", "None"] {
            let mut document = assembled();
            virtual_hosts_of(&mut document)[0]["require_tls"] = json!(level);
            verified_against(FIXTURE, &document).expect(level);
        }
        let mut document = assembled();
        virtual_hosts_of(&mut document)[0]["require_tls"] = json!("external_only");
        refuses(&document, "require_tls");
    }

    // Static resources only.

    #[test]
    fn listeners_or_routes_by_discovery_are_refused() {
        for (member, value) in [
            ("lds_config", json!({"ads": {}})),
            ("ads_config", json!({"api_type": "GRPC"})),
        ] {
            let mut document = assembled();
            document["dynamic_resources"] = json!({ member: value });
            refuses(&document, member);
        }
        let mut document = assembled();
        manager(&mut document)["route_config"]["vhds"] = json!({"config_source": {"ads": {}}});
        refuses(&document, "VHDS");
        let mut document = assembled();
        chain(&mut document).insert(
            3,
            json!({"name": "host-ecds", "config_discovery": {"config_source": {"ads": {}}}}),
        );
        refuses(&document, "config_discovery");
    }

    #[test]
    fn rds_in_a_second_connection_manager_is_refused() {
        let mut document = assembled();
        let mut second = listener("second", json!(["internal.example"]), json!([]));
        let typed = &mut second["filter_chains"][0]["filters"][0]["typed_config"];
        typed
            .as_object_mut()
            .expect("manager")
            .remove("route_config");
        typed["rds"] = json!({"route_config_name": "x", "config_source": {"ads": {}}});
        listeners(&mut document).push(second);
        refuses(&document, "RDS");
    }

    // Every connection manager.

    #[test]
    fn an_http3_listener_without_the_filters_is_refused() {
        let mut document = assembled();
        let mut h3 = listener(
            "h3",
            json!(["app.example"]),
            json!([marker_removing_route(
                "documents",
                json!({"prefix": "/api/documents/"})
            ),]),
        );
        h3["udp_listener_config"] = json!({"quic_options": {}});
        h3["filter_chains"][0]["filters"][0]["typed_config"]["codec_type"] = json!("HTTP3");
        listeners(&mut document).push(h3);
        refuses(&document, "listener h3");
    }

    #[test]
    fn an_internal_manager_with_exact_internal_domains_passes() {
        let mut document = assembled();
        listeners(&mut document).push(listener(
            "internal",
            json!(["documents.internal", "documents.internal:8080"]),
            json!([{"name": "direct", "match": {"prefix": "/"}, "route": {"cluster": "documents"}}]),
        ));
        verified_against(FIXTURE, &document).expect("passes");
    }

    #[test]
    fn a_manager_that_can_serve_the_authority_gets_the_full_check() {
        for domains in [
            json!(["*"]),
            json!(["*.example"]),
            json!(["APP.example:443"]),
            json!(["app.example."]),
        ] {
            let mut document = assembled();
            listeners(&mut document).push(listener(
                "other",
                domains.clone(),
                json!([marker_removing_route("x", json!({"prefix": "/"}))]),
            ));
            refuses(&document, "listener other");
        }
    }

    #[test]
    fn a_network_filter_other_than_the_connection_manager_is_refused() {
        let mut document = assembled();
        listeners(&mut document).push(json!({"name": "raw", "filter_chains": [{"filters": [{
            "name": "envoy.filters.network.tcp_proxy",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
                "stat_prefix": "raw",
                "cluster": "documents",
            },
        }]}]}));
        refuses(&document, "not an HTTP connection manager");
    }

    #[test]
    fn a_wrapped_typed_config_is_refused() {
        let mut document = assembled();
        let typed = manager(&mut document).clone();
        *manager(&mut document) = json!({
            "@type": "type.googleapis.com/xds.type.v3.TypedStruct",
            "type_url": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
            "value": typed,
        });
        refuses(&document, "TypedStruct");
    }

    // Upgrades.

    #[test]
    fn an_upgrade_with_its_own_filter_chain_is_refused() {
        let mut document = assembled();
        manager(&mut document)["upgrade_configs"] =
            json!([{"upgrade_type": "websocket", "filters": [router()]}]);
        refuses(&document, "upgrade");
        let mut document = assembled();
        manager(&mut document)["upgrade_configs"] = json!([{"upgrade_type": "websocket"}]);
        verified_against(FIXTURE, &document).expect("an upgrade on the main chain passes");
    }

    // Per-filter switches and other levels.

    fn strip_switch() -> Value {
        json!({"registry-session.strip-cookies": {
            "@type": "type.googleapis.com/envoy.config.route.v3.FilterConfig",
            "disabled": true,
        }})
    }

    #[test]
    fn a_session_switch_above_or_below_the_route_is_refused() {
        let mut document = assembled();
        virtual_hosts_of(&mut document)[0]["typed_per_filter_config"] = strip_switch();
        refuses(&document, "configures one of the service's filters");
        let mut document = assembled();
        manager(&mut document)["route_config"]["typed_per_filter_config"] = strip_switch();
        refuses(&document, "configures one of the service's filters");
        let mut document = assembled();
        let host = route(&mut document, "host-api");
        host["route"] = json!({"weighted_clusters": {"clusters": [
            {"name": "api", "weight": 1, "typed_per_filter_config": strip_switch()},
        ]}});
        refuses(&document, "configures one of the service's filters");
        let mut document = assembled();
        route(&mut document, "host-api")["per_filter_config"] = json!({"x": {}});
        refuses(&document, "per_filter_config");
    }

    #[test]
    fn a_second_instance_of_a_session_filter_is_refused() {
        let mut document = assembled();
        let mut second = chain(&mut document)[1].clone();
        second["typed_config"]["failure_mode_allow"] = json!(true);
        chain(&mut document).insert(4, second);
        refuses(&document, "second");
    }

    #[test]
    fn a_later_local_reply_mapper_that_redirects_is_refused() {
        let mut document = assembled();
        manager(&mut document)["local_reply_config"]["mappers"]
            .as_array_mut()
            .expect("mappers")
            .push(json!({
                "filter": {"status_code_filter": {"comparison": {
                    "op": "EQ", "value": {"default_value": 401, "runtime_key": "x"},
                }}},
                "status_code": 302,
                "headers_to_add": [{"header": {"key": "location", "value": "/"}}],
            }));
        refuses(&document, "3xx");
    }

    #[test]
    fn a_runtime_layer_that_could_set_the_mappers_key_is_refused() {
        for layer in [
            json!({"name": "s", "static_layer": {"registry-session.local-reply.status": 500}}),
            json!({"name": "s", "static_layer": {"registry-session": {"local-reply": {"status": 500}}}}),
            json!({"name": "d", "disk_layer": {"symlink_root": "/srv/runtime"}}),
        ] {
            let mut document = assembled();
            document["layered_runtime"] = json!({"layers": [layer]});
            refuses(&document, "runtime");
        }
        let mut document = assembled();
        document["layered_runtime"] = json!({"layers": [
            {"name": "s", "static_layer": {"overload.global_downstream_max_connections": 1000}},
            {"name": "a", "admin_layer": {}},
        ]});
        verified_against(FIXTURE, &document).expect("other runtime keys pass");
    }

    #[test]
    fn a_host_filter_naming_the_answer_marker_is_refused() {
        let mut document = assembled();
        chain(&mut document)[3]["typed_config"] = json!({
            "@type": "type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation",
            "mutations": {"response_mutations": [{"append": {"header": {
                "key": "Registry-Session-Answer", "value": "1",
            }}}]},
        });
        refuses(&document, "envoy.filters.http.cors names the answer marker");
    }

    #[test]
    fn a_kept_host_filter_naming_authorization_is_refused_and_an_unkept_one_passes() {
        let names_authorization = json!({
            "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua",
            "default_source_code": {"inline_string": "function envoy_on_request(h) h:headers():remove('Authorization') end"},
        });
        let mut document = assembled();
        chain(&mut document)[5]["typed_config"] = names_authorization.clone();
        refuses(&document, "envoy.filters.http.rbac");
        let mut document = assembled();
        chain(&mut document)[3]["typed_config"] = names_authorization;
        verified_against(FIXTURE, &document).expect("a filter no route keeps passes");
    }

    #[test]
    fn a_header_addition_above_the_routes_naming_authorization_or_cookie_is_refused() {
        let add = |key: &str| json!([{"header": {"key": key, "value": "x"}, "append_action": "OVERWRITE_IF_EXISTS_OR_ADD"}]);
        let mut document = assembled();
        virtual_hosts_of(&mut document)[0]["request_headers_to_add"] = add("Authorization");
        refuses(&document, "authorization");
        let mut document = assembled();
        manager(&mut document)["route_config"]["request_headers_to_add"] = add("cookie");
        refuses(&document, "cookie");
    }

    #[test]
    fn request_mirroring_is_refused() {
        let mut document = assembled();
        route(&mut document, "host-api")["route"]["request_mirror_policies"] =
            json!([{"cluster": "mirror"}]);
        refuses(&document, "mirror");
        let mut document = assembled();
        virtual_hosts_of(&mut document)[0]["request_mirror_policies"] =
            json!([{"cluster": "mirror"}]);
        refuses(&document, "mirror");
    }

    // Virtual hosts.

    #[test]
    fn a_host_route_under_a_generated_prefix_is_refused() {
        for prefix in ["/api/registry/legacy/", "/API/Registry/", "/Session/x"] {
            let mut document = assembled();
            host_routes(&mut document)
                .push(marker_removing_route("late", json!({ "prefix": prefix })));
            refuses(&document, "under");
        }
    }

    #[test]
    fn a_host_route_matched_in_a_way_the_check_cannot_compare_is_refused() {
        let mut document = assembled();
        host_routes(&mut document).push(marker_removing_route(
            "regex",
            json!({"safe_regex": {"regex": "/.*"}}),
        ));
        refuses(&document, "cannot compare");
    }

    #[test]
    fn an_inverted_authority_match_is_refused() {
        let mut document = assembled();
        let mut late = marker_removing_route("late", json!({ "prefix": "/rest2/" }));
        late["match"]["headers"] = json!([{
            "name": ":authority",
            "string_match": { "exact": "internal.example" },
            "invert_match": true,
        }]);
        host_routes(&mut document).push(late);
        refuses(&document, "invert_match");
    }

    #[test]
    fn a_host_route_to_a_module_page_or_service_cluster_is_refused() {
        for action in [
            json!({"cluster": "documents"}),
            json!({"cluster": "pages"}),
            json!({"cluster": "registry-session-check"}),
            json!({"weighted_clusters": {"clusters": [{"name": "documents", "weight": 1}]}}),
        ] {
            let mut document = assembled();
            virtual_hosts_of(&mut document).push(json!({
                "name": "other",
                "domains": ["*"],
                "routes": [{
                    "name": "side",
                    "match": {"prefix": "/"},
                    "route": action,
                    "response_headers_to_remove": ["registry-session-answer"],
                }],
            }));
            refuses(&document, "only the generated routes may reach");
        }
        let mut document = assembled();
        route(&mut document, "host-api")["route"] = json!({"cluster_header": "x-cluster"});
        refuses(&document, "cluster_header");
    }

    #[test]
    fn ignoring_the_port_in_host_matching_is_refused_when_the_authority_has_one() {
        let ported = FIXTURE.replacen(
            "publicOrigin: https://app.example",
            "publicOrigin: https://app.example:8443",
            1,
        );
        let mut document = assembled_from(&ported);
        manager(&mut document)["route_config"]["ignore_port_in_host_matching"] = json!(true);
        let Err(GatewayError::Assembled(found)) = verified_against(&ported, &document) else {
            panic!("expected findings");
        };
        assert!(
            found
                .iter()
                .any(|finding| finding.contains("strips the port")),
            "{found:?}"
        );
    }

    // Host filters on the generated routes.

    #[test]
    fn a_host_filter_not_listed_is_refused() {
        let mut document = assembled();
        chain(&mut document).insert(
            4,
            json!({"name": "host.rewrite", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua",
                "default_source_code": {"inline_string": "function envoy_on_request(h) h:headers():replace(':path', '/legacy/') h:clearRouteCache() end"},
            }}),
        );
        refuses(
            &document,
            "host.rewrite is not listed in gateway.hostFilters",
        );
    }

    #[test]
    fn a_hand_removed_host_filter_switch_on_a_module_route_is_refused() {
        let mut document = assembled();
        route(&mut document, "module-data")["typed_per_filter_config"]
            .as_object_mut()
            .expect("per-filter config")
            .remove("envoy.filters.http.cors")
            .expect("the unkept filter is switched off");
        refuses(&document, "module-data");
    }

    #[test]
    fn the_router_must_end_the_chain() {
        let mut document = assembled();
        chain(&mut document).pop();
        refuses(&document, "router");
        let mut document = assembled();
        let router = chain(&mut document).pop().expect("router");
        chain(&mut document).insert(3, router);
        refuses(&document, "router");
    }
}
