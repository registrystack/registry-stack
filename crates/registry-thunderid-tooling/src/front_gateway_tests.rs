use serde_json::Value;

use super::*;

/// The generated file, parsed. Its comments are dropped; the tests read the
/// routes the gateway would apply.
fn parsed() -> Value {
    #[allow(
        clippy::disallowed_methods,
        reason = "reads back the Envoy file this crate rendered, an external format Envoy owns"
    )]
    serde_norway::from_str(&render("1.1.0")).expect("the front gateway file is YAML")
}

fn connection_manager(config: &Value) -> &Value {
    &config["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
}

fn routes(config: &Value) -> Vec<Value> {
    connection_manager(config)["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes")
        .clone()
}

/// What the gateway does with a request, as the first matching route says.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Refused { status: u64, problem: String },
    NotFound,
    Forwarded,
}

/// The paths the sign-in text expression matches, written out by segment: the
/// language list, and the two resolve paths under one language. The test
/// reads only this expression; Envoy itself checks it in the validation run.
fn sign_in_text(regex: &str, path: &str) -> bool {
    assert_eq!(
        regex,
        "^/i18n/languages(/[^/]+/translations(/ns/[^/]+/keys/[^/]+)?/resolve)?$",
        "the test knows only this expression"
    );
    let Some(rest) = path.strip_prefix("/i18n/languages") else {
        return false;
    };
    let segments: Vec<&str> = rest.split('/').skip(1).collect();
    rest.is_empty()
        || (rest.starts_with('/')
            && segments.iter().all(|segment| !segment.is_empty())
            && matches!(
                segments.as_slice(),
                [_, "translations", "resolve"]
                    | [_, "translations", "ns", _, "keys", _, "resolve"]
            ))
}

/// Whether `route` matches, as Envoy would apply it.
fn may_match(route: &Value, method: &str, path: &str, headers: &[&str]) -> bool {
    let matcher = &route["match"];
    let insensitive = matcher["case_sensitive"] == Value::Bool(false);
    let fold = |text: &str| {
        if insensitive {
            text.to_ascii_lowercase()
        } else {
            text.to_owned()
        }
    };
    let path_matches = if let Some(exact) = matcher["path"].as_str() {
        fold(path) == fold(exact)
    } else if let Some(prefix) = matcher["prefix"].as_str() {
        fold(path).starts_with(&fold(prefix))
    } else if let Some(regex) = matcher["safe_regex"]["regex"].as_str() {
        sign_in_text(regex, path)
    } else {
        panic!("a route with no path matcher: {route}")
    };
    let headers_match = matcher["headers"].as_array().is_none_or(|required| {
        required.iter().all(|header| {
            let name = header["name"].as_str().expect("header name");
            if header["present_match"] == Value::Bool(true) {
                headers.contains(&name)
            } else if name == ":method" {
                header["string_match"]["exact"].as_str() == Some(method)
            } else {
                panic!("an unexpected header matcher: {header}")
            }
        })
    });
    path_matches && headers_match
}

fn outcome(method: &str, path: &str, headers: &[&str]) -> Outcome {
    let config = parsed();
    let Some(route) = routes(&config)
        .into_iter()
        .find(|route| may_match(route, method, path, headers))
    else {
        return Outcome::NotFound;
    };
    if route["route"]["cluster"].as_str() == Some(PROVIDER_CLUSTER) {
        return Outcome::Forwarded;
    }
    let status = route["direct_response"]["status"]
        .as_u64()
        .expect("a direct response");
    if status == 404 {
        return Outcome::NotFound;
    }
    let body: Value = serde_json::from_str(
        route["direct_response"]["body"]["inline_string"]
            .as_str()
            .expect("a problem body"),
    )
    .expect("the body is JSON");
    Outcome::Refused {
        status,
        problem: body["type"].as_str().expect("a type").to_owned(),
    }
}

fn self_edit_refused() -> Outcome {
    Outcome::Refused {
        status: 403,
        problem: ProblemKind::SelfServiceEditRefused.type_uri(),
    }
}

const SELF_EDIT_PATHS: [&str; 6] = [
    "/users/me",
    "/users/me/",
    "/users/me/meta",
    "/users/me/update-credentials",
    "/users/me/a/b",
    "/Users/Me",
];

#[test]
fn self_edits_are_refused_before_any_pass_route() {
    for method in ["PUT", "PATCH", "DELETE"] {
        for path in SELF_EDIT_PATHS {
            assert_eq!(
                outcome(method, path, &[]),
                self_edit_refused(),
                "{method} {path}"
            );
        }
    }
}

#[test]
fn the_refusal_routes_precede_every_route_that_forwards() {
    let config = parsed();
    let routes = routes(&config);
    let last_refusal = routes
        .iter()
        .rposition(|route| route["direct_response"]["status"] == 403)
        .expect("refusal routes");
    let first_forward = routes
        .iter()
        .position(|route| route["route"]["cluster"].as_str() == Some(PROVIDER_CLUSTER))
        .expect("pass routes");
    assert!(last_refusal < first_forward);
}

#[test]
fn the_refusal_is_a_fixed_problem_answer() {
    let config = parsed();
    for route in routes(&config)
        .iter()
        .filter(|route| route["direct_response"]["status"] == 403)
    {
        let headers = route["response_headers_to_add"]
            .as_array()
            .expect("response headers");
        let header = |name: &str| {
            headers
                .iter()
                .find(|entry| entry["header"]["key"] == name)
                .map(|entry| entry["header"]["value"].as_str().unwrap().to_owned())
        };
        assert_eq!(
            header("content-type").as_deref(),
            Some("application/problem+json")
        );
        assert_eq!(header("cache-control").as_deref(), Some("no-store"));
        let body: Value =
            serde_json::from_str(route["direct_response"]["body"]["inline_string"].as_str().unwrap())
                .unwrap();
        let kind = ProblemKind::ALL
            .into_iter()
            .find(|kind| body["type"] == kind.type_uri())
            .expect("a registered problem type");
        assert_eq!(body["title"], kind.title());
        assert_eq!(body["status"], 403);
        assert_eq!(body["code"], kind.code());
    }
}

#[test]
fn method_override_headers_are_refused_on_every_path() {
    for header in ["x-http-method-override", "x-method-override", "x-http-method"] {
        for (method, path) in [
            ("POST", "/users/me"),
            ("GET", "/users/me"),
            ("POST", "/oauth2/token"),
            ("POST", "/users/me/update-credentials"),
        ] {
            assert_eq!(
                outcome(method, path, &[header]),
                Outcome::Refused {
                    status: 403,
                    problem: ProblemKind::MethodOverrideRefused.type_uri(),
                },
                "{header} on {method} {path}"
            );
        }
    }
}

#[test]
fn reading_the_record_changing_a_password_and_signing_in_pass() {
    for (method, path) in [
        ("GET", "/users/me"),
        ("OPTIONS", "/users/me"),
        ("GET", "/users/me/meta"),
        ("POST", "/users/me/update-credentials"),
        ("GET", "/oauth2/authorize"),
        ("POST", "/oauth2/token"),
        ("GET", "/oauth2/jwks"),
        ("POST", "/oauth2/auth/callback"),
        ("GET", "/.well-known/openid-configuration"),
        ("GET", "/flow/meta"),
        ("POST", "/flow/execute"),
        ("GET", "/gate/signin"),
        ("GET", "/gate/assets/index.js"),
        ("GET", "/design/resolve"),
        ("GET", "/i18n/languages"),
        ("GET", "/i18n/languages/en-US/translations/resolve"),
        ("GET", "/i18n/languages/en-US/translations/ns/flows/keys/title/resolve"),
    ] {
        assert_eq!(
            outcome(method, path, &[]),
            Outcome::Forwarded,
            "{method} {path}"
        );
    }
}

#[test]
fn admin_and_console_paths_are_not_routed() {
    for path in [
        "/console",
        "/console/",
        "/console/index.html",
        "/users",
        "/users/0193-user",
        "/users/me/groups",
        "/users/tree/registry",
        "/groups",
        "/organization-units",
        "/applications",
        "/agents",
        "/roles",
        "/resource-servers",
        "/connections",
        "/flows",
        "/design/themes",
        "/design/layouts",
        "/i18n/languages/en-US/translations",
        "/import",
        "/export",
        "/server-config",
        "/user-types",
        "/agent-types",
        "/health/liveness",
        "/mcp",
        "/auth/credentials/authenticate",
        "/register/passkey/start",
        "/access/v1/evaluation",
        "/oauth2/dcr/register",
        "/openid4vp/request",
        "/openid4vci/credential",
    ] {
        for method in ["GET", "POST"] {
            assert_eq!(
                outcome(method, path, &[]),
                Outcome::NotFound,
                "{method} {path}"
            );
        }
    }
}

#[test]
fn paths_are_normalised_and_escaped_slashes_refused() {
    let config = parsed();
    let manager = connection_manager(&config);
    assert_eq!(manager["normalize_path"], true);
    assert_eq!(manager["merge_slashes"], true);
    assert_eq!(manager["path_with_escaped_slashes_action"], "REJECT_REQUEST");
}

#[test]
fn the_gateway_listens_on_its_port_and_forwards_to_the_provider() {
    let config = parsed();
    let listener = &config["static_resources"]["listeners"][0]["address"]["socket_address"];
    assert_eq!(listener["port_value"], u64::from(LISTEN_PORT));
    let clusters = config["static_resources"]["clusters"].as_array().unwrap();
    assert_eq!(clusters.len(), 1);
    let endpoint = &clusters[0]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]
        ["endpoint"]["address"]["socket_address"];
    assert_eq!(endpoint["address"], PROVIDER_HOST);
    assert_eq!(endpoint["port_value"], u64::from(PROVIDER_PORT));
}

#[test]
fn the_problem_inventory_pins_its_wire_metadata() {
    for (kind, suffix) in [
        (ProblemKind::SelfServiceEditRefused, "self-service-edit-refused"),
        (ProblemKind::MethodOverrideRefused, "method-override-refused"),
    ] {
        assert_eq!(kind.code(), format!("identity.{suffix}"));
        assert_eq!(
            kind.type_uri(),
            format!("https://id.registrystack.org/problems/registry-platform/identity/{suffix}")
        );
        assert_eq!(kind.http_status(), 403);
        assert!(!kind.title().is_empty());
        assert!(!kind.description().is_empty());
    }
    assert_eq!(ProblemKind::ALL.len(), 2);
}

#[test]
fn the_file_names_the_version_and_says_the_provider_publishes_no_port() {
    let text = render("1.1.0");
    assert!(text.starts_with("# Generated for ThunderID 1.1.0"));
    assert!(text.contains("must publish no host port"));
}
