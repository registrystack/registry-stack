// SPDX-License-Identifier: Apache-2.0
//! The pure function profile carries the extra string helpers and the basic
//! number helpers. Calls to names the profile lacks are refused when the
//! project is checked, and `explain functions` lists what the profile has.
use registry_coordinator::{authoring, definition::Definition};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path, process::Command, time::Duration};

fn write_project(root: &Path, source: &str) {
    let workflow = json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id": "helpers", "version": "1"},
        "functions": {
            "probe": {"runtime":"rhai","source":"functions.rhai","entrypoint":"probe","inputs":{"request":{"type":"object"}},"output":{}}
        },
        "workflow": {"input": {"type": "object"}, "deadlineSeconds": 86400, "start": "done",
            "steps": {
                "done": {"type": "finish", "outcome": "measured", "output": {"type": "function", "function": "probe", "inputs": {"request":{"type": "input"}}}}
            }, "outcomes": {"measured": {}}
        }
    });
    fs::write(
        root.join("workflow.yaml"),
        serde_json::to_string(&workflow).unwrap(),
    )
    .unwrap();
    fs::write(root.join("functions.rhai"), source).unwrap();
}

fn load(body: &str) -> registry_coordinator::Result<Definition> {
    let root = tempfile::tempdir().unwrap();
    write_project(root.path(), &format!("fn probe(inputs) {{ {body} }}\n"));
    Definition::load(root.path())
}

fn run(body: &str, request: Value) -> registry_coordinator::Result<Value> {
    load(body)
        .unwrap()
        .evaluate("done", &request, &BTreeMap::new())
}

/// Run `work` on its own thread and fail the test if it does not finish, so a
/// native loop that never ends shows up as a failure instead of a hung run.
fn within<T: Send + 'static>(seconds: u64, work: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    receiver
        .recv_timeout(Duration::from_secs(seconds))
        .expect("the call returned in time")
}

fn cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(arguments)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap()
}

#[test]
fn string_helpers_work_in_the_pure_profile() {
    // trim, replace and pad change the string they are called on and return
    // nothing, so each works on its own copy.
    let value = run(
        r#"
        let text = inputs.request.text;
        let trimmed = text; trimmed.trim();
        let replaced = trimmed; replaced.replace("cd", "-");
        let padded = "7"; padded.pad(3, '0');
        #{
            trimmed: trimmed,
            upper: text.to_upper(),
            length: text.len(),
            starts: text.starts_with("  ab"),
            ends: text.ends_with("ef  "),
            contains: text.contains("cd"),
            index: text.index_of("cd"),
            part: text.sub_string(2, 4),
            split: "a,b,c".split(","),
            padded: padded,
            replaced: replaced,
        }
        "#,
        json!({"text": "  abcdef  "}),
    )
    .unwrap();
    assert_eq!(
        value,
        json!({
            "trimmed": "abcdef", "upper": "  ABCDEF  ", "length": 10,
            "starts": true, "ends": true, "contains": true, "index": 4,
            "part": "abcd", "split": ["a", "b", "c"], "padded": "700",
            "replaced": "ab-ef",
        })
    );
}

#[test]
fn number_helpers_work_in_the_pure_profile() {
    let value = run(
        r#"
        #{
            parsed: parse_int(inputs.request.digits),
            decimal: parse_float("2.5"),
            absolute: abs(-3),
            widened: to_float(2),
            truncated: to_int(2.7),
            floor: floor(2.7),
        }
        "#,
        json!({"digits": "1234"}),
    )
    .unwrap();
    assert_eq!(
        value,
        json!({"parsed": 1234, "decimal": 2.5, "absolute": 3, "widened": 2.0, "truncated": 2, "floor": 2.0})
    );
}

#[test]
fn helpers_that_make_longer_strings_stay_inside_the_string_budget() {
    // string_bytes is 16384: a pad, a replace and a doubling loop each stop
    // at the budget as an ordinary resource-limit refusal.
    for body in [
        r#"let s = "x"; s.pad(20000, 'x'); s"#,
        r#"let s = "x"; s.pad(20000, "ab"); s"#,
        r#"let s = ""; for n in 0..2000 { s += "abcdefghijklmnop"; } s"#,
        r#"let s = "aaaaaaaa"; s.replace("a", "0123456789012345678901234567890123456789"); s"#,
    ] {
        let source = body.replace("aaaaaaaa", &"a".repeat(1024));
        let error = run(&source, json!({})).unwrap_err();
        assert_eq!(error.code, "function.resource_limit", "{body}");
    }
}

#[test]
fn an_oversized_replace_reaches_a_loaded_project_as_a_resource_limit_refusal() {
    // This proves the refusal code through a loaded project. That the string is
    // refused before it is built is held by the unit test
    // `replace_refuses_before_it_builds_a_string_over_the_budget`; the engine's
    // own check afterwards gives the same code.
    let big = "a".repeat(16_000);
    let error = run(
        r#"let s = inputs.request.big; s.replace("a", inputs.request.big); s.len()"#,
        json!({"big": big}),
    )
    .unwrap_err();
    assert_eq!(error.code, "function.resource_limit");
}

#[test]
fn a_call_to_a_name_the_profile_lacks_is_refused_at_load_with_its_position_and_a_hint() {
    let error = load("parse_decimal(inputs.request.digits)")
        .err()
        .expect("unknown helper is refused");
    assert_eq!(error.code, "coordinator.function.unknown-call");
    assert!(
        error.message.contains("`parse_decimal`"),
        "{}",
        error.message
    );
    assert!(
        error
            .suggested_action
            .as_deref()
            .unwrap()
            .contains("coordinatorctl explain functions"),
        "{error:?}"
    );
    let source = error.diagnostics[0]
        .source
        .as_ref()
        .expect("a source position");
    assert_eq!(source.file, "functions.rhai");
    assert_eq!((source.line, source.column), (Some(1), Some(20)));
}

#[test]
fn every_unknown_call_is_reported_and_known_calls_and_local_functions_pass() {
    let root = tempfile::tempdir().unwrap();
    write_project(
        root.path(),
        "fn twice(n) { n * 2 }\nfn probe(inputs) {\n  let a = twice(parse_int(\"4\"));\n  let b = inputs.request.text.shout();\n  to_decimal(a) + frobnicate(b)\n}\n",
    );
    let output = cli(&[
        "--format",
        "json",
        "check",
        "--project",
        root.path().to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["code"] == "coordinator.function.unknown-call")
        .map(|d| d["message"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 3, "{report}");
    for name in ["shout", "to_decimal", "frobnicate"] {
        assert!(
            findings.iter().any(|m| m.contains(&format!("`{name}`"))),
            "{name}: {findings:?}"
        );
    }
    assert!(!findings
        .iter()
        .any(|m| m.contains("`twice`") || m.contains("`parse_int`")));
}

#[test]
fn explain_functions_lists_the_helpers_of_the_profile() {
    let output = cli(&["--format", "json", "explain", "functions"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let helpers = report["helpers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect::<Vec<_>>();
    for name in [
        "parse_int",
        "starts_with",
        "trim",
        "sub_string",
        "index_of",
        "split",
        "pad",
        "replace",
        "add_seconds",
        "seconds_between",
        "len",
        "push",
        "sqrt",
        "floor",
        "to_float",
    ] {
        assert!(helpers.contains(&name), "{name} missing from {helpers:?}");
    }
    for name in [
        "timestamp",
        "print",
        "eval",
        "rand",
        "sin",
        "exp",
        "ln",
        "hypot",
        "log",
    ] {
        assert!(!helpers.contains(&name), "{name} listed");
    }
    let mut sorted = helpers.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(helpers, sorted, "sorted and without repeats");
    assert!(report["interpreterAbi"].as_str().unwrap().contains("/v2;"));
    assert_eq!(report["limits"]["stringBytes"], 16384);

    let human = cli(&["explain", "functions"]);
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.starts_with("Pure function helpers"), "{text}");
    assert!(text.contains("parse_int"), "{text}");
    assert!(text.contains("Notes:"), "{text}");
    assert!(text.contains("global::NAME"), "{text}");
    assert!(text.contains("trim, replace and pad"), "{text}");
    let notes = report["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 2, "{notes:?}");
}

#[test]
fn explain_without_a_project_names_the_argument_and_its_help_lists_the_topic() {
    let output = cli(&["--format", "json", "explain"]);
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["message"],
        "missing required argument --project"
    );
    let help = cli(&["explain", "--help"]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("functions"), "{text}");
    assert!(text.contains("--project"), "{text}");
}

#[test]
fn pad_with_an_empty_padding_string_is_refused_instead_of_looping() {
    // The package pad loops forever on empty padding; the host overload
    // refuses it, whether the empty string is authored or arrives as input.
    for (body, request) in [
        (r#"let s = "a"; s.pad(5, ""); s"#, json!({})),
        (
            r#"let s = "a"; s.pad(5, inputs.request.fill); s"#,
            json!({"fill": ""}),
        ),
    ] {
        let error = within(10, move || run(body, request)).unwrap_err();
        assert_eq!(error.code, "function.execution", "{body}");
    }
}

#[test]
fn pad_with_a_string_fills_to_the_length_and_stops_at_the_budget() {
    let value = run(
        r#"
        let a = "x"; a.pad(6, "abc");
        let b = "hello"; b.pad(3, "abc");
        let c = "x"; c.pad(-4, "abc");
        let d = "é"; d.pad(4, "ñ😀");
        let e = "x"; e.pad(4, "abc");
        [a, b, c, d, e]
        "#,
        json!({}),
    )
    .unwrap();
    assert_eq!(value, json!(["xabcab", "hello", "x", "éñ😀ñ", "xabc"]));
    // 16384 characters of a 4-byte padding is 64 KiB: refused up front.
    for body in [
        r#"let s = ""; s.pad(16384, "😀"); s"#,
        r#"let s = ""; s.pad(9223372036854775807, "ab"); s"#,
    ] {
        let error = within(10, move || run(body, json!({}))).unwrap_err();
        assert_eq!(error.code, "function.resource_limit", "{body}");
    }
}

#[test]
fn package_string_helpers_end_on_empty_zero_and_extreme_arguments() {
    // Every MoreStringPackage function that loops or sizes a buffer from an
    // argument, called with empty, zero, negative and extreme values. Each must
    // return or refuse, never run on.
    let min = "(-9223372036854775807 - 1)";
    let max = "9223372036854775807";
    let calls = [
        r#"s.pad(0, 'x')"#.to_owned(),
        r#"s.pad(-1, 'x')"#.to_owned(),
        format!("s.pad({max}, 'x')"),
        format!("s.pad({min}, 'x')"),
        format!("s.pad({max}, \"ab\")"),
        format!("s.pad({min}, \"ab\")"),
        r#"s.split("")"#.to_owned(),
        r#"s.split(' ')"#.to_owned(),
        r#"s.split()"#.to_owned(),
        r#"s.split("", 0)"#.to_owned(),
        r#"s.split("", -1)"#.to_owned(),
        format!("s.split(\"\", {max})"),
        format!("s.split(' ', {min})"),
        r#"s.split_rev("")"#.to_owned(),
        r#"s.split_rev("", 0)"#.to_owned(),
        format!("s.split_rev(\"\", {max})"),
        format!("s.split({max})"),
        format!("s.split({min})"),
        r#"s.to_chars()"#.to_owned(),
        r#"s.index_of("")"#.to_owned(),
        format!("s.index_of(\"\", {max})"),
        format!("s.index_of(\"o\", {min})"),
        format!("s.index_of('o', {max})"),
        format!("s.index_of('o', {min})"),
        format!("s.sub_string({max}, {max})"),
        format!("s.sub_string({min}, {max})"),
        format!("s.sub_string(0, {min})"),
        format!("s.sub_string({min})"),
        format!("s.sub_string({max})"),
        "s.sub_string(0..3)".to_owned(),
        "s.sub_string(0..=3)".to_owned(),
        format!("s.crop({max}, {max})"),
        format!("s.crop({min}, {max})"),
        format!("s.crop(0, {min})"),
        format!("s.crop({min})"),
        format!("s.crop({max})"),
        "s.crop(0..3)".to_owned(),
        "s.crop(0..=3)".to_owned(),
        format!("s.truncate({max})"),
        format!("s.truncate({min})"),
        "s.truncate(0)".to_owned(),
        r#"s.trim()"#.to_owned(),
        r#"s.remove("")"#.to_owned(),
        r#"s.remove('z')"#.to_owned(),
        r#"s.replace("", "")"#.to_owned(),
        r#"s.replace("", "ab")"#.to_owned(),
        r#"s.replace('l', 'ñ')"#.to_owned(),
        r#"s.pop(0)"#.to_owned(),
        format!("s.pop({max})"),
        format!("s.pop({min})"),
        "s.pop()".to_owned(),
        format!("s.get({max})"),
        format!("s.get({min})"),
        format!("s.set({max}, 'x')"),
        format!("s.set({min}, 'x')"),
        "s.to_blob()".to_owned(),
        "s.make_upper()".to_owned(),
        "s.make_lower()".to_owned(),
        "s.bytes".to_owned(),
        "s.contains(\"\")".to_owned(),
        "s.starts_with(\"\")".to_owned(),
        "s.ends_with(\"\")".to_owned(),
    ];
    for call in calls {
        let body = format!("let s = \"héllo wörld\"; let r = {call}; [r, s]");
        let outcome = within(10, move || run(&body, json!({})));
        if let Err(error) = outcome {
            assert!(
                [
                    "function.execution",
                    "function.resource_limit",
                    "function.output"
                ]
                .contains(&error.code.as_ref()),
                "{call}: {error:?}"
            );
        }
    }
}

#[test]
fn only_math_whose_result_is_the_same_on_every_host_is_available() {
    // Function results are recomputed when waits replay, so a result that
    // differs by host libm would change a frozen definition's meaning.
    for name in [
        "sin(1.0)",
        "cos(1.0)",
        "tan(1.0)",
        "sinh(1.0)",
        "cosh(1.0)",
        "tanh(1.0)",
        "asin(0.5)",
        "acos(0.5)",
        "atan(0.5)",
        "atan(1.0, 2.0)",
        "asinh(1.0)",
        "acosh(2.0)",
        "atanh(0.5)",
        "hypot(3.0, 4.0)",
        "exp(1.0)",
        "ln(2.0)",
        "log(8.0, 2.0)",
        "log(100.0)",
    ] {
        let error = load(name)
            .err()
            .unwrap_or_else(|| panic!("{name} is available"));
        assert_eq!(error.code, "coordinator.function.unknown-call", "{name}");
    }
    let value = run(
        r#"
        let x = inputs.request.x;
        #{
            sqrt: sqrt(16.0), floor: floor(2.7), ceiling: ceiling(2.1), round: round(2.5),
            int: int(-2.7), fraction: fraction(2.25), nan: is_nan(x), finite: is_finite(1.0),
            infinite: is_infinite(1.0), pi: PI() > 3.14, e: E() > 2.71, deg: to_degrees(PI()),
            rad: to_radians(180.0) > 3.14, parsed: parse_float("2.5"), widened: to_float(3),
            narrowed: to_int(2.7), from_char: to_int('a'), radix: parse_int("ff", 16),
            getter: 2.7.floor, abs: abs(-2.5), sign: sign(-2.5), min: min(1.0, 2.0), max: max(1, 2),
        }
        "#,
        json!({"x": 1.0}),
    )
    .unwrap();
    assert_eq!(
        value,
        json!({
            "sqrt": 4.0, "floor": 2.0, "ceiling": 3.0, "round": 3.0, "int": -2.0, "fraction": 0.25,
            "nan": false, "finite": true, "infinite": false, "pi": true, "e": true, "deg": 180.0,
            "rad": true, "parsed": 2.5, "widened": 3.0, "narrowed": 2, "from_char": 97,
            "radix": 255, "getter": 2.0, "abs": 2.5, "sign": -1, "min": 1.0, "max": 2,
        })
    );
}

#[test]
fn a_result_holding_nan_or_infinity_is_refused_not_turned_into_null() {
    for body in [
        "0.0 / 0.0",
        "1.0 / 0.0",
        "-1.0 / 0.0",
        "sqrt(-1.0)",
        "#{ a: [1, 2.0 * (1.0 / 0.0)] }",
        "[#{ deep: 0.0 / 0.0 }]",
        "parse_float(\"inf\")",
        "parse_float(\"NaN\")",
    ] {
        let error = run(body, json!({})).unwrap_err();
        assert_eq!(error.code, "function.execution", "{body}");
    }
    // Finite numbers, and a NaN that is only tested, still pass.
    assert_eq!(
        run("[1.5, is_nan(0.0 / 0.0)]", json!({})).unwrap(),
        json!([1.5, true])
    );
}

fn unknown_call_names(source: &str) -> Vec<String> {
    let root = tempfile::tempdir().unwrap();
    write_project(root.path(), source);
    let output = cli(&[
        "--format",
        "json",
        "check",
        "--project",
        root.path().to_str().unwrap(),
    ]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut names = report["diagnostics"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|d| d["code"] == "coordinator.function.unknown-call")
        .map(|d| {
            let message = d["message"].as_str().unwrap();
            message.split('`').nth(1).unwrap().to_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn a_method_call_on_a_function_pointer_property_is_not_refused() {
    let source = "fn twice(n) { n * 2 }
fn probe(inputs) {
  let m = #{ f: Fn(\"twice\") };
  m.g = Fn(\"twice\");
  m.h = Fn(\"twice\");
  [m.f(1), m.g(2), m[\"i\"] = Fn(\"twice\"), m.i(3)]
}
";
    assert_eq!(unknown_call_names(source), Vec::<String>::new());
    let source =
        "fn twice(n) { n * 2 }\nfn probe(inputs) { let m = #{ f: Fn(\"twice\") }; m.f(1) }\n";
    assert_eq!(unknown_call_names(source), Vec::<String>::new());
    // A method name the source never uses as a key or property is still refused.
    let source = "fn probe(inputs) { let m = #{ f: 1 }; m.shout(1) }\n";
    assert_eq!(unknown_call_names(source), ["shout"]);
}

#[test]
fn a_function_name_given_as_a_string_literal_is_checked() {
    let source = r#"fn twice(n) { n * 2 }
fn probe(inputs) {
  let a = call(Fn("nope_a"));
  let b = Fn("nope_b").call();
  let c = curry(Fn("nope_c"), 1);
  let d = [1].map(Fn("nope_d"));
  let e = [1].map("nope_e");
  let f = is_def_fn("nope_f", 1);
  let g = [1].filter("nope_g");
  let h = [1].reduce("nope_h");
  #{ a: a, b: b, c: c, d: d, e: e, f: f, g: g, h: h }
}
"#;
    assert_eq!(
        unknown_call_names(source),
        ["nope_a", "nope_b", "nope_c", "nope_d", "nope_e", "nope_f", "nope_g", "nope_h"]
    );
    // Known names, local functions and string search arguments pass.
    let source = r#"fn twice(n) { n * 2 }
fn probe(inputs) {
  let s = "text";
  [Fn("twice"), [1].map("twice"), [1].map(Fn("abs")), is_def_fn("twice", 1),
   s.index_of("nope"), s.contains("nope"), s.split("nope"), s.replace("nope", "x")]
}
"#;
    assert_eq!(unknown_call_names(source), Vec::<String>::new());
}
