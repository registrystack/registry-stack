#![no_main]

//! The shared configuration reader over arbitrary bytes: the YAML subset,
//! the envelope, and substitution, with the report invariants in
//! `yaml_support`. The seed corpus includes nesting far past the depth bound.

mod yaml_support;

use libfuzzer_sys::fuzz_target;
use registry_platform_yaml::{Expect, Reader};
use yaml_support::{check_report, contains, Substitute, EXEMPT, FILE, FORMATS, MARKER};

fuzz_target!(|data: &[u8]| {
    let forbid_marker = !contains(data, MARKER.as_bytes());

    match Reader::new(FILE).scan(data) {
        Ok(Some(root)) => {
            let _ = root.to_json_value();
        }
        Ok(None) => {}
        Err(report) => check_report(&report, false),
    }

    match Reader::new(FILE).read(data, &Expect::new(FORMATS)) {
        Ok(document) => {
            let _ = document.to_json_value();
            check_report(&document.warnings(), false);
            if let Err(report) = document.decode::<serde_json::Value>() {
                check_report(&report, false);
            }
        }
        Err(report) => check_report(&report, false),
    }

    if let Err(report) = Reader::new(FILE).read(data, &Expect::one(&EXEMPT)) {
        check_report(&report, false);
    }

    let mut hook = Substitute;
    match Reader::new(FILE)
        .with_hook(&mut hook)
        .read(data, &Expect::new(FORMATS))
    {
        Ok(document) => {
            check_report(&document.warnings(), forbid_marker);
            if let Err(report) = document.decode::<serde_json::Value>() {
                check_report(&report, forbid_marker);
            }
        }
        Err(report) => check_report(&report, forbid_marker),
    }
});
