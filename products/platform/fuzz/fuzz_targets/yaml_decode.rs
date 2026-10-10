#![no_main]

//! Typed decoding through the shared configuration reader: a document type
//! that uses every shared value type, both union recipes, a shared block,
//! and an externally tagged enum, decoded with and without substitution.

mod yaml_support;

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use registry_platform_yaml::{
    shape_union, tagged_union, BoundedU32, BoundedU64, DataLiteral, Digest, Expect, ExternalId,
    Identified, LocalId, ProjectIdentity, Reader, UniqueIdList, UniqueList, Url,
};
use serde::Deserialize;
use yaml_support::{check_report, contains, Substitute, EXEMPT, FILE, FORMATS, MARKER};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Root {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/project"))]
    project: ProjectIdentity,
    title: Option<String>,
    port: Option<u16>,
    offset: Option<i32>,
    ratio: Option<f64>,
    enabled: Option<bool>,
    retention_days: Option<BoundedU32<1, 36500>>,
    maximum_bytes: Option<BoundedU64<1, 10_000_000_000>>,
    issuer_id: Option<ExternalId>,
    digest: Option<Digest>,
    endpoint: Option<Url>,
    value: Option<DataLiteral>,
    values: Option<Vec<DataLiteral>>,
    scopes: Option<UniqueList<String>>,
    steps: Option<UniqueIdList<Step>>,
    labels: Option<BTreeMap<String, String>>,
    source: Option<Source>,
    auth: Option<Auth>,
    audience: Option<Audience>,
    mode: Option<Mode>,
    pair: Option<(u8, String)>,
    listener: Option<Listener>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct Listener {
    bind: String,
    #[serde(alias = "portNumber")]
    port: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Step {
    id: LocalId,
    title: Option<String>,
}

impl Identified for Step {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
#[allow(dead_code)]
enum Source {
    Http {
        base_url: Url,
        timeout_seconds: Option<BoundedU32<1, 60>>,
    },
    File {
        path: String,
    },
    None {},
}
tagged_union!(Source);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
#[allow(dead_code)]
enum Auth {
    Bearer { token_ref: String },
    Basic { user_ref: String },
}

#[allow(dead_code)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
shape_union!(Audience { scalar => One, list => Many });

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
enum Mode {
    Strict,
    Lenient,
}

fuzz_target!(|data: &[u8]| {
    let forbid_marker = !contains(data, MARKER.as_bytes());
    let expect = Expect::new(FORMATS);

    match Reader::new(FILE).decode::<Root>(data, &expect) {
        Ok(decoded) => {
            check_report(&decoded.document.warnings(), false);
            if let Err(report) = decoded.document.decode_at::<Listener>("/listener") {
                check_report(&report, false);
            }
        }
        Err(report) => check_report(&report, false),
    }

    if let Err(report) = Reader::new(FILE).decode::<Root>(data, &Expect::one(&EXEMPT)) {
        check_report(&report, false);
    }

    let mut hook = Substitute;
    match Reader::new(FILE)
        .with_hook(&mut hook)
        .decode::<Root>(data, &expect)
    {
        Ok(decoded) => check_report(&decoded.document.warnings(), forbid_marker),
        Err(report) => check_report(&report, forbid_marker),
    }
});
