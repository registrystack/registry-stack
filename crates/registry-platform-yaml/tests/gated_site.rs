// SPDX-License-Identifier: Apache-2.0
//! A development-only newtype learns where it sits in the document.
mod common;

use common::{codes, decode, refusal};
use registry_platform_yaml::{gated_site, tagged_union, GatedSite, DEVELOPMENT_ONLY};
use serde::de::{Deserializer, Visitor};
use serde::Deserialize;

/// A stand-in for a gate type: it asks for `DEVELOPMENT_ONLY`, reads the site
/// before it decodes the value, and keeps it.
#[derive(Debug)]
struct Probe {
    site: Option<GatedSite>,
}

impl<'de> Deserialize<'de> for Probe {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reads;
        impl<'de> Visitor<'de> for Reads {
            type Value = Probe;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a probed value")
            }
            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                inner: D,
            ) -> Result<Probe, D::Error> {
                let site = gated_site();
                bool::deserialize(inner)?;
                Ok(Probe { site })
            }
        }
        deserializer.deserialize_newtype_struct(DEVELOPMENT_ONLY, Reads)
    }
}

fn site(pointer: &str, exact: bool) -> (String, bool) {
    (pointer.to_string(), exact)
}

fn seen(probe: &Probe) -> (String, bool) {
    let site = probe.site.as_ref().expect("the reader sets the site");
    assert!(site.position.is_some(), "the site carries a position");
    (site.pointer.clone(), site.exact)
}

#[derive(Debug, Deserialize)]
struct Inner {
    b: Probe,
}

#[derive(Debug, Deserialize)]
struct Outer {
    a: Inner,
}

#[derive(Debug, Deserialize)]
struct Listed {
    a: Vec<Inner>,
}

#[test]
fn a_member_has_an_exact_pointer() {
    let read: Outer = decode("a:\n  b: true\n").unwrap();
    assert_eq!(seen(&read.a.b), site("/a/b", true));
}

#[test]
fn a_list_item_has_an_exact_pointer() {
    let read: Listed = decode("a:\n  - b: true\n").unwrap();
    assert_eq!(seen(&read.a[0].b), site("/a/0/b", true));
}

#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum Source {
    Http { gate: Probe },
    None {},
}
tagged_union!(Source);

#[derive(Debug, Deserialize)]
struct Sourced {
    source: Source,
}

#[test]
fn a_member_of_a_tagged_union_variant_has_an_exact_pointer() {
    let read: Sourced = decode("source:\n  type: http\n  gate: true\n").unwrap();
    let Source::Http { gate } = read.source else {
        panic!("an http source");
    };
    assert_eq!(seen(&gate), site("/source/gate", true));
}

#[derive(Debug, Deserialize)]
struct Flattened {
    #[serde(flatten)]
    shared: Shared,
}

#[derive(Debug, Deserialize)]
struct Shared {
    allow: Probe,
}

#[derive(Debug, Deserialize)]
struct Host {
    issuer: Flattened,
}

#[test]
fn under_flatten_the_site_is_the_parent_mapping_and_inexact() {
    let read: Host = decode("issuer:\n  allow: true\n").unwrap();
    assert_eq!(seen(&read.issuer.shared.allow), site("/issuer", false));
}

#[test]
fn the_site_is_cleared_after_a_decode_and_after_a_decode_error() {
    assert_eq!(gated_site(), None);
    let _: Outer = decode("a:\n  b: true\n").unwrap();
    assert_eq!(gated_site(), None);
    let _: Host = decode("issuer:\n  allow: true\n").unwrap();
    assert_eq!(gated_site(), None);
    let report = refusal::<Outer>("a:\n  b: true\n  extra: 1\n");
    assert_eq!(codes(&report), ["config.unknown-key"]);
    assert_eq!(gated_site(), None);
    let report = refusal::<Outer>("a:\n  b: 7\n");
    assert_eq!(codes(&report), ["config.expected-boolean"]);
    assert_eq!(gated_site(), None);
}

#[test]
fn a_panic_while_the_site_is_set_restores_the_previous_site() {
    #[derive(Debug)]
    struct Boom;
    impl<'de> Deserialize<'de> for Boom {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Panics;
            impl<'de> Visitor<'de> for Panics {
                type Value = Boom;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a value")
                }
                fn visit_newtype_struct<D: Deserializer<'de>>(
                    self,
                    _: D,
                ) -> Result<Boom, D::Error> {
                    assert!(gated_site().is_some());
                    panic!("a decoder bug");
                }
            }
            deserializer.deserialize_newtype_struct(DEVELOPMENT_ONLY, Panics)
        }
    }
    #[derive(Debug, Deserialize)]
    struct Wrapper {
        _a: Boom,
    }
    let result = std::panic::catch_unwind(|| decode::<Wrapper>("_a: true\n"));
    assert!(result.is_err());
    assert_eq!(gated_site(), None);
}
