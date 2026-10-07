// SPDX-License-Identifier: Apache-2.0
//! Formats a reader accepts and the envelope check (CFG-ENV-1, CFG-CHANGE-2).

use crate::messages::{self, Problem};
use crate::node::{Node, NodeValue, Position};

/// Whether a declared `apiVersion` is current or on its way out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionStatus {
    Current,
    /// Accepted with a `config.deprecated-api-version` warning.
    Deprecated,
}

/// One `apiVersion` a format accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiVersion<'a> {
    pub name: &'a str,
    pub status: VersionStatus,
}

impl<'a> ApiVersion<'a> {
    pub const fn current(name: &'a str) -> ApiVersion<'a> {
        ApiVersion {
            name,
            status: VersionStatus::Current,
        }
    }

    pub const fn deprecated(name: &'a str) -> ApiVersion<'a> {
        ApiVersion {
            name,
            status: VersionStatus::Deprecated,
        }
    }
}

/// An `apiVersion` the format no longer accepts, with the sentence that says
/// what to do instead (CFG-CHANGE-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredApiVersion<'a> {
    pub api_version: &'a str,
    pub replacement: &'a str,
}

/// A key a format removed or renamed (CFG-CHANGE-2). `pointer` is an RFC 6901
/// pointer in which a `*` segment matches any key or list index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemovedKey<'a> {
    pub pointer: &'a str,
    /// A sentence naming what to write instead.
    pub replacement: &'a str,
}

/// How a format's documents identify themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeRule<'a> {
    /// The top-level mapping carries `apiVersion` and `kind` (CFG-ENV-1).
    ApiVersionKind {
        api_versions: &'a [ApiVersion<'a>],
        retired_api_versions: &'a [RetiredApiVersion<'a>],
    },
    /// The format is registered as an exception to CFG-ENV-1 and carries no
    /// envelope. An exempt format is read alone: it is the only format in
    /// its [`Expect`].
    Exempt { reason: &'a str },
}

/// One format a reader accepts. A format is usually a `const`; the lifetime
/// lets a caller that learns its format at run time build one as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormatSpec<'a> {
    pub kind: &'a str,
    pub envelope: EnvelopeRule<'a>,
    pub removed_keys: &'a [RemovedKey<'a>],
}

impl<'a> FormatSpec<'a> {
    fn accepted_versions(&self) -> Vec<&'a str> {
        match self.envelope {
            EnvelopeRule::ApiVersionKind { api_versions, .. } => {
                api_versions.iter().map(|version| version.name).collect()
            }
            EnvelopeRule::Exempt { .. } => Vec::new(),
        }
    }

    fn current_versions(&self) -> Vec<&'a str> {
        match self.envelope {
            EnvelopeRule::ApiVersionKind { api_versions, .. } => api_versions
                .iter()
                .filter(|version| version.status == VersionStatus::Current)
                .map(|version| version.name)
                .collect(),
            EnvelopeRule::Exempt { .. } => Vec::new(),
        }
    }
}

/// The formats one read accepts. A command that reads one format passes
/// one; a command that dispatches on `kind` passes several.
#[derive(Clone, Copy, Debug)]
pub struct Expect<'a> {
    formats: &'a [FormatSpec<'a>],
}

impl<'a> Expect<'a> {
    /// Accept any of `formats`.
    ///
    /// # Panics
    ///
    /// When `formats` is empty, or when an exempt format is not alone.
    pub const fn new(formats: &'a [FormatSpec<'a>]) -> Expect<'a> {
        assert!(!formats.is_empty(), "a reader accepts at least one format");
        if formats.len() > 1 {
            let mut index = 0;
            while index < formats.len() {
                assert!(
                    matches!(formats[index].envelope, EnvelopeRule::ApiVersionKind { .. }),
                    "an exempt format is read alone"
                );
                index += 1;
            }
        }
        Expect { formats }
    }

    /// Accept exactly `format`.
    pub const fn one(format: &'a FormatSpec<'a>) -> Expect<'a> {
        Expect::new(std::slice::from_ref(format))
    }

    pub fn formats(&self) -> &'a [FormatSpec<'a>] {
        self.formats
    }

    fn kinds(&self) -> Vec<&'a str> {
        self.formats.iter().map(|format| format.kind).collect()
    }

    /// The kind diagnostics carry before the document's own is known.
    pub(crate) fn default_artifact(&self) -> Option<&'a str> {
        match self.formats {
            [only] => Some(only.kind),
            _ => None,
        }
    }

    fn start_phrase(&self) -> String {
        match self.formats {
            [only] => match only.current_versions().first() {
                Some(version) => format!("`apiVersion: {version}` and `kind: {}`", only.kind),
                None => format!("apiVersion and `kind: {}`", only.kind),
            },
            _ => format!(
                "apiVersion and kind for one of {}",
                messages::list(&self.kinds())
            ),
        }
    }
}

/// What the envelope check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The kind of the matched format.
    pub kind: String,
    /// The document's `apiVersion`, absent for an exempt format.
    pub api_version: Option<String>,
}

pub(crate) struct EnvelopeOutcome {
    pub matched: Option<(usize, Envelope)>,
    pub problems: Vec<Problem>,
    pub warnings: Vec<Problem>,
}

/// `reported` says whether a problem was already reported at a pointer.
pub(crate) fn check(
    root: Option<&Node>,
    expect: &Expect<'_>,
    reported: impl Fn(&str) -> bool,
) -> EnvelopeOutcome {
    let mut outcome = EnvelopeOutcome {
        matched: None,
        problems: Vec::new(),
        warnings: Vec::new(),
    };
    if let [only] = expect.formats {
        if matches!(only.envelope, EnvelopeRule::Exempt { .. }) {
            if root.is_none() {
                outcome.problems.push(Problem::error(
                    "config.invalid-type",
                    "",
                    Some(Position::START),
                    messages::empty_exempt_document(only.kind),
                ));
                return outcome;
            }
            outcome.matched = Some((
                0,
                Envelope {
                    kind: only.kind.to_owned(),
                    api_version: None,
                },
            ));
            return outcome;
        }
    }
    let start = expect.start_phrase();
    let root = match root {
        None
        | Some(Node {
            value: NodeValue::Null,
            ..
        }) => {
            outcome.problems.push(Problem::error(
                "config.missing-envelope",
                "",
                Some(Position::START),
                messages::missing_envelope(&start),
            ));
            return outcome;
        }
        Some(root) => root,
    };
    let NodeValue::Mapping(_) = &root.value else {
        outcome.problems.push(Problem::error(
            "config.invalid-type",
            "",
            Some(root.span.start),
            messages::root_not_mapping(root.kind_phrase(), &start),
        ));
        return outcome;
    };
    // The top-level mapping has no key, so a missing envelope member is
    // reported where the mapping starts.
    let api_version = root.get("apiVersion");
    let kind = root.get("kind");
    let missing: Vec<&str> = [
        ("apiVersion", api_version.is_none()),
        ("kind", kind.is_none()),
    ]
    .into_iter()
    .filter_map(|(member, absent)| absent.then_some(member))
    .collect();
    if !missing.is_empty() {
        outcome.problems.push(Problem::error(
            "config.missing-envelope",
            "",
            Some(root.span.start),
            messages::missing_envelope_members(&missing, &start),
        ));
    }
    // A member already refused, such as one whose substitution a hook
    // refused, names no format: matching it would repeat the refusal in other
    // words.
    let api_version = api_version.filter(|_| !reported("/apiVersion"));
    let api_version = api_version.and_then(|entry| {
        text_member(
            &entry.value,
            "/apiVersion",
            "apiVersion",
            &mut outcome.problems,
        )
    });
    let kind_entry = kind.filter(|_| !reported("/kind"));
    let kind = kind_entry
        .and_then(|entry| text_member(&entry.value, "/kind", "kind", &mut outcome.problems));
    let Some(kind) = kind else {
        return outcome;
    };
    let Some((index, format)) = expect
        .formats
        .iter()
        .enumerate()
        .find(|(_, format)| format.kind == kind)
    else {
        let at = kind_entry.map(|entry| entry.value.span.start);
        outcome.problems.push(Problem::error(
            "config.wrong-kind",
            "/kind",
            at,
            messages::wrong_kind(&expect.kinds()),
        ));
        return outcome;
    };
    let Some(version) = api_version else {
        return outcome;
    };
    let EnvelopeRule::ApiVersionKind {
        api_versions,
        retired_api_versions,
    } = format.envelope
    else {
        return outcome;
    };
    let version_at = root.get("apiVersion").map(|entry| entry.value.span.start);
    match api_versions
        .iter()
        .find(|declared| declared.name == version)
    {
        Some(declared) => {
            if declared.status == VersionStatus::Deprecated {
                let mut warning = Problem::error(
                    "config.deprecated-api-version",
                    "/apiVersion",
                    version_at,
                    messages::deprecated_api_version(declared.name, &format.current_versions()),
                );
                warning.severity = crate::diagnostic::Severity::Warning;
                outcome.warnings.push(warning);
            }
            outcome.matched = Some((
                index,
                Envelope {
                    kind: format.kind.to_owned(),
                    api_version: Some(declared.name.to_string()),
                },
            ));
        }
        None => match retired_api_versions
            .iter()
            .find(|retired| retired.api_version == version)
        {
            Some(retired) => outcome.problems.push(Problem::error(
                "config.retired-api-version",
                "/apiVersion",
                version_at,
                messages::retired_api_version(
                    retired.api_version,
                    &format.current_versions(),
                    retired.replacement,
                ),
            )),
            None => outcome.problems.push(Problem::error(
                "config.unsupported-api-version",
                "/apiVersion",
                version_at,
                messages::unsupported_api_version(format.kind, &format.accepted_versions()),
            )),
        },
    }
    outcome
}

fn text_member<'n>(
    node: &'n Node,
    pointer: &str,
    member: &str,
    problems: &mut Vec<Problem>,
) -> Option<&'n str> {
    match &node.value {
        // The envelope names the format before any substitution can apply
        // (CFG-ENV-1), so a hook's replacement is refused here as well.
        NodeValue::String(text) if text.substituted => {
            problems.push(Problem::error(
                "config.substitution-not-allowed",
                pointer,
                Some(node.span.start),
                messages::envelope_substituted(member),
            ));
            None
        }
        NodeValue::String(text) => Some(&text.text),
        _ => {
            problems.push(Problem::error(
                "config.expected-string",
                pointer,
                Some(node.span.start),
                messages::envelope_not_string(member),
            ));
            None
        }
    }
}
