// SPDX-License-Identifier: Apache-2.0
//! The project's OpenAPI description, analysed the way `registry-evidencectl` resolves an operation in
//! it.
//!
//! A question written in the compact form names no source document. It names an operation of
//! `source.openapi.yaml`, selects its subject by one of that operation's path parameters, and
//! projects its facts out of that operation's response. None of those names is declared by an
//! authored document, so the edges that spell them can only be resolved by reading the description,
//! which is the one project file [`crate::evidence::load_project_documents`] deliberately leaves on
//! disk.
//!
//! Reading it is bounded twice, and both bounds start from the opened descriptor's size before its
//! bytes are read, because a ceiling applied only after the read has already paid for the read.
//! The bounded descriptor read checks both against the bytes actually returned as well, because an
//! authored file may grow after it is opened.
//! [`MAX_OPENAPI_BYTES`] is the authoring form's own ceiling on this document and bounds the
//! semantic reading: past it there is no analysis, which is exactly what the compiler does with the
//! same file. [`MAX_POSITION_BYTES`] bounds only the second, positional reading: past it the
//! description is still analysed, so an operation still resolves and the three edges that depend on
//! one are still checked, and only the place a definition points at degrades to the start of the
//! file. Degrading there is the whole point. Refusing to analyse a description because it is too
//! large to index positions in would leave every compact-form question in a large project reporting
//! nothing, and refusing to resolve its operation would report a project the compiler builds.
//!
//! Everything here is read the way `unique_operation`
//! (`crates/registry-evidencectl/src/authoring.rs:1532-1573`) and `exact_path_selectors`
//! (`crates/registry-evidencectl/src/authoring.rs:1575-1646`) read it, and where those two refuse a
//! document outright this module produces no analysis at all. That is the quiet direction: a
//! description the compiler will not read is one the editor says nothing about, rather than one it
//! guesses at.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
};

use ls_types::Range;
use registry_evidence_authoring::{
    layout::{MAX_OPENAPI_BYTES, OPENAPI_FILE},
    openapi::{openapi::Spec, selectable_leaves, types::OperationKey},
};
use serde_json::{Map, Value};

use crate::{
    refs::DOCUMENT_START,
    yaml::{parse_yaml, YamlValue},
};

/// The eight HTTP methods an `operationId` may be published under, in the order
/// `crates/registry-evidencectl/src/authoring.rs:1533-1535` spells them.
///
/// All eight, not just `get`. The compiler resolves an identifier across every one of them and only
/// then refuses a resolved operation whose method is not `get`, with a sentence about the method. An
/// editor that looked only at `get` would tell an author that a name the description really
/// publishes is not published, which is a sentence the compiler never prints.
const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// How large `source.openapi.yaml` may be for the editor to record where each operation is written.
///
/// The position index is a second parse of the same text, and it exists only so that "go to
/// definition" lands on the line that publishes an operation rather than on the top of the file.
/// That is worth one megabyte and not sixteen.
const MAX_POSITION_BYTES: u64 = 1024 * 1024;

/// How many operations' response leaves one build keeps.
///
/// Flattening a response is the expensive half of this module and a project may name many
/// operations, so what has been flattened is kept and the rest is recomputed. The ceiling bounds
/// what is retained and never what is answered: past it a leaf set is still computed and still
/// returned, so nothing the editor reports depends on what it happened to have kept.
const MAX_RETAINED_LEAF_SETS: usize = 32;

/// One operation the description publishes an identifier for.
#[derive(Debug)]
pub struct PublishedOperation {
    /// The operation as the compiler names it when it reads the response schema:
    /// `crates/registry-evidencectl/src/authoring.rs:1653-1656` uppercases the method.
    pub key: OperationKey,
    /// Where the `operationId` is written, or the start of the file past [`MAX_POSITION_BYTES`].
    pub range: Range,
    /// The operation's required string path parameters, and `None` when the parameters are not
    /// readable the way `exact_path_selectors` reads them. `None` is not "no parameters": it is
    /// "this editor does not know", and the caller must stay quiet on it.
    pub selectors: Option<BTreeSet<String>>,
}

/// One reading of a project's description, and the response leaves asked for during one build.
pub struct Description {
    analysis: Arc<Analysis>,
    leaves: BTreeMap<(String, String), Option<Arc<BTreeSet<String>>>>,
}

/// A required retained description that the compiler cannot read or version-check.
pub struct DescriptionFailure {
    path: PathBuf,
    message: String,
}

impl DescriptionFailure {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// The part of a reading that depends only on the text, so it can be kept between builds.
#[derive(Debug)]
struct Analysis {
    path: PathBuf,
    operations: BTreeMap<String, Vec<PublishedOperation>>,
    spec: Spec,
}

impl Description {
    /// Analyse the retained description text supplied by the host adapter.
    ///
    /// An unreadable document or one without a supported OpenAPI version is an error because the
    /// compiler stops there before reading dependent inputs. `Ok(None)` is reserved for later
    /// structural analysis that cannot safely publish operations.
    pub fn from_text(path: &Path, text: &str) -> Result<Option<Self>, DescriptionFailure> {
        let size = u64::try_from(text.len()).unwrap_or(u64::MAX);
        if size > MAX_OPENAPI_BYTES {
            return Err(description_failure(
                path.to_path_buf(),
                format!(
                    "The retained OpenAPI description exceeds its {MAX_OPENAPI_BYTES}-byte limit"
                ),
            ));
        }
        let analysis = analysis_for(path, text, size <= MAX_POSITION_BYTES)
            .map_err(|message| description_failure(path.to_path_buf(), message))?;
        Ok(analysis.map(|analysis| Self {
            analysis,
            leaves: BTreeMap::new(),
        }))
    }

    /// The file the description was read from, which is where its operations are defined.
    pub fn path(&self) -> &Path {
        &self.analysis.path
    }

    /// Every operation identifier the description publishes, with the operation carrying it. An
    /// identifier two operations publish appears twice, because that is what makes it ambiguous.
    pub fn published(&self) -> impl Iterator<Item = (&str, &PublishedOperation)> {
        self.analysis
            .operations
            .iter()
            .flat_map(|(id, operations)| operations.iter().map(move |o| (id.as_str(), o)))
    }

    /// The one operation `operation_id` names, when exactly one operation carries it.
    ///
    /// Exactly one is the compiler's own condition: `unique_operation` refuses none and refuses two
    /// with the same sentence (`crates/registry-evidencectl/src/authoring.rs:1565-1567`), and it
    /// reads nothing further about the question in either case.
    pub fn resolved(&self, operation_id: &str) -> Option<&PublishedOperation> {
        match self.analysis.operations.get(operation_id)?.as_slice() {
            [operation] => Some(operation),
            _ => None,
        }
    }

    /// The pointers an author may select from one operation's response, and `None` when that
    /// response cannot be read or flattened.
    ///
    /// The set is [`selectable_leaves`], the function the compiler selects against
    /// (`crates/registry-evidencectl/src/authoring.rs:1661`), asked the same question about the same
    /// operation. There is no second flattening here and there must never be one: an editor
    /// offering a different set from the compiler's would refuse paths the build accepts.
    pub fn selectable(&mut self, key: &OperationKey) -> Option<Arc<BTreeSet<String>>> {
        let retained = (key.method.clone(), key.path.clone());
        if let Some(leaves) = self.leaves.get(&retained) {
            return leaves.clone();
        }
        let leaves = selectable_leaves(&self.analysis.spec, key)
            .ok()
            .map(|leaves| {
                Arc::new(
                    leaves
                        .into_iter()
                        .map(|leaf| leaf.pointer)
                        .collect::<BTreeSet<_>>(),
                )
            });
        if self.leaves.len() < MAX_RETAINED_LEAF_SETS {
            self.leaves.insert(retained, leaves.clone());
        }
        leaves
    }
}

/// The one description kept between index builds.
///
/// A rebuild happens on every keystroke in any project document, and the description is the one
/// document that changes for none of them. A client may well be sending its buffer: an editor whose
/// selector is every YAML file sends this one like any other. The buffer is not what is read here.
/// The description is read from the root's own path so that what an operation resolves against is
/// the file the compiler will open, rather than a half-finished edit whose errors would be drawn
/// across every question in the project at once, and so that a document the form allows to reach
/// 16 MiB goes through a semantic parse when it is saved rather than between one keystroke and the
/// next. Re-reading its text every time is cheap and is what proves the entry is still current;
/// re-parsing and re-flattening it every time is neither.
///
/// One entry, because an author edits one project at a time and a second root costs exactly what no
/// memo at all would cost. The entry holds the text it was built from rather than a size and a
/// timestamp: a description that changed within a filesystem's timestamp resolution would otherwise
/// keep answering with names it no longer publishes, and reporting an operation an author has just
/// written as one the description does not publish is the failure this whole module is written to
/// avoid.
static MEMO: Mutex<Option<Memo>> = Mutex::new(None);

struct Memo {
    path: PathBuf,
    text: String,
    /// Kept even when it is unavailable or invalid, so a description that does not analyse is not
    /// re-parsed on every keystroke elsewhere in the project.
    analysis: Result<Option<Arc<Analysis>>, String>,
}

fn description_failure(path: PathBuf, message: impl Into<String>) -> DescriptionFailure {
    DescriptionFailure {
        path,
        message: message.into(),
    }
}

pub fn missing_description(path: PathBuf) -> DescriptionFailure {
    description_failure(
        path,
        "The required source.openapi.yaml is missing or is not a regular project file",
    )
}

pub fn unavailable_description(path: PathBuf, message: impl Into<String>) -> DescriptionFailure {
    description_failure(path, message)
}

fn analysis_for(
    path: &Path,
    text: &str,
    index_positions: bool,
) -> Result<Option<Arc<Analysis>>, String> {
    let mut memo = MEMO.lock().unwrap_or_else(PoisonError::into_inner);
    reuse_or_parse(&mut memo, path, text, index_positions)
}

/// The memo's whole rule, apart from the lock, so it can be exercised without one.
fn reuse_or_parse(
    memo: &mut Option<Memo>,
    path: &Path,
    text: &str,
    index_positions: bool,
) -> Result<Option<Arc<Analysis>>, String> {
    if let Some(held) = memo
        .as_ref()
        .filter(|held| held.path == path && held.text == text)
    {
        return held.analysis.clone();
    }
    let analysis =
        Analysis::parse(path, text, index_positions).map(|analysis| analysis.map(Arc::new));
    *memo = Some(Memo {
        path: path.to_path_buf(),
        text: text.to_owned(),
        analysis: analysis.clone(),
    });
    analysis
}

impl Analysis {
    fn parse(path: &Path, text: &str, index_positions: bool) -> Result<Option<Self>, String> {
        let document = serde_norway::from_str::<Value>(text).map_err(|error| {
            format!("The retained OpenAPI description does not parse as YAML or JSON: {error}")
        })?;
        // The compiler applies this gate before it reads selectors, sources, or questions.
        let spec = Spec::from_value(document.clone(), OPENAPI_FILE)
            .map_err(|error| format!("The retained OpenAPI description is invalid: {error}"))?;
        // A description too large to index positions in is analysed without them, and every
        // operation it publishes is then defined at the start of the file.
        let ranges = index_positions
            .then(|| parse_yaml(text).ok())
            .flatten()
            .map(|parsed| operation_id_ranges(&parsed.value))
            .unwrap_or_default();
        let Some(operations) = published_operations(&document, &ranges) else {
            return Ok(None);
        };
        Ok(Some(Self {
            path: path.to_path_buf(),
            operations,
            spec,
        }))
    }
}

/// Every operation identifier the document publishes, read exactly as `unique_operation` reads it.
///
/// `None` where that function bails: a `paths` that is not an object, a path item that is not an
/// object, a path item behind a `$ref`, and an operation that is not an object are four documents
/// the compiler refuses to resolve anything in. An analysis built from part of one would answer
/// questions about operations that may be hiding in the part that was skipped.
fn published_operations(
    document: &Value,
    ranges: &BTreeMap<(String, String), Range>,
) -> Option<BTreeMap<String, Vec<PublishedOperation>>> {
    let paths = document.get("paths").and_then(Value::as_object)?;
    let mut published: BTreeMap<String, Vec<PublishedOperation>> = BTreeMap::new();
    for (path, item) in paths {
        let item = item.as_object()?;
        if item.contains_key("$ref") {
            return None;
        }
        for method in METHODS {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let operation = operation.as_object()?;
            // An operation with no identifier publishes no name, so nothing can spell it and
            // nothing here has to know about it.
            let Some(id) = operation.get("operationId").and_then(Value::as_str) else {
                continue;
            };
            published
                .entry(id.to_owned())
                .or_default()
                .push(PublishedOperation {
                    key: OperationKey {
                        method: method.to_ascii_uppercase(),
                        path: path.clone(),
                    },
                    range: ranges
                        .get(&(path.clone(), method.to_owned()))
                        .copied()
                        .unwrap_or(DOCUMENT_START),
                    selectors: path_selectors(item, operation),
                });
        }
    }
    Some(published)
}

/// The names of one operation's required string path parameters, and `None` when the parameters are
/// not readable.
///
/// This is `exact_path_selectors` (`crates/registry-evidencectl/src/authoring.rs:1575-1619`) minus
/// its comparison: the same two owners in the same order, the same refusal of a `$ref`, of a
/// parameter that is not `in: path`, not `required: true`, or not `schema.type: string`, and of a
/// name written twice. Every one of those makes the compiler refuse the project, so the answer here
/// is `None` rather than a shorter set, and a caller that cannot name the parameters says nothing
/// about the selectors written against them.
///
/// One rule of that function is deliberately not restated: it also refuses a parameter carrying any
/// key beyond `name`, `in`, `required`, and `schema`. That refusal does not change which names are
/// required string path parameters, so a description that states a parameter's `description` still
/// answers this question correctly, and the project it belongs to is refused for its own reason.
fn path_selectors(
    path_item: &Map<String, Value>,
    operation: &Map<String, Value>,
) -> Option<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for owner in [path_item, operation] {
        let Some(values) = owner.get("parameters") else {
            continue;
        };
        for parameter in values.as_array()? {
            let parameter = parameter.as_object()?;
            let schema = parameter.get("schema").and_then(Value::as_object)?;
            let name = parameter.get("name").and_then(Value::as_str)?;
            if parameter.contains_key("$ref")
                || parameter.get("in").and_then(Value::as_str) != Some("path")
                || parameter.get("required").and_then(Value::as_bool) != Some(true)
                || schema.get("type").and_then(Value::as_str) != Some("string")
                || !names.insert(name.to_owned())
            {
                return None;
            }
        }
    }
    Some(names)
}

/// Where each `operationId` is written, by the path and method that carry it.
///
/// The two readings of the document walk it separately, so a place found here is matched to an
/// operation found above by the pair that names it. A pair with no entry is an operation the
/// positional parse did not recover, and it is defined at the start of the file rather than left
/// undefined: the name is published either way, and an author who cannot jump to it is better
/// served than one told it does not exist.
fn operation_id_ranges(value: &YamlValue) -> BTreeMap<(String, String), Range> {
    let mut ranges = BTreeMap::new();
    let Some(paths) = value.get("paths").and_then(YamlValue::as_mapping) else {
        return ranges;
    };
    for path in paths {
        let Some(item) = path.value.as_mapping() else {
            continue;
        };
        for method in item {
            if !METHODS.contains(&method.key.value.as_str()) {
                continue;
            }
            let Some(id) = method.value.get_scalar("operationId") else {
                continue;
            };
            ranges.insert((path.key.value.clone(), method.key.value.clone()), id.range);
        }
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESCRIPTION: &str = concat!(
        "openapi: 3.1.0\n",
        "paths:\n",
        "  /people/{person_id}:\n",
        "    get:\n",
        "      operationId: readPerson\n",
        "      parameters:\n",
        "        - {name: person_id, in: path, required: true, schema: {type: string}}\n",
        "      responses:\n",
        "        '200':\n",
        "          content:\n",
        "            application/json:\n",
        "              schema: {type: object, properties: {name: {type: string}}}\n",
    );

    fn analysis(text: &str, index_positions: bool) -> Option<Analysis> {
        Analysis::parse(
            Path::new("/project/source.openapi.yaml"),
            text,
            index_positions,
        )
        .expect("the retained description passes its prerequisite checks")
    }

    #[test]
    fn an_operation_is_published_under_its_identifier_with_its_selectors_and_its_place() {
        let analysis = analysis(DESCRIPTION, true).expect("the description analyses");

        let published = &analysis.operations["readPerson"];
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].key.method, "GET");
        assert_eq!(published[0].key.path, "/people/{person_id}");
        assert_eq!(published[0].range.start.line, 4);
        assert_eq!(
            published[0].selectors,
            Some(BTreeSet::from(["person_id".to_owned()]))
        );
    }

    /// The one thing the positional ceiling changes. Everything else about the description is still
    /// known, so an operation still resolves and the edges that depend on one are still checked.
    #[test]
    fn a_description_too_large_to_index_positions_in_still_publishes_its_operations() {
        let analysis = analysis(DESCRIPTION, false).expect("the description analyses");

        let published = &analysis.operations["readPerson"];
        assert_eq!(published[0].range, DOCUMENT_START);
        assert_eq!(published[0].key.method, "GET");
        assert_eq!(
            published[0].selectors,
            Some(BTreeSet::from(["person_id".to_owned()]))
        );
    }

    /// The documents `unique_operation` refuses to resolve anything in, one per case.
    #[test]
    fn a_description_the_compiler_will_not_resolve_in_analyses_to_nothing() {
        for refused in [
            "openapi: 3.1.0\n",
            "openapi: 3.1.0\npaths: []\n",
            "openapi: 3.1.0\npaths:\n  /people: not-an-object\n",
            "openapi: 3.1.0\npaths:\n  /people:\n    $ref: '#/components/pathItems/people'\n",
            "openapi: 3.1.0\npaths:\n  /people:\n    get: not-an-object\n",
        ] {
            assert!(
                analysis(refused, true).is_none(),
                "this description must analyse to nothing: {refused:?}"
            );
        }
    }

    #[test]
    fn an_invalid_openapi_prerequisite_is_distinct_from_later_unavailable_analysis() {
        for invalid in [
            "openapi: 2.0\npaths: {}\n",
            "paths: {}\n",
            "openapi: 3.1.0\npaths: {\n",
        ] {
            assert!(
                Analysis::parse(Path::new("/project/source.openapi.yaml"), invalid, true,).is_err(),
                "this description fails before dependent documents are read: {invalid:?}"
            );
        }
    }

    /// A parameter set that is not readable the way the compiler reads it is `None` rather than a
    /// shorter set, so a caller can tell "no path parameters" from "not knowable".
    #[test]
    fn a_parameter_the_compiler_refuses_leaves_the_selectors_unknown() {
        for unreadable in [
            "        - {name: person_id, in: query, required: true, schema: {type: string}}\n",
            "        - {name: person_id, in: path, required: false, schema: {type: string}}\n",
            "        - {name: person_id, in: path, required: true, schema: {type: integer}}\n",
            "        - {$ref: '#/components/parameters/person'}\n",
            "        - not-an-object\n",
        ] {
            let text = DESCRIPTION.replace(
                "        - {name: person_id, in: path, required: true, schema: {type: string}}\n",
                unreadable,
            );
            assert_ne!(text, DESCRIPTION, "the fixture must rewrite its parameter");
            let analysis = analysis(&text, true).expect("the description still analyses");
            assert_eq!(
                analysis.operations["readPerson"][0].selectors, None,
                "this parameter must leave the selectors unknown: {unreadable:?}"
            );
        }
    }

    /// An operation with no parameters at all has an empty set of them, which is knowable and is
    /// not the same answer as the one above.
    #[test]
    fn an_operation_with_no_parameters_declares_no_selectors() {
        let text = DESCRIPTION
            .replace(
                "      parameters:\n",
                "      responses: {'204': {description: nothing}}\n",
            )
            .replace(
                "        - {name: person_id, in: path, required: true, schema: {type: string}}\n",
                "",
            );

        let analysis = analysis(&text, true).expect("the description analyses");

        assert_eq!(
            analysis.operations["readPerson"][0].selectors,
            Some(BTreeSet::new())
        );
    }

    /// The memo answers from the text it was built for and rebuilds for any other, so a description
    /// an author has just changed is never read from the one they changed it from.
    #[test]
    fn a_description_is_analysed_once_until_its_text_changes() {
        let path = Path::new("/project/source.openapi.yaml");
        let mut memo = None;

        let first = reuse_or_parse(&mut memo, path, DESCRIPTION, true)
            .expect("the prerequisite is valid")
            .expect("it analyses");
        let again = reuse_or_parse(&mut memo, path, DESCRIPTION, true)
            .expect("the prerequisite is valid")
            .expect("it analyses");
        assert!(
            Arc::ptr_eq(&first, &again),
            "the same text is analysed once"
        );

        let changed = DESCRIPTION.replace("readPerson", "readPersonRecord");
        let after = reuse_or_parse(&mut memo, path, &changed, true)
            .expect("the prerequisite is valid")
            .expect("it analyses");
        assert!(
            !Arc::ptr_eq(&first, &after),
            "changed text is analysed again"
        );
        assert!(after.operations.contains_key("readPersonRecord"));

        // Another project's description of the same name replaces the entry rather than answering
        // from it.
        let other = Path::new("/other-project/source.openapi.yaml");
        let elsewhere = reuse_or_parse(&mut memo, other, &changed, true)
            .expect("the prerequisite is valid")
            .expect("it analyses");
        assert!(!Arc::ptr_eq(&after, &elsewhere));
        assert_eq!(elsewhere.path, other);
    }

    /// A description that does not analyse is remembered as one, so the parse that failed is not
    /// repeated on every keystroke elsewhere in the project.
    #[test]
    fn a_description_that_does_not_analyse_is_remembered_as_one() {
        let path = Path::new("/project/source.openapi.yaml");
        let mut memo = None;
        let refused = "openapi: 3.1.0\n";

        assert!(reuse_or_parse(&mut memo, path, refused, true)
            .expect("the prerequisite is valid")
            .is_none());
        let held = memo.as_ref().expect("the memo holds the reading");
        assert_eq!(held.text, refused);
        assert!(held
            .analysis
            .as_ref()
            .expect("the prerequisite is valid")
            .is_none());
    }

    /// Leaves are answered whether or not they are retained, so what the editor reports never
    /// depends on what it happens to have kept.
    #[test]
    fn leaves_are_answered_past_the_ceiling_on_what_is_retained() {
        let mut description = Description {
            analysis: Arc::new(analysis(DESCRIPTION, true).expect("the description analyses")),
            leaves: BTreeMap::new(),
        };
        let published = OperationKey {
            method: "GET".to_owned(),
            path: "/people/{person_id}".to_owned(),
        };

        for filler in 0..MAX_RETAINED_LEAF_SETS {
            description.leaves.insert(
                (format!("GET{filler}"), String::new()),
                Some(Arc::new(BTreeSet::new())),
            );
        }
        let leaves = description
            .selectable(&published)
            .expect("the response reads");

        assert_eq!(*leaves, BTreeSet::from(["/name".to_owned()]));
        assert_eq!(
            description.leaves.len(),
            MAX_RETAINED_LEAF_SETS,
            "nothing is retained past the ceiling"
        );
    }

    /// An operation whose response cannot be read answers `None`, and the caller stays quiet rather
    /// than reporting every fact path against an empty set.
    #[test]
    fn an_operation_with_no_readable_response_offers_no_leaves() {
        let mut description = Description {
            analysis: Arc::new(analysis(DESCRIPTION, true).expect("the description analyses")),
            leaves: BTreeMap::new(),
        };

        assert!(description
            .selectable(&OperationKey {
                method: "GET".to_owned(),
                path: "/nowhere".to_owned(),
            })
            .is_none());
    }
}
