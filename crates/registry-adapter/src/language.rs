// SPDX-License-Identifier: Apache-2.0

//! The expression languages, externally tagged by language as in Camel
//! (`products/adapter/CONCEPT.md` section 8.5): `constant`, `header`,
//! and `exchangeProperty` inline; `jsonpath`, RFC 9535, inline, on the
//! IETF standard rather than Jayway's dialect; and `rhai`, a
//! digest-pinned script file and entrypoint through
//! `registry-platform-script`. Camel's Simple language, Groovy,
//! JavaScript, and `bean` are not ported.
//!
//! A predicate is an expression whose result is a boolean; a non-boolean
//! result is an error, never a truthiness guess. A singular JSONPath
//! query (RFC 9535 section 2.3.5) yields its one value, or absent when
//! nothing matches; any other query yields the node list as a JSON
//! array, empty when nothing matches (section 8.11.8).
//!
//! # Selector bounds
//!
//! A `jsonpath` selector is digest-pinned authored pack content, not
//! runtime attacker input, but the runtime never assumes it was checked
//! first (`CONCEPT.md` section 5.5). [`compile_selector`] enforces the
//! declared length and nesting bounds on the raw selector text before
//! any parse, because pest 2.8.x, held below 2.9 by the workspace's
//! steering pin, carries no stack-overflow guard of its own and a
//! deeply nested query recurses until the stack fails. jsonpath-rust
//! 1.0.x additionally scans for nesting deeper than 128 before its own
//! parse; the declared bound is tighter, so it stays a second layer and
//! the engine's contract never depends on it.
//!
//! # Code maps
//!
//! Code maps convert an upstream's own code values through an explicit
//! table (`CONCEPT.md` section 8.6); [`CodeMapIndex`] resolves a map's
//! literal id against a pack's inventory, the resolving half of the
//! `code_map(id, key)` helper Rhai scripts and `convertBodyTo` share.
//! The value lookup is core's single `CodeMap::lookup`: a miss or a
//! non-string input raises `conversion.unmapped`, and there is no second
//! key lookup in v1. The helper stays unregistered until that lookup
//! lands in core.
//!
//! # Evaluation
//!
//! [`JsonPathSelector::evaluate`] applies the section 8.11.8 result
//! rules: a singular query yields its one value or absent; any other
//! query yields the matched nodes as a list, empty when nothing matches.
//! [`JsonPathSelector::evaluate_predicate`] is the boolean rule: only a
//! singular query may be a predicate (`check` refuses a non-singular
//! one, and the runtime repeats the refusal), it must yield a boolean,
//! and absent counts as false, the one place absence has a meaning.
//! Evaluation reads bodies that upstream serde_json parsing already
//! bounded, so the default recursion limit stays on (never
//! `unbounded_depth`): a descendant `..` selector therefore walks a
//! depth-bounded tree, and the matched-node count per expression is
//! capped at [`MATCHED_NODE_MAXIMUM`], exceeded reported as a typed
//! problem, never truncated.

use std::collections::BTreeMap;
use std::fmt;

use jsonpath_rust::parser::errors::JsonPathError;
use jsonpath_rust::parser::model::{Segment, Selector};
use jsonpath_rust::parser::parse_json_path;
use jsonpath_rust::query::js_path_process;
use registry_adapter_core::CodeMap;
use serde_json::Value;

/// The longest selector the engine compiles, in bytes.
///
/// Authored selectors are a handful of segments; the bound exists so a
/// pathological pack cannot hand the parser unbounded input. `check`
/// refuses longer selectors at authoring time, and the runtime repeats
/// the bound rather than trusting that it ran.
pub const SELECTOR_MAXIMUM_BYTES: usize = 4_096;

/// The deepest raw nesting the engine compiles.
///
/// Grouping (`(` inside filters, `[` selections) is the only source of
/// parse recursion, so the raw-text scan of [`compile_selector`] bounds
/// exactly that. The bound sits well below jsonpath-rust's own 128 so
/// the engine's refusal, with its declared maximum, is the one a route
/// author sees.
pub const SELECTOR_MAXIMUM_DEPTH: usize = 64;

/// The most nodes one expression may match per evaluation.
///
/// A descendant `..` or wildcard selector over a large upstream body can
/// match a node for much of the body; the cap bounds what one expression
/// materializes. Bodies are already depth-bounded at parse time by
/// serde_json's default recursion limit, which stays on, so the budget
/// guards width, not parser recursion. The cap is inclusive: exactly
/// [`MATCHED_NODE_MAXIMUM`] nodes evaluate, one more is refused.
pub const MATCHED_NODE_MAXIMUM: usize = 4_096;

/// Why a selector or a code map reference failed.
#[derive(Clone, Debug, PartialEq)]
pub enum LanguageError {
    /// The selector is longer than [`SELECTOR_MAXIMUM_BYTES`].
    SelectorTooLong {
        /// The selector's length in bytes.
        length: usize,
        /// The declared bound.
        maximum: usize,
    },
    /// The selector nests deeper than [`SELECTOR_MAXIMUM_DEPTH`].
    SelectorTooDeep {
        /// The deepest still-open grouping run in the raw text.
        depth: usize,
        /// The declared bound.
        maximum: usize,
    },
    /// The parser refused the selector.
    SelectorInvalid(JsonPathError),
    /// Two code maps in one inventory carry the same id. A parsed pack
    /// cannot reach this (`UniqueIdList` refuses duplicates), so it
    /// names a caller bug, never pack content.
    CodeMapDuplicateId(String),
    /// No code map entry carries the key, or the input is not a string:
    /// the `conversion.unmapped` miss rule of `CONCEPT.md` section 8.6.
    /// The upstream value the key came from is not carried; only the
    /// reviewed map id is.
    ConversionUnmapped {
        /// The map the lookup went through.
        map_id: String,
    },
    /// The selector failed while evaluating, not while parsing. The
    /// parser accepts queries this body shape cannot resolve through.
    EvaluationFailed(JsonPathError),
    /// The expression matched more nodes than [`MATCHED_NODE_MAXIMUM`].
    /// Nothing is truncated: the evaluation fails as a whole.
    MatchedNodeBudgetExceeded {
        /// The node count the expression matched.
        count: usize,
        /// The declared bound.
        maximum: usize,
    },
    /// A non-singular query was used as a predicate. `check` refuses
    /// such a route, and the runtime repeats the refusal rather than
    /// treating a node list as a truthiness answer (CONCEPT 8.11.8).
    PredicateNotSingular,
    /// A singular predicate yielded a value that is not a boolean. The
    /// value itself is upstream data and is not carried; only its JSON
    /// kind is named.
    PredicateNotBoolean {
        /// The JSON kind of the yielded value.
        kind: &'static str,
    },
}

impl fmt::Display for LanguageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectorTooLong { length, maximum } => {
                write!(
                    f,
                    "selector is {length} bytes, over the {maximum}-byte bound"
                )
            }
            Self::SelectorTooDeep { depth, maximum } => {
                write!(
                    f,
                    "selector nests {depth} levels deep, over the {maximum}-level bound"
                )
            }
            Self::SelectorInvalid(error) => write!(f, "selector does not parse: {error}"),
            Self::CodeMapDuplicateId(id) => write!(f, "two code maps carry the id {id}"),
            Self::ConversionUnmapped { map_id } => {
                write!(f, "code map {map_id} has no entry for the key")
            }
            Self::EvaluationFailed(error) => write!(f, "selector does not evaluate: {error}"),
            Self::MatchedNodeBudgetExceeded { count, maximum } => {
                write!(
                    f,
                    "selector matched {count} nodes, over the {maximum}-node budget"
                )
            }
            Self::PredicateNotSingular => {
                write!(f, "only a singular query can be a predicate")
            }
            Self::PredicateNotBoolean { kind } => {
                write!(f, "predicate yielded a {kind}, not a boolean")
            }
        }
    }
}

/// One compiled `jsonpath` selector: parsed once, evaluated per exchange.
///
/// The parsed form is retained rather than the text so evaluation never
/// re-enters the parser; the bounds ran once, at [`compile_selector`].
#[derive(Clone, Debug, PartialEq)]
pub struct JsonPathSelector {
    query: jsonpath_rust::parser::model::JpQuery,
}

/// Compiles an inline RFC 9535 selector under the declared bounds.
///
/// The length and nesting bounds run on the raw text before the parser
/// is invoked, so nothing the bounds refuse ever reaches pest. This is
/// the runtime compile path for every `jsonpath` expression a project
/// loads; `adapterctl check` enforces the same bounds at authoring time,
/// and the runtime does not assume it did.
///
/// # Errors
///
/// [`LanguageError::SelectorTooLong`] or
/// [`LanguageError::SelectorTooDeep`] when a bound is exceeded,
/// [`LanguageError::SelectorInvalid`] when the parser refuses the
/// selector.
pub fn compile_selector(selector: &str) -> Result<JsonPathSelector, LanguageError> {
    let length = selector.len();
    if length > SELECTOR_MAXIMUM_BYTES {
        return Err(LanguageError::SelectorTooLong {
            length,
            maximum: SELECTOR_MAXIMUM_BYTES,
        });
    }
    let depth = raw_nesting_depth(selector);
    if depth > SELECTOR_MAXIMUM_DEPTH {
        return Err(LanguageError::SelectorTooDeep {
            depth,
            maximum: SELECTOR_MAXIMUM_DEPTH,
        });
    }
    let query = parse_json_path(selector).map_err(LanguageError::SelectorInvalid)?;
    Ok(JsonPathSelector { query })
}

/// The result of one evaluation, in the shape section 8.11.8 fixes: a
/// singular query yields its one value or absent, any other query yields
/// the matched nodes as a list, empty when nothing matches. The borrowed
/// nodes live inside the evaluated body.
#[derive(Debug, PartialEq)]
pub enum JsonPathResult<'v> {
    /// The singular query's one value, or absent.
    Singular(Option<&'v Value>),
    /// The matched node list, possibly empty.
    List(Vec<&'v Value>),
}

impl JsonPathSelector {
    /// Whether the query is singular (RFC 9535 section 2.3.5): every
    /// segment is a name or an index selector, so it yields at most one
    /// node. A singular query and any other query have different result
    /// shapes (`CONCEPT.md` section 8.11.8), and `check` refuses a
    /// non-singular query used as a predicate.
    #[must_use]
    pub fn is_singular(&self) -> bool {
        self.query.segments.iter().all(|segment| {
            matches!(
                segment,
                Segment::Selector(Selector::Name(_)) | Segment::Selector(Selector::Index(_))
            )
        })
    }

    /// Evaluates the selector against a body under the declared budget.
    ///
    /// # Errors
    ///
    /// [`LanguageError::MatchedNodeBudgetExceeded`] when the expression
    /// matches more than [`MATCHED_NODE_MAXIMUM`] nodes,
    /// [`LanguageError::EvaluationFailed`] when the query engine refuses
    /// the evaluation.
    pub fn evaluate<'v>(&self, body: &'v Value) -> Result<JsonPathResult<'v>, LanguageError> {
        let matched = self.matched_nodes(body)?;
        if self.is_singular() {
            Ok(JsonPathResult::Singular(matched.first().copied()))
        } else {
            Ok(JsonPathResult::List(matched))
        }
    }

    /// Evaluates the selector as a predicate under the boolean rule.
    ///
    /// Absent counts as false, the one place absence has a meaning
    /// (`CONCEPT.md` section 8.11.8).
    ///
    /// # Errors
    ///
    /// [`LanguageError::PredicateNotSingular`] when the query is not
    /// singular, [`LanguageError::PredicateNotBoolean`] when it yields a
    /// value that is not a boolean, plus the [`Self::evaluate`] errors.
    pub fn evaluate_predicate(&self, body: &Value) -> Result<bool, LanguageError> {
        if !self.is_singular() {
            return Err(LanguageError::PredicateNotSingular);
        }
        let matched = self.matched_nodes(body)?;
        match matched.first() {
            None => Ok(false),
            Some(&value) => value
                .as_bool()
                .ok_or_else(|| LanguageError::PredicateNotBoolean {
                    kind: json_kind(value),
                }),
        }
    }

    /// The matched nodes, under the matched-node budget.
    fn matched_nodes<'v>(&self, body: &'v Value) -> Result<Vec<&'v Value>, LanguageError> {
        let matched =
            js_path_process(&self.query, body).map_err(LanguageError::EvaluationFailed)?;
        let count = matched.len();
        if count > MATCHED_NODE_MAXIMUM {
            return Err(LanguageError::MatchedNodeBudgetExceeded {
                count,
                maximum: MATCHED_NODE_MAXIMUM,
            });
        }
        Ok(matched.into_iter().map(|reference| reference.val).collect())
    }
}

/// The JSON kind of a value, for the typed non-boolean predicate
/// problem. Kind names carry no content, so an upstream value never
/// travels inside the error.
fn json_kind(value: &Value) -> &'static str {
    if value.is_null() {
        "null"
    } else if value.is_boolean() {
        "boolean"
    } else if value.is_number() {
        "number"
    } else if value.is_string() {
        "string"
    } else if value.is_array() {
        "array"
    } else {
        "object"
    }
}

/// The deepest run of still-open `(` and `[` in the raw selector text,
/// skipping string-literal contents, where quotes delimit data rather
/// than grouping.
fn raw_nesting_depth(selector: &str) -> usize {
    let mut depth = 0usize;
    let mut deepest = 0usize;
    let mut string_delim: Option<char> = None;
    let mut escaped = false;

    for character in selector.chars() {
        if let Some(delim) = string_delim {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delim {
                string_delim = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => string_delim = Some(character),
            '(' | '[' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            ')' | ']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// The id-resolving half of the `code_map(id, key)` seam.
///
/// A pack's code maps are stored as a list; every route reference is a
/// literal id that resolves (`CONCEPT.md` section 8.6). The index binds
/// each map's id once, at route-compile time, so the per-exchange path
/// is one slice lookup and never a linear scan. The value lookup is not
/// reimplemented here: once core's `CodeMap::lookup` lands, the
/// interpreter registers the Rhai helper `code_map(id, key)` over that
/// single function, with [`LanguageError::ConversionUnmapped`] as the
/// miss rule; there is no second key lookup in v1.
#[derive(Debug, PartialEq)]
pub struct CodeMapIndex<'m> {
    by_id: BTreeMap<&'m str, &'m CodeMap>,
}

impl<'m> CodeMapIndex<'m> {
    /// Indexes a pack's code maps by id.
    ///
    /// # Errors
    ///
    /// [`LanguageError::CodeMapDuplicateId`] when two maps carry the
    /// same id.
    pub fn build(maps: &'m [CodeMap]) -> Result<Self, LanguageError> {
        let mut by_id = BTreeMap::new();
        for map in maps {
            let id = map.id.as_str();
            if by_id.insert(id, map).is_some() {
                return Err(LanguageError::CodeMapDuplicateId(id.to_owned()));
            }
        }
        Ok(Self { by_id })
    }

    /// The declared map a literal id resolves to, if any.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&'m CodeMap> {
        self.by_id.get(id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_with_brackets_does_not_count_toward_the_nesting_depth() {
        // The quote contents are data; only the delimiters are scanned.
        assert_eq!(raw_nesting_depth(r#"$.a["[("]"#), 1);
        assert_eq!(raw_nesting_depth(r#"$.a["(\")"]"#), 1);
        assert_eq!(raw_nesting_depth("$.a[0]"), 1);
        assert_eq!(raw_nesting_depth(&deep_filter_text(3)), 5);
    }

    /// Local to the unit test so the integration suite keeps its own
    /// deep-selector helper.
    fn deep_filter_text(groups: usize) -> String {
        format!("$[?({}@.a{})]", "(".repeat(groups), ")".repeat(groups))
    }
}
