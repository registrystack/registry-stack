//! Narrowing a resolved response schema to the Evidence closed schema subset.
//!
//! The runtime validates a projected response against a bundle-relative
//! `responseSchema` written in the closed Version 1 subset: objects are closed
//! and declare bounded properties, arrays declare `maxItems` in `1..=256`,
//! integers declare both `minimum` and `maximum` or an enumeration or a
//! constant, strings declare `maxLength` or one of the two date formats or an
//! enumeration or a constant, and the only admitted union is the response-role
//! pair `[T, "null"]`. Two relaxations belong to the response role alone:
//! `required` may be a subset of the declared properties, because projection
//! drops a selected leaf the record did not carry, and a node may be null.
//!
//! This module does two things over that subset and nothing else:
//!
//! - [`plan_advisories`] enumerates the bounds the subset demands and the OpenAPI
//!   document does not already state, each with the best suggestion the
//!   inputs support and the provenance of that suggestion.
//! - [`apply`] prunes the schema to the projection selection and rewrites it
//!   into the subset, inserting the bounds a human confirmed and omitting the
//!   ones nobody did.
//!
//! The module never invents a bound. An unresolved bound is left out of the
//! emitted schema and reported in [`NarrowOutcome::unresolved`], so the draft
//! fails `evidence check` until an operator supplies it. The runtime stays the
//! only validator of the subset; this module only generates toward it.

use std::collections::BTreeMap;

use anyhow::{bail, Context as _, Result};
use serde_json::{Map as JsonMap, Value};

use super::types::{
    BoundKind, BoundNeed, BoundValues, NarrowOutcome, Observations, Observed, Provenance,
    ResolvedSchema, SuggestedBound,
};

/// The largest `maxItems` the closed subset admits.
const MAX_ITEMS_CEILING: u64 = 256;
/// The largest `maxLength` the closed subset admits.
const MAX_LENGTH_CEILING: u64 = 65_536;
/// The largest number of properties one closed object may declare.
const MAX_PROPERTIES: usize = 64;
/// The largest enumeration the closed subset admits.
const MAX_ENUM_MEMBERS: usize = 256;
/// The byte length of a canonical hyphenated UUID.
const UUID_LENGTH: u64 = 36;
/// The smallest string bound derived from a sample. Below this a bound says
/// more about the one response that was read than about the source.
const SAMPLE_STRING_FLOOR: u64 = 16;
/// The bucket a sampled array length is rounded up to.
const SAMPLE_ARRAY_BUCKET: u64 = 8;
/// The smallest integer maximum derived from a sample, for the same reason as
/// the string floor.
const SAMPLE_INTEGER_FLOOR: u64 = 10;

/// Everything the narrowing stage can say about a schema before a human
/// decides anything: the bounds the subset still demands, and the findings
/// that are not bound decisions.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// Bounds the closed subset demands and the specification does not state,
    /// in schema order.
    pub needs: Vec<BoundNeed>,
    /// Facts an operator should see that are not bound decisions.
    pub advisories: Vec<Advisory>,
}

/// One thing worth telling the operator about a node that is not a missing
/// bound. Advisories never change the emitted schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// The extended projection pointer of the node it concerns.
    pub pointer: String,
    pub kind: AdvisoryKind,
}

/// What an [`Advisory`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryKind {
    /// The sample carried an explicit null where the specification does not
    /// admit one. The emitted schema follows the specification, so the draft
    /// rejects that response until the operator writes the node as the
    /// response-role pair `[T, "null"]`.
    NullOutsideSpec,
    /// A string `format` outside the closed subset was dropped. The subset
    /// admits `date` and `date-time` only; every other format survives, if at
    /// all, as a length bound.
    DroppedFormat(String),
}

impl Advisory {
    /// A one-line explanation, safe to print: it names the pointer and the
    /// rule, never a sampled value.
    pub fn message(&self) -> String {
        match &self.kind {
            AdvisoryKind::NullOutsideSpec => format!(
                "`{}` was null in the sample but the specification does not admit null; \
                 write the node as the pair [T, \"null\"] if the source really reports it",
                display_pointer(&self.pointer)
            ),
            AdvisoryKind::DroppedFormat(format) => format!(
                "`{}` declares format `{format}`, which the closed subset does not admit; \
                 the subset admits `date` and `date-time` only",
                display_pointer(&self.pointer)
            ),
        }
    }
}

/// Enumerates every bound the closed subset demands of the selected subtrees
/// and the specification does not already satisfy.
///
/// Contract:
///
/// - `selection` holds extended projection pointers (`~0`/`~1` escapes, `*`
///   for every array element). Duplicates, ancestor and descendant overlaps,
///   pointers absent from the schema, and numeric array indexes are errors:
///   bundle validation would reject the projection they describe, so they
///   fail here first.
/// - A bound the specification states inside the subset raises no need at all.
/// - Each need carries the best derivable suggestion, by precedence
///   `Spec` > `Format` > `Sample`. `Spec` appears when a stated bound is
///   outside the subset and can be clamped into it; `Format` only for `uuid`,
///   which is a fixed 36-byte string; `Sample` is widened by the policy
///   documented on [`widen_integer_range`], [`widen_string_length`] and
///   [`widen_array_items`]. A need with no derivable value carries none: this
///   module never invents a bound.
/// - Needs are returned in schema order.
///
/// The returned [`Plan`] also carries the findings that are not bound
/// decisions: an explicit null the specification does not admit, and every
/// string format the closed subset made this stage drop.
pub fn plan_advisories(
    schema: &ResolvedSchema,
    selection: &[String],
    observations: &Observations,
) -> Result<Plan> {
    let selected = build_selection(selection)?;
    let mut narrowing = Narrowing {
        observations,
        resolutions: &[],
        needs: Vec::new(),
        advisories: Vec::new(),
    };
    narrowing.narrow(&schema.0, &selected, "", true)?;
    Ok(Plan {
        needs: narrowing.needs,
        advisories: narrowing.advisories,
    })
}

/// Produces the closed-subset response schema for the selected subtrees.
///
/// Contract:
///
/// - The selection is validated exactly as in [`plan_advisories`].
/// - The result is pruned to the selected subtrees and the containers needed
///   to reach them. Selecting a container keeps its whole subtree.
/// - Every object is closed with `additionalProperties: false` and declares
///   `required` as the members the specification marks required among the
///   members that were kept. A record reached through `*` therefore requires
///   nothing unless the specification guarantees that member of every record.
/// - Enumerations, constants, `uniqueItems`, in-subset bounds and the `date`
///   and `date-time` formats are carried through. Every other format is
///   dropped, because the subset admits no other. A `[T, "null"]` type pair is
///   preserved.
/// - A bound in `resolutions` is written into the schema after being checked
///   against the subset limits; a bound nobody resolved is omitted entirely
///   and returned in [`NarrowOutcome::unresolved`] in schema order. A
///   resolution matching no need is an error rather than a silent no-op.
/// - Arrays declare `minItems`, from the specification when it states one and
///   `0` otherwise: an empty page survives projection, and saying so
///   constrains nothing.
pub fn apply(
    schema: &ResolvedSchema,
    selection: &[String],
    resolutions: &BTreeMap<(String, BoundKind), BoundValues>,
) -> Result<NarrowOutcome> {
    let entries: Vec<Resolution> = resolutions
        .iter()
        .map(|(key, values)| (key.clone(), values.clone()))
        .collect();
    apply_entries(schema, selection, &entries)
}

/// [`apply`] over resolutions held as a slice rather than a map.
///
/// [`apply`] takes the map form `Decisions` declares and delegates here; this
/// entry point takes the same pairs as a slice, for a caller holding them in
/// schema order rather than keyed. Order is not significant; duplicate keys
/// resolve to the first entry.
pub fn apply_entries(
    schema: &ResolvedSchema,
    selection: &[String],
    resolutions: &[Resolution],
) -> Result<NarrowOutcome> {
    let selected = build_selection(selection)?;
    let observations = Observations::default();
    let mut narrowing = Narrowing {
        observations: &observations,
        resolutions,
        needs: Vec::new(),
        advisories: Vec::new(),
    };
    let narrowed = narrowing.narrow(&schema.0, &selected, "", true)?;
    for (pointer, kind) in resolutions.iter().map(|(key, _)| key) {
        if !narrowing
            .needs
            .iter()
            .any(|need| &need.pointer == pointer && &need.kind == kind)
        {
            bail!(
                "the resolved {} for `{}` matches no bound this schema needs; \
                 check the pointer against the selection",
                kind.label(),
                display_pointer(pointer)
            );
        }
    }
    let unresolved = narrowing
        .needs
        .into_iter()
        .filter(|need| resolution(resolutions, &need.pointer, &need.kind).is_none())
        .collect();
    Ok(NarrowOutcome {
        schema: narrowed,
        unresolved,
    })
}

/// Rounds a sampled array length up to the next multiple of eight, with eight
/// as the floor, clamped to the subset ceiling of 256.
///
/// One response is weak evidence of how long a page can be, so the bound is
/// deliberately looser than what was seen. It still has to stay inside the
/// subset, and an operator confirms it before it is written.
fn widen_array_items(observed: u64) -> u64 {
    let bucketed = observed
        .max(1)
        .div_ceil(SAMPLE_ARRAY_BUCKET)
        .saturating_mul(SAMPLE_ARRAY_BUCKET);
    bucketed.clamp(SAMPLE_ARRAY_BUCKET, MAX_ITEMS_CEILING)
}

/// Rounds a sampled string byte length up to the next power of two, with 16 as
/// the floor, clamped to the subset ceiling of 65,536.
fn widen_string_length(observed: u64) -> u64 {
    let mut widened = SAMPLE_STRING_FLOOR;
    while widened < observed && widened < MAX_LENGTH_CEILING {
        widened = widened.saturating_mul(2);
    }
    widened.clamp(SAMPLE_STRING_FLOOR, MAX_LENGTH_CEILING)
}

/// Widens a sampled integer range outward to round numbers.
///
/// A non-negative observed minimum is kept at `0`: a count or a total that
/// never went below zero in one sample is not evidence of a floor above it. A
/// negative minimum is widened by half again of its magnitude, rounded away
/// from zero to the next number of the form `{1,2,5} x 10^k`.
///
/// The maximum is treated far more generously, because a sampled integer is
/// usually a counter and one response says almost nothing about how high it
/// can climb: it becomes the next power of ten at or above twice what was
/// observed, with a floor of ten. Observing 12 therefore suggests 100 and
/// observing 60 suggests 1000. A ceiling that is merely snug around the sample
/// is the bound most likely to reject a legitimate response later, and the
/// operator confirms it before it is written.
fn widen_integer_range(min_observed: i64, max_observed: i64) -> (i64, i64) {
    let minimum = if min_observed >= 0 {
        0
    } else {
        let magnitude = min_observed.unsigned_abs();
        let widened = round_up_to_round_number(magnitude.saturating_add(magnitude / 2));
        i64::try_from(widened).map_or(i64::MIN, |widened| -widened)
    };
    let target = if max_observed <= 0 {
        0
    } else {
        max_observed.unsigned_abs().saturating_mul(2)
    };
    let maximum = next_power_of_ten(target.max(SAMPLE_INTEGER_FLOOR));
    (minimum, i64::try_from(maximum).unwrap_or(i64::MAX))
}

/// The smallest power of ten that is at least `value`.
fn next_power_of_ten(value: u64) -> u64 {
    let mut power: u64 = 1;
    while power < value {
        let Some(next) = power.checked_mul(10) else {
            return u64::MAX;
        };
        power = next;
    }
    power
}

/// The smallest number of the form `{1,2,5} x 10^k` that is at least `value`.
fn round_up_to_round_number(value: u64) -> u64 {
    if value <= 1 {
        return 1;
    }
    let mut scale: u64 = 1;
    loop {
        for step in [1, 2, 5] {
            let Some(candidate) = scale.checked_mul(step) else {
                return u64::MAX;
            };
            if candidate >= value {
                return candidate;
            }
        }
        let Some(next) = scale.checked_mul(10) else {
            return u64::MAX;
        };
        scale = next;
    }
}

/// One segment of an extended projection pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// An ordinary object member, already unescaped.
    Key(String),
    /// The reserved segment `*`, visiting every element of an array.
    Wildcard,
}

/// The selection as a tree. A node either terminates a projection entry, in
/// which case its whole subtree is projected, or names the children selected
/// beneath it.
#[derive(Debug, Default)]
struct Selected {
    /// The projection entry terminating here, kept for error messages.
    terminal: Option<String>,
    children: Vec<(Segment, Selected)>,
}

impl Selected {
    fn child(&self, segment: &Segment) -> Option<&Selected> {
        self.children
            .iter()
            .find_map(|(candidate, node)| (candidate == segment).then_some(node))
    }

    /// Any projection entry terminating at or beneath this node.
    fn first_terminal(&self) -> Option<&str> {
        if let Some(terminal) = &self.terminal {
            return Some(terminal);
        }
        self.children
            .iter()
            .find_map(|(_, node)| node.first_terminal())
    }

    /// The entry to name in a message about this node.
    fn blamed(&self) -> &str {
        self.first_terminal().unwrap_or("(unknown entry)")
    }
}

/// Parses and validates the selection into a tree.
///
/// Duplicate entries and ancestor/descendant overlaps are rejected here,
/// naming both entries, because bundle validation would reject the projection
/// they describe and a failure at authoring time is cheaper to read.
fn build_selection(selection: &[String]) -> Result<Selected> {
    if selection.is_empty() {
        bail!("the projection selection is empty: select at least one response leaf");
    }
    let mut root = Selected::default();
    for pointer in selection {
        let segments = parse_pointer(pointer)?;
        insert_selection(&mut root, &segments, pointer)?;
    }
    Ok(root)
}

fn insert_selection(node: &mut Selected, segments: &[Segment], pointer: &str) -> Result<()> {
    let Some((head, tail)) = segments.split_first() else {
        if let Some(owner) = &node.terminal {
            bail!("projection entry `{pointer}` duplicates `{owner}`");
        }
        if let Some(descendant) = node.first_terminal() {
            bail!(
                "projection entries `{pointer}` and `{descendant}` overlap: \
                 `{pointer}` already selects every leaf beneath it"
            );
        }
        node.terminal = Some(pointer.to_owned());
        return Ok(());
    };
    if let Some(owner) = &node.terminal {
        bail!(
            "projection entries `{owner}` and `{pointer}` overlap: \
             `{owner}` already selects every leaf beneath it"
        );
    }
    let index = match node
        .children
        .iter()
        .position(|(segment, _)| segment == head)
    {
        Some(index) => index,
        None => {
            node.children.push((head.clone(), Selected::default()));
            node.children.len() - 1
        }
    };
    insert_selection(&mut node.children[index].1, tail, pointer)
}

/// Splits an extended projection pointer into segments.
fn parse_pointer(pointer: &str) -> Result<Vec<Segment>> {
    if pointer.is_empty() {
        bail!("a projection entry is empty: an entry names at least one segment, e.g. `/total`");
    }
    let Some(body) = pointer.strip_prefix('/') else {
        bail!("projection entry `{pointer}` must start with `/`");
    };
    body.split('/')
        .map(|raw| parse_segment(raw, pointer))
        .collect()
}

fn parse_segment(raw: &str, pointer: &str) -> Result<Segment> {
    if raw == "*" {
        return Ok(Segment::Wildcard);
    }
    if raw.is_empty() {
        bail!("projection entry `{pointer}` has an empty segment");
    }
    let mut decoded = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => bail!(
                "projection entry `{pointer}` has an invalid escape: \
                 RFC 6901 defines `~0` and `~1` only"
            ),
        }
    }
    Ok(Segment::Key(decoded))
}

/// Appends one already-decoded member name to a pointer, re-escaping it.
fn child_pointer(parent: &str, key: &str) -> String {
    format!("{parent}/{}", key.replace('~', "~0").replace('/', "~1"))
}

/// Renders a pointer for a message, naming the root rather than printing an
/// empty string.
fn display_pointer(pointer: &str) -> &str {
    if pointer.is_empty() {
        "(response root)"
    } else {
        pointer
    }
}

/// One confirmed bound, keyed the way [`Decisions::resolutions`] keys it.
///
/// [`Decisions::resolutions`]: super::types::Decisions::resolutions
pub type Resolution = ((String, BoundKind), BoundValues);

/// Looks a resolution up. [`BoundKind`] carries no ordering, so resolutions
/// are scanned rather than searched; a selection is a handful of entries.
fn resolution<'a>(
    resolutions: &'a [Resolution],
    pointer: &str,
    kind: &BoundKind,
) -> Option<&'a BoundValues> {
    resolutions
        .iter()
        .find_map(|((candidate, candidate_kind), values)| {
            (candidate == pointer && candidate_kind == kind).then_some(values)
        })
}

/// One narrowing pass. It emits the pruned schema and collects, in schema
/// order, every bound the subset demands and every advisory.
struct Narrowing<'a> {
    observations: &'a Observations,
    resolutions: &'a [Resolution],
    needs: Vec<BoundNeed>,
    advisories: Vec<Advisory>,
}

impl Narrowing<'_> {
    fn observed(&self, pointer: &str) -> Option<&Observed> {
        self.observations.by_pointer.get(pointer)
    }

    /// Records a demanded bound and returns the resolution for it, when a
    /// human supplied one.
    fn demand(
        &mut self,
        pointer: &str,
        kind: BoundKind,
        suggestion: Option<SuggestedBound>,
    ) -> Option<BoundValues> {
        let resolved = resolution(self.resolutions, pointer, &kind).cloned();
        self.needs.push(BoundNeed {
            pointer: pointer.to_owned(),
            kind,
            suggestion,
        });
        resolved
    }

    fn advise(&mut self, pointer: &str, kind: AdvisoryKind) {
        self.advisories.push(Advisory {
            pointer: pointer.to_owned(),
            kind,
        });
    }

    fn narrow(
        &mut self,
        schema: &Value,
        selected: &Selected,
        pointer: &str,
        at_root: bool,
    ) -> Result<Value> {
        let node = schema.as_object().with_context(|| {
            format!(
                "the schema node at `{}` is not an object; every node in the closed subset is one",
                display_pointer(pointer)
            )
        })?;
        let Some((base, nullable)) = node_type(node, pointer)? else {
            // A node with no type but a bounded const is admitted as it is.
            reject_descent(selected, pointer)?;
            let mut narrowed = JsonMap::new();
            carry(node, "const", &mut narrowed);
            return Ok(Value::Object(narrowed));
        };
        if nullable && at_root {
            bail!(
                "the response schema root is a plain object in the closed subset; \
                 the `[T, \"null\"]` pair is not admitted there"
            );
        }
        if !nullable && self.observed(pointer).is_some_and(|seen| seen.saw_null) {
            self.advise(pointer, AdvisoryKind::NullOutsideSpec);
        }
        let mut narrowed = JsonMap::new();
        narrowed.insert(
            "type".to_owned(),
            if nullable {
                Value::Array(vec![Value::from(base), Value::from("null")])
            } else {
                Value::from(base)
            },
        );
        match base {
            "object" => self.narrow_object(node, selected, pointer, &mut narrowed)?,
            "array" => self.narrow_array(node, selected, pointer, &mut narrowed)?,
            "string" => {
                reject_descent(selected, pointer)?;
                self.narrow_string(node, pointer, &mut narrowed)?;
            }
            "integer" => {
                reject_descent(selected, pointer)?;
                self.narrow_integer(node, pointer, &mut narrowed)?;
            }
            "boolean" => {
                reject_descent(selected, pointer)?;
                carry(node, "enum", &mut narrowed);
                carry(node, "const", &mut narrowed);
            }
            other => bail!(
                "the node at `{}` has type `{other}`, which is outside the closed Version 1 \
                 subset; that subset admits object, array, string, integer and boolean",
                display_pointer(pointer)
            ),
        }
        Ok(Value::Object(narrowed))
    }

    fn narrow_object(
        &mut self,
        node: &JsonMap<String, Value>,
        selected: &Selected,
        pointer: &str,
        narrowed: &mut JsonMap<String, Value>,
    ) -> Result<()> {
        let properties = node
            .get("properties")
            .and_then(Value::as_object)
            .with_context(|| {
                format!(
                    "the object at `{}` declares no properties; the closed subset needs them",
                    display_pointer(pointer)
                )
            })?;
        let whole = selected.terminal.is_some();
        if !whole {
            for (segment, child) in &selected.children {
                let Segment::Key(key) = segment else {
                    bail!(
                        "projection entry `{}` uses `*` at `{}`, which is an object, not an array",
                        child.blamed(),
                        display_pointer(pointer)
                    );
                };
                if !properties.contains_key(key) {
                    bail!(
                        "projection entry `{}` names `{key}`, which the response schema does \
                         not declare at `{}`",
                        child.blamed(),
                        display_pointer(pointer)
                    );
                }
            }
        }
        let spec_required: Vec<&str> = node
            .get("required")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut kept = JsonMap::new();
        let mut required = Vec::new();
        for (key, child_schema) in properties {
            let child_selected = if whole {
                selected
            } else {
                match selected.child(&Segment::Key(key.clone())) {
                    Some(child) => child,
                    None => continue,
                }
            };
            let child = child_pointer(pointer, key);
            let narrowed_child = self.narrow(child_schema, child_selected, &child, false)?;
            if spec_required.contains(&key.as_str()) {
                required.push(Value::from(key.clone()));
            }
            kept.insert(key.clone(), narrowed_child);
        }
        if kept.is_empty() {
            bail!(
                "no member of the object at `{}` is selected; a closed object declares at \
                 least one property",
                display_pointer(pointer)
            );
        }
        if kept.len() > MAX_PROPERTIES {
            bail!(
                "the object at `{}` keeps {} members; the closed subset admits at most \
                 {MAX_PROPERTIES}",
                display_pointer(pointer),
                kept.len()
            );
        }
        narrowed.insert("additionalProperties".to_owned(), Value::Bool(false));
        narrowed.insert("required".to_owned(), Value::Array(required));
        narrowed.insert("properties".to_owned(), Value::Object(kept));
        Ok(())
    }

    fn narrow_array(
        &mut self,
        node: &JsonMap<String, Value>,
        selected: &Selected,
        pointer: &str,
        narrowed: &mut JsonMap<String, Value>,
    ) -> Result<()> {
        let items = node.get("items").with_context(|| {
            format!(
                "the array at `{}` does not close its item type; the closed subset needs `items`",
                display_pointer(pointer)
            )
        })?;
        let child_selected = if selected.terminal.is_some() {
            selected
        } else {
            match selected.child(&Segment::Wildcard) {
                Some(child) => child,
                None => bail!(
                    "projection entry `{}` addresses the array at `{}` by member name; \
                     an array is visited with the reserved segment `*`, and numeric indexes \
                     are not projection syntax",
                    selected.blamed(),
                    display_pointer(pointer)
                ),
            }
        };
        let spec_minimum = node.get("minItems").and_then(Value::as_u64);
        let spec_maximum = node.get("maxItems").and_then(Value::as_u64);
        let stated_in_subset = spec_maximum.is_some_and(|maximum| {
            (1..=MAX_ITEMS_CEILING).contains(&maximum) && maximum >= spec_minimum.unwrap_or(0)
        });
        let maximum = if stated_in_subset {
            spec_maximum
        } else {
            let suggestion = self.array_suggestion(pointer, spec_maximum, spec_minimum);
            match self.demand(pointer, BoundKind::ArrayMaxItems, suggestion) {
                Some(values) => Some(accept_max_items(&values, pointer)?),
                None => None,
            }
        };
        let minimum = match (spec_minimum, maximum) {
            (Some(minimum), Some(maximum)) => minimum.min(maximum),
            (Some(minimum), None) => minimum,
            (None, _) => 0,
        };
        narrowed.insert("minItems".to_owned(), Value::from(minimum));
        if let Some(maximum) = maximum {
            narrowed.insert("maxItems".to_owned(), Value::from(maximum));
        }
        if node.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
            narrowed.insert("uniqueItems".to_owned(), Value::Bool(true));
        }
        carry(node, "const", narrowed);
        let child = format!("{pointer}/*");
        let narrowed_items = self.narrow(items, child_selected, &child, false)?;
        narrowed.insert("items".to_owned(), narrowed_items);
        Ok(())
    }

    /// The best `maxItems` the inputs support: a stated bound clamped into the
    /// subset, else a widened sample observation, else nothing.
    fn array_suggestion(
        &self,
        pointer: &str,
        spec_maximum: Option<u64>,
        spec_minimum: Option<u64>,
    ) -> Option<SuggestedBound> {
        let floor = spec_minimum.unwrap_or(0).clamp(1, MAX_ITEMS_CEILING);
        if let Some(stated) = spec_maximum {
            return Some(SuggestedBound {
                values: BoundValues::MaxItems(stated.clamp(floor, MAX_ITEMS_CEILING)),
                provenance: Provenance::Spec,
            });
        }
        let observed = self.observed(pointer)?.max_array_items?;
        Some(SuggestedBound {
            values: BoundValues::MaxItems(widen_array_items(observed).max(floor)),
            provenance: Provenance::Sample,
        })
    }

    fn narrow_string(
        &mut self,
        node: &JsonMap<String, Value>,
        pointer: &str,
        narrowed: &mut JsonMap<String, Value>,
    ) -> Result<()> {
        let format = node.get("format").and_then(Value::as_str);
        let dated = matches!(format, Some("date" | "date-time"));
        if let Some(dropped) = format.filter(|_| !dated) {
            self.advise(pointer, AdvisoryKind::DroppedFormat(dropped.to_owned()));
        }
        let spec_minimum = node.get("minLength").and_then(Value::as_u64);
        let spec_maximum = node.get("maxLength").and_then(Value::as_u64);
        let bounded =
            spec_maximum.is_some_and(|maximum| (1..=MAX_LENGTH_CEILING).contains(&maximum));
        let enumerated = is_bounded_enum(node, Value::is_string);
        let constant = node
            .get("const")
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() as u64 <= MAX_LENGTH_CEILING);
        if dated {
            if let Some(format) = format {
                narrowed.insert("format".to_owned(), Value::from(format));
            }
        }
        if enumerated {
            carry(node, "enum", narrowed);
        }
        if constant {
            carry(node, "const", narrowed);
        }
        if bounded || dated || enumerated || constant {
            if let Some((minimum, maximum)) = spec_minimum.zip(spec_maximum) {
                if minimum > 0 && minimum <= maximum {
                    narrowed.insert("minLength".to_owned(), Value::from(minimum));
                }
            }
            if let Some(maximum) = spec_maximum.filter(|_| bounded) {
                narrowed.insert("maxLength".to_owned(), Value::from(maximum));
            }
            return Ok(());
        }
        let suggestion = self.string_suggestion(pointer, format, spec_minimum, spec_maximum);
        let Some(values) = self.demand(pointer, BoundKind::StringLength, suggestion) else {
            return Ok(());
        };
        let (minimum, maximum) = accept_string_length(&values, pointer)?;
        if minimum > 0 {
            narrowed.insert("minLength".to_owned(), Value::from(minimum));
        }
        narrowed.insert("maxLength".to_owned(), Value::from(maximum));
        Ok(())
    }

    /// The best string length the inputs support: a stated bound clamped into
    /// the subset, else the fixed length a `uuid` format implies, else a
    /// widened sample observation, else nothing.
    fn string_suggestion(
        &self,
        pointer: &str,
        format: Option<&str>,
        spec_minimum: Option<u64>,
        spec_maximum: Option<u64>,
    ) -> Option<SuggestedBound> {
        let minimum = spec_minimum.unwrap_or(0);
        if spec_maximum.is_some_and(|maximum| maximum > MAX_LENGTH_CEILING) {
            return Some(SuggestedBound {
                values: BoundValues::StringLength {
                    min_length: minimum.min(MAX_LENGTH_CEILING),
                    max_length: MAX_LENGTH_CEILING,
                },
                provenance: Provenance::Spec,
            });
        }
        if format == Some("uuid") {
            return Some(SuggestedBound {
                values: BoundValues::StringLength {
                    min_length: UUID_LENGTH,
                    max_length: UUID_LENGTH,
                },
                provenance: Provenance::Format,
            });
        }
        let observed = self.observed(pointer)?.max_string_bytes?;
        let maximum = widen_string_length(observed);
        Some(SuggestedBound {
            values: BoundValues::StringLength {
                min_length: minimum.min(maximum),
                max_length: maximum,
            },
            provenance: Provenance::Sample,
        })
    }

    fn narrow_integer(
        &mut self,
        node: &JsonMap<String, Value>,
        pointer: &str,
        narrowed: &mut JsonMap<String, Value>,
    ) -> Result<()> {
        let spec_minimum = node.get("minimum").and_then(Value::as_i64);
        let spec_maximum = node.get("maximum").and_then(Value::as_i64);
        let stated = spec_minimum
            .zip(spec_maximum)
            .filter(|(minimum, maximum)| minimum <= maximum);
        let enumerated = is_bounded_enum(node, |value| value.as_i64().is_some());
        let constant = node.get("const").and_then(Value::as_i64).is_some();
        if enumerated {
            carry(node, "enum", narrowed);
        }
        if constant {
            carry(node, "const", narrowed);
        }
        if let Some((minimum, maximum)) = stated {
            narrowed.insert("minimum".to_owned(), Value::from(minimum));
            narrowed.insert("maximum".to_owned(), Value::from(maximum));
            return Ok(());
        }
        if enumerated || constant {
            return Ok(());
        }
        let suggestion = self.integer_suggestion(pointer, spec_minimum, spec_maximum);
        let Some(values) = self.demand(pointer, BoundKind::IntegerRange, suggestion) else {
            return Ok(());
        };
        let (minimum, maximum) = accept_integer_range(&values, pointer)?;
        narrowed.insert("minimum".to_owned(), Value::from(minimum));
        narrowed.insert("maximum".to_owned(), Value::from(maximum));
        Ok(())
    }

    /// The best integer range the inputs support. A stated end is kept as it
    /// stands and only the missing end is derived from the sample; with no
    /// sample and only one stated end there is no suggestion, because the
    /// other end would have to be invented.
    fn integer_suggestion(
        &self,
        pointer: &str,
        spec_minimum: Option<i64>,
        spec_maximum: Option<i64>,
    ) -> Option<SuggestedBound> {
        let observed = self.observed(pointer);
        let seen_minimum = observed.and_then(|seen| seen.min_integer);
        let seen_maximum = observed.and_then(|seen| seen.max_integer);
        let widened = seen_minimum
            .or(seen_maximum)
            .zip(seen_maximum.or(seen_minimum))
            .map(|(minimum, maximum)| widen_integer_range(minimum, maximum));
        let minimum = spec_minimum.or(widened.map(|(minimum, _)| minimum))?;
        let maximum = spec_maximum.or(widened.map(|(_, maximum)| maximum))?;
        if minimum > maximum {
            return None;
        }
        Some(SuggestedBound {
            values: BoundValues::IntegerRange { minimum, maximum },
            provenance: if spec_minimum.is_some() && spec_maximum.is_some() {
                Provenance::Spec
            } else {
                Provenance::Sample
            },
        })
    }
}

/// Reads the one type a node declares, admitting the response-role pair
/// `[T, "null"]`. Returns `None` for a node that declares a bounded const
/// instead of a type.
fn node_type<'node>(
    node: &'node JsonMap<String, Value>,
    pointer: &str,
) -> Result<Option<(&'node str, bool)>> {
    match node.get("type") {
        None => {
            if node.get("const").is_some() {
                return Ok(None);
            }
            bail!(
                "the node at `{}` declares no type; the closed subset needs one type \
                 or one bounded const",
                display_pointer(pointer)
            )
        }
        Some(Value::String(name)) => Ok(Some((name.as_str(), false))),
        Some(Value::Array(members)) => match members.as_slice() {
            [Value::String(name), Value::String(null)] if null == "null" && name != "null" => {
                Ok(Some((name.as_str(), true)))
            }
            _ => bail!(
                "the node at `{}` declares a type union the closed subset does not admit; \
                 a response node may write `[T, \"null\"]` and nothing else",
                display_pointer(pointer)
            ),
        },
        Some(_) => bail!(
            "the node at `{}` declares a type that is neither a name nor a `[T, \"null\"]` pair",
            display_pointer(pointer)
        ),
    }
}

/// Fails when a projection entry descends past a leaf.
fn reject_descent(selected: &Selected, pointer: &str) -> Result<()> {
    if selected.terminal.is_some() {
        return Ok(());
    }
    bail!(
        "projection entry `{}` descends past the leaf at `{}`",
        selected.blamed(),
        display_pointer(pointer)
    )
}

/// Copies one keyword through unchanged when the node declares it.
fn carry(node: &JsonMap<String, Value>, keyword: &str, narrowed: &mut JsonMap<String, Value>) {
    if let Some(value) = node.get(keyword) {
        narrowed.insert(keyword.to_owned(), value.clone());
    }
}

/// True when the node declares an enumeration the closed subset admits.
fn is_bounded_enum(node: &JsonMap<String, Value>, member: fn(&Value) -> bool) -> bool {
    node.get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            !values.is_empty() && values.len() <= MAX_ENUM_MEMBERS && values.iter().all(member)
        })
}

/// Checks a resolved `maxItems` against the subset before it is written.
fn accept_max_items(values: &BoundValues, pointer: &str) -> Result<u64> {
    let BoundValues::MaxItems(maximum) = values else {
        bail!(
            "the resolution for `{}` is not a maxItems value, but the array there needs one",
            display_pointer(pointer)
        );
    };
    if !(1..=MAX_ITEMS_CEILING).contains(maximum) {
        bail!(
            "the resolved maxItems {maximum} for `{}` is outside the closed subset range \
             1..={MAX_ITEMS_CEILING}",
            display_pointer(pointer)
        );
    }
    Ok(*maximum)
}

/// Checks a resolved string length against the subset before it is written.
fn accept_string_length(values: &BoundValues, pointer: &str) -> Result<(u64, u64)> {
    let BoundValues::StringLength {
        min_length,
        max_length,
    } = values
    else {
        bail!(
            "the resolution for `{}` is not a string length, but the string there needs one",
            display_pointer(pointer)
        );
    };
    if *max_length == 0 || *max_length > MAX_LENGTH_CEILING || min_length > max_length {
        bail!(
            "the resolved string length {min_length}..={max_length} for `{}` is outside the \
             closed subset range 1..={MAX_LENGTH_CEILING}",
            display_pointer(pointer)
        );
    }
    Ok((*min_length, *max_length))
}

/// Checks a resolved integer range against the subset before it is written.
fn accept_integer_range(values: &BoundValues, pointer: &str) -> Result<(i64, i64)> {
    let BoundValues::IntegerRange { minimum, maximum } = values else {
        bail!(
            "the resolution for `{}` is not an integer range, but the integer there needs one",
            display_pointer(pointer)
        );
    };
    if minimum > maximum {
        bail!(
            "the resolved integer range {minimum}..={maximum} for `{}` is empty",
            display_pointer(pointer)
        );
    }
    Ok((*minimum, *maximum))
}
