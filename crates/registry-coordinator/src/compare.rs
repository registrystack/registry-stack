// SPDX-License-Identifier: Apache-2.0
//! The compare decision of a choose step: an ordered list of tests over typed
//! values that routes to `matched` or `unmatched`. A compare holds no Function,
//! no nesting and no clock, so the same input and step outputs always take the
//! same route.
//!
//! Conditions run in order and stop at the first decisive one: `all` at the
//! first condition that does not hold, `any` at the first that does. A value
//! that is missing or of the wrong type for its test fails the run, never a
//! quiet `unmatched`; `present` is the one test that reads absence.

use std::{cmp::Ordering, collections::BTreeMap};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};

use crate::{
    definition::{authored, Reference, Step},
    functions::check_value,
    CoordinatorError, Result,
};

/// The most conditions one compare holds.
pub(crate) const MAXIMUM_CONDITIONS: usize = 16;
/// The case a compare routes to when it holds.
pub(crate) const MATCHED: &str = "matched";
/// The case a compare routes to when it does not hold.
pub(crate) const UNMATCHED: &str = "unmatched";

const NO_TEST: &str = "a condition has exactly one test: equals, oneOf, less, greater or present";
const EQUALS: &str = "equals takes a string, a number or a boolean";
const ONE_OF: &str = "oneOf takes a list of strings, numbers or booleans of one kind";
const ORDER: &str = "less and greater take a number or a calendar date such as 2026-01-31";
const MISSING: &str = "the value this condition reads is missing";
const WRONG_TYPE: &str = "the value this condition reads is not of the type its test takes";

/// Exactly one of `all` (every condition holds) or `any` (one holds).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Compare {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<Condition>>,
}

/// One reference and exactly one test of it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Condition {
    pub value: Reference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub less: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub greater: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
}

/// A condition's test with its operand checked.
pub(crate) enum Test<'a> {
    Equals(&'a Value),
    OneOf(&'a [Value]),
    /// The value must order this way against the bound.
    Order(Ordering, Bound),
    Present(bool),
}

/// What `less` and `greater` order a value against.
pub(crate) enum Bound {
    Number(f64),
    Date(NaiveDate),
}

/// A calendar date written `YYYY-MM-DD`, with a real month and day.
pub(crate) fn calendar_date(text: &str) -> Option<NaiveDate> {
    let shaped = text.len() == 10
        && text.bytes().enumerate().all(|(at, byte)| match at {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        });
    shaped
        .then(|| NaiveDate::parse_from_str(text, "%Y-%m-%d").ok())
        .flatten()
}

fn is_scalar(value: &Value) -> bool {
    matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
}

fn bound(value: &Value) -> Option<Bound> {
    match value {
        Value::Number(number) => number.as_f64().map(Bound::Number),
        Value::String(text) => calendar_date(text).map(Bound::Date),
        _ => None,
    }
}

fn numbers_equal(a: &Number, b: &Number) -> bool {
    match (a.as_i64(), b.as_i64()) {
        (Some(a), Some(b)) => a == b,
        _ => match (a.as_u64(), b.as_u64()) {
            (Some(a), Some(b)) => a == b,
            _ => a.as_f64() == b.as_f64(),
        },
    }
}

/// Whether two scalars are equal, or `None` when they are of different kinds.
fn scalar_equal(value: &Value, literal: &Value) -> Option<bool> {
    match (value, literal) {
        (Value::String(a), Value::String(b)) => Some(a == b),
        (Value::Bool(a), Value::Bool(b)) => Some(a == b),
        (Value::Number(a), Value::Number(b)) => Some(numbers_equal(a, b)),
        _ => None,
    }
}

impl Condition {
    /// The one test this condition names, or the reason it does not.
    pub(crate) fn test(&self) -> std::result::Result<Test<'_>, &'static str> {
        let named = [
            self.equals.is_some(),
            self.one_of.is_some(),
            self.less.is_some(),
            self.greater.is_some(),
            self.present.is_some(),
        ];
        if named.into_iter().filter(|named| *named).count() != 1 {
            return Err(NO_TEST);
        }
        if let Some(literal) = &self.equals {
            return is_scalar(literal)
                .then_some(Test::Equals(literal))
                .ok_or(EQUALS);
        }
        if let Some(literals) = &self.one_of {
            let one_kind = literals.iter().all(|literal| {
                is_scalar(literal)
                    && std::mem::discriminant(literal) == std::mem::discriminant(&literals[0])
            });
            return (!literals.is_empty() && one_kind)
                .then_some(Test::OneOf(literals))
                .ok_or(ONE_OF);
        }
        if let Some(literal) = &self.less {
            return bound(literal)
                .map(|bound| Test::Order(Ordering::Less, bound))
                .ok_or(ORDER);
        }
        if let Some(literal) = &self.greater {
            return bound(literal)
                .map(|bound| Test::Order(Ordering::Greater, bound))
                .ok_or(ORDER);
        }
        Ok(Test::Present(self.present.unwrap_or_default()))
    }

    /// Whether the condition holds, or why its value cannot be tested. The
    /// reason names the failure, never the value.
    fn holds<'r>(
        &'r self,
        read: &impl Fn(&'r Reference) -> Result<&'r Value>,
    ) -> std::result::Result<bool, &'static str> {
        let test = self.test()?;
        let value = read(&self.value).ok().filter(|value| !value.is_null());
        if let Test::Present(wanted) = test {
            return Ok(value.is_some() == wanted);
        }
        let value = value.ok_or(MISSING)?;
        match test {
            Test::Equals(literal) => scalar_equal(value, literal).ok_or(WRONG_TYPE),
            Test::OneOf(literals) => {
                let mut any = false;
                for literal in literals {
                    any |= scalar_equal(value, literal).ok_or(WRONG_TYPE)?;
                }
                Ok(any)
            }
            Test::Order(wanted, bound) => match bound {
                Bound::Number(limit) => {
                    value.as_f64().and_then(|number| number.partial_cmp(&limit))
                }
                Bound::Date(limit) => value
                    .as_str()
                    .and_then(calendar_date)
                    .map(|date| date.cmp(&limit)),
            }
            .map(|ordering| ordering == wanted)
            .ok_or(WRONG_TYPE),
            Test::Present(_) => unreachable!("present returned above"),
        }
    }
}

impl Condition {
    /// An operand holds to the bounds every literal holds to, so a compare
    /// cannot carry a value a mapping literal would be refused for.
    fn check_operand(&self, at: &str) -> Result<()> {
        let one_of = self.one_of.clone().map(Value::Array);
        for (member, operand) in [
            ("equals", self.equals.as_ref()),
            ("oneOf", one_of.as_ref()),
            ("less", self.less.as_ref()),
            ("greater", self.greater.as_ref()),
        ] {
            let Some(operand) = operand else { continue };
            check_value(operand).map_err(|_| {
                authored(
                    "mapping.literal",
                    &format!("{at}.{member}"),
                    &format!("the {member} operand exceeds the structured value bounds"),
                    "Shorten the operand or decide in a function; literals hold at most 32 levels, 4096 nodes, 16384-byte strings, 131072 canonical bytes, and integers within 2^53 - 1.",
                )
            })?;
        }
        Ok(())
    }
}

impl Compare {
    /// The conditions with their member names below the compare, such as
    /// `all.0`.
    pub(crate) fn conditions(&self) -> impl Iterator<Item = (String, &Condition)> {
        fn numbered<'a>(
            name: &'static str,
            list: &'a Option<Vec<Condition>>,
        ) -> impl Iterator<Item = (String, &'a Condition)> {
            list.iter()
                .flatten()
                .enumerate()
                .map(move |(at, condition)| (format!("{name}.{at}"), condition))
        }
        numbered("all", &self.all).chain(numbered("any", &self.any))
    }

    /// Each reference with its member path below the mapping.
    pub(crate) fn references(&self) -> Vec<(String, &Reference)> {
        self.conditions()
            .map(|(member, condition)| (format!(".{member}.value"), &condition.value))
            .collect()
    }

    /// Check a compare's form and where it is used: in a choose step that
    /// routes to exactly `matched` and `unmatched`.
    pub(crate) fn check(&self, step: &Step, name: &str) -> Result<()> {
        let base = format!("steps.{name}.{}", step.role());
        let Step::Choose { cases, .. } = step else {
            return Err(authored(
                "definition.compare-placement",
                &base,
                "a compare decides a choose step; it cannot build a value",
                "Use compare as the choose of a step with the cases matched and unmatched, or build the value with a function or fields.",
            ));
        };
        let (list, conditions) = match (&self.all, &self.any) {
            (Some(conditions), None) => ("all", conditions),
            (None, Some(conditions)) => ("any", conditions),
            _ => {
                return Err(authored(
                    "definition.compare-conditions",
                    &base,
                    "a compare has exactly one of all or any",
                    "Write the conditions under all when every one must hold, or under any when one is enough.",
                ))
            }
        };
        if conditions.is_empty() || conditions.len() > MAXIMUM_CONDITIONS {
            return Err(authored(
                "definition.compare-conditions",
                &format!("{base}.{list}"),
                "a compare holds 1 to 16 conditions",
                "Keep between one and sixteen conditions, or move a longer decision into a function.",
            ));
        }
        for (at, condition) in conditions.iter().enumerate() {
            condition.test().map_err(|message| {
                authored(
                    "definition.compare-test",
                    &format!("{base}.{list}.{at}"),
                    message,
                    "Give the condition a value and one test with an operand the test takes.",
                )
            })?;
            condition.check_operand(&format!("{base}.{list}.{at}"))?;
        }
        check_cases(cases, &format!("steps.{name}.cases"))
    }

    /// Whether the compare holds over the input and step outputs `read`
    /// resolves. A condition that cannot be tested fails with
    /// `mapping.choice`, naming the condition by `field`.
    pub(crate) fn matches<'r>(
        &'r self,
        field: &str,
        read: impl Fn(&'r Reference) -> Result<&'r Value>,
    ) -> Result<bool> {
        let (list, conditions, decisive) = match (&self.all, &self.any) {
            (Some(conditions), None) => ("all", conditions, false),
            (None, Some(conditions)) => ("any", conditions, true),
            _ => {
                return Err(authored(
                    "definition.compare-conditions",
                    field,
                    "a compare has exactly one of all or any",
                    "Write the conditions under all or under any, not both.",
                ))
            }
        };
        for (at, condition) in conditions.iter().enumerate() {
            let holds = condition.holds(&read).map_err(|reason| {
                CoordinatorError::new("mapping.choice", reason)
                    .at("workflow.yaml", format!("{field}.{list}.{at}"))
                    .suggest("Guard an optional value with a present test before the test that reads it, or correct the value the step produces.")
            })?;
            if holds == decisive {
                return Ok(decisive);
            }
        }
        Ok(!decisive)
    }
}

/// A compare routes to exactly `matched` and `unmatched`.
fn check_cases(cases: &BTreeMap<String, String>, field: &str) -> Result<()> {
    if cases.len() == 2 && cases.contains_key(MATCHED) && cases.contains_key(UNMATCHED) {
        return Ok(());
    }
    Err(authored(
        "definition.compare-cases",
        field,
        "a compare routes to exactly the cases matched and unmatched",
        "Name the step a compare routes to under cases matched and unmatched, and remove any other case.",
    ))
}

/// The failure code a choose step's evaluation error is recorded under. A
/// compare that cannot test its value is a failed choice; every other
/// evaluation error is a failed mapping.
pub(crate) fn failure_code(error: &CoordinatorError) -> &'static str {
    if error.code == "mapping.choice" {
        "choice-invalid"
    } else {
        "mapping-invalid"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_compare_that_cannot_test_its_value_is_a_failed_choice() {
        let choice = CoordinatorError::new("mapping.choice", "the value is missing");
        assert_eq!(failure_code(&choice), "choice-invalid");
        for code in ["mapping.path", "mapping.branch", "function.failed"] {
            let error = CoordinatorError::new(code, "refused");
            assert_eq!(failure_code(&error), "mapping-invalid", "{code}");
        }
    }

    #[test]
    fn a_calendar_date_is_strict_about_its_shape_and_its_day() {
        assert!(calendar_date("2028-02-29").is_some());
        for text in [
            "2027-02-29",
            "2026-2-1",
            "2026-02-1",
            "26-02-01",
            "2026/02/01",
            "2026-02-01T00:00:00Z",
            "+2026-02-01",
            "",
        ] {
            assert!(calendar_date(text).is_none(), "{text}");
        }
    }
}
