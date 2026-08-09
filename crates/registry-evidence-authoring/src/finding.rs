//! What a check reports: the field it applies to, a stable code, and the
//! sentence an author reads.
//!
//! A finding is deliberately not an error type. An error carries one failure
//! out of a call; a finding is a value a caller may collect, sort, rank, or
//! render next to the field it names, which is what an editor needs and what a
//! compiler can still reduce to a single message.

use std::fmt::{self, Display, Formatter};

/// One step from the root of an authored document to the field a finding
/// applies to.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FieldStep {
    /// A field the authoring form declares, spelled as it is written in the
    /// document rather than as the Rust field is named.
    Key(&'static str),
    /// A position within a sequence.
    Index(usize),
    /// A key of a mapping whose names the form leaves to the author.
    MapKey(String),
}

impl Display for FieldStep {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(name) => write!(formatter, ".{name}"),
            Self::Index(position) => write!(formatter, "[{position}]"),
            Self::MapKey(name) => write!(formatter, "[{name:?}]"),
        }
    }
}

/// Where in an authored document a finding applies.
///
/// The empty path is the document itself, which is the honest answer for a
/// check that reads several fields at once and cannot blame one of them.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FieldPath {
    steps: Vec<FieldStep>,
}

impl FieldPath {
    /// The document itself.
    #[must_use]
    pub const fn root() -> Self {
        Self { steps: Vec::new() }
    }

    /// This path, followed by a declared field.
    #[must_use]
    pub fn key(mut self, name: &'static str) -> Self {
        self.steps.push(FieldStep::Key(name));
        self
    }

    /// This path, followed by a position in a sequence.
    #[must_use]
    pub fn index(mut self, position: usize) -> Self {
        self.steps.push(FieldStep::Index(position));
        self
    }

    /// This path, followed by an authored mapping key.
    #[must_use]
    pub fn map_key(mut self, name: impl Into<String>) -> Self {
        self.steps.push(FieldStep::MapKey(name.into()));
        self
    }

    /// This path read as relative to `base`.
    ///
    /// A check that reports against its own root does not know where that root
    /// sits in the containing document; the caller that invoked it does.
    #[must_use]
    pub fn under(self, base: &Self) -> Self {
        let mut steps = base.steps.clone();
        steps.extend(self.steps);
        Self { steps }
    }

    /// The steps from the document root, outermost first.
    #[must_use]
    pub fn steps(&self) -> &[FieldStep] {
        &self.steps
    }

    /// Whether this path is the document itself.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.steps.is_empty()
    }
}

impl Display for FieldPath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        if self.steps.is_empty() {
            return formatter.write_str(".");
        }
        for step in &self.steps {
            write!(formatter, "{step}")?;
        }
        Ok(())
    }
}

/// One way an authored document departs from the authoring form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    /// The field the finding applies to.
    pub field: FieldPath,
    /// A stable identifier for the rule, for callers that group or filter
    /// findings rather than print them.
    pub code: &'static str,
    /// The sentence an author reads. This text is a contract: the same
    /// departure has produced the same sentence since before this crate
    /// existed, and `tests/finding_messages.rs` holds it there.
    pub message: String,
}

impl Finding {
    /// A finding against `field`.
    pub fn new(field: FieldPath, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            code,
            message: message.into(),
        }
    }

    /// This finding with its field read as relative to `base`.
    #[must_use]
    pub fn under(self, base: &FieldPath) -> Self {
        Self {
            field: self.field.under(base),
            ..self
        }
    }
}

impl Display for Finding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldPath, FieldStep, Finding};

    #[test]
    fn a_path_renders_each_kind_of_step() {
        let path = FieldPath::root()
            .key("source")
            .key("facts")
            .index(2)
            .map_key("/records");
        assert_eq!(path.to_string(), ".source.facts[2][\"/records\"]");
        assert_eq!(path.steps().len(), 4);
        assert_eq!(path.steps()[0], FieldStep::Key("source"));
    }

    #[test]
    fn the_root_path_renders_as_the_document_itself() {
        assert!(FieldPath::root().is_root());
        assert_eq!(FieldPath::root().to_string(), ".");
    }

    #[test]
    fn a_finding_moves_under_the_path_its_caller_knows() {
        let base = FieldPath::root().key("answers").index(1);
        let finding =
            Finding::new(FieldPath::root().key("schema"), "example", "message").under(&base);
        assert_eq!(finding.field.to_string(), ".answers[1].schema");
        assert_eq!(finding.to_string(), "message");
    }
}
