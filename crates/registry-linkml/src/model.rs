//! The in-memory form of a LinkML bundle after every reference has been
//! resolved.
//!
//! The types here carry only the LinkML subset adopter tooling consumes:
//! classes with their inheritance and slot lists, slots with a resolved
//! range, and enums with their permissible values. Every URI is absolute;
//! CURIEs are expanded while reading. Keys the reader does not model are
//! dropped, except the ones whose absence would change a class's shape,
//! which the reader refuses (see [`crate::reader::ReadError::Unsupported`]).

use std::collections::BTreeMap;

/// A resolved LinkML bundle: one model assembled from every file passed to
/// the reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    /// The `id` of the root schema, the first file in the bundle.
    pub id: String,
    /// The `name` of the root schema.
    pub name: String,
    /// The root schema's `version`, when it states one.
    pub version: Option<String>,
    /// The root schema's `license`, when it states one.
    pub license: Option<String>,
    /// Every prefix declared by any file in the bundle, merged.
    pub prefixes: BTreeMap<String, String>,
    /// Classes by name.
    pub classes: BTreeMap<String, ClassDef>,
    /// Slots by name.
    pub slots: BTreeMap<String, SlotDef>,
    /// Enums by name.
    pub enums: BTreeMap<String, EnumDef>,
}

/// A class definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDef {
    pub name: String,
    /// The absolute class URI.
    pub uri: String,
    pub title: Option<String>,
    pub description: Option<String>,
    /// The direct superclass, when the class declares one.
    pub is_a: Option<String>,
    /// Mixin classes whose slots this class also carries.
    pub mixins: Vec<String>,
    /// True for a class that exists only to be specialised.
    pub is_abstract: bool,
    /// The slots the class declares itself, in declaration order. Inherited
    /// slots are not listed here; see [`Model::induced_slots`].
    pub slots: Vec<String>,
    /// Scalar annotations, with booleans and numbers rendered as text.
    pub annotations: BTreeMap<String, String>,
    /// The `name` of the schema file that defined the class.
    pub schema: String,
}

/// A slot definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotDef {
    pub name: String,
    /// The absolute slot URI.
    pub uri: String,
    pub title: Option<String>,
    pub description: Option<String>,
    /// The resolved range.
    pub range: Range,
    pub multivalued: bool,
    pub required: bool,
    /// True when the slot is the class identifier (LinkML `identifier`).
    pub identifier: bool,
    /// Scalar annotations, with booleans and numbers rendered as text.
    pub annotations: BTreeMap<String, String>,
    /// The `name` of the schema file that defined the slot.
    pub schema: String,
}

/// What a slot's values are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Range {
    /// A LinkML built-in type such as `string`, `integer`, or `date`.
    Type(String),
    /// A value from the named enum.
    Enum(String),
    /// An instance of the named class, or of one of its descendants.
    Class(String),
}

/// An enum definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumDef {
    pub name: String,
    /// The absolute enum URI.
    pub uri: String,
    pub title: Option<String>,
    pub description: Option<String>,
    /// Permissible values in declaration order.
    pub values: Vec<PermissibleValue>,
    /// Scalar annotations, with booleans and numbers rendered as text.
    pub annotations: BTreeMap<String, String>,
    /// The `name` of the schema file that defined the enum.
    pub schema: String,
}

/// One permissible value of an enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissibleValue {
    /// The value's text, the key it is declared under.
    pub text: String,
    /// The absolute concept URI the value means, when it states one.
    pub meaning: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    /// Scalar annotations, with booleans and numbers rendered as text.
    pub annotations: BTreeMap<String, String>,
}

/// A reference to a class, slot, or enum that the model does not define, or
/// an inheritance graph that loops back on itself.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    #[error("class `{0}` is not defined")]
    UnknownClass(String),
    #[error("class `{0}` inherits from itself")]
    InheritanceCycle(String),
}

impl Model {
    /// Every slot an instance of `class` carries: the slots of its `is_a`
    /// ancestors first, root-most ancestor first, then the slots of each
    /// mixin, then the class's own, with later repeats of a name dropped.
    pub fn induced_slots(&self, class: &str) -> Result<Vec<&SlotDef>, ModelError> {
        let mut names = Vec::new();
        let mut visiting = Vec::new();
        self.collect_induced_slots(class, &mut visiting, &mut names)?;
        Ok(names
            .iter()
            .map(|name| {
                self.slots
                    .get(*name)
                    .expect("the reader resolves every slot a class lists")
            })
            .collect())
    }

    fn collect_induced_slots<'a>(
        &'a self,
        class: &str,
        visiting: &mut Vec<&'a str>,
        names: &mut Vec<&'a str>,
    ) -> Result<(), ModelError> {
        let definition = self
            .classes
            .get(class)
            .ok_or_else(|| ModelError::UnknownClass(class.to_owned()))?;
        if visiting.contains(&definition.name.as_str()) {
            return Err(ModelError::InheritanceCycle(class.to_owned()));
        }
        visiting.push(&definition.name);
        if let Some(parent) = &definition.is_a {
            self.collect_induced_slots(parent, visiting, names)?;
        }
        for mixin in &definition.mixins {
            self.collect_induced_slots(mixin, visiting, names)?;
        }
        for slot in &definition.slots {
            if !names.contains(&slot.as_str()) {
                names.push(slot);
            }
        }
        visiting.pop();
        Ok(())
    }

    /// True when `class` is `ancestor` or reaches it along `is_a` links.
    /// Mixins do not count: a mixin lends slots, it does not make a subtype.
    pub fn is_subclass_of(&self, class: &str, ancestor: &str) -> Result<bool, ModelError> {
        let mut current = class;
        let mut seen = Vec::new();
        loop {
            if current == ancestor {
                return Ok(true);
            }
            if seen.contains(&current) {
                return Err(ModelError::InheritanceCycle(class.to_owned()));
            }
            seen.push(current);
            let definition = self
                .classes
                .get(current)
                .ok_or_else(|| ModelError::UnknownClass(current.to_owned()))?;
            match &definition.is_a {
                Some(parent) => current = parent,
                None => return Ok(false),
            }
        }
    }

    /// Every non-abstract class that is `class` or reaches it along `is_a`
    /// links, in name order.
    pub fn concrete_descendants(&self, class: &str) -> Result<Vec<&ClassDef>, ModelError> {
        if !self.classes.contains_key(class) {
            return Err(ModelError::UnknownClass(class.to_owned()));
        }
        let mut descendants = Vec::new();
        for candidate in self.classes.values() {
            if !candidate.is_abstract && self.is_subclass_of(&candidate.name, class)? {
                descendants.push(candidate);
            }
        }
        Ok(descendants)
    }
}
