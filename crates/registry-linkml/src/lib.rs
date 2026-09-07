//! Reader for the LinkML subset Registry Stack adopter tooling consumes, and
//! the embedded PublicSchema reference model that tooling offers as a
//! starting point.
//!
//! The crate has two halves. [`reader`] turns a bundle of LinkML schema files
//! into one resolved [`model::Model`]; it understands classes, slots, enums,
//! inheritance, and CURIE prefixes, and refuses the LinkML features it does
//! not model rather than reading them wrong. [`publicschema`] embeds a pinned
//! snapshot of the PublicSchema reference model and the annotation
//! conventions it uses, so a tool can list its concepts and properties
//! without a network or a checkout.
//!
//! Nothing here knows what a registry is. The mapping from a model to a
//! registry project belongs to the tool that writes the project.

pub mod model;
pub mod publicschema;
pub mod reader;

pub use model::{ClassDef, EnumDef, Model, ModelError, PermissibleValue, Range, SlotDef};
pub use reader::{read_bundle, ReadError};
