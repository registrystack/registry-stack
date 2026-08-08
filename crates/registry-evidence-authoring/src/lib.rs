//! The Evidence authoring form: the shape an adopter writes under a project
//! directory, and the single implementation of the checks that shape must
//! satisfy.
//!
//! This is a library beside `evidencectl`, not a second runtime. It sits
//! outside the frozen Version 1 runtime contract and adds no Evidence
//! semantics of its own: it describes what an adopter may write and reports
//! where a written document departs from it, so that a compiler and an editor
//! reach the same verdict from the same code.
//!
//! # Crate invariant: no input or output
//!
//! Nothing here reads a file, opens a socket, or starts a process. Every entry
//! point takes text or already-parsed values and returns values or
//! [`Finding`]s. Reading the bytes is the caller's job, which is what lets an
//! editor run these checks against an unsaved buffer and a compiler run them
//! against a file on disk without either of them owning a second copy of the
//! rules.
//!
//! The invariant is enforced by `tests/no_io.rs`, which sweeps this crate's own
//! sources and its dependency list rather than trusting this paragraph.

pub mod derivation;
pub mod finding;
pub mod layout;
pub mod model;
pub mod openapi;
pub mod validate;

pub use derivation::validate_authored_answer;
pub use finding::{FieldPath, FieldStep, Finding};
pub use model::{
    default_response_formats, AnswerType, FactCombination, Question, QuestionAnswer,
    QuestionDisclosure, QuestionFact, QuestionGovernance, QuestionResponseFormat, QuestionSdJwtVc,
    QuestionSdJwtVcDisclosure, QuestionSource, QuestionSubject, RequirementKind,
};
pub use validate::{
    question_subjects, valid_field_name, valid_local_identifier, validate_answer, validate_question,
};
