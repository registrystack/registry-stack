// SPDX-License-Identifier: Apache-2.0
//! The shared Registry Stack configuration reader.
//!
//! Every Registry Stack file a person or an agent writes is read here: one
//! YAML subset, one value table, one envelope check, and typed decoding with
//! diagnostics that carry a stable code, a path, a line and column, a
//! message, and the action that fixes it. A diagnostic never repeats a value
//! from the file (CFG-SEC-3).
//!
//! # Reading a file
//!
//! ```
//! use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
//! use serde::Deserialize;
//!
//! const FORMAT: FormatSpec = FormatSpec {
//!     kind: "ExampleRuntime",
//!     envelope: EnvelopeRule::ApiVersionKind {
//!         api_versions: &[ApiVersion::current("example.registrystack.org/v1")],
//!         retired_api_versions: &[],
//!     },
//!     removed_keys: &[],
//! };
//!
//! #[derive(Debug, Deserialize)]
//! #[serde(rename_all = "camelCase")]
//! struct Runtime {
//!     listen_port: u16,
//! }
//!
//! let text = "apiVersion: example.registrystack.org/v1\nkind: ExampleRuntime\nlistenPort: 8080\n";
//! let decoded = Reader::new("runtime.yaml")
//!     .decode::<Runtime>(text.as_bytes(), &Expect::one(&FORMAT))
//!     .unwrap();
//! assert_eq!(decoded.value.listen_port, 8080);
//!
//! let typo = "apiVersion: example.registrystack.org/v1\nkind: ExampleRuntime\nlistenPrt: 8080\n";
//! let report = Reader::new("runtime.yaml")
//!     .decode::<Runtime>(typo.as_bytes(), &Expect::one(&FORMAT))
//!     .unwrap_err();
//! let codes: Vec<&str> = report.diagnostics().iter().map(|d| d.code.as_str()).collect();
//! assert_eq!(codes, ["config.missing-key", "config.unknown-key"]);
//! ```
//!
//! The envelope members `apiVersion` and `kind` are checked by the reader
//! and need not be fields of the decoded type; a type that declares them
//! receives them.
//!
//! # Decoding rules
//!
//! The decoder is a serde `Deserializer` over the checked tree. It differs
//! from a general-purpose one on purpose:
//!
//! - every struct refuses unknown keys, whatever its serde attributes say
//!   (except through serde's `flatten`, below), and every unknown key the
//!   decoder reaches is reported, not only the first;
//! - decoding stops at the first other error, which is placed at the node
//!   it concerns; the rest of the mapping it stopped in is still checked
//!   for unknown keys (CFG-DIAG-5);
//! - null is refused everywhere except inside [`DataLiteral`] (CFG-EMPTY-1);
//!   an optional member is written by leaving the key out;
//! - an integer, a boolean, or a number is written as one, never as quoted
//!   text, and a value a hook substituted is always text (CFG-VAL-1);
//! - a message a type's own `Deserialize` code writes is never passed
//!   through: the reader writes its own sentence from the node. A type that
//!   checks its input returns an [`Invalid`], which names what was expected
//!   and how to fix it without repeating the value.
//!
//! # Shared blocks
//!
//! A platform shared block, such as [`ProjectIdentity`], may place its
//! members beside the host's own (CFG-SCHEMA-8). Mark the field with a
//! deserialize rename that starts with [`SHARED_BLOCK_PREFIX`]:
//!
//! ```
//! use registry_platform_yaml::ProjectIdentity;
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! #[serde(rename_all = "camelCase")]
//! struct Package {
//!     #[serde(rename(deserialize = "registry-platform-yaml/shared-block/project"))]
//!     project: ProjectIdentity,
//!     title: String,
//! }
//! ```
//!
//! The block's members then keep their positions, and an unknown key beside
//! them names every accepted key of the host and the block. serde's
//! `#[serde(flatten)]` still decodes, but serde places errors inside the
//! block at the host mapping, reports only its first unknown key, and
//! reports none unless the host denies unknown fields; use the marker in new
//! code. For a schema, add
//! `#[cfg_attr(feature = "schema", schemars(flatten))]` to the same field.
//!
//! # Unions
//!
//! [`tagged_union!`] decodes an internally tagged enum (a `type` member, or
//! another named tag, chooses the variant) with positions kept inside the
//! variant. An externally tagged enum (a single key names the variant)
//! needs no macro: derive `Deserialize` as usual. In both, every variant is
//! a struct variant, `Variant {}` when it has no members. [`shape_union!`]
//! decodes an enum whose variants differ by node kind. Do not use serde's
//! `#[serde(tag = "...")]` or `#[serde(untagged)]`: they buffer the mapping
//! without positions.

mod de;
mod diagnostic;
mod document;
mod envelope;
mod messages;
mod node;
mod scalar;
mod structure;
mod types;
mod union;

pub use de::{Invalid, SHARED_BLOCK_PREFIX};
pub use diagnostic::{Diagnostic, Related, Report, Severity, Source};
pub use document::{
    decode_document, read_document, Decoded, Document, Reader, MAXIMUM_DIAGNOSTICS_PER_FILE,
    MAXIMUM_DOCUMENT_BYTES,
};
pub use envelope::{
    ApiVersion, Envelope, EnvelopeRule, Expect, FormatSpec, RemovedKey, RetiredApiVersion,
    VersionStatus,
};
pub use messages::{CodeInfo, CODES};
pub use node::{escape_pointer_segment, Entry, Node, NodeValue, Position, ScalarStyle, Span, Text};
pub use structure::{Refusal, ScalarHook, ScalarSite, MAXIMUM_DEPTH};
pub use types::{
    BoundedU32, BoundedU64, DataLiteral, Digest, ExternalId, Identified, LocalId, ProjectIdentity,
    UniqueIdList, UniqueList, Url, MAXIMUM_EXTERNAL_ID_CHARS, MAXIMUM_URL_CHARS,
};
#[doc(hidden)]
pub use union::__private;
