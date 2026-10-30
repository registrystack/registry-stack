// SPDX-License-Identifier: Apache-2.0

//! The route model (`products/adapter/CONCEPT.md` sections 8.3 and 8.4).
//!
//! A route is a sequence of EIP steps read from a pack's route templates
//! and internal routes in the platform YAML formats, in the shape of
//! Camel's YAML DSL: an externally tagged step union keyed by the Camel
//! EIP name. The engine's boundedness rules hold here: one route has one
//! `from`, `from` URIs are `direct:` only, the route call graph through
//! `direct:` is acyclic and depth bounded, every `loop` and `split`
//! declares its maximum, and inline code is refused, so `rhai` always
//! names a digest-pinned file.
//!
//! Route templates carry typed parameters instantiated at `check` time
//! and at startup, never per request; a parameter carries authored values
//! only, never environment values. A template omits `from`, and the
//! instantiated route's `from` is `direct:<routeId>`.
