// SPDX-License-Identifier: Apache-2.0

//! Source-neutral core of the Registry Stack Adapter.
//!
//! This crate owns the Adapter's source-neutral model: the profile, pack,
//! project, and call-plan artifacts, their wire DTOs, the closed
//! `adapter.*` problem vocabulary, and the pure authoring checks those
//! artifacts must satisfy (`products/adapter/CONCEPT.md` section 8.1). It
//! contains no I/O: no network, no file access, no clock, and no upstream
//! or product types, so the runtime, the operator tooling, and the
//! offline `adapterctl check` read the same contract.
//!
//! The runtime crate `registry-adapter` builds its facade, plan
//! interpreter, security surface, and journal on top of this model, and
//! `registry-adapterctl` drives its checks. The dependency runs one way:
//! this crate depends on no other Adapter crate.
