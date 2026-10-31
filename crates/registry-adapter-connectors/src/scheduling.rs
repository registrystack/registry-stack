// SPDX-License-Identifier: Apache-2.0
//! The Scheduling connector: catalogue and availability reads, holds
//! and release, appointments, and busy preview and apply, over
//! `registry-scheduling-client` (`products/adapter/CONCEPT.md`
//! section 17.3).
//!
//! Task grants are host-supplied and never minted here; a capacity
//! command without a grant is refused.
