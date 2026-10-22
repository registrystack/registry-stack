// SPDX-License-Identifier: Apache-2.0
//! Public Registry Stack launcher and component manager.

pub mod assets;
mod cli;
pub mod install;
mod model;
pub mod store;

pub use cli::command;
pub use model::{Asset, ComponentManifest, ReleaseManifest, Selection, SelectionPlan};
pub use store::{
    CleanupReport, Generation, GenerationStore, InvocationLease, MutationGuard, PreserveReason,
    PreservedGeneration, PublicLinkStatus, StagedGeneration,
};

pub fn run() -> i32 {
    cli::run()
}
