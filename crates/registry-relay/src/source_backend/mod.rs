// SPDX-License-Identifier: Apache-2.0
//! Request-aware source backends for governed consultations.
//!
//! SnapshotExact is deliberately separate from the generic entity-query and
//! connector boundaries. A consultation can capture only an immutable handle
//! that was published through the durable materialization state plane.

mod datafusion;
mod materialization;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use ::datafusion::catalog::TableProvider;
use arc_swap::ArcSwapOption;
use thiserror::Error;
use ulid::Ulid;

use crate::consultation::SnapshotGenerationId;
use crate::source_plan::{CompiledConsultationRegistry, CompiledSourcePlan, SourcePlanKind};

pub(crate) use datafusion::{
    decode_snapshot_rows, execute_snapshot_exact, SnapshotExactBackendError,
    SnapshotExactBackendResult, SnapshotExactRecord,
};
pub(crate) use materialization::{
    ActiveSnapshotCandidate, SnapshotMaterializationCandidate, SnapshotMaterializationCoordinator,
};

const SLOT_UNAVAILABLE: u8 = 0;
const SLOT_PUBLISHING: u8 = 1;
const SLOT_READY: u8 = 2;

/// Restricted digest of the complete immutable snapshot bytes.
///
/// It is retained only in the state plane and the private published handle.
/// It is never serialized into public consultation provenance.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SnapshotContentDigest([u8; 32]);

impl SnapshotContentDigest {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SnapshotContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SnapshotContentDigest(<restricted>)")
    }
}

/// Exact immutable snapshot captured for one consultation.
///
/// The provider is paired with the identity and digest that were atomically
/// made active. Callers cannot replace any member independently.
pub(crate) struct PublishedSnapshotHandle {
    generation: SnapshotGenerationId,
    digest: SnapshotContentDigest,
    published_at_unix_ms: i64,
    source_revision: Option<Box<str>>,
    source_observed_at_unix_ms: Option<i64>,
    provider: Arc<dyn TableProvider>,
}

impl PublishedSnapshotHandle {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        generation: Ulid,
        digest: SnapshotContentDigest,
        published_at_unix_ms: i64,
        source_revision: Option<String>,
        source_observed_at_unix_ms: Option<i64>,
        provider: Arc<dyn TableProvider>,
    ) -> Result<Self, SnapshotRegistryError> {
        let generation = SnapshotGenerationId::try_from(generation.to_string().as_str())
            .map_err(|_| SnapshotRegistryError::InvalidPublication)?;
        if published_at_unix_ms <= 0
            || source_revision
                .as_deref()
                .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
            || source_observed_at_unix_ms.is_some_and(|value| value <= 0)
            || source_observed_at_unix_ms.is_some_and(|value| value > published_at_unix_ms)
        {
            return Err(SnapshotRegistryError::InvalidPublication);
        }
        Ok(Self {
            generation,
            digest,
            published_at_unix_ms,
            source_revision: source_revision.map(String::into_boxed_str),
            source_observed_at_unix_ms,
            provider,
        })
    }

    pub(crate) const fn generation(&self) -> SnapshotGenerationId {
        self.generation
    }

    pub(crate) const fn published_at_unix_ms(&self) -> i64 {
        self.published_at_unix_ms
    }

    pub(crate) fn provider(&self) -> Arc<dyn TableProvider> {
        Arc::clone(&self.provider)
    }
}

impl fmt::Debug for PublishedSnapshotHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedSnapshotHandle")
            .field("generation", &self.generation)
            .field("digest", &self.digest)
            .field("published_at_unix_ms", &self.published_at_unix_ms)
            .field(
                "source_revision",
                &self.source_revision.as_ref().map(|_| "<set>"),
            )
            .field(
                "source_observed_at_unix_ms",
                &self.source_observed_at_unix_ms.map(|_| "<set>"),
            )
            .field("provider", &"<private>")
            .finish()
    }
}

struct SnapshotSlot {
    dependent_plans: BTreeSet<(Box<str>, u64, Box<str>)>,
    state: AtomicU8,
    handle: ArcSwapOption<PublishedSnapshotHandle>,
}

impl SnapshotSlot {
    fn matches_plan(&self, plan: &CompiledSourcePlan) -> bool {
        self.dependent_plans.contains(&(
            plan.profile().id().as_str().into(),
            plan.profile().version().get(),
            plan.binding_hash().into(),
        ))
    }
}

/// Immutable registry of SnapshotExact publication slots.
///
/// One immutable publication slot may serve several compatible consultation
/// profiles. Each profile remains independently authorized and readiness-gated.
pub(crate) struct PublishedSnapshotRegistry {
    by_provider: BTreeMap<Box<str>, Arc<SnapshotSlot>>,
}

impl PublishedSnapshotRegistry {
    pub(crate) fn compile(
        registry: &CompiledConsultationRegistry,
    ) -> Result<Self, SnapshotRegistryError> {
        let mut dependencies = BTreeMap::<Box<str>, BTreeSet<(Box<str>, u64, Box<str>)>>::new();
        for plan in registry
            .plans_for_concrete_activation()
            .filter(|plan| plan.kind() == SourcePlanKind::SnapshotExact)
        {
            let binding = plan
                .snapshot_binding()
                .ok_or(SnapshotRegistryError::InvalidPlan)?;
            let provider: Box<str> = binding.table_provider().into();
            dependencies.entry(provider).or_default().insert((
                plan.profile().id().as_str().into(),
                plan.profile().version().get(),
                plan.binding_hash().into(),
            ));
        }
        let by_provider = dependencies
            .into_iter()
            .map(|(provider, dependent_plans)| {
                (
                    provider,
                    Arc::new(SnapshotSlot {
                        dependent_plans,
                        state: AtomicU8::new(SLOT_UNAVAILABLE),
                        handle: ArcSwapOption::empty(),
                    }),
                )
            })
            .collect();
        Ok(Self { by_provider })
    }

    pub(crate) fn begin_publication(
        &self,
        table_provider: &str,
    ) -> Result<SnapshotPublicationGuard, SnapshotRegistryError> {
        let slot = self
            .by_provider
            .get(table_provider)
            .cloned()
            .ok_or(SnapshotRegistryError::UnknownProvider)?;
        let claimed = slot
            .state
            .compare_exchange(
                SLOT_READY,
                SLOT_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
            || slot
                .state
                .compare_exchange(
                    SLOT_UNAVAILABLE,
                    SLOT_PUBLISHING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok();
        if !claimed {
            return Err(SnapshotRegistryError::PublicationInProgress);
        }
        Ok(SnapshotPublicationGuard {
            slot,
            completed: false,
        })
    }

    pub(crate) fn capture(
        &self,
        plan: &CompiledSourcePlan,
    ) -> Result<Arc<PublishedSnapshotHandle>, SnapshotRegistryError> {
        let binding = plan
            .snapshot_binding()
            .ok_or(SnapshotRegistryError::InvalidPlan)?;
        let slot = self
            .by_provider
            .get(binding.table_provider())
            .ok_or(SnapshotRegistryError::UnknownProvider)?;
        if !slot.matches_plan(plan) || slot.state.load(Ordering::Acquire) != SLOT_READY {
            return Err(SnapshotRegistryError::Unavailable);
        }
        slot.handle
            .load_full()
            .ok_or(SnapshotRegistryError::Unavailable)
    }

    pub(crate) fn is_current(
        &self,
        plan: &CompiledSourcePlan,
        handle: &Arc<PublishedSnapshotHandle>,
    ) -> bool {
        let Some(binding) = plan.snapshot_binding() else {
            return false;
        };
        let Some(slot) = self.by_provider.get(binding.table_provider()) else {
            return false;
        };
        slot.matches_plan(plan)
            && slot.state.load(Ordering::Acquire) == SLOT_READY
            && slot
                .handle
                .load_full()
                .is_some_and(|current| Arc::ptr_eq(&current, handle))
    }

    #[cfg(test)]
    pub(crate) fn all_ready(&self) -> bool {
        self.by_provider.values().all(|slot| {
            slot.state.load(Ordering::Acquire) == SLOT_READY && slot.handle.load().is_some()
        })
    }

    pub(crate) fn is_ready(&self, plan: &CompiledSourcePlan) -> bool {
        let Some(binding) = plan.snapshot_binding() else {
            return true;
        };
        self.by_provider
            .get(binding.table_provider())
            .is_some_and(|slot| {
                slot.matches_plan(plan)
                    && slot.state.load(Ordering::Acquire) == SLOT_READY
                    && slot.handle.load().is_some()
            })
    }
}

impl fmt::Debug for PublishedSnapshotRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedSnapshotRegistry")
            .field("provider_count", &self.by_provider.len())
            .finish()
    }
}

/// Critical-section guard that leaves the profile unavailable unless the
/// exact durably published handle is installed.
pub(crate) struct SnapshotPublicationGuard {
    slot: Arc<SnapshotSlot>,
    completed: bool,
}

impl SnapshotPublicationGuard {
    pub(crate) fn publish(mut self, handle: PublishedSnapshotHandle) {
        self.slot.handle.store(Some(Arc::new(handle)));
        self.slot.state.store(SLOT_READY, Ordering::Release);
        self.completed = true;
    }
}

impl Drop for SnapshotPublicationGuard {
    fn drop(&mut self) {
        if !self.completed {
            // Once replacement starts, the old handle cannot be used as a
            // stale fallback. A later successful publication is required.
            self.slot.state.store(SLOT_UNAVAILABLE, Ordering::Release);
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum SnapshotRegistryError {
    #[error("snapshot exact plan is invalid")]
    InvalidPlan,
    #[error("snapshot exact provider is unknown")]
    UnknownProvider,
    #[error("snapshot exact publication is already in progress")]
    PublicationInProgress,
    #[error("snapshot exact publication is invalid")]
    InvalidPublication,
    #[error("snapshot exact provider is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use ::datafusion::arrow::datatypes::{Schema, SchemaRef};
    use ::datafusion::catalog::TableProvider;
    use ::datafusion::datasource::MemTable;

    use super::*;

    fn empty_provider() -> Arc<dyn TableProvider> {
        let schema: SchemaRef = Arc::new(Schema::empty());
        Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("empty table provider"))
    }

    fn registry() -> Arc<PublishedSnapshotRegistry> {
        let slot = Arc::new(SnapshotSlot {
            dependent_plans: BTreeSet::from([(
                "synthetic.profile".into(),
                1,
                format!("sha256:{}", "a".repeat(64)).into(),
            )]),
            state: AtomicU8::new(SLOT_UNAVAILABLE),
            handle: ArcSwapOption::empty(),
        });
        Arc::new(PublishedSnapshotRegistry {
            by_provider: BTreeMap::from([("synthetic__persons".into(), slot)]),
        })
    }

    fn handle(generation: &str, published_at_unix_ms: i64) -> PublishedSnapshotHandle {
        PublishedSnapshotHandle::new(
            Ulid::from_string(generation).expect("test generation"),
            SnapshotContentDigest::from_bytes([0xab; 32]),
            published_at_unix_ms,
            Some(format!("sha256:{}", "b".repeat(64))),
            Some(published_at_unix_ms - 1),
            empty_provider(),
        )
        .expect("valid snapshot handle")
    }

    #[test]
    fn compatible_profiles_capture_one_shared_immutable_publication() {
        let compiled = crate::source_plan::shared_snapshot_registry_fixture();
        let plans = compiled
            .plans_for_concrete_activation()
            .filter(|plan| plan.kind() == SourcePlanKind::SnapshotExact)
            .collect::<Vec<_>>();
        assert_eq!(plans.len(), 2);
        let snapshots = PublishedSnapshotRegistry::compile(&compiled)
            .expect("compatible shared provider compiles");
        assert_eq!(snapshots.by_provider.len(), 1);
        let provider = plans[0]
            .snapshot_binding()
            .expect("snapshot binding")
            .table_provider();
        snapshots
            .begin_publication(provider)
            .expect("publication starts")
            .publish(handle("01JZ0000000000000000000001", 1_750_000_000_000));
        let first = snapshots.capture(plans[0]).expect("first profile ready");
        let second = snapshots.capture(plans[1]).expect("second profile ready");
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn unavailable_snapshot_marks_only_its_dependent_profiles_unready() {
        let compiled = crate::source_plan::shared_snapshot_registry_fixture();
        let snapshot_plan = compiled
            .plans_for_concrete_activation()
            .next()
            .expect("snapshot plan");
        let unrelated = crate::source_plan::dhis2_runtime_vector_plan_fixture();
        let snapshots =
            PublishedSnapshotRegistry::compile(&compiled).expect("snapshot registry compiles");
        assert!(!snapshots.is_ready(snapshot_plan));
        assert!(snapshots.is_ready(&unrelated));
    }

    #[test]
    fn publication_slot_has_one_atomic_writer_and_no_stale_fallback() {
        let registry = registry();
        let start = Arc::new(Barrier::new(9));
        let joins = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    registry.begin_publication("synthetic__persons")
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        let mut guards = joins
            .into_iter()
            .filter_map(|join| join.join().expect("writer joins").ok())
            .collect::<Vec<_>>();
        assert_eq!(guards.len(), 1);
        assert!(!registry.all_ready());

        guards
            .pop()
            .expect("one writer")
            .publish(handle("01J00000000000000000000001", 1_720_612_800_000));
        assert!(registry.all_ready());

        let replacement = registry
            .begin_publication("synthetic__persons")
            .expect("replacement writer claims slot");
        assert!(!registry.all_ready());
        drop(replacement);
        assert!(
            !registry.all_ready(),
            "old handle cannot become a stale fallback"
        );
    }

    #[test]
    fn snapshot_handle_rejects_invalid_provenance_ordering() {
        let result = PublishedSnapshotHandle::new(
            Ulid::from_string("01J00000000000000000000001").expect("test generation"),
            SnapshotContentDigest::from_bytes([0xab; 32]),
            1_720_612_800_000,
            None,
            Some(1_720_612_800_001),
            empty_provider(),
        );
        assert!(matches!(
            result,
            Err(SnapshotRegistryError::InvalidPublication)
        ));
    }
}
