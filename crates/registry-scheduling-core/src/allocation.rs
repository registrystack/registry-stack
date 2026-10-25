// SPDX-License-Identifier: Apache-2.0

//! Pure allocation of one logical reservation across bounded resource supply.
//!
//! Policy resolution, authorization, persistence, and lifecycle transitions
//! stay outside this module. Callers pass already-resolved, disjoint candidate
//! sets and standing allocations from one capacity snapshot. The allocator
//! either returns every resource allocation or no allocation at all.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use thiserror::Error;

/// The occupied half-open interval `[start, end)` used for capacity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationInterval {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl AllocationInterval {
    fn is_valid(&self) -> bool {
        self.start < self.end
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// One resource that may satisfy an allocation requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCandidate {
    pub resource_id: String,
    /// Simultaneous units this resource can supply.
    pub capacity_units: u32,
}

/// One independently resolved line of a logical reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationRequirement {
    /// Stable identity within the logical reservation.
    pub id: String,
    /// Occupied interval for this line, including its own setup and cleanup.
    pub interval: AllocationInterval,
    /// Resource units requested, distinct from people and window units.
    pub units: u32,
    /// Exact selection is one candidate; fungible selection may carry several.
    pub candidates: Vec<AllocationCandidate>,
}

/// One standing allocation in the authoritative capacity snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingAllocation {
    /// The logical reservation identity, shared by every child allocation.
    pub reservation_id: String,
    pub resource_id: String,
    pub interval: AllocationInterval,
    pub units: u32,
}

/// Explicit work and quantity limits supplied by the owning model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationLimits {
    pub maximum_requirements: usize,
    pub maximum_units_per_requirement: u32,
    pub maximum_candidate_resources: usize,
    pub maximum_standing_allocations: usize,
}

/// Complete input to one pure allocation decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationContext {
    pub requirements: Vec<AllocationRequirement>,
    pub standing_allocations: Vec<StandingAllocation>,
    /// The logical reservation replaced by a reschedule, if any.
    pub exclude_reservation: Option<String>,
    pub limits: AllocationLimits,
}

/// One child resource allocation returned for the logical reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatedResource {
    pub requirement_id: String,
    pub resource_id: String,
    pub units: u32,
}

/// A fail-closed refusal from the pure allocator.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AllocationError {
    #[error("an allocation bundle must contain at least one requirement")]
    EmptyBundle,
    #[error("the allocation bundle exceeds the maximum of {maximum} requirements")]
    TooManyRequirements { maximum: usize },
    #[error("the capacity snapshot exceeds the maximum of {maximum} standing allocations")]
    SnapshotTooLarge { maximum: usize },
    #[error("allocation requirement {requirement_id} must have a non-empty occupied interval")]
    InvalidInterval { requirement_id: String },
    #[error("an allocation requirement must have a non-empty identity")]
    InvalidRequirementId,
    #[error("allocation requirement {requirement_id} appears more than once")]
    DuplicateRequirement { requirement_id: String },
    #[error("allocation requirement {requirement_id} must request at least one unit")]
    InvalidUnits { requirement_id: String },
    #[error(
        "allocation requirement {requirement_id} exceeds the maximum quantity of {maximum} units"
    )]
    TooManyUnits {
        requirement_id: String,
        maximum: u32,
    },
    #[error("the allocation bundle exceeds the maximum of {maximum} candidate resources")]
    TooManyCandidateResources { maximum: usize },
    #[error("an allocation candidate must have a non-empty resource identity")]
    InvalidResourceId,
    #[error("candidate resource {resource_id} must provide at least one capacity unit")]
    InvalidCapacity { resource_id: String },
    #[error("requirement {requirement_id} repeats candidate resource {resource_id}")]
    DuplicateCandidateResource {
        requirement_id: String,
        resource_id: String,
    },
    #[error(
        "resource {resource_id} is a candidate for both requirements {first_requirement_id} and {second_requirement_id}; combine quantities for the same fungible pool or use disjoint exact selections"
    )]
    OverlappingRequirements {
        resource_id: String,
        first_requirement_id: String,
        second_requirement_id: String,
    },
    #[error("the standing allocation for reservation {reservation_id} and resource {resource_id} is invalid")]
    InvalidStandingAllocation {
        reservation_id: String,
        resource_id: String,
    },
    #[error("standing occupancy for resource {resource_id} exceeds the supported quantity")]
    OccupancyOverflow { resource_id: String },
    #[error("standing occupancy events for resource {resource_id} are inconsistent")]
    OccupancyInconsistent { resource_id: String },
    #[error("capacity is exhausted for allocation requirement {requirement_id}")]
    CapacityExhausted { requirement_id: String },
}

/// Allocate every resolved requirement or return one refusal and no result.
///
/// Requirement and candidate order do not influence the result. A requirement
/// may split its units across several interchangeable candidates. Candidate
/// sets may not overlap across requirements: that ambiguity is refused before
/// capacity evaluation rather than solved with an arbitrary assignment.
pub fn allocate_bundle(
    context: &AllocationContext,
) -> Result<Vec<AllocatedResource>, AllocationError> {
    validate_context(context)?;

    let mut requirements: Vec<&AllocationRequirement> = context.requirements.iter().collect();
    requirements.sort_by(|left, right| left.id.cmp(&right.id));

    let mut allocated = Vec::new();
    for requirement in requirements {
        let mut candidates: Vec<&AllocationCandidate> = requirement.candidates.iter().collect();
        candidates.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));

        let mut remaining = requirement.units;
        for candidate in candidates {
            let occupied = maximum_concurrent_units(
                &candidate.resource_id,
                &requirement.interval,
                &context.standing_allocations,
                context.exclude_reservation.as_deref(),
            )?;
            let free = candidate.capacity_units.saturating_sub(occupied);
            let taken = remaining.min(free);
            if taken > 0 {
                allocated.push(AllocatedResource {
                    requirement_id: requirement.id.clone(),
                    resource_id: candidate.resource_id.clone(),
                    units: taken,
                });
                remaining -= taken;
            }
            if remaining == 0 {
                break;
            }
        }
        if remaining > 0 {
            return Err(AllocationError::CapacityExhausted {
                requirement_id: requirement.id.clone(),
            });
        }
    }

    Ok(allocated)
}

fn validate_context(context: &AllocationContext) -> Result<(), AllocationError> {
    if context.requirements.is_empty() {
        return Err(AllocationError::EmptyBundle);
    }
    if context.requirements.len() > context.limits.maximum_requirements {
        return Err(AllocationError::TooManyRequirements {
            maximum: context.limits.maximum_requirements,
        });
    }
    if context.standing_allocations.len() > context.limits.maximum_standing_allocations {
        return Err(AllocationError::SnapshotTooLarge {
            maximum: context.limits.maximum_standing_allocations,
        });
    }

    for standing in &context.standing_allocations {
        if standing.reservation_id.is_empty()
            || standing.resource_id.is_empty()
            || standing.units == 0
            || !standing.interval.is_valid()
        {
            return Err(AllocationError::InvalidStandingAllocation {
                reservation_id: standing.reservation_id.clone(),
                resource_id: standing.resource_id.clone(),
            });
        }
    }

    let mut requirements: Vec<&AllocationRequirement> = context.requirements.iter().collect();
    requirements.sort_by(|left, right| left.id.cmp(&right.id));
    let mut requirement_ids = BTreeSet::new();
    let mut resource_owners: BTreeMap<&str, &str> = BTreeMap::new();
    let mut candidate_count = 0usize;

    for requirement in requirements {
        if requirement.id.is_empty() {
            return Err(AllocationError::InvalidRequirementId);
        }
        if !requirement.interval.is_valid() {
            return Err(AllocationError::InvalidInterval {
                requirement_id: requirement.id.clone(),
            });
        }
        if !requirement_ids.insert(requirement.id.as_str()) {
            return Err(AllocationError::DuplicateRequirement {
                requirement_id: requirement.id.clone(),
            });
        }
        if requirement.units == 0 {
            return Err(AllocationError::InvalidUnits {
                requirement_id: requirement.id.clone(),
            });
        }
        if requirement.units > context.limits.maximum_units_per_requirement {
            return Err(AllocationError::TooManyUnits {
                requirement_id: requirement.id.clone(),
                maximum: context.limits.maximum_units_per_requirement,
            });
        }

        let mut line_resources = BTreeSet::new();
        for candidate in &requirement.candidates {
            if candidate.resource_id.is_empty() {
                return Err(AllocationError::InvalidResourceId);
            }
            if candidate.capacity_units == 0 {
                return Err(AllocationError::InvalidCapacity {
                    resource_id: candidate.resource_id.clone(),
                });
            }
            if !line_resources.insert(candidate.resource_id.as_str()) {
                return Err(AllocationError::DuplicateCandidateResource {
                    requirement_id: requirement.id.clone(),
                    resource_id: candidate.resource_id.clone(),
                });
            }
            if let Some(first) =
                resource_owners.insert(candidate.resource_id.as_str(), requirement.id.as_str())
            {
                return Err(AllocationError::OverlappingRequirements {
                    resource_id: candidate.resource_id.clone(),
                    first_requirement_id: first.to_owned(),
                    second_requirement_id: requirement.id.clone(),
                });
            }
            candidate_count = candidate_count.checked_add(1).ok_or(
                AllocationError::TooManyCandidateResources {
                    maximum: context.limits.maximum_candidate_resources,
                },
            )?;
            if candidate_count > context.limits.maximum_candidate_resources {
                return Err(AllocationError::TooManyCandidateResources {
                    maximum: context.limits.maximum_candidate_resources,
                });
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum EventKind {
    End,
    Start,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OccupancyEvent {
    at: DateTime<Utc>,
    kind: EventKind,
    units: u32,
}

/// Peak standing occupancy for one resource inside a requested half-open
/// interval. End events sort before starts at the same instant.
pub fn maximum_concurrent_units(
    resource_id: &str,
    requested: &AllocationInterval,
    standing_allocations: &[StandingAllocation],
    exclude_reservation: Option<&str>,
) -> Result<u32, AllocationError> {
    let mut events = Vec::new();
    for standing in standing_allocations.iter().filter(|standing| {
        standing.resource_id == resource_id
            && Some(standing.reservation_id.as_str()) != exclude_reservation
            && standing.interval.overlaps(requested)
    }) {
        let start = standing.interval.start.max(requested.start);
        let end = standing.interval.end.min(requested.end);
        events.push(OccupancyEvent {
            at: start,
            kind: EventKind::Start,
            units: standing.units,
        });
        events.push(OccupancyEvent {
            at: end,
            kind: EventKind::End,
            units: standing.units,
        });
    }
    events.sort_by_key(|event| (event.at, event.kind));

    let mut current = 0u32;
    let mut maximum = 0u32;
    for event in events {
        match event.kind {
            EventKind::End => {
                current = current.checked_sub(event.units).ok_or_else(|| {
                    AllocationError::OccupancyInconsistent {
                        resource_id: resource_id.to_owned(),
                    }
                })?;
            }
            EventKind::Start => {
                current = current.checked_add(event.units).ok_or_else(|| {
                    AllocationError::OccupancyOverflow {
                        resource_id: resource_id.to_owned(),
                    }
                })?;
                maximum = maximum.max(current);
            }
        }
    }

    Ok(maximum)
}
