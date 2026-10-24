// SPDX-License-Identifier: Apache-2.0

#[path = "../src/allocation.rs"]
mod allocation;

use allocation::{
    allocate_bundle, AllocatedResource, AllocationCandidate, AllocationContext, AllocationError,
    AllocationInterval, AllocationLimits, AllocationRequirement, StandingAllocation,
};
use chrono::{DateTime, TimeZone as _, Utc};

fn at(hour: u32, minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 23, hour, minute, 0).unwrap()
}

fn interval(start_hour: u32, end_hour: u32) -> AllocationInterval {
    interval_at(start_hour, 0, end_hour, 0)
}

fn interval_at(
    start_hour: u32,
    start_minute: u32,
    end_hour: u32,
    end_minute: u32,
) -> AllocationInterval {
    AllocationInterval {
        start: at(start_hour, start_minute),
        end: at(end_hour, end_minute),
    }
}

fn candidate(resource_id: &str, capacity_units: u32) -> AllocationCandidate {
    AllocationCandidate {
        resource_id: resource_id.to_owned(),
        capacity_units,
    }
}

fn requirement(
    id: &str,
    units: u32,
    candidates: Vec<AllocationCandidate>,
) -> AllocationRequirement {
    AllocationRequirement {
        id: id.to_owned(),
        interval: interval(9, 11),
        units,
        candidates,
    }
}

fn standing(
    reservation_id: &str,
    resource_id: &str,
    interval: AllocationInterval,
    units: u32,
) -> StandingAllocation {
    StandingAllocation {
        reservation_id: reservation_id.to_owned(),
        resource_id: resource_id.to_owned(),
        interval,
        units,
    }
}

fn limits() -> AllocationLimits {
    AllocationLimits {
        maximum_requirements: 8,
        maximum_units_per_requirement: 100,
        maximum_candidate_resources: 16,
        maximum_standing_allocations: 32,
    }
}

fn context(requirements: Vec<AllocationRequirement>) -> AllocationContext {
    AllocationContext {
        requirements,
        standing_allocations: Vec::new(),
        exclude_reservation: None,
        limits: limits(),
    }
}

#[test]
fn the_existing_one_resource_case_is_one_line_one_unit() {
    let allocation = allocate_bundle(&context(vec![requirement(
        "primary",
        1,
        vec![candidate("room-a", 1)],
    )]))
    .expect("one exclusive resource should allocate");

    assert_eq!(
        allocation,
        vec![AllocatedResource {
            requirement_id: "primary".to_owned(),
            resource_id: "room-a".to_owned(),
            units: 1,
        }]
    );
}

#[test]
fn a_room_projector_and_counted_chairs_allocate_as_one_bundle() {
    let allocation = allocate_bundle(&context(vec![
        requirement("room", 1, vec![candidate("room-a", 1)]),
        requirement("projector", 1, vec![candidate("projector-stock", 4)]),
        requirement("chairs", 30, vec![candidate("chair-stock", 60)]),
    ]))
    .expect("all three requirements fit");

    assert_eq!(
        allocation,
        vec![
            AllocatedResource {
                requirement_id: "chairs".to_owned(),
                resource_id: "chair-stock".to_owned(),
                units: 30,
            },
            AllocatedResource {
                requirement_id: "projector".to_owned(),
                resource_id: "projector-stock".to_owned(),
                units: 1,
            },
            AllocatedResource {
                requirement_id: "room".to_owned(),
                resource_id: "room-a".to_owned(),
                units: 1,
            },
        ]
    );
}

#[test]
fn quantity_can_split_across_interchangeable_capacity_one_members() {
    let allocation = allocate_bundle(&context(vec![requirement(
        "projectors",
        3,
        vec![
            candidate("projector-c", 1),
            candidate("projector-a", 1),
            candidate("projector-b", 1),
        ],
    )]))
    .expect("three capacity-one members should satisfy three units");

    assert_eq!(
        allocation,
        vec![
            AllocatedResource {
                requirement_id: "projectors".to_owned(),
                resource_id: "projector-a".to_owned(),
                units: 1,
            },
            AllocatedResource {
                requirement_id: "projectors".to_owned(),
                resource_id: "projector-b".to_owned(),
                units: 1,
            },
            AllocatedResource {
                requirement_id: "projectors".to_owned(),
                resource_id: "projector-c".to_owned(),
                units: 1,
            },
        ]
    );
}

#[test]
fn occupancy_uses_peak_concurrency_not_the_sum_of_every_overlapping_claim() {
    let mut request = context(vec![requirement(
        "chairs",
        2,
        vec![candidate("chair-stock", 10)],
    )]);
    request.standing_allocations = vec![
        standing("morning", "chair-stock", interval(9, 10), 8),
        standing("afternoon", "chair-stock", interval(10, 11), 8),
    ];

    assert_eq!(
        allocate_bundle(&request).expect("peak use is eight, leaving two units"),
        vec![AllocatedResource {
            requirement_id: "chairs".to_owned(),
            resource_id: "chair-stock".to_owned(),
            units: 2,
        }]
    );
}

#[test]
fn half_open_intervals_release_capacity_at_the_end_instant() {
    let mut request = context(vec![requirement("room", 1, vec![candidate("room-a", 1)])]);
    request.requirements[0].interval = interval(10, 11);
    request.standing_allocations = vec![standing("earlier", "room-a", interval(9, 10), 1)];

    assert!(allocate_bundle(&request).is_ok());
}

#[test]
fn every_requirement_uses_its_own_occupied_interval() {
    let mut room = requirement("room", 1, vec![candidate("room-a", 1)]);
    room.interval = interval_at(8, 45, 11, 15);
    let mut projector = requirement("projector", 1, vec![candidate("projector-a", 1)]);
    projector.interval = interval(9, 11);
    let mut request = context(vec![room, projector]);
    request.standing_allocations = vec![standing(
        "earlier-projector",
        "projector-a",
        interval(8, 9),
        1,
    )];

    assert!(
        allocate_bundle(&request).is_ok(),
        "a projector allocation ending at 09:00 must not overlap its line"
    );

    request.standing_allocations.push(standing(
        "earlier-room",
        "room-a",
        interval_at(8, 30, 8, 50),
        1,
    ));
    assert_eq!(
        allocate_bundle(&request),
        Err(AllocationError::CapacityExhausted {
            requirement_id: "room".to_owned(),
        }),
        "the room line must retain its longer setup buffer"
    );
}

#[test]
fn insufficient_stock_refuses_the_complete_bundle() {
    let mut request = context(vec![
        requirement("room", 1, vec![candidate("room-a", 1)]),
        requirement("chairs", 30, vec![candidate("chair-stock", 30)]),
    ]);
    request.standing_allocations = vec![standing(
        "other-reservation",
        "chair-stock",
        interval(9, 11),
        1,
    )];

    assert_eq!(
        allocate_bundle(&request),
        Err(AllocationError::CapacityExhausted {
            requirement_id: "chairs".to_owned(),
        })
    );
}

#[test]
fn duplicate_requirement_ids_and_candidate_resources_are_refused() {
    let duplicate_id = context(vec![
        requirement("equipment", 1, vec![candidate("projector", 1)]),
        requirement("equipment", 1, vec![candidate("speaker", 1)]),
    ]);
    assert_eq!(
        allocate_bundle(&duplicate_id),
        Err(AllocationError::DuplicateRequirement {
            requirement_id: "equipment".to_owned(),
        })
    );

    let duplicate_resource = context(vec![
        requirement("presentation", 1, vec![candidate("projector", 1)]),
        requirement("equipment", 1, vec![candidate("projector", 1)]),
    ]);
    let overlap = allocate_bundle(&duplicate_resource).unwrap_err();
    assert_eq!(
        overlap,
        AllocationError::OverlappingRequirements {
            resource_id: "projector".to_owned(),
            first_requirement_id: "equipment".to_owned(),
            second_requirement_id: "presentation".to_owned(),
        }
    );
    assert!(
        overlap.to_string().contains(
            "combine quantities for the same fungible pool or use disjoint exact selections"
        ),
        "the refusal should tell an adopter how to remove the ambiguous overlap"
    );

    let repeated_within_line = context(vec![requirement(
        "equipment",
        1,
        vec![candidate("projector", 1), candidate("projector", 1)],
    )]);
    assert_eq!(
        allocate_bundle(&repeated_within_line),
        Err(AllocationError::DuplicateCandidateResource {
            requirement_id: "equipment".to_owned(),
            resource_id: "projector".to_owned(),
        })
    );
}

#[test]
fn rescheduling_excludes_every_allocation_of_the_logical_reservation() {
    let mut request = context(vec![
        requirement("room", 1, vec![candidate("room-a", 1)]),
        requirement("chairs", 30, vec![candidate("chair-stock", 30)]),
    ]);
    request.standing_allocations = vec![
        standing("reservation-1", "room-a", interval(9, 11), 1),
        standing("reservation-1", "chair-stock", interval(9, 11), 30),
    ];

    assert_eq!(
        allocate_bundle(&request),
        Err(AllocationError::CapacityExhausted {
            requirement_id: "chairs".to_owned(),
        })
    );
    request.exclude_reservation = Some("reservation-1".to_owned());
    assert!(allocate_bundle(&request).is_ok());
}

#[test]
fn allocation_is_deterministic_across_requirement_and_candidate_order() {
    let first = context(vec![
        requirement(
            "room",
            1,
            vec![candidate("room-b", 1), candidate("room-a", 1)],
        ),
        requirement(
            "equipment",
            2,
            vec![candidate("speaker-b", 1), candidate("speaker-a", 1)],
        ),
    ]);
    let second = context(vec![
        requirement(
            "equipment",
            2,
            vec![candidate("speaker-a", 1), candidate("speaker-b", 1)],
        ),
        requirement(
            "room",
            1,
            vec![candidate("room-a", 1), candidate("room-b", 1)],
        ),
    ]);

    assert_eq!(
        allocate_bundle(&first).expect("first spelling should allocate"),
        allocate_bundle(&second).expect("second spelling should allocate")
    );
}

#[test]
fn request_lines_units_and_candidate_resources_are_bounded() {
    let empty = context(Vec::new());
    assert_eq!(allocate_bundle(&empty), Err(AllocationError::EmptyBundle));

    let mut too_many_lines = context(vec![
        requirement("one", 1, vec![candidate("one", 1)]),
        requirement("two", 1, vec![candidate("two", 1)]),
    ]);
    too_many_lines.limits.maximum_requirements = 1;
    assert_eq!(
        allocate_bundle(&too_many_lines),
        Err(AllocationError::TooManyRequirements { maximum: 1 })
    );

    let zero_units = context(vec![requirement(
        "chairs",
        0,
        vec![candidate("chairs", 30)],
    )]);
    assert_eq!(
        allocate_bundle(&zero_units),
        Err(AllocationError::InvalidUnits {
            requirement_id: "chairs".to_owned(),
        })
    );

    let too_many_units = context(vec![requirement(
        "chairs",
        101,
        vec![candidate("chairs", 101)],
    )]);
    assert_eq!(
        allocate_bundle(&too_many_units),
        Err(AllocationError::TooManyUnits {
            requirement_id: "chairs".to_owned(),
            maximum: 100,
        })
    );

    let mut too_many_resources = context(vec![requirement(
        "rooms",
        1,
        vec![candidate("room-a", 1), candidate("room-b", 1)],
    )]);
    too_many_resources.limits.maximum_candidate_resources = 1;
    assert_eq!(
        allocate_bundle(&too_many_resources),
        Err(AllocationError::TooManyCandidateResources { maximum: 1 })
    );

    let mut oversized_snapshot =
        context(vec![requirement("room", 1, vec![candidate("room-a", 1)])]);
    oversized_snapshot.limits.maximum_standing_allocations = 1;
    oversized_snapshot.standing_allocations = vec![
        standing("one", "room-a", interval(7, 8), 1),
        standing("two", "room-a", interval(8, 9), 1),
    ];
    assert_eq!(
        allocate_bundle(&oversized_snapshot),
        Err(AllocationError::SnapshotTooLarge { maximum: 1 })
    );
}

#[test]
fn malformed_intervals_and_zero_capacity_fail_closed() {
    let mut invalid_interval = context(vec![requirement("room", 1, vec![candidate("room-a", 1)])]);
    invalid_interval.requirements[0].interval.end = invalid_interval.requirements[0].interval.start;
    assert_eq!(
        allocate_bundle(&invalid_interval),
        Err(AllocationError::InvalidInterval {
            requirement_id: "room".to_owned(),
        })
    );

    let zero_capacity = context(vec![requirement("room", 1, vec![candidate("room-a", 0)])]);
    assert_eq!(
        allocate_bundle(&zero_capacity),
        Err(AllocationError::InvalidCapacity {
            resource_id: "room-a".to_owned(),
        })
    );

    let mut overflowing_occupancy = context(vec![requirement(
        "room",
        1,
        vec![candidate("room-a", u32::MAX)],
    )]);
    overflowing_occupancy.standing_allocations = vec![
        standing("one", "room-a", interval(9, 11), u32::MAX),
        standing("two", "room-a", interval(9, 11), 1),
    ];
    assert_eq!(
        allocate_bundle(&overflowing_occupancy),
        Err(AllocationError::OccupancyOverflow {
            resource_id: "room-a".to_owned(),
        })
    );
}
