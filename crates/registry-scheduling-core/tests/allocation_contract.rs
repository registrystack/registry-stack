// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, TimeZone as _, Utc};
use registry_scheduling_core::{
    admission_request_hash, AdditionalAllocationRequest, AdmissionRequest, AllocationDocument,
    AllocationRequirementDocument, AvailabilityEntry, AvailabilityPreviewDocument,
    AvailabilityPreviewRequest, HoldDocument, PoolMember, MAXIMUM_ADDITIONAL_ALLOCATIONS,
    MAXIMUM_RESOURCE_UNITS,
};

fn at(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 23, hour, 0, 0).unwrap()
}

fn request() -> AdmissionRequest {
    AdmissionRequest {
        offering: "room".to_owned(),
        start: at(9),
        duration_minutes: Some(120),
        resource: Some("room-a".to_owned()),
        resource_units: 1,
        additional_allocations: Vec::new(),
        party: None,
        manager: None,
        channel: None,
        duplicate_key: None,
        policy_revision: 7,
        window_revision: None,
        capabilities: Vec::new(),
        prerequisites: Vec::new(),
        external_references: Vec::new(),
        party_references: Vec::new(),
    }
}

fn additional(offering: &str, resource: Option<&str>, units: u32) -> AdditionalAllocationRequest {
    AdditionalAllocationRequest {
        offering: offering.to_owned(),
        resource: resource.map(str::to_owned),
        units,
    }
}

#[test]
fn one_primary_unit_preserves_the_existing_wire_shape_and_hash() {
    let request = request();
    let json = serde_json::to_value(&request).unwrap();
    assert!(json.get("resourceUnits").is_none());
    assert!(json.get("additionalAllocations").is_none());

    let legacy: AdmissionRequest = serde_json::from_value(json).unwrap();
    assert_eq!(legacy.resource_units, 1);
    assert!(legacy.additional_allocations.is_empty());
    assert_eq!(
        admission_request_hash(&legacy),
        admission_request_hash(&request)
    );
}

#[test]
fn bundle_hashes_are_order_independent_without_discarding_duplicates() {
    let mut first = request();
    first.resource_units = 2;
    first.additional_allocations = vec![
        additional("projector", Some("projector-a"), 1),
        additional("chairs", None, 30),
    ];
    let mut reordered = first.clone();
    reordered.additional_allocations.reverse();
    assert_eq!(
        admission_request_hash(&first),
        admission_request_hash(&reordered)
    );

    let mut duplicate = first.clone();
    duplicate
        .additional_allocations
        .push(additional("chairs", None, 30));
    assert_ne!(
        admission_request_hash(&first),
        admission_request_hash(&duplicate),
        "hashing must preserve an invalid duplicate so validation can refuse it"
    );
}

#[test]
fn request_lines_and_quantities_are_bounded_at_deserialization() {
    let mut json = serde_json::to_value(request()).unwrap();
    json["resourceUnits"] = serde_json::json!(0);
    assert!(serde_json::from_value::<AdmissionRequest>(json).is_err());

    let mut json = serde_json::to_value(request()).unwrap();
    json["resourceUnits"] = serde_json::json!(u64::from(MAXIMUM_RESOURCE_UNITS) + 1);
    assert!(serde_json::from_value::<AdmissionRequest>(json).is_err());

    let mut json = serde_json::to_value(request()).unwrap();
    json["additionalAllocations"] = serde_json::Value::Array(
        (0..=MAXIMUM_ADDITIONAL_ALLOCATIONS)
            .map(|index| {
                serde_json::json!({
                    "offering": format!("offering-{index}"),
                    "units": 1
                })
            })
            .collect(),
    );
    assert!(serde_json::from_value::<AdmissionRequest>(json).is_err());

    let mut preview = serde_json::json!({
        "offering": "room",
        "start": at(9),
    });
    preview["additionalAllocations"] = serde_json::Value::Array(
        (0..=MAXIMUM_ADDITIONAL_ALLOCATIONS)
            .map(|index| {
                serde_json::json!({
                    "offering": format!("offering-{index}"),
                    "units": 1
                })
            })
            .collect(),
    );
    assert!(serde_json::from_value::<AvailabilityPreviewRequest>(preview).is_err());
}

#[test]
fn counted_supply_defaults_to_one_and_can_represent_complete_loss() {
    let legacy: PoolMember = serde_json::from_value(serde_json::json!({
        "resourceId": "chairs",
        "available": true
    }))
    .unwrap();
    assert_eq!(legacy.capacity_units, 1);
    assert!(serde_json::to_value(&legacy)
        .unwrap()
        .get("capacityUnits")
        .is_none());

    let absent: PoolMember = serde_json::from_value(serde_json::json!({
        "resourceId": "chairs",
        "available": true,
        "capacityUnits": 0
    }))
    .unwrap();
    assert_eq!(absent.capacity_units, 0);
}

#[test]
fn authorized_documents_identify_requirements_and_their_occupied_spans() {
    let allocations = vec![
        AllocationDocument {
            requirement: AllocationRequirementDocument::Primary,
            offering: "room".to_owned(),
            resource: "room-a".to_owned(),
            units: 1,
            occupied_start: at(8),
            occupied_end: at(12),
        },
        AllocationDocument {
            requirement: AllocationRequirementDocument::Additional { index: 0 },
            offering: "projector".to_owned(),
            resource: "projector-a".to_owned(),
            units: 1,
            occupied_start: at(9),
            occupied_end: at(11),
        },
    ];
    let hold = HoldDocument {
        hold_id: "hold-1".to_owned(),
        offering: "room".to_owned(),
        start: at(9),
        end: at(11),
        resource: Some("room-a".to_owned()),
        units: 1,
        allocations: allocations.clone(),
        party: None,
        manager: None,
        party_references: Vec::new(),
        expires_at: at(10),
        policy_revision: 7,
        external_references: Vec::new(),
    };
    let json = serde_json::to_value(&hold).unwrap();
    assert_eq!(json["allocations"][0]["requirement"]["kind"], "primary");
    assert_eq!(
        json["allocations"][1]["requirement"],
        serde_json::json!({"kind": "additional", "index": 0})
    );
    assert_eq!(
        json["allocations"][0]["occupiedStart"],
        serde_json::to_value(at(8)).unwrap()
    );
    assert_eq!(serde_json::from_value::<HoldDocument>(json).unwrap(), hold);
}

#[test]
fn capacity_preview_is_a_closed_physical_request_and_not_an_admission_request() {
    let preview: AvailabilityPreviewRequest = serde_json::from_value(serde_json::json!({
        "offering": "room",
        "start": at(9),
        "durationMinutes": 120,
        "resource": "room-a",
        "resourceUnits": 1,
        "additionalAllocations": [
            {"offering": "chairs", "units": 30}
        ],
        "party": {"recipients": 10, "attendees": 12}
    }))
    .unwrap();
    assert_eq!(preview.resource_units, 1);
    assert_eq!(preview.additional_allocations[0].units, 30);

    for forbidden in ["manager", "partyReferences", "duplicateKey", "capabilities"] {
        let mut json = serde_json::to_value(&preview).unwrap();
        json[forbidden] = serde_json::json!("assertion");
        assert!(serde_json::from_value::<AvailabilityPreviewRequest>(json).is_err());
    }

    let answer = AvailabilityPreviewDocument {
        offering: "room".to_owned(),
        start: at(9),
        end: at(11),
        capacity_available: false,
        public_code: Some("capacity.exhausted".to_owned()),
    };
    let json = serde_json::to_value(answer).unwrap();
    assert_eq!(json["capacityAvailable"], false);
    assert_eq!(json["publicCode"], "capacity.exhausted");
}

#[test]
fn slot_member_count_and_physical_units_are_distinct() {
    let slot = AvailabilityEntry::Slot {
        start: at(9),
        end: at(10),
        free: 1,
        available_units: Some(30),
    };
    let json = serde_json::to_value(slot).unwrap();
    assert_eq!(json["free"], 1);
    assert_eq!(json["availableUnits"], 30);
}
