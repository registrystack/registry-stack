// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::IssuerPrincipal;

/// A live directory fact. Recording an absence does not move existing work
/// or grant the cover any source authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbsenceRecord {
    pub absence_id: Uuid,
    pub person: IssuerPrincipal,
    pub from: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub cover: IssuerPrincipal,
    pub revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbsenceList {
    pub directory_revision: i64,
    pub items: Vec<AbsenceRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbsenceInput {
    pub person: IssuerPrincipal,
    pub from: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub cover: IssuerPrincipal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AbsenceError {
    #[error("the absence must end after it starts")]
    InvalidPeriod,
    #[error("a person cannot cover their own absence")]
    SelfCover,
    #[error("the person already has an absence during this period")]
    OverlappingPeriod,
    #[error("the cover would form a cycle during this period")]
    CoverCycle,
}

/// Validate against directory records read under the directory mutation lock.
/// For an update, the caller excludes the record being replaced.
pub fn validate_absence(
    existing: &[AbsenceRecord],
    candidate: &AbsenceInput,
) -> Result<(), AbsenceError> {
    if candidate.from >= candidate.until {
        return Err(AbsenceError::InvalidPeriod);
    }
    if candidate.person == candidate.cover {
        return Err(AbsenceError::SelfCover);
    }
    if existing.iter().any(|record| {
        record.person == candidate.person
            && record.from < candidate.until
            && candidate.from < record.until
    }) {
        return Err(AbsenceError::OverlappingPeriod);
    }
    // Keep the intersection of all intervals along the path. Pairwise overlap
    // alone would reject a cycle whose edges are never active together.
    let mut pending = vec![(
        &candidate.cover,
        candidate.from,
        candidate.until,
        BTreeSet::new(),
    )];
    while let Some((person, from, until, mut visited)) = pending.pop() {
        if person == &candidate.person {
            return Err(AbsenceError::CoverCycle);
        }
        if !visited.insert(person) {
            continue;
        }
        for record in existing.iter().filter(|record| &record.person == person) {
            let overlap_from = from.max(record.from);
            let overlap_until = until.min(record.until);
            if overlap_from < overlap_until {
                pending.push((&record.cover, overlap_from, overlap_until, visited.clone()));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbsenceCover {
    pub person: IssuerPrincipal,
    pub absence_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentRequest {
    pub assignee: IssuerPrincipal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegateRequest {
    pub delegate: IssuerPrincipal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseloadMoveRequest {
    pub from: IssuerPrincipal,
    pub to: IssuerPrincipal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_id: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseloadItemSelection {
    pub item_id: Uuid,
    pub expected_revision: i64,
}

/// Apply only explicitly reviewed items. The service refuses more than 100
/// selections and checks each revision in its own atomic transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseloadApplyRequest {
    pub movement: CaseloadMoveRequest,
    pub items: Vec<CaseloadItemSelection>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseloadItemOutcome {
    Moved,
    NotVisible,
    NotEligible,
    AttemptInProgress,
    Conflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseloadItemResult {
    pub item_id: Uuid,
    pub result: CaseloadItemOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<i64>,
}

/// Preview pages contain only caller-visible work items; an apply response
/// contains results only for the explicit selections supplied by that caller.
pub type CaseloadPreviewPage = crate::Page<crate::WorkItem>;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseloadPreviewQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Resolve routing only. The caller must check current queue membership and
/// retain unassignable work in its serving queue with a staffing diagnostic.
pub fn resolve_absence_cover(
    person: &IssuerPrincipal,
    now: DateTime<Utc>,
    records: &[AbsenceRecord],
) -> Result<AbsenceCover, AbsenceError> {
    let mut current = person;
    let mut visited = BTreeSet::new();
    let mut absence_ids = Vec::new();
    loop {
        if !visited.insert(current) {
            return Err(AbsenceError::CoverCycle);
        }
        let mut active = records
            .iter()
            .filter(|record| &record.person == current && record.from <= now && now < record.until);
        let Some(record) = active.next() else {
            return Ok(AbsenceCover {
                person: current.clone(),
                absence_ids,
            });
        };
        if active.next().is_some() {
            return Err(AbsenceError::OverlappingPeriod);
        }
        absence_ids.push(record.absence_id);
        current = &record.cover;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(subject: &str) -> IssuerPrincipal {
        IssuerPrincipal {
            issuer: "https://idp.example".into(),
            subject: subject.into(),
        }
    }

    fn time(hour: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(hour * 3600, 0).unwrap()
    }

    fn absence(subject: &str, cover: &str, from: i64, until: i64) -> AbsenceRecord {
        AbsenceRecord {
            absence_id: Uuid::new_v4(),
            person: person(subject),
            cover: person(cover),
            from: time(from),
            until: time(until),
            revision: 1,
        }
    }

    fn input(record: &AbsenceRecord) -> AbsenceInput {
        AbsenceInput {
            person: record.person.clone(),
            cover: record.cover.clone(),
            from: record.from,
            until: record.until,
        }
    }

    #[test]
    fn cover_interval_is_start_inclusive_end_exclusive_and_records_chain() {
        let records = [absence("a", "b", 10, 20), absence("b", "c", 10, 15)];
        assert_eq!(
            resolve_absence_cover(&person("a"), time(9), &records)
                .unwrap()
                .person,
            person("a")
        );
        let covered = resolve_absence_cover(&person("a"), time(10), &records).unwrap();
        assert_eq!(covered.person, person("c"));
        assert_eq!(covered.absence_ids, records.map(|record| record.absence_id));
        let records = [absence("a", "b", 10, 20), absence("b", "c", 10, 15)];
        assert_eq!(
            resolve_absence_cover(&person("a"), time(15), &records)
                .unwrap()
                .person,
            person("b")
        );
        assert_eq!(
            resolve_absence_cover(&person("a"), time(20), &records)
                .unwrap()
                .person,
            person("a")
        );
    }

    #[test]
    fn cycles_require_one_shared_instant_across_the_whole_path() {
        let candidate = input(&absence("a", "b", 0, 30));
        assert_eq!(
            validate_absence(
                &[absence("b", "c", 0, 10), absence("c", "a", 10, 20)],
                &candidate
            ),
            Ok(())
        );
        assert_eq!(
            validate_absence(
                &[absence("b", "c", 0, 11), absence("c", "a", 10, 20)],
                &candidate
            ),
            Err(AbsenceError::CoverCycle)
        );
    }

    #[test]
    fn invalid_or_ambiguous_absences_are_refused() {
        assert_eq!(
            validate_absence(&[], &input(&absence("a", "a", 0, 10))),
            Err(AbsenceError::SelfCover)
        );
        assert_eq!(
            validate_absence(&[], &input(&absence("a", "b", 10, 10))),
            Err(AbsenceError::InvalidPeriod)
        );
        let existing = [absence("a", "b", 0, 10)];
        assert_eq!(
            validate_absence(&existing, &input(&absence("a", "c", 9, 20))),
            Err(AbsenceError::OverlappingPeriod)
        );
        assert_eq!(
            validate_absence(&existing, &input(&absence("a", "c", 10, 20))),
            Ok(())
        );
        let corrupt = [absence("a", "b", 0, 10), absence("b", "a", 0, 10)];
        assert_eq!(
            resolve_absence_cover(&person("a"), time(5), &corrupt),
            Err(AbsenceError::CoverCycle)
        );
    }
}
