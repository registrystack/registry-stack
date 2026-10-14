// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use chrono::NaiveDate;
use registry_breg::statistics::{
    apply_disclosure, build_exact_cells, canonical_document_and_digest, current_period,
    document_csv, period_for_code, period_range, Cell, CellStatus, DatasetDocument,
    DimensionDomain, DisclosureDocument, DisclosureParameters, GroupedCell, LiveDocument, Measure,
    PeriodDocument, PeriodGranularity, PeriodKind, ReleaseDocument, ReleaseStatus,
    StatisticsDocument, StatisticsError, TOTAL_CODE, UNKNOWN_CODE,
};

fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("test date is valid")
}

#[test]
fn periods_cover_leap_day_and_calendar_boundaries() {
    let today = date(2024, 2, 29);
    let day = current_period(PeriodGranularity::Day, today).unwrap();
    assert_eq!(
        (
            day.code.as_str(),
            day.start,
            day.end,
            day.reference_date,
            day.ended
        ),
        ("2024-02-29", today, date(2024, 3, 1), today, false)
    );

    let month = period_for_code(PeriodGranularity::Month, "2024-02", today).unwrap();
    assert_eq!(
        (month.start, month.end, month.reference_date, month.ended),
        (date(2024, 2, 1), date(2024, 3, 1), today, false)
    );
    let ended_month = period_for_code(PeriodGranularity::Month, "2024-01", today).unwrap();
    assert_eq!(
        (ended_month.reference_date, ended_month.ended),
        (date(2024, 1, 31), true)
    );

    let quarter = period_for_code(PeriodGranularity::Quarter, "2025-Q4", date(2026, 1, 1)).unwrap();
    assert_eq!(
        (
            quarter.start,
            quarter.end,
            quarter.reference_date,
            quarter.ended
        ),
        (
            date(2025, 10, 1),
            date(2026, 1, 1),
            date(2025, 12, 31),
            true
        )
    );
    let year = period_for_code(PeriodGranularity::Year, "2025", date(2025, 12, 31)).unwrap();
    assert_eq!(
        (year.start, year.end, year.reference_date, year.ended),
        (
            date(2025, 1, 1),
            date(2026, 1, 1),
            date(2025, 12, 31),
            false
        )
    );
}

#[test]
fn period_range_is_inclusive_and_bounded_to_366() {
    let leap_year = period_range(
        PeriodGranularity::Day,
        "2024-01-01",
        "2024-12-31",
        date(2025, 1, 1),
    )
    .unwrap();
    assert_eq!(leap_year.len(), 366);
    assert_eq!(leap_year.first().unwrap().code, "2024-01-01");
    assert_eq!(leap_year.last().unwrap().code, "2024-12-31");
    assert_eq!(
        period_range(
            PeriodGranularity::Day,
            "2023-12-31",
            "2024-12-31",
            date(2025, 1, 1),
        ),
        Err(StatisticsError::TooManyPeriods)
    );
    assert!(matches!(
        period_range(
            PeriodGranularity::Month,
            "2025-02",
            "2025-01",
            date(2025, 2, 1),
        ),
        Err(StatisticsError::ReversedPeriodRange)
    ));
}

#[test]
fn period_codes_are_strict_sdmx_calendar_codes() {
    for (granularity, code) in [
        (PeriodGranularity::Day, "2023-02-29"),
        (PeriodGranularity::Day, "2024-2-01"),
        (PeriodGranularity::Day, "2024/02/01"),
        (PeriodGranularity::Month, "2024-13"),
        (PeriodGranularity::Quarter, "2024-Q0"),
        (PeriodGranularity::Quarter, "2024-q1"),
        (PeriodGranularity::Year, "24"),
    ] {
        assert!(matches!(
            period_for_code(granularity, code, date(2024, 1, 1)),
            Err(StatisticsError::InvalidPeriodCode { .. })
        ));
    }
}

#[test]
fn period_codes_refuse_non_ascii_without_panicking() {
    for (granularity, code) in [
        (PeriodGranularity::Quarter, "2025€"),
        (PeriodGranularity::Quarter, "a😀xx"),
        (PeriodGranularity::Month, "2025éx"),
        (PeriodGranularity::Day, "２０25-01"),
    ] {
        assert!(matches!(
            period_for_code(granularity, code, date(2025, 1, 1)),
            Err(StatisticsError::InvalidPeriodCode { .. })
        ));
    }
}

#[test]
fn period_codes_require_positive_four_digit_years_for_every_frequency() {
    for (granularity, code) in [
        (PeriodGranularity::Day, "0000-01-01"),
        (PeriodGranularity::Day, "-001-01-01"),
        (PeriodGranularity::Month, "0000-01"),
        (PeriodGranularity::Quarter, "0000-Q1"),
        (PeriodGranularity::Year, "0000"),
    ] {
        assert!(matches!(
            period_for_code(granularity, code, date(2025, 1, 1)),
            Err(StatisticsError::InvalidPeriodCode { .. })
        ));
    }
}

#[test]
fn period_codes_keep_the_exclusive_end_in_the_four_digit_date_domain() {
    for (granularity, code) in [
        (PeriodGranularity::Day, "9999-12-31"),
        (PeriodGranularity::Month, "9999-12"),
        (PeriodGranularity::Quarter, "9999-Q4"),
        (PeriodGranularity::Year, "9999"),
    ] {
        assert!(matches!(
            period_for_code(granularity, code, date(2025, 1, 1)),
            Err(StatisticsError::InvalidPeriodCode { .. })
        ));
    }
    for (granularity, code) in [
        (PeriodGranularity::Day, "9999-12-30"),
        (PeriodGranularity::Month, "9999-11"),
        (PeriodGranularity::Quarter, "9999-Q3"),
        (PeriodGranularity::Year, "9998"),
    ] {
        period_for_code(granularity, code, date(2025, 1, 1))
            .expect("periods whose exclusive end fits the wire date domain remain valid");
    }
}

#[test]
fn grouped_rows_are_zero_filled_and_margins_are_exact_sums() {
    let periods = period_range(
        PeriodGranularity::Month,
        "2025-01",
        "2025-01",
        date(2025, 2, 1),
    )
    .unwrap();
    let dimensions = vec![
        DimensionDomain {
            field: "region".to_owned(),
            vocabulary: "regions".to_owned(),
            codes: vec!["A".to_owned(), "B".to_owned()],
            include_unknown: true,
        },
        DimensionDomain {
            field: "eligible".to_owned(),
            vocabulary: "boolean".to_owned(),
            codes: vec!["true".to_owned(), "false".to_owned()],
            include_unknown: false,
        },
    ];
    let grouped = vec![
        GroupedCell {
            period: "2025-01".to_owned(),
            codes: vec!["A".to_owned(), "true".to_owned()],
            value: 2,
        },
        GroupedCell {
            period: "2025-01".to_owned(),
            codes: vec!["A".to_owned(), "false".to_owned()],
            value: 3,
        },
        GroupedCell {
            period: "2025-01".to_owned(),
            codes: vec![UNKNOWN_CODE.to_owned(), "true".to_owned()],
            value: 4,
        },
    ];
    let cells = build_exact_cells("enrolments", &periods, &dimensions, &grouped).unwrap();
    assert_eq!(cells.len(), 12);
    assert_eq!(cell_value(&cells, &[TOTAL_CODE, TOTAL_CODE]), Some(9));
    assert_eq!(cell_value(&cells, &["A", TOTAL_CODE]), Some(5));
    assert_eq!(cell_value(&cells, &[TOTAL_CODE, "true"]), Some(6));
    assert_eq!(cell_value(&cells, &["B", "true"]), Some(0));
    assert!(cells.iter().all(|cell| cell.status == CellStatus::Exact));
    assert_eq!(
        dimensions[0].document().codes,
        ["A", "B", UNKNOWN_CODE, TOTAL_CODE]
    );
}

#[test]
fn unknown_code_error_names_dataset_and_dimension_but_not_value() {
    let periods = vec![current_period(PeriodGranularity::Year, date(2025, 1, 1)).unwrap()];
    let dimensions = vec![DimensionDomain {
        field: "region".to_owned(),
        vocabulary: "regions".to_owned(),
        codes: vec!["known".to_owned()],
        include_unknown: false,
    }];
    let error = build_exact_cells(
        "enrolments",
        &periods,
        &dimensions,
        &[GroupedCell {
            period: "2025".to_owned(),
            codes: vec!["secret-new-code".to_owned()],
            value: 1,
        }],
    )
    .unwrap_err();
    assert_eq!(
        error,
        StatisticsError::UnknownCode {
            dataset: "enrolments".to_owned(),
            dimension: "region".to_owned()
        }
    );
    assert!(!error.to_string().contains("secret-new-code"));
}

#[test]
fn margins_use_checked_integer_arithmetic() {
    let periods = vec![current_period(PeriodGranularity::Year, date(2025, 1, 1)).unwrap()];
    let dimensions = vec![DimensionDomain {
        field: "region".to_owned(),
        vocabulary: "regions".to_owned(),
        codes: vec!["A".to_owned(), "B".to_owned()],
        include_unknown: false,
    }];
    let error = build_exact_cells(
        "enrolments",
        &periods,
        &dimensions,
        &[
            GroupedCell {
                period: "2025".to_owned(),
                codes: vec!["A".to_owned()],
                value: u64::MAX,
            },
            GroupedCell {
                period: "2025".to_owned(),
                codes: vec!["B".to_owned()],
                value: 1,
            },
        ],
    )
    .unwrap_err();
    assert_eq!(error, StatisticsError::CountOverflow);
}

#[test]
fn disclosure_threshold_rounding_and_halves_up_are_exact() {
    let mut cells = cells_with_values(&[0, 1, 4, 5, 7, 8]);
    apply_disclosure(
        &mut cells,
        DisclosureParameters {
            minimum_count: 5,
            rounding_base: 5,
        },
    )
    .unwrap();
    assert_eq!(
        cells
            .iter()
            .map(|cell| (cell.value, cell.status))
            .collect::<Vec<_>>(),
        vec![
            (Some(0), CellStatus::Exact),
            (None, CellStatus::Suppressed),
            (None, CellStatus::Suppressed),
            (Some(5), CellStatus::Rounded),
            (Some(5), CellStatus::Rounded),
            (Some(10), CellStatus::Rounded),
        ]
    );

    let mut exact_half = cells_with_values(&[6]);
    apply_disclosure(
        &mut exact_half,
        DisclosureParameters {
            minimum_count: 2,
            rounding_base: 4,
        },
    )
    .unwrap();
    assert_eq!(
        (exact_half[0].value, exact_half[0].status),
        (Some(8), CellStatus::Rounded)
    );

    let mut rounded_to_zero = cells_with_values(&[2]);
    apply_disclosure(
        &mut rounded_to_zero,
        DisclosureParameters {
            minimum_count: 2,
            rounding_base: 10,
        },
    )
    .unwrap();
    assert_eq!(
        (rounded_to_zero[0].value, rounded_to_zero[0].status),
        (Some(0), CellStatus::Rounded)
    );
}

#[test]
fn disclosure_property_values_are_null_zero_or_a_rounding_multiple() {
    for minimum_count in 2..=12 {
        for rounding_base in 2..=12 {
            let mut cells = cells_with_values(&(0..=200).collect::<Vec<_>>());
            apply_disclosure(
                &mut cells,
                DisclosureParameters {
                    minimum_count,
                    rounding_base,
                },
            )
            .unwrap();
            for cell in cells {
                assert!(cell
                    .value
                    .is_none_or(|value| value == 0 || value % rounding_base == 0));
                assert_eq!(cell.value.is_none(), cell.status == CellStatus::Suppressed);
            }
        }
    }
}

#[test]
fn rounded_zero_exists_only_below_half_of_the_rounding_base() {
    for minimum_count in 2..=12 {
        for rounding_base in 2..=12 {
            let mut cells = cells_with_values(&(0..=200).collect::<Vec<_>>());
            apply_disclosure(
                &mut cells,
                DisclosureParameters {
                    minimum_count,
                    rounding_base,
                },
            )
            .unwrap();
            let rounded_zeros = (0..=200)
                .zip(&cells)
                .filter(|(_, cell)| cell.value == Some(0) && cell.status == CellStatus::Rounded)
                .map(|(true_count, _)| true_count)
                .collect::<Vec<u64>>();
            assert_eq!(
                rounded_zeros,
                (minimum_count..rounding_base.div_ceil(2)).collect::<Vec<_>>(),
                "minimum {minimum_count}, base {rounding_base}"
            );
            let suppressed = (0..=200)
                .zip(&cells)
                .filter(|(_, cell)| cell.status == CellStatus::Suppressed)
                .map(|(true_count, _)| true_count)
                .collect::<Vec<u64>>();
            assert_eq!(suppressed, (1..minimum_count).collect::<Vec<_>>());
        }
    }
}

#[test]
fn accepted_suppression_residual_is_pinned_for_four_plus_four_and_seven_ones() {
    let parameters = DisclosureParameters {
        minimum_count: 5,
        rounding_base: 5,
    };
    let recovered_two = candidates_consistent_with_published_total(2, parameters, 10);
    assert_eq!(recovered_two, vec![vec![4, 4]]);
    let recovered_seven = candidates_consistent_with_published_total(7, parameters, 5);
    assert_eq!(recovered_seven, vec![vec![1, 1, 1, 1, 1, 1, 1]]);
}

#[test]
fn canonical_document_is_stable_has_allocated_version_and_no_self_digest() {
    let document = release_document();
    let first = canonical_document_and_digest(&document).unwrap();
    let second = canonical_document_and_digest(&document.clone()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.content_digest.len(), 71);
    assert!(first.content_digest.starts_with("sha256:"));
    assert!(first.content_digest[7..]
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    let value: serde_json::Value = serde_json::from_slice(&first.bytes).unwrap();
    assert_eq!(value["release"]["version"], 7);
    assert!(value.get("contentDigest").is_none());
    assert!(!String::from_utf8(first.bytes)
        .unwrap()
        .contains(&first.content_digest));

    let mut unallocated = document;
    unallocated.release.as_mut().unwrap().version = 0;
    assert!(matches!(
        canonical_document_and_digest(&unallocated),
        Err(StatisticsError::InvalidDocument(message)) if message.contains("allocated")
    ));
}

#[test]
fn csv_is_rfc4180_and_carries_period_bounds_on_every_row() {
    let mut document = release_document();
    document.dimensions[0].codes = vec!["north,\"one".to_owned(), TOTAL_CODE.to_owned()];
    document.cells[0]
        .dimensions
        .insert("region".to_owned(), "north,\"one".to_owned());
    let csv = String::from_utf8(document_csv(&document).unwrap()).unwrap();
    assert!(csv.starts_with("period,periodStart,periodEnd,region,value,status\r\n"));
    assert_eq!(csv.lines().count(), 2);
    assert!(csv.contains("2025-01,2025-01-01,2025-02-01,\"north,\"\"one\""));
    assert!(csv.ends_with(",5,rounded\r\n"));
}

#[test]
fn release_without_history_snapshot_is_canonical_and_csv_readable() {
    let mut document = release_document();
    document
        .release
        .as_mut()
        .expect("release document has a release envelope")
        .snapshot = None;

    let canonical = canonical_document_and_digest(&document).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&canonical.bytes).unwrap();
    assert_eq!(value["release"]["snapshot"], serde_json::Value::Null);
    let decoded: StatisticsDocument = serde_json::from_slice(&canonical.bytes).unwrap();
    assert_eq!(decoded.release.unwrap().snapshot, None);

    let csv = String::from_utf8(document_csv(&document).unwrap()).unwrap();
    assert!(csv.starts_with("period,periodStart,periodEnd,region,value,status\r\n"));
    assert!(csv.ends_with(",5,rounded\r\n"));
}

#[test]
fn live_document_uses_the_same_wire_shape_without_disclosure() {
    let period = current_period(PeriodGranularity::Month, date(2025, 1, 15)).unwrap();
    let document = StatisticsDocument {
        dataset: dataset_document(),
        periods: vec![PeriodDocument::from(&period)],
        dimensions: vec![],
        cells: vec![Cell {
            period: "2025-01".to_owned(),
            dimensions: BTreeMap::new(),
            value: Some(3),
            status: CellStatus::Exact,
        }],
        release: None,
        live: Some(LiveDocument {
            evaluated_at: "2025-01-15".to_owned(),
            access_profile: "analyst".to_owned(),
        }),
        disclosure: None,
    };
    let canonical = canonical_document_and_digest(&document).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&canonical.bytes).unwrap();
    assert_eq!(value["live"]["accessProfile"], "analyst");
    assert!(value.get("release").is_none());
    assert!(value.get("disclosure").is_none());
}

fn cell_value(cells: &[Cell], codes: &[&str]) -> Option<u64> {
    cells
        .iter()
        .find(|cell| {
            cell.dimensions.get("region").map(String::as_str) == Some(codes[0])
                && cell.dimensions.get("eligible").map(String::as_str) == Some(codes[1])
        })
        .and_then(|cell| cell.value)
}

fn cells_with_values(values: &[u64]) -> Vec<Cell> {
    values
        .iter()
        .map(|value| Cell {
            period: "2025".to_owned(),
            dimensions: BTreeMap::new(),
            value: Some(*value),
            status: CellStatus::Exact,
        })
        .collect()
}

fn candidates_consistent_with_published_total(
    cell_count: usize,
    parameters: DisclosureParameters,
    published_total: u64,
) -> Vec<Vec<u64>> {
    fn recurse(
        current: &mut Vec<u64>,
        cell_count: usize,
        parameters: DisclosureParameters,
        published_total: u64,
        found: &mut Vec<Vec<u64>>,
    ) {
        if current.len() == cell_count {
            let total = current.iter().sum();
            let mut total_cell = cells_with_values(&[total]);
            apply_disclosure(&mut total_cell, parameters).unwrap();
            if total_cell[0].value == Some(published_total) {
                found.push(current.clone());
            }
            return;
        }
        for value in 1..parameters.minimum_count {
            current.push(value);
            recurse(current, cell_count, parameters, published_total, found);
            current.pop();
        }
    }
    let mut found = Vec::new();
    recurse(
        &mut Vec::new(),
        cell_count,
        parameters,
        published_total,
        &mut found,
    );
    found
}

fn dataset_document() -> DatasetDocument {
    DatasetDocument {
        id: "enrolments".to_owned(),
        unit: "household".to_owned(),
        measure: Measure::Count,
        period_kind: PeriodKind::Flow,
        granularity: PeriodGranularity::Month,
        population: "programme eq 'cash-transfer'".to_owned(),
        definition_digest: "definition-sha256".to_owned(),
    }
}

fn release_document() -> StatisticsDocument {
    let period = period_for_code(PeriodGranularity::Month, "2025-01", date(2025, 2, 1)).unwrap();
    StatisticsDocument {
        dataset: dataset_document(),
        periods: vec![PeriodDocument::from(&period)],
        dimensions: vec![registry_breg::statistics::DimensionDocument {
            field: "region".to_owned(),
            vocabulary: "regions".to_owned(),
            codes: vec!["north".to_owned(), TOTAL_CODE.to_owned()],
        }],
        cells: vec![Cell {
            period: "2025-01".to_owned(),
            dimensions: BTreeMap::from([("region".to_owned(), "north".to_owned())]),
            value: Some(5),
            status: CellStatus::Rounded,
        }],
        release: Some(ReleaseDocument {
            period: "2025-01".to_owned(),
            version: 7,
            status: ReleaseStatus::Final,
            snapshot: Some("opaque-snapshot".to_owned()),
            computed_at: "2025-02-01T00:00:00Z".to_owned(),
            package_digest: "package-sha256".to_owned(),
        }),
        live: None,
        disclosure: Some(DisclosureDocument::from(DisclosureParameters {
            minimum_count: 5,
            rounding_base: 5,
        })),
    }
}
