// SPDX-License-Identifier: Apache-2.0

//! The complete starter projects `schedulingctl init` writes.
//!
//! Each template is a working project: its policy passes the check with zero
//! findings and its fixtures replay all-Pass offline, which the tests prove
//! end to end. The files are the committed examples under
//! `products/scheduling/examples`, so the two cannot drift, and every file
//! carries its schema modeline on its first line.

/// The example directory one template's files are read from.
macro_rules! example {
    ($template:literal, $file:literal) => {
        include_str!(concat!(
            "../../../products/scheduling/examples/",
            $template,
            "/",
            $file
        ))
    };
}

/// The files one template writes, relative to the project directory, in
/// write order. The first entry is always the authored policy.
pub(super) fn template_files(template: &str) -> Option<Vec<(&'static str, &'static str)>> {
    match template {
        "standalone-exact-time" => Some(vec![
            (
                "scheduling.yaml",
                example!("standalone-exact-time", "scheduling.yaml"),
            ),
            (
                "runtime.example.yaml",
                example!("standalone-exact-time", "runtime.example.yaml"),
            ),
            (
                "records.yaml",
                example!("standalone-exact-time", "records.yaml"),
            ),
            (
                "fixtures/counter-stations.yaml",
                example!("standalone-exact-time", "fixtures/counter-stations.yaml"),
            ),
            (
                "fixtures/fold-day-rebooking.yaml",
                example!("standalone-exact-time", "fixtures/fold-day-rebooking.yaml"),
            ),
        ]),
        "standalone-arrival-window" => Some(vec![
            (
                "scheduling.yaml",
                example!("standalone-arrival-window", "scheduling.yaml"),
            ),
            (
                "runtime.example.yaml",
                example!("standalone-arrival-window", "runtime.example.yaml"),
            ),
            (
                "records.yaml",
                example!("standalone-arrival-window", "records.yaml"),
            ),
            (
                "fixtures/household-morning.yaml",
                example!(
                    "standalone-arrival-window",
                    "fixtures/household-morning.yaml"
                ),
            ),
            (
                "fixtures/household-afternoon.yaml",
                example!(
                    "standalone-arrival-window",
                    "fixtures/household-afternoon.yaml"
                ),
            ),
        ]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_scheduling_core::{
        AboveHighestBand, CaseStatus, RequiredUnitsPolicy, SchedulingFixture, SchedulingPolicy,
        SchedulingRecords, AUTHORED_POLICY_FILE, SCHEDULING_FIXTURE_API_VERSION,
        SCHEDULING_FIXTURE_KIND, SCHEDULING_POLICY_API_VERSION, SCHEDULING_POLICY_KIND,
    };

    const TEMPLATE_NAMES: [&str; 2] = ["standalone-exact-time", "standalone-arrival-window"];

    fn policy_of(files: &[(&'static str, &'static str)]) -> SchedulingPolicy {
        SchedulingPolicy::read(files[0].0, files[0].1.as_bytes())
            .unwrap_or_else(|report| panic!("{}", report.render_human()))
            .value
    }

    fn file<'a>(files: &'a [(&'static str, &'static str)], name: &str) -> &'a str {
        files
            .iter()
            .find(|(relative, _)| *relative == name)
            .unwrap_or_else(|| panic!("the template carries {name}"))
            .1
    }

    #[test]
    fn the_templates_are_exactly_the_two_standalone_projects() {
        for template in TEMPLATE_NAMES {
            assert!(template_files(template).is_some(), "{template}");
        }
        assert!(template_files("standalone-decision").is_none());
        assert!(template_files("").is_none());
    }

    /// CFG-SCHEMA-7: every YAML file `init` writes names its schema on its
    /// first line.
    #[test]
    fn every_template_file_names_its_schema_on_its_first_line() {
        for template in TEMPLATE_NAMES {
            for (relative, contents) in template_files(template).unwrap() {
                let format = match relative {
                    "scheduling.yaml" => "project",
                    "records.yaml" => "records",
                    "runtime.example.yaml" => "runtime",
                    _ if relative.starts_with("fixtures/") => "fixture",
                    _ => panic!("{template}: unexpected file {relative}"),
                };
                assert_eq!(
                    contents.lines().next(),
                    Some(
                        format!(
                            "# yaml-language-server: $schema=https://id.registrystack.org/\
                             schemas/scheduling/{format}/{format}.v1alpha1.schema.json"
                        )
                        .as_str()
                    ),
                    "{template}/{relative}"
                );
            }
        }
    }

    #[test]
    fn every_template_carries_records_that_read_against_its_policy() {
        for template in TEMPLATE_NAMES {
            let files = template_files(template).unwrap();
            let policy = policy_of(&files);
            let facts = SchedulingRecords::read(
                "records.yaml",
                file(&files, "records.yaml").as_bytes(),
                &policy,
            )
            .unwrap_or_else(|report| panic!("{template}: {}", report.render_human()))
            .value
            .into_facts();
            for offering in &policy.offerings {
                assert!(
                    facts.location(&offering.location).is_some(),
                    "{template}: an offering names a location the records do not carry"
                );
                if let Some(exact_time) = &offering.exact_time {
                    assert!(
                        facts.pool(&exact_time.pool).is_some(),
                        "{template}: an offering names a pool the records do not carry"
                    );
                }
            }
        }
    }

    #[test]
    fn every_template_policy_reads_clean_with_pinned_names() {
        for template in TEMPLATE_NAMES {
            let files = template_files(template).unwrap();
            assert_eq!(files[0].0, AUTHORED_POLICY_FILE);
            let policy = policy_of(&files);
            assert_eq!(policy.api_version, SCHEDULING_POLICY_API_VERSION);
            assert_eq!(policy.kind, SCHEDULING_POLICY_KIND);
        }
    }

    #[test]
    fn every_template_fixture_reads_and_fits_its_policy() {
        for template in TEMPLATE_NAMES {
            let files = template_files(template).unwrap();
            let policy = policy_of(&files);
            for (relative, contents) in template_fixtures(&files) {
                let fixture = SchedulingFixture::read(relative, contents.as_bytes(), &policy)
                    .unwrap_or_else(|report| panic!("{}", report.render_human()))
                    .value;
                assert_eq!(fixture.api_version, SCHEDULING_FIXTURE_API_VERSION);
                assert_eq!(fixture.kind, SCHEDULING_FIXTURE_KIND);
            }
        }
    }

    /// The acceptance proof for both templates: every fixture replays
    /// all-Pass against its own template policy.
    #[test]
    fn every_template_fixture_replays_all_pass() {
        for template in TEMPLATE_NAMES {
            let files = template_files(template).unwrap();
            let policy = policy_of(&files);
            for (relative, contents) in template_fixtures(&files) {
                let fixture = SchedulingFixture::read(relative, contents.as_bytes(), &policy)
                    .unwrap_or_else(|report| panic!("{}", report.render_human()))
                    .value;
                let outcomes = fixture
                    .replay(&policy)
                    .unwrap_or_else(|error| panic!("{relative}: the fixture replays: {error}"));
                assert!(
                    outcomes
                        .iter()
                        .all(|outcome| outcome.status == CaseStatus::Pass),
                    "{template}/{relative}: {outcomes:?}"
                );
            }
        }
    }

    /// The template's replay fixtures, in write order. The runtime example is
    /// written beside the policy and is not a fixture.
    fn template_fixtures<'a>(
        files: &'a [(&'static str, &'static str)],
    ) -> Vec<(&'static str, &'a str)> {
        files
            .iter()
            .filter(|(relative, _)| {
                relative.starts_with("fixtures/") && relative.ends_with(".yaml")
            })
            .map(|(relative, contents)| (*relative, *contents))
            .collect()
    }

    /// The arrival-window template's second offering exists so an adopter has
    /// a working example of a banded units table that refuses a party above
    /// its highest band, rather than only the fixed per-recipient table the
    /// first offering demonstrates.
    #[test]
    fn the_arrival_window_template_demonstrates_a_banded_table_refusing_above_its_highest_band() {
        let files = template_files("standalone-arrival-window").unwrap();
        let policy = policy_of(&files);
        let records = SchedulingRecords::read(
            "records.yaml",
            file(&files, "records.yaml").as_bytes(),
            &policy,
        )
        .unwrap_or_else(|report| panic!("{}", report.render_human()))
        .value
        .into_facts();
        let window = records
            .windows
            .iter()
            .find(|window| window.id == "household-afternoon-window")
            .expect("the afternoon window is published");
        assert!(matches!(
            window.units_policy,
            RequiredUnitsPolicy::BandedTable {
                above_highest_band: AboveHighestBand::Refuse {},
                ..
            }
        ));

        let (relative, contents) = template_fixtures(&files)
            .into_iter()
            .find(|(relative, _)| relative.contains("household-afternoon"))
            .expect("the afternoon fixture ships with the template");
        let fixture = SchedulingFixture::read(relative, contents.as_bytes(), &policy)
            .unwrap_or_else(|report| panic!("{}", report.render_human()))
            .value;
        let outcomes = fixture
            .replay(&policy)
            .unwrap_or_else(|error| panic!("{relative}: the fixture replays: {error}"));
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.status == CaseStatus::Pass),
            "{outcomes:?}"
        );
        let refused = outcomes
            .iter()
            .find(|outcome| outcome.name.contains("above-the-highest-band"))
            .expect("a case exercises the above-highest-band refusal");
        assert!(
            refused
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("party.capacity-inadequate")),
            "{refused:?}"
        );
    }

    #[test]
    fn the_exact_time_template_carries_the_example_and_both_fixtures() {
        let files = template_files("standalone-exact-time").unwrap();
        let names: Vec<&str> = files.into_iter().map(|(relative, _)| relative).collect();
        assert_eq!(
            names,
            vec![
                "scheduling.yaml",
                "runtime.example.yaml",
                "records.yaml",
                "fixtures/counter-stations.yaml",
                "fixtures/fold-day-rebooking.yaml",
            ]
        );
    }
}
