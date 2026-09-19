// SPDX-License-Identifier: Apache-2.0

//! How a party maps to the recipient units a capacity window allocates.
//!
//! The grammar is closed: a window either fixes the units, scales them per
//! service recipient, or reads them from a banded table whose only input is
//! the service recipient count. Whichever form is chosen, the function from
//! party to units must be total over every party size the offering accepts,
//! and what happens above the highest band must be declared, never defaulted.

use serde::{Deserialize, Serialize};

use crate::diagnostics::{PolicyCheckReason, SchedulingDiagnostic};

/// The closed input set a banded table may read. Tier 1 reads exactly one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BandedInput {
    ServiceRecipientCount,
}

/// One band of a banded units table: parties up to `up_to` recipients cost
/// `units`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnitBand {
    pub up_to: u32,
    pub units: u32,
    pub because: String,
}

/// What a party above the highest band costs, or that it is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "policy", rename_all = "camelCase", deny_unknown_fields)]
pub enum AboveHighestBand {
    Refuse,
    Units { units: u32 },
}

/// How an offering converts a party into consumed recipient units.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RequiredUnitsPolicy {
    /// Every party costs the same fixed units.
    Fixed { units: u32, because: String },
    /// A party costs its recipient count times `per_recipient`.
    PerRecipient { per_recipient: u32, because: String },
    /// A party costs whatever band its recipient count falls in.
    BandedTable {
        input: BandedInput,
        bands: Vec<UnitBand>,
        above_highest_band: AboveHighestBand,
        because: String,
    },
}

/// A units table refused a party instead of guessing a cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UnitsEvaluationError {
    #[error("the recipient count falls above the highest band and the table refuses it")]
    RefusedAboveHighestBand,
    #[error("the units arithmetic overflowed")]
    Overflow,
}

impl RequiredUnitsPolicy {
    /// The total function from service recipient count to consumed units.
    pub fn evaluate(&self, recipients: u32) -> Result<u32, UnitsEvaluationError> {
        match self {
            Self::Fixed { units, .. } => Ok(*units),
            Self::PerRecipient { per_recipient, .. } => u64::from(*per_recipient)
                .checked_mul(u64::from(recipients))
                .filter(|total| *total <= u64::from(u32::MAX))
                .map(|total| total as u32)
                .ok_or(UnitsEvaluationError::Overflow),
            Self::BandedTable {
                bands,
                above_highest_band,
                ..
            } => {
                let band = bands.iter().find(|band| recipients <= band.up_to);
                match (band, above_highest_band) {
                    (Some(band), _) => Ok(band.units),
                    // Above the highest band the table does what it declares:
                    // refuse, or cost the declared units. Never a guess.
                    (None, AboveHighestBand::Refuse) => {
                        Err(UnitsEvaluationError::RefusedAboveHighestBand)
                    }
                    (None, AboveHighestBand::Units { units }) => Ok(*units),
                }
            }
        }
    }

    /// Check the authored form: bands must exist, rise strictly, carry
    /// positive units, declare their behavior above the highest band, and
    /// every `because` must hold its bytes.
    pub fn check(&self, path: &str) -> Vec<SchedulingDiagnostic> {
        let mut findings = Vec::new();
        match self {
            Self::Fixed { units, because } => {
                if *units == 0 {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.units"),
                        PolicyCheckReason::InvalidBound,
                    ));
                }
                check_because(because, &format!("{path}.because"), &mut findings);
            }
            Self::PerRecipient {
                per_recipient,
                because,
            } => {
                if *per_recipient == 0 {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.perRecipient"),
                        PolicyCheckReason::InvalidBound,
                    ));
                }
                check_because(because, &format!("{path}.because"), &mut findings);
            }
            Self::BandedTable {
                input: _,
                bands,
                above_highest_band,
                because,
            } => {
                if bands.is_empty() {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.bands"),
                        PolicyCheckReason::InvalidBands,
                    ));
                }
                let mut highest = 0;
                for (index, band) in bands.iter().enumerate() {
                    let band_path = format!("{path}.bands[{index}]");
                    if band.up_to <= highest || band.units == 0 {
                        findings.push(SchedulingDiagnostic::new(
                            band_path.clone(),
                            PolicyCheckReason::InvalidBands,
                        ));
                    }
                    highest = highest.max(band.up_to);
                    check_because(
                        &band.because,
                        &format!("{band_path}.because"),
                        &mut findings,
                    );
                }
                if let AboveHighestBand::Units { units } = above_highest_band {
                    if *units == 0 {
                        findings.push(SchedulingDiagnostic::new(
                            format!("{path}.aboveHighestBand.units"),
                            PolicyCheckReason::InvalidBound,
                        ));
                    }
                }
                check_because(because, &format!("{path}.because"), &mut findings);
            }
        }
        findings
    }
}

/// A `because` must be present, non-blank, and at most 256 bytes: every rule
/// that decides capacity carries its recorded reason.
pub fn check_because(because: &str, path: &str, findings: &mut Vec<SchedulingDiagnostic>) {
    if because.trim().is_empty() || because.len() > MAXIMUM_BECAUSE_BYTES {
        findings.push(SchedulingDiagnostic::new(
            path,
            PolicyCheckReason::InvalidBecause,
        ));
    }
}

/// The byte bound every recorded `because` obeys.
pub const MAXIMUM_BECAUSE_BYTES: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    fn banded() -> RequiredUnitsPolicy {
        RequiredUnitsPolicy::BandedTable {
            input: BandedInput::ServiceRecipientCount,
            bands: vec![
                UnitBand {
                    up_to: 1,
                    units: 1,
                    because: "A single recipient consumes one serving slot.".to_owned(),
                },
                UnitBand {
                    up_to: 4,
                    units: 2,
                    because: "A household of up to four shares one officers' block.".to_owned(),
                },
            ],
            above_highest_band: AboveHighestBand::Refuse,
            because: "Household sizing reviewed by the registry office in 2026.".to_owned(),
        }
    }

    #[test]
    fn fixed_per_recipient_and_banded_tables_are_total_over_their_domain() {
        let fixed = RequiredUnitsPolicy::Fixed {
            units: 1,
            because: "One appointment per party.".to_owned(),
        };
        assert_eq!(fixed.evaluate(3), Ok(1));

        let per_recipient = RequiredUnitsPolicy::PerRecipient {
            per_recipient: 1,
            because: "Each recipient consumes one serving slot.".to_owned(),
        };
        assert_eq!(per_recipient.evaluate(3), Ok(3));

        let table = banded();
        assert_eq!(table.evaluate(1), Ok(1));
        assert_eq!(table.evaluate(2), Ok(2));
        assert_eq!(table.evaluate(4), Ok(2));
    }

    #[test]
    fn above_the_highest_band_the_table_does_what_it_declares_and_nothing_else() {
        assert_eq!(
            banded().evaluate(5),
            Err(UnitsEvaluationError::RefusedAboveHighestBand)
        );

        let capped = RequiredUnitsPolicy::BandedTable {
            input: BandedInput::ServiceRecipientCount,
            bands: vec![UnitBand {
                up_to: 2,
                units: 1,
                because: "A pair shares one block.".to_owned(),
            }],
            above_highest_band: AboveHighestBand::Units { units: 3 },
            because: "Larger parties consume a full officer block.".to_owned(),
        };
        assert_eq!(capped.evaluate(9), Ok(3));
    }

    #[test]
    fn per_recipient_arithmetic_refuses_to_overflow_silently() {
        let scaling = RequiredUnitsPolicy::PerRecipient {
            per_recipient: u32::MAX,
            because: "Pathological scaling kept for the bound test.".to_owned(),
        };
        assert_eq!(scaling.evaluate(2), Err(UnitsEvaluationError::Overflow));
    }

    #[test]
    fn well_formed_policies_carry_no_findings() {
        assert!(banded().check("windows[0].unitsPolicy").is_empty());

        let per_recipient = RequiredUnitsPolicy::PerRecipient {
            per_recipient: 1,
            because: "Each recipient consumes one serving slot.".to_owned(),
        };
        assert!(per_recipient.check("windows[0].unitsPolicy").is_empty());
    }

    #[test]
    fn broken_tables_are_named_band_by_band() {
        let broken = RequiredUnitsPolicy::BandedTable {
            input: BandedInput::ServiceRecipientCount,
            bands: vec![
                UnitBand {
                    up_to: 4,
                    units: 2,
                    because: "A household of up to four shares one block.".to_owned(),
                },
                UnitBand {
                    up_to: 4,
                    units: 0,
                    because: " ".to_owned(),
                },
            ],
            above_highest_band: AboveHighestBand::Units { units: 0 },
            because: String::new(),
        };
        let findings = broken.check("windows[0].unitsPolicy");
        let rendered: Vec<String> = findings.iter().map(|finding| finding.to_string()).collect();
        // Band 0 declares four first, so band 1 fails both the non-rising and
        // the zero-units rule; its blank because is named separately.
        assert_eq!(
            rendered,
            vec![
                "windows[0].unitsPolicy.bands[1]: invalid-bands".to_owned(),
                "windows[0].unitsPolicy.bands[1].because: invalid-because".to_owned(),
                "windows[0].unitsPolicy.aboveHighestBand.units: invalid-bound".to_owned(),
                "windows[0].unitsPolicy.because: invalid-because".to_owned(),
            ]
        );
    }

    #[test]
    fn because_bounds_are_inclusive_at_256_bytes() {
        let at_bound = RequiredUnitsPolicy::Fixed {
            units: 1,
            because: "x".repeat(MAXIMUM_BECAUSE_BYTES),
        };
        assert!(at_bound.check("p").is_empty());

        let over_bound = RequiredUnitsPolicy::Fixed {
            units: 1,
            because: "x".repeat(MAXIMUM_BECAUSE_BYTES + 1),
        };
        assert_eq!(
            over_bound.check("p"),
            vec![SchedulingDiagnostic::new(
                "p.because",
                PolicyCheckReason::InvalidBecause
            )]
        );
    }

    #[test]
    fn the_units_grammar_is_closed() {
        // Tier 1 reads exactly one input, spelled one way.
        assert!(serde_norway::from_str::<BandedInput>("serviceRecipientCount").is_ok());
        assert!(serde_norway::from_str::<BandedInput>("partyCount").is_err());

        let yaml = "kind: fixed\nunits: 1\nbecause: One appointment per party.\n";
        assert!(serde_norway::from_str::<RequiredUnitsPolicy>(yaml).is_ok());
        assert!(serde_norway::from_str::<RequiredUnitsPolicy>(
            "kind: fixed\nunits: 1\nbecause: One appointment per party.\nmystery: true\n"
        )
        .is_err());

        // Above the highest band is declared, never defaulted: dropping the
        // field is a deserialization failure, not a silent choice.
        let banded_yaml = "kind: bandedTable\ninput: serviceRecipientCount\n\
                           bands:\n  - upTo: 2\n    units: 1\n    because: A pair shares one block.\n";
        assert!(serde_norway::from_str::<RequiredUnitsPolicy>(banded_yaml).is_err());
        assert!(serde_norway::from_str::<RequiredUnitsPolicy>(&format!(
            "{banded_yaml}aboveHighestBand:\n  policy: refuse\nbecause: Sizing reviewed.\n"
        ))
        .is_ok());
        assert!(serde_norway::from_str::<RequiredUnitsPolicy>(&format!(
            "{banded_yaml}aboveHighestBand:\n  policy: units\n  units: 3\nbecause: Sizing reviewed.\n"
        ))
        .is_ok());
    }
}
