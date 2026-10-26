//! The fixed transition table every status change goes through.

use thiserror::Error;

/// The status of one Token Status List entry, with its two-bit value.
///
/// `0x03` is never written, so it has no variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryStatus {
    Valid,
    Invalid,
    Suspended,
}

impl EntryStatus {
    /// The two-bit Token Status List value of this status.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Valid => 0x00,
            Self::Invalid => 0x01,
            Self::Suspended => 0x02,
        }
    }

    /// The status a stored two-bit value names, or `None` for a value this
    /// profile never writes.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::Valid),
            0x01 => Some(Self::Invalid),
            0x02 => Some(Self::Suspended),
            _ => None,
        }
    }
}

/// The authorization class a transition arrives through. Each is a distinct
/// audit cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransitionCause {
    Hook,
    Operator,
    Reconciliation,
}

impl TransitionCause {
    /// The stored name of this cause.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::Operator => "operator",
            Self::Reconciliation => "reconciliation",
        }
    }
}

/// What the transition table allows for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// The entry moves from `from` to `to`.
    Change { from: EntryStatus, to: EntryStatus },
    /// The entry already holds the requested status, so nothing changes.
    Unchanged(EntryStatus),
}

/// Why the transition table refuses a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum Refusal {
    /// INVALID is terminal for every cause.
    #[error("the entry is INVALID, which is terminal")]
    Terminal,
    /// Only an operator may move SUSPENDED to VALID; a hook or reconciliation
    /// raises a pending reinstatement instead.
    #[error("only an operator may reinstate a SUSPENDED entry; raise a pending reinstatement")]
    RaisePendingReinstatement,
}

/// Apply the fixed transition table to one request.
///
/// Hooks and reconciliation only move entries away from VALID. SUSPENDED to
/// VALID is the one reversal and is operator-only. INVALID is terminal.
/// Reapplying the current status changes nothing.
pub fn transition(
    from: EntryStatus,
    to: EntryStatus,
    cause: TransitionCause,
) -> Result<Transition, Refusal> {
    use EntryStatus::{Invalid, Suspended, Valid};
    match (from, to) {
        (Valid, Valid) | (Suspended, Suspended) | (Invalid, Invalid) => {
            Ok(Transition::Unchanged(from))
        }
        (Invalid, Valid | Suspended) => Err(Refusal::Terminal),
        (Valid, Suspended | Invalid) | (Suspended, Invalid) => Ok(Transition::Change { from, to }),
        (Suspended, Valid) => match cause {
            TransitionCause::Operator => Ok(Transition::Change { from, to }),
            TransitionCause::Hook | TransitionCause::Reconciliation => {
                Err(Refusal::RaisePendingReinstatement)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{transition, EntryStatus, Refusal, Transition, TransitionCause};
    use proptest::prelude::*;

    use EntryStatus::{Invalid, Suspended, Valid};
    use TransitionCause::{Hook, Operator, Reconciliation};

    const CAUSES: [TransitionCause; 3] = [Hook, Operator, Reconciliation];
    const STATUSES: [EntryStatus; 3] = [Valid, Invalid, Suspended];

    fn change(from: EntryStatus, to: EntryStatus) -> Result<Transition, Refusal> {
        Ok(Transition::Change { from, to })
    }

    #[test]
    fn every_cell_of_the_transition_table() {
        // (from, to, cause, expected): all 27 combinations, written out so a
        // change to any one cell fails here by name.
        let table = [
            (Valid, Valid, Hook, Ok(Transition::Unchanged(Valid))),
            (Valid, Valid, Operator, Ok(Transition::Unchanged(Valid))),
            (
                Valid,
                Valid,
                Reconciliation,
                Ok(Transition::Unchanged(Valid)),
            ),
            (Valid, Suspended, Hook, change(Valid, Suspended)),
            (Valid, Suspended, Operator, change(Valid, Suspended)),
            (Valid, Suspended, Reconciliation, change(Valid, Suspended)),
            (Valid, Invalid, Hook, change(Valid, Invalid)),
            (Valid, Invalid, Operator, change(Valid, Invalid)),
            (Valid, Invalid, Reconciliation, change(Valid, Invalid)),
            (Suspended, Invalid, Hook, change(Suspended, Invalid)),
            (Suspended, Invalid, Operator, change(Suspended, Invalid)),
            (
                Suspended,
                Invalid,
                Reconciliation,
                change(Suspended, Invalid),
            ),
            (
                Suspended,
                Valid,
                Hook,
                Err(Refusal::RaisePendingReinstatement),
            ),
            (Suspended, Valid, Operator, change(Suspended, Valid)),
            (
                Suspended,
                Valid,
                Reconciliation,
                Err(Refusal::RaisePendingReinstatement),
            ),
            (
                Suspended,
                Suspended,
                Hook,
                Ok(Transition::Unchanged(Suspended)),
            ),
            (
                Suspended,
                Suspended,
                Operator,
                Ok(Transition::Unchanged(Suspended)),
            ),
            (
                Suspended,
                Suspended,
                Reconciliation,
                Ok(Transition::Unchanged(Suspended)),
            ),
            (Invalid, Valid, Hook, Err(Refusal::Terminal)),
            (Invalid, Valid, Operator, Err(Refusal::Terminal)),
            (Invalid, Valid, Reconciliation, Err(Refusal::Terminal)),
            (Invalid, Suspended, Hook, Err(Refusal::Terminal)),
            (Invalid, Suspended, Operator, Err(Refusal::Terminal)),
            (Invalid, Suspended, Reconciliation, Err(Refusal::Terminal)),
            (Invalid, Invalid, Hook, Ok(Transition::Unchanged(Invalid))),
            (
                Invalid,
                Invalid,
                Operator,
                Ok(Transition::Unchanged(Invalid)),
            ),
            (
                Invalid,
                Invalid,
                Reconciliation,
                Ok(Transition::Unchanged(Invalid)),
            ),
        ];
        assert_eq!(table.len(), STATUSES.len() * STATUSES.len() * CAUSES.len());
        for (from, to, cause, expected) in table {
            assert_eq!(
                transition(from, to, cause),
                expected,
                "{from:?} to {to:?} by {cause:?}"
            );
        }
    }

    #[test]
    fn hooks_and_reconciliation_never_move_an_entry_towards_valid() {
        for cause in [Hook, Reconciliation] {
            for from in STATUSES {
                if let Ok(Transition::Change { to, .. }) = transition(from, Valid, cause) {
                    panic!("{cause:?} moved {from:?} to {to:?}");
                }
            }
        }
    }

    #[test]
    fn status_codes_are_the_two_bit_values_and_three_is_never_written() {
        assert_eq!(Valid.code(), 0x00);
        assert_eq!(Invalid.code(), 0x01);
        assert_eq!(Suspended.code(), 0x02);
        for status in STATUSES {
            assert_eq!(EntryStatus::from_code(status.code()), Some(status));
        }
        assert_eq!(EntryStatus::from_code(0x03), None);
        assert_eq!(EntryStatus::from_code(0xff), None);
    }

    #[test]
    fn causes_have_their_stored_names() {
        assert_eq!(Hook.as_str(), "hook");
        assert_eq!(Operator.as_str(), "operator");
        assert_eq!(Reconciliation.as_str(), "reconciliation");
    }

    fn any_status() -> impl Strategy<Value = EntryStatus> {
        prop::sample::select(STATUSES.to_vec())
    }

    fn any_cause() -> impl Strategy<Value = TransitionCause> {
        prop::sample::select(CAUSES.to_vec())
    }

    proptest! {
        #[test]
        fn no_sequence_of_requests_leaves_invalid(
            start in any_status(),
            requests in prop::collection::vec((any_status(), any_cause()), 0..64),
        ) {
            let mut current = start;
            let mut reached_invalid = current == Invalid;
            for (to, cause) in requests {
                if let Ok(Transition::Change { from, to }) = transition(current, to, cause) {
                    prop_assert_eq!(from, current);
                    current = to;
                }
                if reached_invalid {
                    prop_assert_eq!(current, Invalid);
                }
                reached_invalid |= current == Invalid;
            }
        }
    }
}
