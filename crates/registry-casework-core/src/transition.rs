use crate::OccurrenceState;

/// A product-owned lifecycle event. Source adapters translate their native
/// lifecycle into these events; storage only persists the reducer's result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OccurrenceEvent {
    Claim,
    Release,
    AttemptReserved,
    AttemptUncertain,
    AttemptCompleted,
    AttemptRefused,
    ObserveOpen,
    ObserveWaitingApplicant,
    ObserveWaitingApplication,
    Complete,
    Supersede,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the occurrence event is invalid for the current state")]
pub struct InvalidOccurrenceTransition;

/// Apply the fixed Casework occurrence lifecycle without performing I/O.
pub fn transition(
    state: OccurrenceState,
    event: OccurrenceEvent,
) -> Result<OccurrenceState, InvalidOccurrenceTransition> {
    use OccurrenceEvent as Event;
    use OccurrenceState as State;

    match (state, event) {
        (State::Open, Event::Claim) => Ok(State::Claimed),
        (State::Claimed, Event::Release) => Ok(State::Open),
        (State::Claimed, Event::AttemptReserved) => Ok(State::Synchronizing),
        (State::Synchronizing, Event::AttemptUncertain | Event::AttemptCompleted) => {
            Ok(State::Synchronizing)
        }
        (State::Synchronizing, Event::AttemptRefused) => Ok(State::Claimed),

        (State::Claimed, Event::ObserveOpen) => Ok(State::Claimed),
        (
            State::Open
            | State::WaitingApplicant
            | State::WaitingApplication
            | State::Synchronizing,
            Event::ObserveOpen,
        ) => Ok(State::Open),
        (
            State::Open
            | State::Claimed
            | State::WaitingApplicant
            | State::WaitingApplication
            | State::Synchronizing,
            Event::ObserveWaitingApplicant,
        ) => Ok(State::WaitingApplicant),
        (
            State::Open
            | State::Claimed
            | State::WaitingApplicant
            | State::WaitingApplication
            | State::Synchronizing,
            Event::ObserveWaitingApplication,
        ) => Ok(State::WaitingApplication),
        (
            State::Open
            | State::Claimed
            | State::WaitingApplicant
            | State::WaitingApplication
            | State::Synchronizing,
            Event::Complete,
        ) => Ok(State::Completed),
        (
            State::Open
            | State::Claimed
            | State::WaitingApplicant
            | State::WaitingApplication
            | State::Synchronizing,
            Event::Supersede,
        ) => Ok(State::Superseded),
        (
            State::Open
            | State::Claimed
            | State::WaitingApplicant
            | State::WaitingApplication
            | State::Synchronizing,
            Event::Cancel,
        ) => Ok(State::Cancelled),
        _ => Err(InvalidOccurrenceTransition),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! transition_case {
        ($name:ident, $from:expr, $event:expr, $to:expr) => {
            #[test]
            fn $name() {
                assert_eq!(transition($from, $event), Ok($to));
            }
        };
    }

    transition_case!(
        claim_opens_a_holding,
        OccurrenceState::Open,
        OccurrenceEvent::Claim,
        OccurrenceState::Claimed
    );
    transition_case!(
        release_returns_to_the_queue,
        OccurrenceState::Claimed,
        OccurrenceEvent::Release,
        OccurrenceState::Open
    );
    transition_case!(
        reservation_fences_the_item,
        OccurrenceState::Claimed,
        OccurrenceEvent::AttemptReserved,
        OccurrenceState::Synchronizing
    );
    transition_case!(
        uncertainty_keeps_the_fence,
        OccurrenceState::Synchronizing,
        OccurrenceEvent::AttemptUncertain,
        OccurrenceState::Synchronizing
    );
    transition_case!(
        completion_waits_for_authoritative_readback,
        OccurrenceState::Synchronizing,
        OccurrenceEvent::AttemptCompleted,
        OccurrenceState::Synchronizing
    );
    transition_case!(
        definitive_refusal_restores_the_holding,
        OccurrenceState::Synchronizing,
        OccurrenceEvent::AttemptRefused,
        OccurrenceState::Claimed
    );
    transition_case!(
        open_readback_preserves_a_holding,
        OccurrenceState::Claimed,
        OccurrenceEvent::ObserveOpen,
        OccurrenceState::Claimed
    );
    transition_case!(
        correction_releases_the_holding,
        OccurrenceState::Claimed,
        OccurrenceEvent::ObserveWaitingApplicant,
        OccurrenceState::WaitingApplicant
    );
    transition_case!(
        application_wait_releases_the_holding,
        OccurrenceState::Claimed,
        OccurrenceEvent::ObserveWaitingApplication,
        OccurrenceState::WaitingApplication
    );
    transition_case!(
        terminal_readback_completes_work,
        OccurrenceState::Claimed,
        OccurrenceEvent::Complete,
        OccurrenceState::Completed
    );
    transition_case!(
        revised_binding_supersedes_work,
        OccurrenceState::Claimed,
        OccurrenceEvent::Supersede,
        OccurrenceState::Superseded
    );
    transition_case!(
        cancellation_closes_work,
        OccurrenceState::Claimed,
        OccurrenceEvent::Cancel,
        OccurrenceState::Cancelled
    );

    const STATES: [OccurrenceState; 8] = [
        OccurrenceState::Open,
        OccurrenceState::Claimed,
        OccurrenceState::WaitingApplicant,
        OccurrenceState::WaitingApplication,
        OccurrenceState::Synchronizing,
        OccurrenceState::Completed,
        OccurrenceState::Superseded,
        OccurrenceState::Cancelled,
    ];
    const EVENTS: [OccurrenceEvent; 12] = [
        OccurrenceEvent::Claim,
        OccurrenceEvent::Release,
        OccurrenceEvent::AttemptReserved,
        OccurrenceEvent::AttemptUncertain,
        OccurrenceEvent::AttemptCompleted,
        OccurrenceEvent::AttemptRefused,
        OccurrenceEvent::ObserveOpen,
        OccurrenceEvent::ObserveWaitingApplicant,
        OccurrenceEvent::ObserveWaitingApplication,
        OccurrenceEvent::Complete,
        OccurrenceEvent::Supersede,
        OccurrenceEvent::Cancel,
    ];

    fn expected(state: OccurrenceState, event: OccurrenceEvent) -> Option<OccurrenceState> {
        use OccurrenceEvent as Event;
        use OccurrenceState as State;
        let active = state.is_active();
        match (state, event) {
            (State::Open, Event::Claim) => Some(State::Claimed),
            (State::Claimed, Event::Release) => Some(State::Open),
            (State::Claimed, Event::AttemptReserved) => Some(State::Synchronizing),
            (State::Synchronizing, Event::AttemptUncertain | Event::AttemptCompleted) => {
                Some(State::Synchronizing)
            }
            (State::Synchronizing, Event::AttemptRefused) => Some(State::Claimed),
            (State::Claimed, Event::ObserveOpen) => Some(State::Claimed),
            (_, Event::ObserveOpen) if active => Some(State::Open),
            (_, Event::ObserveWaitingApplicant) if active => Some(State::WaitingApplicant),
            (_, Event::ObserveWaitingApplication) if active => Some(State::WaitingApplication),
            (_, Event::Complete) if active => Some(State::Completed),
            (_, Event::Supersede) if active => Some(State::Superseded),
            (_, Event::Cancel) if active => Some(State::Cancelled),
            _ => None,
        }
    }

    #[test]
    fn every_state_event_pair_matches_the_transition_table() {
        for state in STATES {
            for event in EVENTS {
                assert_eq!(
                    transition(state, event).ok(),
                    expected(state, event),
                    "{state:?} + {event:?}"
                );
            }
        }
    }

    #[test]
    fn terminal_occurrences_cannot_be_reopened() {
        for state in [
            OccurrenceState::Completed,
            OccurrenceState::Superseded,
            OccurrenceState::Cancelled,
        ] {
            for event in EVENTS {
                assert_eq!(transition(state, event), Err(InvalidOccurrenceTransition));
            }
        }
    }
}
