// SPDX-License-Identifier: Apache-2.0

//! The run-time failure taxonomy every product reports for hook failures, so
//! that every product reports the same thing for the same failure.
//!
//! `registry-platform-script` exists only on an unmerged branch today, so the
//! category set is defined here. Step 3 (script destinations in `after`)
//! depends on that crate and unifies the two; until then this enum is the
//! contract and the branch's executor errors map onto it.

/// One of the five run-time failure categories.
///
/// The per-kind mapping, fixed by the design note:
///
/// | category | local kinds (`rhai`, `wasm`) | `url` kind |
/// |---|---|---|
/// | [`Deadline`](Self::Deadline) | epoch deadline reached | attempt timeout reached |
/// | [`Resource`](Self::Resource) | fuel, memory, table, input or output ceiling | response body over ceiling |
/// | [`Execution`](Self::Execution) | trap or script error | non-2xx status |
/// | [`Source`](Self::Source) | module or script refused at prepare | malformed response body |
/// | [`Unavailable`](Self::Unavailable) | not applicable | DNS, connect or TLS failure |
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorCategory {
    /// A budget of time ran out: the epoch deadline on a local kind, the
    /// attempt timeout on a `url` kind.
    Deadline,
    /// A budget of space or fuel ran out: fuel, memory, table, input or output
    /// ceiling on a local kind; a response body over the ceiling on a `url`
    /// kind.
    Resource,
    /// The handler ran and failed: a trap or script error on a local kind, a
    /// non-2xx status on a `url` kind.
    Execution,
    /// The handler input was refused before or after the run: module or script
    /// refused at prepare on a local kind, a malformed response body on a
    /// `url` kind.
    Source,
    /// The handler could not be reached. Only the `url` kind reports this:
    /// DNS, connect or TLS failure. Not applicable to local kinds, which have
    /// no transport to fail.
    Unavailable,
}

impl ErrorCategory {
    /// Every category, for exhaustive contract tests.
    pub const ALL: [Self; 5] = [
        Self::Deadline,
        Self::Resource,
        Self::Execution,
        Self::Source,
        Self::Unavailable,
    ];

    /// The category's stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::Resource => "resource",
            Self::Execution => "execution",
            Self::Source => "source",
            Self::Unavailable => "unavailable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_category_set_is_exactly_five_categories() {
        assert_eq!(
            ErrorCategory::ALL,
            [
                ErrorCategory::Deadline,
                ErrorCategory::Resource,
                ErrorCategory::Execution,
                ErrorCategory::Source,
                ErrorCategory::Unavailable,
            ]
        );
    }

    #[test]
    fn category_spellings_are_pinned() {
        let spellings: Vec<&str> = ErrorCategory::ALL
            .iter()
            .map(|category| category.as_str())
            .collect();
        assert_eq!(
            spellings,
            ["deadline", "resource", "execution", "source", "unavailable"]
        );
    }
}
