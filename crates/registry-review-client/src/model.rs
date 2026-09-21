use registry_platform_httputil::client::BearerToken;
use registry_review_protocol::{ReviewResult, ReviewResultFeedPage, ReviewResultLookup};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAXIMUM_PAGE_SIZE: usize = 100;

/// Authentication and authority profile for exactly one producer operation.
pub struct ReviewAuth<'a> {
    pub token: &'a BearerToken,
    pub profile: &'a str,
}

impl<'a> ReviewAuth<'a> {
    #[must_use]
    pub fn new(token: &'a BearerToken, profile: &'a str) -> Self {
        Self { token, profile }
    }

    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if self.profile.is_empty()
            || self.profile.len() > 128
            || !self.profile.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err("the Casework profile is invalid");
        }
        Ok(())
    }
}

impl std::fmt::Debug for ReviewAuth<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReviewAuth")
            .field("token", &"<redacted>")
            .field("profile", &"<selected>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewComplete<T> {
    pub value: T,
    pub trace_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReviewResultResponse {
    Available(Box<ReviewComplete<ReviewResult>>),
    Pending { trace_id: String },
    ConcealedOrUnknown { trace_id: String },
    Expired { trace_id: String },
}

impl ReviewResultResponse {
    #[must_use]
    pub fn lookup(&self) -> ReviewResultLookup {
        match self {
            Self::Available(_) => ReviewResultLookup::Available,
            Self::Pending { .. } => ReviewResultLookup::Pending,
            Self::ConcealedOrUnknown { .. } => ReviewResultLookup::ConcealedOrUnknown,
            Self::Expired { .. } => ReviewResultLookup::Expired,
        }
    }

    #[must_use]
    pub fn trace_id(&self) -> &str {
        match self {
            Self::Available(complete) => &complete.trace_id,
            Self::Pending { trace_id }
            | Self::ConcealedOrUnknown { trace_id }
            | Self::Expired { trace_id } => trace_id,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewResultsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl ReviewResultsQuery {
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if self
            .limit
            .is_some_and(|limit| limit == 0 || limit > MAXIMUM_PAGE_SIZE)
        {
            return Err("the result page size is invalid");
        }
        Ok(())
    }
}

pub(crate) fn check_result_page(page: &ReviewResultFeedPage) -> Result<(), &'static str> {
    if page.items.len() > MAXIMUM_PAGE_SIZE {
        return Err("the result page contains too many entries");
    }
    // A nil event identifier cannot anchor a resumable position or correlate
    // a completion; a nil final entry would be checkpointed as a cursor no
    // conforming authority can resolve, replaying the same page forever.
    if page.items.iter().any(|entry| entry.event_id.is_nil()) {
        return Err("the result page contains a nil event identifier");
    }
    // A continuation names the position of the final returned entry, so a
    // page whose cursor points anywhere else would let a consumer durably
    // skip the entries in between.
    if let Some(cursor) = page.next_cursor {
        if page
            .items
            .last()
            .is_none_or(|entry| entry.event_id != cursor)
        {
            return Err("the result page cursor does not match its final entry");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use registry_review_protocol::ReviewResultFeedEntry;

    #[test]
    fn result_query_continuations_are_uuid_positions() {
        assert!(ReviewResultsQuery {
            cursor: Some(Uuid::from_u128(7)),
            limit: None,
        }
        .check()
        .is_ok());
    }

    #[test]
    fn result_page_continuations_are_uuid_positions() {
        let final_entry = ReviewResultFeedEntry {
            event_id: Uuid::from_u128(7),
            request_id: Uuid::from_u128(8),
            result_id: Uuid::from_u128(9),
            completed_at: DateTime::from_timestamp(0, 0).expect("fixture timestamp"),
        };
        let valid = ReviewResultFeedPage {
            items: vec![final_entry.clone()],
            next_cursor: Some(Uuid::from_u128(7)),
        };
        assert!(check_result_page(&valid).is_ok());

        let terminal = ReviewResultFeedPage {
            items: vec![final_entry],
            next_cursor: None,
        };
        assert!(check_result_page(&terminal).is_ok());

        // A cursor is the position of the final returned entry, so an empty
        // page or a cursor pointing past unreturned entries would durably
        // skip them.
        let empty = ReviewResultFeedPage {
            items: Vec::new(),
            next_cursor: Some(Uuid::from_u128(7)),
        };
        assert!(check_result_page(&empty).is_err());

        let skipped = ReviewResultFeedPage {
            items: vec![ReviewResultFeedEntry {
                event_id: Uuid::from_u128(7),
                request_id: Uuid::from_u128(8),
                result_id: Uuid::from_u128(9),
                completed_at: DateTime::from_timestamp(0, 0).expect("fixture timestamp"),
            }],
            next_cursor: Some(Uuid::from_u128(10)),
        };
        assert!(check_result_page(&skipped).is_err());
    }

    #[test]
    fn result_page_rejects_nil_event_identifiers() {
        // A nil final entry would be checkpointed as a cursor no conforming
        // authority can resolve, replaying the same page forever.
        let nil_cursor = ReviewResultFeedPage {
            items: vec![ReviewResultFeedEntry {
                event_id: Uuid::nil(),
                request_id: Uuid::from_u128(8),
                result_id: Uuid::from_u128(9),
                completed_at: DateTime::from_timestamp(0, 0).expect("fixture timestamp"),
            }],
            next_cursor: Some(Uuid::nil()),
        };
        assert!(check_result_page(&nil_cursor).is_err());

        // A nil entry anywhere also fails completion correlation, even when
        // the cursor names a real later entry.
        let nil_entry = ReviewResultFeedPage {
            items: vec![
                ReviewResultFeedEntry {
                    event_id: Uuid::nil(),
                    request_id: Uuid::from_u128(8),
                    result_id: Uuid::from_u128(9),
                    completed_at: DateTime::from_timestamp(0, 0).expect("fixture timestamp"),
                },
                ReviewResultFeedEntry {
                    event_id: Uuid::from_u128(7),
                    request_id: Uuid::from_u128(8),
                    result_id: Uuid::from_u128(10),
                    completed_at: DateTime::from_timestamp(0, 0).expect("fixture timestamp"),
                },
            ],
            next_cursor: Some(Uuid::from_u128(7)),
        };
        assert!(check_result_page(&nil_entry).is_err());
    }
}
