use registry_review_protocol::{ReviewResult, ReviewResultFeedPage, ReviewResultLookup};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAXIMUM_CURSOR_BYTES: usize = 4096;
const MAXIMUM_PAGE_SIZE: usize = 100;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewComplete<T> {
    pub value: T,
    pub trace_id: String,
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
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
pub struct ReviewResultsQuery<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl ReviewResultsQuery<'_> {
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if self.cursor.is_some_and(|cursor| {
            cursor.is_empty()
                || cursor.len() > MAXIMUM_CURSOR_BYTES
                || cursor.chars().any(char::is_control)
        }) {
            return Err("the result cursor is invalid");
        }
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
    if page.next_cursor.as_ref().is_some_and(|cursor| {
        cursor.is_empty()
            || cursor.len() > MAXIMUM_CURSOR_BYTES
            || cursor.chars().any(char::is_control)
            || Uuid::parse_str(cursor).is_err()
    }) {
        return Err("the result page cursor is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_page_continuations_are_uuid_positions() {
        let valid = ReviewResultFeedPage {
            items: Vec::new(),
            next_cursor: Some(Uuid::from_u128(7).to_string()),
        };
        assert!(check_result_page(&valid).is_ok());

        let invalid = ReviewResultFeedPage {
            items: Vec::new(),
            next_cursor: Some("bounded-but-not-a-uuid".to_owned()),
        };
        assert!(check_result_page(&invalid).is_err());
    }
}
