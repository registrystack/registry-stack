// SPDX-License-Identifier: Apache-2.0

//! The 15-minute context-bound listing cursors.
//!
//! A cursor is an opaque token carrying one server-stored cursor id. The row
//! it names holds the listing context it was minted for and the position the
//! next page resumes from, and it expires after fifteen minutes: a listing is
//! a bounded view of a live ledger, not a snapshot a caller may walk forever.
//!
//! Context binding is the load-bearing part. The context string names the
//! exact listing and every parameter that defines its result set, so a cursor
//! replayed against a different listing, a different offering, or a different
//! range is refused as invalid rather than silently returning rows from the
//! wrong view.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

/// How long a cursor stays resolvable. The bound is part of the listing
/// contract: past it, a caller restarts the listing from its first page.
pub const CURSOR_LIFETIME_MINUTES: i64 = 15;

/// The most bytes of one encoded cursor a caller may present.
const MAXIMUM_CURSOR_BYTES: usize = 256;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CursorError {
    #[error("the cursor is not a valid cursor of this listing")]
    Invalid,
    #[error("the cursor expired; restart the listing from its first page")]
    Expired,
}

/// The decoded wire form of one cursor.
#[derive(Serialize, Deserialize)]
struct CursorToken {
    v: u8,
    id: Uuid,
}

/// One stored cursor row.
#[derive(Clone, Debug)]
pub struct StoredCursor {
    pub cursor_id: Uuid,
    pub context: String,
    pub position: Value,
    pub expires_at: DateTime<Utc>,
}

/// Encode a cursor id as the opaque token a caller carries.
#[must_use]
pub fn encode_cursor(cursor_id: Uuid) -> String {
    let token = CursorToken {
        v: 1,
        id: cursor_id,
    };
    let bytes = serde_json::to_vec(&token).expect("a cursor token always serializes");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode an opaque token back to its cursor id, refusing anything that is
/// not exactly a cursor of this wire form.
pub fn decode_cursor(encoded: &str) -> Result<Uuid, CursorError> {
    if encoded.len() > MAXIMUM_CURSOR_BYTES {
        return Err(CursorError::Invalid);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CursorError::Invalid)?;
    let token: CursorToken = serde_json::from_slice(&bytes).map_err(|_| CursorError::Invalid)?;
    if token.v != 1 {
        return Err(CursorError::Invalid);
    }
    Ok(token.id)
}

/// The expiry a newly minted cursor carries.
#[must_use]
pub fn cursor_expiry(now: DateTime<Utc>) -> DateTime<Utc> {
    now.checked_add_signed(TimeDelta::minutes(CURSOR_LIFETIME_MINUTES))
        .expect("fifteen minutes is always representable")
}

/// The position a listing resumes from, typed by what each listing walks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListingPosition {
    /// Resume strictly after this catalogue id.
    AfterId { last_id: String },
    /// Resume strictly after this UTC instant.
    FromInstant { after: DateTime<Utc> },
    /// Resume strictly before this instant and id, walking newest first: the
    /// position one history page leaves behind.
    BeforeInstantAndId {
        before: DateTime<Utc>,
        last_id: String,
    },
}

impl ListingPosition {
    /// The JSON the stored row carries. The shape is internal: callers only
    /// ever see the opaque token.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::AfterId { last_id } => serde_json::json!({"afterId": last_id}),
            Self::FromInstant { after } => {
                serde_json::json!({"after": after.to_rfc3339()})
            }
            Self::BeforeInstantAndId { before, last_id } => {
                serde_json::json!({"before": before.to_rfc3339(), "lastId": last_id})
            }
        }
    }

    /// Read back a stored position, refusing one a different listing shape
    /// wrote. A position that does not parse is a corrupt row, not a caller
    /// error, so it surfaces as invalid the same way a foreign cursor does.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        if let Some(last_id) = value.get("afterId").and_then(Value::as_str) {
            return Some(Self::AfterId {
                last_id: last_id.to_owned(),
            });
        }
        if let (Some(before), Some(last_id)) = (
            value.get("before").and_then(Value::as_str),
            value.get("lastId").and_then(Value::as_str),
        ) {
            return DateTime::parse_from_rfc3339(before).ok().map(|before| {
                Self::BeforeInstantAndId {
                    before: before.with_timezone(&Utc),
                    last_id: last_id.to_owned(),
                }
            });
        }
        value
            .get("after")
            .and_then(Value::as_str)
            .and_then(|after| DateTime::parse_from_rfc3339(after).ok())
            .map(|after| Self::FromInstant {
                after: after.with_timezone(&Utc),
            })
    }
}

/// Check a resolved cursor row against the listing trying to continue it.
pub fn bind_stored(
    stored: &StoredCursor,
    context: &str,
    now: DateTime<Utc>,
) -> Result<ListingPosition, CursorError> {
    if stored.context != context {
        return Err(CursorError::Invalid);
    }
    if stored.expires_at <= now {
        return Err(CursorError::Expired);
    }
    ListingPosition::from_json(&stored.position).ok_or(CursorError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(context: &str, position: Value, minutes_left: i64) -> StoredCursor {
        StoredCursor {
            cursor_id: Uuid::new_v4(),
            context: context.to_owned(),
            position,
            expires_at: Utc::now() + TimeDelta::minutes(minutes_left),
        }
    }

    #[test]
    fn a_cursor_round_trips_through_its_opaque_form() {
        let cursor_id = Uuid::new_v4();
        let encoded = encode_cursor(cursor_id);
        assert_eq!(decode_cursor(&encoded), Ok(cursor_id));
        // Overwriting the final character with a byte outside the base64url
        // alphabet corrupts the token deterministically, whatever the id.
        let corrupted = format!("{}!", &encoded[..encoded.len() - 1]);
        for foreign in ["", "not-a-cursor", "AAAA", &"A".repeat(512), &corrupted] {
            assert_eq!(decode_cursor(foreign), Err(CursorError::Invalid));
        }
    }

    #[test]
    fn a_cursor_binds_to_its_listing_context_and_expires() {
        let now = Utc::now();
        let position = ListingPosition::AfterId {
            last_id: "registry-update-30".to_owned(),
        };
        let row = stored("offerings", position.to_json(), 10);
        assert_eq!(
            bind_stored(&row, "offerings", now),
            Ok(ListingPosition::AfterId {
                last_id: "registry-update-30".to_owned()
            })
        );
        assert_eq!(
            bind_stored(&row, "services", now),
            Err(CursorError::Invalid)
        );
        assert_eq!(
            bind_stored(&row, "offerings", row.expires_at),
            Err(CursorError::Expired)
        );
    }

    #[test]
    fn positions_round_trip_and_refuse_foreign_shapes() {
        for position in [
            ListingPosition::AfterId {
                last_id: "w1".to_owned(),
            },
            ListingPosition::FromInstant { after: Utc::now() },
            ListingPosition::BeforeInstantAndId {
                before: Utc::now(),
                last_id: "event-1".to_owned(),
            },
        ] {
            assert_eq!(
                ListingPosition::from_json(&position.to_json()),
                Some(position.clone())
            );
        }
        assert_eq!(
            ListingPosition::from_json(&serde_json::json!({"x": 1})),
            None
        );
    }

    #[test]
    fn cursor_expiry_is_fifteen_minutes_out() {
        let now = Utc::now();
        assert_eq!(
            cursor_expiry(now).signed_duration_since(now).num_minutes(),
            CURSOR_LIFETIME_MINUTES
        );
    }
}
