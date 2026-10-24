// SPDX-License-Identifier: Apache-2.0

//! Privacy-minimal RFC 5545 projection of current Scheduling appointments.
//!
//! This module serializes a bounded snapshot. It owns no calendar account,
//! invitation, subscription, recurrence, or synchronization state. Callers
//! obtain current appointment documents through the ordinary Scheduling
//! client authorization boundary before projecting them here.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use chrono::{DateTime, Timelike as _, Utc};
use registry_scheduling_core::{
    AppointmentDocument, AppointmentStateDocument, OperationalAppointmentDocument,
};
use thiserror::Error;

/// Maximum number of source rows accepted for one calendar snapshot.
///
/// Duplicate appointment rows count toward this ceiling before they are
/// reconciled. This keeps a repeated or overlapping page from weakening the
/// exporter's memory bound.
pub const MAXIMUM_CALENDAR_EVENTS: usize = 500;

const UID_DOMAIN: &str = "appointments.scheduling.registrystack.org";
const PRODUCT_IDENTIFIER: &str = "-//Registry Stack//Scheduling Calendar Export//EN";

/// A privacy-minimal current appointment ready for iCalendar serialization.
///
/// Construction accepts only Scheduling's public current-state documents.
/// Offering, service, location, resource, channel, external references,
/// party facts, manager selection, owner data, and cancellation reason are
/// deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalendarEvent {
    appointment_id: String,
    revision: i32,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    state: AppointmentStateDocument,
}

/// A bounded calendar projection refusal.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CalendarExportError {
    #[error("the calendar snapshot contains no appointments")]
    NoEvents,
    #[error("the calendar snapshot exceeds its event bound")]
    TooManyEvents,
    #[error("an appointment interval is not positive")]
    InvalidInterval,
    #[error("an appointment interval uses precision iCalendar cannot preserve")]
    SubsecondPrecisionUnsupported,
    #[error("an appointment identifier cannot be represented safely")]
    InvalidIdentifier,
    #[error("an appointment revision is outside the iCalendar integer range")]
    RevisionOutOfRange,
    #[error("two current rows disagree at the same appointment revision")]
    ConflictingRevision,
}

impl TryFrom<&AppointmentDocument> for CalendarEvent {
    type Error = CalendarExportError;

    fn try_from(value: &AppointmentDocument) -> Result<Self, Self::Error> {
        Self::new(
            value.appointment_id.clone(),
            value.revision,
            value.start,
            value.end,
            value.state,
        )
    }
}

impl TryFrom<&OperationalAppointmentDocument> for CalendarEvent {
    type Error = CalendarExportError;

    fn try_from(value: &OperationalAppointmentDocument) -> Result<Self, Self::Error> {
        Self::new(
            value.appointment_id.clone(),
            value.revision,
            value.displayed_start,
            value.displayed_end,
            value.state,
        )
    }
}

impl CalendarEvent {
    fn new(
        appointment_id: String,
        revision: u64,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        state: AppointmentStateDocument,
    ) -> Result<Self, CalendarExportError> {
        if appointment_id.is_empty()
            || appointment_id.len() > 128
            || appointment_id.chars().any(char::is_control)
        {
            return Err(CalendarExportError::InvalidIdentifier);
        }
        if end <= start {
            return Err(CalendarExportError::InvalidInterval);
        }
        if start.nanosecond() != 0 || end.nanosecond() != 0 {
            return Err(CalendarExportError::SubsecondPrecisionUnsupported);
        }
        let revision =
            i32::try_from(revision).map_err(|_| CalendarExportError::RevisionOutOfRange)?;
        Ok(Self {
            appointment_id,
            revision,
            start,
            end,
            state,
        })
    }
}

/// Render one bounded current-state snapshot as an RFC 5545 iCalendar object.
///
/// Duplicate rows converge on the highest Scheduling revision. Identical
/// duplicates at that revision are harmless; disagreement at the same
/// revision is refused. The explicit `exported_at` becomes every event's
/// `DTSTAMP`, while appointment revisions map directly to `SEQUENCE`.
pub fn render_icalendar(
    events: impl IntoIterator<Item = CalendarEvent>,
    exported_at: DateTime<Utc>,
) -> Result<String, CalendarExportError> {
    let mut current = BTreeMap::<String, CalendarEvent>::new();
    let mut source_rows = 0_usize;
    for event in events {
        source_rows = source_rows
            .checked_add(1)
            .ok_or(CalendarExportError::TooManyEvents)?;
        if source_rows > MAXIMUM_CALENDAR_EVENTS {
            return Err(CalendarExportError::TooManyEvents);
        }
        match current.entry(event.appointment_id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(event);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let existing = entry.get();
                if event.revision > existing.revision {
                    entry.insert(event);
                } else if event.revision == existing.revision && event != *existing {
                    return Err(CalendarExportError::ConflictingRevision);
                }
            }
        }
    }
    if current.is_empty() {
        return Err(CalendarExportError::NoEvents);
    }

    let mut output = String::new();
    write_content_line(&mut output, "BEGIN:VCALENDAR");
    write_content_line(&mut output, &format!("PRODID:{PRODUCT_IDENTIFIER}"));
    write_content_line(&mut output, "VERSION:2.0");
    for event in current.values() {
        write_content_line(&mut output, "BEGIN:VEVENT");
        write_content_line(
            &mut output,
            &format!("UID:{}@{UID_DOMAIN}", escape_text(&event.appointment_id)),
        );
        write_content_line(&mut output, &format!("DTSTAMP:{}", format_utc(exported_at)));
        write_content_line(&mut output, &format!("DTSTART:{}", format_utc(event.start)));
        write_content_line(&mut output, &format!("DTEND:{}", format_utc(event.end)));
        write_content_line(&mut output, &format!("SEQUENCE:{}", event.revision));
        write_content_line(
            &mut output,
            match event.state {
                AppointmentStateDocument::Confirmed => "STATUS:CONFIRMED",
                AppointmentStateDocument::Cancelled => "STATUS:CANCELLED",
            },
        );
        write_content_line(&mut output, "SUMMARY:Appointment");
        write_content_line(&mut output, "TRANSP:OPAQUE");
        write_content_line(&mut output, "END:VEVENT");
    }
    write_content_line(&mut output, "END:VCALENDAR");
    Ok(output)
}

fn format_utc(value: DateTime<Utc>) -> String {
    value.format("%Y%m%dT%H%M%SZ").to_string()
}

fn escape_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            ';' => escaped.push_str("\\;"),
            ',' => escaped.push_str("\\,"),
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                escaped.push_str("\\n");
            }
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn write_content_line(output: &mut String, line: &str) {
    let mut remaining = line;
    let mut maximum = 75_usize;
    loop {
        if remaining.len() <= maximum {
            write!(output, "{remaining}\r\n").expect("writing to a String cannot fail");
            return;
        }

        let mut split = maximum;
        while !remaining.is_char_boundary(split) {
            split -= 1;
        }
        let (part, rest) = remaining.split_at(split);
        write!(output, "{part}\r\n ").expect("writing to a String cannot fail");
        remaining = rest;
        // The leading continuation space occupies one octet of the next
        // physical content line.
        maximum = 74;
    }
}
