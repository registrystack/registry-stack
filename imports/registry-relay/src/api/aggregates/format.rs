// SPDX-License-Identifier: Apache-2.0
//! Aggregate response format negotiation.

use axum::http::{header, HeaderMap};

use crate::error::{AggregateError, Error};

pub(super) const SDMX_JSON: &str = "application/vnd.sdmx.data+json;version=2.1";
const SDMX_JSON_BASE: &str = "application/vnd.sdmx.data+json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AggregateResponseFormat {
    Json,
    Csv,
    SdmxJson,
}

pub(super) fn aggregate_response_format(
    headers: &HeaderMap,
    explicit_format: Option<&str>,
) -> Result<AggregateResponseFormat, Error> {
    if let Some(format) = explicit_format
        .map(str::trim)
        .filter(|format| !format.is_empty())
    {
        return match format.to_ascii_lowercase().as_str() {
            "json" => Ok(AggregateResponseFormat::Json),
            "csv" => Ok(AggregateResponseFormat::Csv),
            "sdmx-json" => Ok(AggregateResponseFormat::SdmxJson),
            _ => Err(AggregateError::FormatUnsupported.into()),
        };
    }
    if accepts_media_type(headers, SDMX_JSON_BASE) {
        Ok(AggregateResponseFormat::SdmxJson)
    } else if accepts_media_type(headers, "text/csv") {
        Ok(AggregateResponseFormat::Csv)
    } else if accepts_known_json(headers) || !has_accept_header(headers) {
        Ok(AggregateResponseFormat::Json)
    } else {
        Err(AggregateError::FormatUnsupported.into())
    }
}

fn accepts_media_type(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                let mut params = part.trim().split(';');
                let media_matches = params
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case(expected));
                let version_matches = if expected.eq_ignore_ascii_case(SDMX_JSON_BASE) {
                    part.trim()
                        .split(';')
                        .skip(1)
                        .find_map(|param| {
                            let (name, value) = param.trim().split_once('=')?;
                            name.trim()
                                .eq_ignore_ascii_case("version")
                                .then(|| value.trim().trim_matches('"').eq("2.1"))
                        })
                        .unwrap_or(true)
                } else {
                    true
                };
                media_matches
                    && version_matches
                    && params
                        .find_map(|param| {
                            let (name, value) = param.trim().split_once('=')?;
                            if name.trim().eq_ignore_ascii_case("q") {
                                Some(
                                    value
                                        .trim()
                                        .parse::<f32>()
                                        .is_ok_and(|quality| quality > 0.0),
                                )
                            } else {
                                None
                            }
                        })
                        .unwrap_or(true)
            })
        })
}

fn accepts_known_json(headers: &HeaderMap) -> bool {
    accepts_media_type(headers, "application/json") || accepts_media_type(headers, "*/*")
}

fn has_accept_header(headers: &HeaderMap) -> bool {
    headers.contains_key(header::ACCEPT)
}
