// SPDX-License-Identifier: Apache-2.0

//! The service's few static HTML pages. None carries a script, a style or a
//! value from the issuer: the only request text in any of them is a return
//! path the sign-in already validated, escaped.

use crate::check::percent_encode;

/// A closed set of reasons a sign-in did not complete, shown as a stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Refused,
    Unavailable,
    AuditUnavailable,
    Busy,
    RateLimited,
}

impl Failure {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Refused => "sign-in-refused",
            Self::Unavailable => "sign-in-unavailable",
            Self::AuditUnavailable => "audit-unavailable",
            Self::Busy => "busy",
            Self::RateLimited => "rate-limited",
        }
    }

    const fn heading(self) -> &'static str {
        match self {
            Self::Refused => "Sign-in did not complete",
            Self::Unavailable => "Sign-in unavailable",
            Self::AuditUnavailable => "Unavailable",
            Self::Busy => "Busy",
            Self::RateLimited => "Too many requests",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Refused => "Sign-in could not be completed.",
            Self::Unavailable => "Sign-in is not available right now. Try again later.",
            Self::AuditUnavailable => {
                "This service cannot record what it does right now, so it does nothing. Try again later."
            }
            Self::Busy => "Too many people are signing in right now. Try again in a few minutes.",
            Self::RateLimited => "Too many requests arrived. Wait a moment and try again.",
        }
    }
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn document(title: &str, body: &str, head: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n{head}\
<title>{title}</title>\n</head>\n<body>\n<main>\n{body}</main>\n</body>\n</html>\n"
    )
}

/// The page that moves the browser from the service's own origin to `path`,
/// so the session cookie travels whatever site the issuer is on.
pub fn continue_to(path: &str) -> String {
    let path = escape(path);
    document(
        "Signed in",
        &format!("<h1>Signed in</h1>\n<p><a href=\"{path}\">Continue</a></p>\n"),
        &format!("<meta http-equiv=\"refresh\" content=\"0;url={path}\">\n"),
    )
}

/// The page a failed sign-in ends on. `return_to`, when the sign-in was
/// valid, lets the person start again for the same page.
pub fn failed(failure: Failure, return_to: Option<&str>) -> String {
    let retry = return_to.map_or_else(String::new, |path| {
        format!(
            "<p><a href=\"/session/sign-in?return={}\">Sign in again</a></p>\n",
            percent_encode(path)
        )
    });
    document(
        failure.heading(),
        &format!(
            "<h1>{}</h1>\n<p>{}</p>\n<p>Code: <code>{}</code></p>\n{retry}",
            failure.heading(),
            failure.message(),
            failure.code()
        ),
        "",
    )
}

pub fn signed_out() -> String {
    document(
        "Signed out",
        "<h1>Signed out</h1>\n<p>You are signed out.</p>\n",
        "",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_return_path_is_escaped_and_no_page_has_a_script() {
        let page = continue_to("/apply/?a=1&b=\"<x>\"");
        assert!(page.contains("/apply/?a=1&amp;b=&quot;&lt;x&gt;&quot;"));
        assert!(!page.contains("<x>"));
        for page in [
            page,
            signed_out(),
            failed(Failure::Refused, Some("/apply/")),
            failed(Failure::Busy, None),
        ] {
            assert!(!page.contains("<script"));
            assert!(!page.contains("<style"));
        }
    }

    #[test]
    fn a_failure_links_back_to_sign_in_only_with_a_known_return_path() {
        assert!(failed(Failure::Refused, Some("/staff/q?x=1"))
            .contains("/session/sign-in?return=%2Fstaff%2Fq%3Fx%3D1"));
        assert!(!failed(Failure::Refused, None).contains("/session/sign-in"));
    }
}
