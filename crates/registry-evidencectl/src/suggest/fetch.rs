//! Reads an OpenAPI document that is published at a URL rather than sitting
//! on disk.
//!
//! Registry APIs publish their description at a well-known URL far more often
//! than they ship it as a file, and making the operator fetch it by hand adds
//! a step that only invites a stale copy. Fetching it here is read-only and
//! touches nothing the runtime will later run: the draft is still reviewed by
//! a human and still carries a `TODO` wherever a bound could not be derived.
//!
//! What a URL does change is trust. The description decides which leaves the
//! operator is offered, and the projection they pick from it is the
//! data-minimization boundary of the finished source, so a tampered document
//! could quietly widen what a deployment reads. The rule applied here is
//! therefore the one the runtime already enforces for the source URLs it will
//! itself call: plain `http` only to a numeric loopback host, `https`
//! everywhere else, and never any credential in the authority. Two tools
//! reading the same rule is one rule to review.
//!
//! Nothing fetched is written anywhere except the draft the operator sees,
//! and no request carries authentication. A description behind a token is
//! fetched by the operator with their own client and passed as a file.

use std::{io::Read, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use url::{Host, Url};

use super::types::SpecSource;

/// How long a connection may take to establish, and how long the whole
/// exchange may take. A description is a single small document from a server
/// the operator chose; a request still running after this is a wedged host,
/// and failing beats hanging a terminal indefinitely.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Redirects are followed because a published description is very often a
/// stable URL pointing at a versioned one. The count is bounded so a
/// redirect loop fails rather than spins.
const MAX_REDIRECTS: u32 = 5;

/// Decides what a `--openapi` argument names, and rejects a URL this tool
/// will not fetch before anything is read or any question is asked.
pub fn spec_source(value: &str) -> Result<SpecSource> {
    if looks_like_url(value) {
        return Ok(SpecSource::Url(check_url(value)?));
    }
    Ok(SpecSource::File(PathBuf::from(value)))
}

/// Whether `value` names a location to fetch rather than a file to open.
///
/// The test is for a URL scheme at the front, not for `://` anywhere in the
/// string, so a local path that merely contains those characters still opens
/// as a path. Any scheme is detected, not only the two that are permitted:
/// `ftp://spec.yaml` is a URL the operator meant as a URL, and telling them
/// the scheme is not permitted is more use than reporting that no such file
/// exists.
pub fn looks_like_url(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && !rest.is_empty()
        && scheme.starts_with(|first: char| first.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+-.".contains(character))
}

/// Parses `value` and accepts it only if it is a URL this tool will fetch.
///
/// Applied to the URL the operator passed and again to the URL the response
/// actually came from, so a document that arrived over a hop the operator
/// would not have permitted is refused rather than drafted from. The redirect
/// has already been followed by the time the second check runs; what it
/// prevents is reading a description whose last hop was open to tampering.
/// Checking the final URL is enough for that: an intermediate hop can only be
/// introduced by a server whose own response was already protected by the
/// scheme of the hop before it.
pub fn check_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).with_context(|| format!("parsing `{value}` as a URL"))?;

    // Reported without quoting the URL back: the thing that makes it
    // unacceptable is the credential inside it, and echoing it to a terminal
    // or a scrollback buffer is exactly what should not happen to a secret.
    if !url.username().is_empty() || url.password().is_some() {
        bail!(
            "the OpenAPI URL carries credentials in its authority; pass a URL without them, and \
             fetch a description that needs authentication with your own client and pass the file"
        );
    }

    match url.scheme() {
        "https" => {}
        "http" => match url.host() {
            Some(Host::Ipv4(address)) if address.is_loopback() => {}
            Some(Host::Ipv6(address)) if address.is_loopback() => {}
            _ => bail!(
                "`{url}` is plain http to a host that is not loopback; a description read in the \
                 clear can be tampered with, and it decides what the drafted projection reads. \
                 Use https, or a numeric loopback host such as `http://127.0.0.1:8080/...` for a \
                 local server"
            ),
        },
        scheme => bail!("`{scheme}` URLs are not fetched; pass an https URL, or a local file path"),
    }
    Ok(url)
}

/// Fetches `url` and returns the document text, refusing a body past
/// `max_bytes`.
///
/// The limit is enforced while reading rather than from `Content-Length`, so
/// a response that never declares a length cannot talk this into buffering
/// whatever the server feels like sending.
pub fn get(url: &Url, max_bytes: u64) -> Result<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirects(MAX_REDIRECTS)
        .user_agent(concat!("evidencectl/", env!("CARGO_PKG_VERSION")))
        .build();

    let response = match agent
        .get(url.as_str())
        .set(
            "Accept",
            "application/yaml, application/json, text/yaml, */*",
        )
        .call()
    {
        Ok(response) => response,
        Err(ureq::Error::Status(status, _)) => bail!(
            "fetching {url} returned HTTP {status}; a description behind authentication has to be \
             fetched with your own client and passed as a file"
        ),
        Err(error) => return Err(error).with_context(|| format!("fetching {url}")),
    };

    let landed = response.get_url().to_owned();
    if landed != url.as_str() {
        check_url(&landed)
            .with_context(|| format!("{url} redirected to a URL that is not read"))?;
    }

    let mut body = Vec::new();
    response
        .into_reader()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut body)
        .with_context(|| format!("reading the response body of {url}"))?;
    if body.len() as u64 > max_bytes {
        bail!("the document at {url} exceeds the {max_bytes} byte limit");
    }

    String::from_utf8(body).with_context(|| format!("decoding the document at {url} as UTF-8"))
}
