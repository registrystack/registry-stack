// SPDX-License-Identifier: Apache-2.0

//! The `http` producer component over
//! `registry-platform-httputil`'s `FixedDestinationPolicy`.
//!
//! `uri: "http:<endpointId>"` names a pack endpoint bound to a base URL
//! in the runtime config. Parameters: `httpMethod`; `path`, an
//! origin-relative template starting with `/` whose `{{name}}` segments
//! are filled from `pathParameters` and percent-encoded as single
//! segments, every placeholder bound and every binding used; or instead
//! of `path`, `httpUri`, an expression yielding an absolute link the
//! source returned, pinned to the endpoint's origin;
//! `query`, engine-encoded and never allowed beside `httpUri`; `body`,
//! marshalled to JSON; `throwExceptionOnFailure` (default true); and
//! `okStatusCodeRange` (default `200-299`).
//!
//! Request headers go out only through the endpoint's `requestHeaders`
//! allowlist and response headers come back only through
//! `responseHeaders`, Camel's `HeaderFilterStrategy` ported as two
//! allowlists with a never-allowlistable set.
//! Authentication is one of the closed kinds, declared
//! on the endpoint and injected at send time, after the allowlist is
//! applied. Redirects are never followed.

pub mod header_filter;
pub mod uri;
