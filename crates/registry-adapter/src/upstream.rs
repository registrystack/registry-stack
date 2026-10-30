// SPDX-License-Identifier: Apache-2.0

//! The seam between the route interpreter and the one outbound send.
//!
//! The interpreter builds one [`OutboundSend`] per `to` step and hands it to
//! the endpoint's [`UpstreamSend`]. What the send does (pin the link to the
//! endpoint origin, filter the exchange headers, carry the credential, bound
//! the reply, classify a failure) is the implementation's; the interpreter
//! only sees a [`SentReply`] or an [`EgressError`] carrying a section 8.7
//! error class. Exactly one implementation serves a deployment, built per
//! endpoint at load.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use registry_adapter_core::ErrorClass;
use serde_json::Value;

use crate::auth::AuthHeader;

/// The HTTP method of one send. The interpreter serves reads only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendMethod {
    Get,
}

/// Everything one outbound send carries.
pub struct OutboundSend<'a> {
    /// The absolute link under the endpoint's origin, path percent-encoded
    /// and query as it is to be sent.
    pub link: &'a str,
    /// Every exchange header as a name and string value; the send keeps
    /// only the endpoint's `requestHeaders` allowlist.
    pub exchange_headers: &'a [(String, String)],
    pub method: SendMethod,
    /// The credential header, when the endpoint's kind produces one.
    pub authorization: Option<&'a AuthHeader>,
    /// The time one attempt may take.
    pub attempt: Duration,
    pub maximum_response_bytes: usize,
    /// The inclusive status range that counts as success.
    pub ok_status_range: (u16, u16),
    pub throw_exception_on_failure: bool,
}

/// A reply the send accepted.
#[derive(Debug)]
pub struct SentReply {
    pub status: u16,
    /// The decoded JSON body; an empty body is `null`.
    pub body: Value,
    /// The endpoint's declared response headers, under their declared
    /// names.
    pub headers: Vec<(String, String)>,
}

/// A send that did not produce an accepted reply.
#[derive(Debug)]
pub enum EgressError {
    /// The engine refused to send; the class is the uncatchable
    /// `egress.refused`. The text is fixed and value-free.
    Refused(&'static str),
    /// The upstream or the transport failed in a catchable class.
    Upstream(UpstreamFailure),
}

impl EgressError {
    /// The section 8.7 class this failure raises.
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::Refused(_) => ErrorClass::EgressRefused,
            Self::Upstream(failure) => failure.class,
        }
    }
}

/// A catchable upstream failure: the class, and for `upstream.http` the
/// status and decoded body the `onWhen` predicate may read.
#[derive(Debug)]
pub struct UpstreamFailure {
    pub class: ErrorClass,
    pub status: Option<u16>,
    pub body: Option<Value>,
}

/// The future one send returns.
pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<SentReply, EgressError>> + Send + 'a>>;

/// One endpoint's outbound send.
pub trait UpstreamSend: Send + Sync {
    fn send<'a>(&'a self, send: OutboundSend<'a>) -> SendFuture<'a>;
}
