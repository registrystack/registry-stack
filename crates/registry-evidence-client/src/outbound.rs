//! Compatibility bridge to the shared outbound client primitives.

pub(crate) use registry_platform_httputil::client::{
    base_url_without_userinfo, build_client, read_failure_kind, send_failure_kind,
    transport_protects_the_credential, OutboundOptions,
};
