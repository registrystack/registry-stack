// SPDX-License-Identifier: Apache-2.0

//! Fixed names of the Messaging runtime artifacts and HTTP wire contract.

/// apiVersion of the operator runtime configuration document.
pub const MESSAGING_RUNTIME_API_VERSION: &str =
    "registry.registrystack.org/messaging-runtime/v1alpha1";

/// Kind of the operator runtime configuration document.
pub const MESSAGING_RUNTIME_KIND: &str = "MessagingRuntimeConfig";

/// apiVersion of the authored package document.
pub const MESSAGING_PACKAGE_API_VERSION: &str =
    "registry.registrystack.org/messaging-package/v1alpha1";

/// Kind of the authored package document.
pub const MESSAGING_PACKAGE_KIND: &str = "MessagingPackage";

/// File name of the authored package document inside `package.root`.
pub const PACKAGE_FILE: &str = "messaging.yaml";

/// File name of the runtime configuration JSON Schema.
pub const RUNTIME_SCHEMA_FILE: &str = "runtime.schema.json";

/// `$id` of the runtime configuration JSON Schema.
pub const MESSAGING_RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/messaging/runtime/runtime.v1alpha1.schema.json";

/// Base of every Messaging problem type URI.
pub const MESSAGING_PROBLEM_TYPE_BASE: &str =
    "https://id.registrystack.org/problems/registry-messaging/";

// HTTP wire names the runtime and every client share. They live here, beside
// the artifact names, because they are contract: a route that moves strands
// every caller at once.

/// Unauthenticated liveness route on the public listener.
pub const HEALTH_PATH: &str = "/health";

/// Unauthenticated readiness route on the public listener.
pub const READY_PATH: &str = "/ready";

/// Prometheus exposition route, served only on the metrics listener.
pub const METRICS_PATH: &str = "/metrics";

/// Route accepting message submissions.
pub const MESSAGES_PATH: &str = "/v1/messages";

/// Route template reading one message.
pub const MESSAGE_PATH: &str = "/v1/messages/{message_id}";

/// Route template rendering one template version without sending it.
pub const TEMPLATE_PREVIEW_PATH: &str = "/v1/templates/{template_id}/versions/{version}/preview";

/// Header carrying the scoped idempotency key of a mutating command.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// The most bytes of one idempotency key, mirroring the stack convention.
pub const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 128;

/// The most bytes of one caller-supplied correlation identifier.
pub const MAXIMUM_CORRELATION_ID_BYTES: usize = 128;

#[cfg(test)]
mod tests {
    use super::*;

    /// The names are contract: a change here is a product decision, never a
    /// formatting pass.
    #[test]
    fn fixed_names_are_pinned() {
        assert_eq!(
            MESSAGING_RUNTIME_API_VERSION,
            "registry.registrystack.org/messaging-runtime/v1alpha1"
        );
        assert_eq!(MESSAGING_RUNTIME_KIND, "MessagingRuntimeConfig");
        assert_eq!(
            MESSAGING_PACKAGE_API_VERSION,
            "registry.registrystack.org/messaging-package/v1alpha1"
        );
        assert_eq!(MESSAGING_PACKAGE_KIND, "MessagingPackage");
        assert_eq!(PACKAGE_FILE, "messaging.yaml");
        assert_eq!(RUNTIME_SCHEMA_FILE, "runtime.schema.json");
        assert_eq!(
            MESSAGING_RUNTIME_SCHEMA_ID,
            "https://id.registrystack.org/schemas/messaging/runtime/runtime.v1alpha1.schema.json"
        );
        assert_eq!(
            MESSAGING_PROBLEM_TYPE_BASE,
            "https://id.registrystack.org/problems/registry-messaging/"
        );
    }

    #[test]
    fn http_wire_names_are_pinned() {
        assert_eq!(HEALTH_PATH, "/health");
        assert_eq!(READY_PATH, "/ready");
        assert_eq!(METRICS_PATH, "/metrics");
        assert_eq!(MESSAGES_PATH, "/v1/messages");
        assert_eq!(MESSAGE_PATH, "/v1/messages/{message_id}");
        assert_eq!(
            TEMPLATE_PREVIEW_PATH,
            "/v1/templates/{template_id}/versions/{version}/preview"
        );
        assert_eq!(IDEMPOTENCY_KEY_HEADER, "idempotency-key");
        assert_eq!(MAXIMUM_IDEMPOTENCY_KEY_BYTES, 128);
        assert_eq!(MAXIMUM_CORRELATION_ID_BYTES, 128);
    }
}
