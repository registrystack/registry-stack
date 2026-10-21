// SPDX-License-Identifier: Apache-2.0

//! Fixed names of the Document Store artifacts and HTTP wire contract.

/// apiVersion of the operator runtime configuration document.
pub const DOCUMENTS_RUNTIME_API_VERSION: &str =
    "id.registrystack.org/formats/documents/runtime/v1alpha1";

/// Kind of the operator runtime configuration document.
pub const DOCUMENTS_RUNTIME_KIND: &str = "DocumentsRuntimeConfig";

/// apiVersion of the authored project document, `documents.yaml`.
pub const DOCUMENTS_PROJECT_API_VERSION: &str =
    "id.registrystack.org/formats/documents/project/v1alpha1";

/// Kind of the authored project document.
pub const DOCUMENTS_PROJECT_KIND: &str = "DocumentsProject";

/// apiVersion of the report every `documentsctl` command writes as JSON.
pub const DOCUMENTS_CTL_REPORT_API_VERSION: &str =
    "id.registrystack.org/formats/documents/ctl-report/v1alpha1";

/// Kind of the report every `documentsctl` command writes as JSON.
pub const DOCUMENTS_CTL_REPORT_KIND: &str = "DocumentsCtlReport";

/// File name of the authored project document inside a project directory
/// and inside `package.root`.
pub const PROJECT_FILE: &str = "documents.yaml";

/// File name of the runtime configuration JSON Schema.
pub const RUNTIME_SCHEMA_FILE: &str = "runtime.schema.json";

/// `$id` of the runtime configuration JSON Schema.
pub const DOCUMENTS_RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/documents/runtime/runtime.v1alpha1.schema.json";

/// File name of the project JSON Schema.
pub const PROJECT_SCHEMA_FILE: &str = "project.schema.json";

/// `$id` of the project JSON Schema.
pub const DOCUMENTS_PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/documents/project/project.v1alpha1.schema.json";

/// Base of every Document Store problem type URI.
pub const DOCUMENTS_PROBLEM_TYPE_BASE: &str =
    "https://id.registrystack.org/problems/registry-documents/";

// HTTP wire names the runtime and every client share. They live here, beside
// the artifact names, because they are contract: a route that moves strands
// every caller at once.

/// Unauthenticated liveness route on the listener.
pub const HEALTH_PATH: &str = "/health";
/// The route that reserves and lists documents.
pub const DOCUMENTS_PATH: &str = "/documents";
/// The route that reads one document.
pub const DOCUMENT_PATH: &str = "/documents/{documentId}";
/// The route that releases the content of one document version.
pub const DOCUMENT_CONTENT_PATH: &str = "/documents/{documentId}/versions/{versionId}/content";
/// The route an upload's content is sent to.
pub const UPLOAD_CONTENT_PATH: &str = "/uploads/{uploadId}/content";
/// The route that issues and lists the grants of one document.
pub const DOCUMENT_GRANTS_PATH: &str = "/documents/{documentId}/grants";
/// The route that lists the grants naming the caller.
pub const GRANTS_PATH: &str = "/document-grants";
/// The route that revokes one grant.
pub const GRANT_PATH: &str = "/document-grants/{grantId}";
/// The route a custodian asks for a document's erasure on.
pub const DOCUMENT_ERASURE_PATH: &str = "/documents/{documentId}/erasure";
/// The route that lists the policies the caller may place documents under.
pub const POLICIES_PATH: &str = "/document-policies";

/// The header a creating request names its idempotency key in.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
/// The longest idempotency key accepted.
pub const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 128;

#[cfg(test)]
mod tests {
    use super::*;

    /// The names are contract: a change here is a product decision, never a
    /// formatting pass.
    #[test]
    fn fixed_names_are_pinned() {
        assert_eq!(
            DOCUMENTS_RUNTIME_API_VERSION,
            "id.registrystack.org/formats/documents/runtime/v1alpha1"
        );
        assert_eq!(DOCUMENTS_RUNTIME_KIND, "DocumentsRuntimeConfig");
        assert_eq!(
            DOCUMENTS_PROJECT_API_VERSION,
            "id.registrystack.org/formats/documents/project/v1alpha1"
        );
        assert_eq!(DOCUMENTS_PROJECT_KIND, "DocumentsProject");
        assert_eq!(
            DOCUMENTS_CTL_REPORT_API_VERSION,
            "id.registrystack.org/formats/documents/ctl-report/v1alpha1"
        );
        assert_eq!(DOCUMENTS_CTL_REPORT_KIND, "DocumentsCtlReport");
        assert_eq!(PROJECT_FILE, "documents.yaml");
        assert_eq!(RUNTIME_SCHEMA_FILE, "runtime.schema.json");
        assert_eq!(
            DOCUMENTS_RUNTIME_SCHEMA_ID,
            "https://id.registrystack.org/schemas/documents/runtime/runtime.v1alpha1.schema.json"
        );
        assert_eq!(PROJECT_SCHEMA_FILE, "project.schema.json");
        assert_eq!(
            DOCUMENTS_PROJECT_SCHEMA_ID,
            "https://id.registrystack.org/schemas/documents/project/project.v1alpha1.schema.json"
        );
        assert_eq!(
            DOCUMENTS_PROBLEM_TYPE_BASE,
            "https://id.registrystack.org/problems/registry-documents/"
        );
    }

    #[test]
    fn http_wire_names_are_pinned() {
        assert_eq!(HEALTH_PATH, "/health");
        assert_eq!(DOCUMENTS_PATH, "/documents");
        assert_eq!(DOCUMENT_PATH, "/documents/{documentId}");
        assert_eq!(
            DOCUMENT_CONTENT_PATH,
            "/documents/{documentId}/versions/{versionId}/content"
        );
        assert_eq!(UPLOAD_CONTENT_PATH, "/uploads/{uploadId}/content");
        assert_eq!(DOCUMENT_GRANTS_PATH, "/documents/{documentId}/grants");
        assert_eq!(GRANTS_PATH, "/document-grants");
        assert_eq!(GRANT_PATH, "/document-grants/{grantId}");
        assert_eq!(DOCUMENT_ERASURE_PATH, "/documents/{documentId}/erasure");
        assert_eq!(POLICIES_PATH, "/document-policies");
        assert_eq!(IDEMPOTENCY_KEY_HEADER, "idempotency-key");
        assert_eq!(MAXIMUM_IDEMPOTENCY_KEY_BYTES, 128);
    }
}
