// SPDX-License-Identifier: Apache-2.0

//! Fixed names of the Scheduling authoring and runtime artifacts.

/// apiVersion of the authored scheduling project file.
pub const SCHEDULING_POLICY_API_VERSION: &str =
    "id.registrystack.org/formats/scheduling/project/v1alpha1";

/// The project file's former apiVersion, refused with the current one named.
pub const RETIRED_SCHEDULING_POLICY_API_VERSION: &str =
    "registry.registrystack.org/scheduling-policy-package/v1alpha1";

/// Kind of the authored scheduling project file.
pub const SCHEDULING_POLICY_KIND: &str = "SchedulingProject";

/// `$id` of the project file's JSON Schema.
pub const SCHEDULING_PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/scheduling/project/project.v1alpha1.schema.json";

/// apiVersion of an operator records document.
pub const SCHEDULING_RECORDS_API_VERSION: &str =
    "id.registrystack.org/formats/scheduling/records/v1alpha1";

/// Kind of an operator records document.
pub const SCHEDULING_RECORDS_KIND: &str = "SchedulingRecords";

/// `$id` of the records document's JSON Schema.
pub const SCHEDULING_RECORDS_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/scheduling/records/records.v1alpha1.schema.json";

/// File name of the authored policy inside a scheduling project.
pub const AUTHORED_POLICY_FILE: &str = "scheduling.yaml";

/// apiVersion of the operator runtime configuration document.
pub const SCHEDULING_RUNTIME_API_VERSION: &str =
    "id.registrystack.org/formats/scheduling/runtime/v1alpha1";

/// The runtime configuration's former apiVersion, refused with the current
/// one named.
pub const RETIRED_SCHEDULING_RUNTIME_API_VERSION: &str =
    "registry.registrystack.org/scheduling-runtime/v1alpha1";

/// Kind of the operator runtime configuration document.
pub const SCHEDULING_RUNTIME_KIND: &str = "SchedulingRuntimeConfig";

/// File name of the runtime configuration document.
pub const RUNTIME_SCHEMA_FILE: &str = "runtime.schema.json";

/// `$id` of the runtime configuration JSON Schema.
pub const SCHEDULING_RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/scheduling/runtime/runtime.v1alpha1.schema.json";

/// Base of every Scheduling problem type URI.
pub const SCHEDULING_PROBLEM_TYPE_BASE: &str =
    "https://id.registrystack.org/problems/registry-scheduling/";

/// apiVersion of an offline replay fixture.
pub const SCHEDULING_FIXTURE_API_VERSION: &str =
    "id.registrystack.org/formats/scheduling/fixture/v1alpha1";

/// A fixture's former apiVersion, refused with the current one named.
pub const RETIRED_SCHEDULING_FIXTURE_API_VERSION: &str =
    "registry.registrystack.org/scheduling-fixture/v1alpha1";

/// Kind of an offline replay fixture.
pub const SCHEDULING_FIXTURE_KIND: &str = "SchedulingFixture";

/// `$id` of the fixture's JSON Schema.
pub const SCHEDULING_FIXTURE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/scheduling/fixture/fixture.v1alpha1.schema.json";

/// apiVersion of the report every `schedulingctl` command writes as JSON.
pub const SCHEDULING_CTL_REPORT_API_VERSION: &str =
    "id.registrystack.org/formats/scheduling/ctl-report/v1alpha1";

/// Kind of the report every `schedulingctl` command writes as JSON.
pub const SCHEDULING_CTL_REPORT_KIND: &str = "SchedulingCtlReport";

// HTTP wire names the runtime and every client share. They live here, beside
// the artifact names, because they are contract: a route that moves strands
// every caller at once.

/// Route answering which deployment and which policy revision.
pub const SCHEDULING_PATH: &str = "/v1/scheduling";

/// Route listing the service catalogue.
pub const SERVICES_PATH: &str = "/v1/services";

/// Route listing the offering catalogue.
pub const OFFERINGS_PATH: &str = "/v1/offerings";

/// Route answering bounded availability searches.
pub const AVAILABILITY_PATH: &str = "/v1/availability";

/// Route answering the separately authorized explanation of one refusal.
pub const AVAILABILITY_EXPLAIN_PATH: &str = "/v1/availability/explain";

/// Route minting holds.
pub const HOLDS_PATH: &str = "/v1/holds";

/// Route confirming holds and creating appointments.
pub const APPOINTMENTS_PATH: &str = "/v1/appointments";

/// Route listing backing resources.
pub const RESOURCES_PATH: &str = "/v1/resources";

/// Route listing locations.
pub const LOCATIONS_PATH: &str = "/v1/locations";

/// Header carrying the scoped idempotency key of a mutating command.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Query parameter continuing a bounded listing.
pub const CURSOR_QUERY_PARAMETER: &str = "cursor";

/// Query parameter capping one page of a bounded listing.
pub const LIMIT_QUERY_PARAMETER: &str = "limit";

/// The most bytes of one idempotency key, mirroring the stack convention.
pub const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 128;

#[cfg(test)]
mod tests {
    use super::*;

    /// The names are contract: a change here is a product decision, never a
    /// formatting pass.
    #[test]
    fn fixed_names_are_pinned() {
        assert_eq!(
            SCHEDULING_POLICY_API_VERSION,
            "id.registrystack.org/formats/scheduling/project/v1alpha1"
        );
        assert_eq!(
            RETIRED_SCHEDULING_POLICY_API_VERSION,
            "registry.registrystack.org/scheduling-policy-package/v1alpha1"
        );
        assert_eq!(SCHEDULING_POLICY_KIND, "SchedulingProject");
        assert_eq!(
            SCHEDULING_PROJECT_SCHEMA_ID,
            "https://id.registrystack.org/schemas/scheduling/project/project.v1alpha1.schema.json"
        );
        assert_eq!(
            SCHEDULING_RECORDS_API_VERSION,
            "id.registrystack.org/formats/scheduling/records/v1alpha1"
        );
        assert_eq!(SCHEDULING_RECORDS_KIND, "SchedulingRecords");
        assert_eq!(
            SCHEDULING_RECORDS_SCHEMA_ID,
            "https://id.registrystack.org/schemas/scheduling/records/records.v1alpha1.schema.json"
        );
        assert_eq!(AUTHORED_POLICY_FILE, "scheduling.yaml");
        assert_eq!(
            SCHEDULING_RUNTIME_API_VERSION,
            "id.registrystack.org/formats/scheduling/runtime/v1alpha1"
        );
        assert_eq!(
            RETIRED_SCHEDULING_RUNTIME_API_VERSION,
            "registry.registrystack.org/scheduling-runtime/v1alpha1"
        );
        assert_eq!(SCHEDULING_RUNTIME_KIND, "SchedulingRuntimeConfig");
        assert_eq!(RUNTIME_SCHEMA_FILE, "runtime.schema.json");
        assert_eq!(
            SCHEDULING_RUNTIME_SCHEMA_ID,
            "https://id.registrystack.org/schemas/scheduling/runtime/runtime.v1alpha1.schema.json"
        );
        assert_eq!(
            SCHEDULING_PROBLEM_TYPE_BASE,
            "https://id.registrystack.org/problems/registry-scheduling/"
        );
        assert_eq!(
            SCHEDULING_FIXTURE_API_VERSION,
            "id.registrystack.org/formats/scheduling/fixture/v1alpha1"
        );
        assert_eq!(
            RETIRED_SCHEDULING_FIXTURE_API_VERSION,
            "registry.registrystack.org/scheduling-fixture/v1alpha1"
        );
        assert_eq!(SCHEDULING_FIXTURE_KIND, "SchedulingFixture");
        assert_eq!(
            SCHEDULING_FIXTURE_SCHEMA_ID,
            "https://id.registrystack.org/schemas/scheduling/fixture/fixture.v1alpha1.schema.json"
        );
        assert_eq!(
            SCHEDULING_CTL_REPORT_API_VERSION,
            "id.registrystack.org/formats/scheduling/ctl-report/v1alpha1"
        );
        assert_eq!(SCHEDULING_CTL_REPORT_KIND, "SchedulingCtlReport");
    }

    /// The HTTP wire names are contract the same way: routes move only with
    /// the product's compatibility decisions, never in a formatting pass.
    #[test]
    fn http_wire_names_are_pinned() {
        assert_eq!(SCHEDULING_PATH, "/v1/scheduling");
        assert_eq!(SERVICES_PATH, "/v1/services");
        assert_eq!(OFFERINGS_PATH, "/v1/offerings");
        assert_eq!(AVAILABILITY_PATH, "/v1/availability");
        assert_eq!(AVAILABILITY_EXPLAIN_PATH, "/v1/availability/explain");
        assert_eq!(HOLDS_PATH, "/v1/holds");
        assert_eq!(APPOINTMENTS_PATH, "/v1/appointments");
        assert_eq!(RESOURCES_PATH, "/v1/resources");
        assert_eq!(LOCATIONS_PATH, "/v1/locations");
        assert_eq!(IDEMPOTENCY_KEY_HEADER, "idempotency-key");
        assert_eq!(CURSOR_QUERY_PARAMETER, "cursor");
        assert_eq!(LIMIT_QUERY_PARAMETER, "limit");
        assert_eq!(MAXIMUM_IDEMPOTENCY_KEY_BYTES, 128);
    }
}
