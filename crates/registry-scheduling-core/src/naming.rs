// SPDX-License-Identifier: Apache-2.0

//! Fixed names of the Scheduling authoring and runtime artifacts.

/// apiVersion of an authored scheduling policy package.
pub const SCHEDULING_POLICY_API_VERSION: &str =
    "registry.registrystack.org/scheduling-policy-package/v1alpha1";

/// Kind of an authored scheduling policy package.
pub const SCHEDULING_POLICY_KIND: &str = "SchedulingPolicyPackage";

/// File name of the package manifest written beside the authored policy.
pub const SCHEDULING_PACKAGE_MANIFEST_FILE: &str = "scheduling.package.json";

/// File name of the authored policy inside a scheduling project.
pub const AUTHORED_POLICY_FILE: &str = "scheduling.yaml";

/// apiVersion of the operator runtime configuration document.
pub const SCHEDULING_RUNTIME_API_VERSION: &str =
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

/// The one reserved hook ABI value. This milestone has no hook engine: the
/// value may appear on the hook policy type, and nowhere else.
pub const SCHEDULING_HOOK_ABI: &str = "registry.scheduling-hook/v1";

/// apiVersion of an offline replay fixture.
pub const SCHEDULING_FIXTURE_API_VERSION: &str =
    "registry.registrystack.org/scheduling-fixture/v1alpha1";

/// Kind of an offline replay fixture.
pub const SCHEDULING_FIXTURE_KIND: &str = "SchedulingFixture";

#[cfg(test)]
mod tests {
    use super::*;

    /// The names are contract: a change here is a product decision, never a
    /// formatting pass.
    #[test]
    fn fixed_names_are_pinned() {
        assert_eq!(
            SCHEDULING_POLICY_API_VERSION,
            "registry.registrystack.org/scheduling-policy-package/v1alpha1"
        );
        assert_eq!(SCHEDULING_POLICY_KIND, "SchedulingPolicyPackage");
        assert_eq!(SCHEDULING_PACKAGE_MANIFEST_FILE, "scheduling.package.json");
        assert_eq!(AUTHORED_POLICY_FILE, "scheduling.yaml");
        assert_eq!(
            SCHEDULING_RUNTIME_API_VERSION,
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
        assert_eq!(SCHEDULING_HOOK_ABI, "registry.scheduling-hook/v1");
        assert_eq!(
            SCHEDULING_FIXTURE_API_VERSION,
            "registry.registrystack.org/scheduling-fixture/v1alpha1"
        );
        assert_eq!(SCHEDULING_FIXTURE_KIND, "SchedulingFixture");
    }
}
