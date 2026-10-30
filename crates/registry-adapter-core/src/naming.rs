// SPDX-License-Identifier: Apache-2.0

//! Fixed names of the Adapter authoring and operator artifacts.

/// apiVersion of the authored facade profile.
pub const ADAPTER_PROFILE_API_VERSION: &str =
    "id.registrystack.org/formats/adapter/profile/v1alpha1";

/// Kind of the authored facade profile.
pub const ADAPTER_PROFILE_KIND: &str = "AdapterProfile";

/// `$id` of the facade profile's JSON Schema.
pub const ADAPTER_PROFILE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/adapter/profile/profile.v1alpha1.schema.json";

/// apiVersion of the authored adapter pack.
pub const ADAPTER_PACK_API_VERSION: &str = "id.registrystack.org/formats/adapter/pack/v1alpha1";

/// Kind of the authored adapter pack.
pub const ADAPTER_PACK_KIND: &str = "AdapterPack";

/// `$id` of the adapter pack's JSON Schema.
pub const ADAPTER_PACK_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/adapter/pack/pack.v1alpha1.schema.json";

/// apiVersion of the authored adapter project.
pub const ADAPTER_PROJECT_API_VERSION: &str =
    "id.registrystack.org/formats/adapter/project/v1alpha1";

/// Kind of the authored adapter project.
pub const ADAPTER_PROJECT_KIND: &str = "AdapterProject";

/// `$id` of the adapter project's JSON Schema.
pub const ADAPTER_PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/adapter/project/project.v1alpha1.schema.json";

/// apiVersion of the operator runtime configuration document.
pub const ADAPTER_RUNTIME_API_VERSION: &str =
    "id.registrystack.org/formats/adapter/runtime/v1alpha1";

/// Kind of the operator runtime configuration document.
pub const ADAPTER_RUNTIME_KIND: &str = "AdapterRuntimeConfig";

/// `$id` of the runtime configuration's JSON Schema.
pub const ADAPTER_RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/adapter/runtime/runtime.v1alpha1.schema.json";

/// apiVersion of an authored fixture transcript.
pub const ADAPTER_FIXTURE_API_VERSION: &str =
    "id.registrystack.org/formats/adapter/fixture/v1alpha1";

/// Kind of an authored fixture transcript.
pub const ADAPTER_FIXTURE_KIND: &str = "AdapterFixture";

/// `$id` of the fixture transcript's JSON Schema.
pub const ADAPTER_FIXTURE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/adapter/fixture/fixture.v1alpha1.schema.json";

/// Base of every Adapter problem type URI.
pub const ADAPTER_PROBLEM_TYPE_BASE: &str =
    "https://id.registrystack.org/problems/registry-adapter/";

/// The most `allowedPrivateCidrs` entries a runtime config may list. It
/// mirrors the platform fixed-destination policy's own bound
/// (`MAX_DESTINATION_PRIVATE_CIDRS` in `registry-platform-httputil`), so a
/// config that passes this check cannot be refused later by the platform.
pub const MAX_ALLOWED_PRIVATE_CIDRS: usize = 16;

/// The most named TLS trust profiles one runtime config may declare, the
/// shared bound Evidence and Messaging put on the same mapping.
pub const MAX_TLS_TRUST_PROFILES: usize = 64;

/// The longest `upstream.<id>.baseUrl` text accepted. It bounds the URL the
/// engine templates and journals; a longer origin does not exist in practice.
pub const MAX_BASE_URL_CHARACTERS: usize = 2048;

/// The longest upstream request path or query value a template or fixture
/// may carry.
pub const MAX_UPSTREAM_PATH_CHARACTERS: usize = 2048;

/// The longest `from` field path a field mapping or code-map entry may name.
pub const MAX_FIELD_PATH_CHARACTERS: usize = 256;

/// The longest token-request text parameter a runtime credential may
/// bind: `scope`, `audience`, `resource`, and `clientAssertionAudience`
/// each travel verbatim in the token request, so the reader refuses an
/// empty or oversized one at authoring time, with the same ceiling the
/// auth plan enforces when it builds the request.
pub const MAX_TOKEN_PARAMETER_BYTES: usize = 512;

/// The upstream retention window an operator may declare for the audit
/// journal, in days. It matches the platform access-log bound.
pub const MAX_AUDIT_RETENTION_DAYS: u32 = 3_650;
