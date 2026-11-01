// SPDX-License-Identifier: Apache-2.0

//! The schema shape of the ingestion job's runtime configuration
//! (`AdapterJobRuntimeConfig`, `products/adapter/CONCEPT.md` sections
//! 10.2 and 17.2). The reader is
//! `registry_adapter::engine::job_sources::JobRuntimeConfig`, whose crate
//! carries no schema derive, so the generator describes the document
//! from these mirror types: the endpoint bindings core owns, the job-only
//! `sources` block, and the job host's `store` block. The tests below
//! hold every member list of the `sources` block to the reader's own, so
//! a source member the reader gains or drops fails them. The `store`
//! block mirrors the reader's `JobStoreConfig`; its member list is held
//! by review.

use std::collections::BTreeMap;

use registry_adapter_core::AdapterEndpointBindings;
use registry_platform_yaml::{BoundedU32, BoundedU64, LocalId, SecretReference};
use schemars::JsonSchema;

// The types below are never constructed: they exist for the schema
// derive alone.

/// The ingestion job's runtime configuration: the endpoint bindings
/// every mode shares, the job source bindings, and the job store. It
/// states none of the facade's members (`listener`, `database`, `oidc`,
/// `allowedClients`, `audit`, `idempotency`, the cursor custody).
#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JobRuntimeDocument {
    #[serde(flatten)]
    bindings: AdapterEndpointBindings,
    /// The governed-ingestion source bindings. Absent, the deployment
    /// binds no job source; a pack whose source route reads one refuses
    /// at the job compile, never at the first read.
    #[serde(default)]
    sources: Option<JobSources>,
    /// The job store: the item table's database. Read by the job host,
    /// not by the job compile; absent, the document configures no job
    /// store and the host refuses to run a pass.
    #[serde(default)]
    store: Option<JobStore>,
}

/// The job source bindings, keyed by the pack endpoint each binds.
#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JobSources {
    /// The file sources, keyed by endpoint id.
    #[serde(default)]
    #[schemars(schema_with = "local_id_map_schema::<FileSource>")]
    file: Option<BTreeMap<LocalId, FileSource>>,
    /// The read-only postgres sources, keyed by endpoint id.
    #[serde(default)]
    #[schemars(schema_with = "local_id_map_schema::<PostgresSource>")]
    postgres: Option<BTreeMap<LocalId, PostgresSource>>,
}

/// The schema of a source map: an object whose property names are
/// `LocalId` (CFG-ID-1) and whose values are `V`, the key discipline the
/// reader holds.
fn local_id_map_schema<V: JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    let names = generator.subschema_for::<LocalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "additionalProperties": generator.subschema_for::<V>(),
    })
}

/// The runtime binding of one `file` source endpoint: the absolute base
/// directory the read never leaves, the namespace the item keys carry,
/// and the read behavior of the camel-file port.
#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileSource {
    /// The absolute path of the directory the read lists and reads. A
    /// relative path refuses at the reader.
    directory: String,
    /// The namespace every item key of this source carries.
    namespace: String,
    /// The Ant-style glob a candidate file name must match; absent,
    /// every file is a candidate. A glob carrying a path separator
    /// refuses at the reader: the read is non-recursive.
    #[serde(default)]
    include: Option<String>,
    /// The done-file a candidate must have beside it: a literal name, or
    /// the candidate's own name inside a fixed prefix and suffix
    /// (`$simple{file:name}` or `${file:name}`). Absent, no done-file
    /// check runs.
    #[serde(default)]
    done_file_name: Option<String>,
    /// The read lock; absent, `none`.
    #[serde(default)]
    read_lock: Option<ReadLock>,
    /// The `changed` lock's timeout, in milliseconds (1 to 10000, the
    /// pollEnrich step's own timeout ceiling); absent, 10000. Refused
    /// beside any read lock but `changed`.
    #[serde(default)]
    read_lock_timeout_milliseconds: Option<BoundedU64<1, 10_000>>,
    /// The `changed` lock's space between its two checks, in
    /// milliseconds (100 to 5000); absent, 1000. Refused beside any read
    /// lock but `changed`.
    #[serde(default)]
    read_lock_check_interval_milliseconds: Option<BoundedU64<100, 5_000>>,
    /// Camel's `maxMessagesPerPoll`, accepted for Camel parity; absent,
    /// 500. One read emits at most one file, so the member bounds
    /// nothing a read does not already bound.
    #[serde(default)]
    max_messages_per_poll: Option<BoundedU32<1, { u32::MAX }>>,
}

/// The read lock of one file source.
#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ReadLock {
    /// No lock: a candidate is read as it stands.
    None,
    /// Camel's `changed` lock: the file's length and last-modified time
    /// stable across two checks spaced the check interval apart.
    Changed,
}

/// The runtime binding of one read-only `postgres` source endpoint: its
/// own pool, with its own credential and TLS posture.
#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostgresSource {
    /// The source host.
    host: String,
    /// The source port (1 to 65535); absent, 5432.
    #[serde(default)]
    port: Option<BoundedU64<1, 65_535>>,
    /// The source database.
    database: String,
    /// The source user.
    user: String,
    /// The reference the source password resolves from.
    password_ref: SecretReference,
    /// The namespace every item key of this source carries.
    namespace: String,
    /// The TLS posture of the connection; absent, the system roots with
    /// TLS required.
    #[serde(default)]
    tls: Option<SourceTls>,
}

/// The TLS posture of one postgres source connection. Plaintext is a
/// test-build posture only and is not part of the format.
#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum SourceTls {
    /// The platform trust roots, TLS required, no client certificate.
    SystemRoots,
    /// One private CA bundle file beside the platform roots.
    #[serde(rename_all = "camelCase")]
    CaBundle {
        /// The absolute path of the PEM file holding the bundle.
        ca_bundle_file: String,
    },
}

/// The job store block: the item table's single connection reference.
/// Secret references only, resolved by the job host.
#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JobStore {
    /// The runtime connection reference of the item table's database.
    runtime_url_ref: SecretReference,
    /// The root certificate the connection trusts beside the platform
    /// roots; absent, the platform roots alone.
    #[serde(default)]
    trusted_root_certificate_ref: Option<SecretReference>,
    /// Plaintext connections for the loopback test database only;
    /// refused when true in any build without the job host's test
    /// feature.
    #[serde(default)]
    test_only_plaintext: Option<bool>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use registry_adapter::engine::job_sources::{JobRuntimeConfig, JobSources};
    use serde_json::Value;

    const SCHEMA_FILE: &str = "job-runtime.v1alpha1.schema.json";

    fn schema() -> Value {
        serde_json::from_str(&crate::schemas::documents().unwrap()[SCHEMA_FILE]).unwrap()
    }

    fn validator() -> jsonschema::JSONSchema {
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema())
            .unwrap()
    }

    fn repository_file(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn yaml_as_json(bytes: &[u8]) -> Value {
        registry_platform_yaml::Reader::new("job-runtime.yaml")
            .scan(bytes)
            .expect("the document is in the YAML subset")
            .expect("the document is not empty")
            .to_json_value()
    }

    /// The members the schema states for one definition, the tag left out.
    fn schema_members(definition: &Value) -> BTreeSet<String> {
        definition["properties"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|member| *member != "type")
            .cloned()
            .collect()
    }

    /// The members a deny-unknown-fields reader names in its refusal of
    /// an unknown member: every backtick-quoted name after "expected".
    fn reader_members(sources: Value) -> BTreeSet<String> {
        let error = serde_json::from_value::<JobSources>(sources)
            .expect_err("the unknown member refuses")
            .to_string();
        let (_, expected) = error
            .split_once("expected")
            .unwrap_or_else(|| panic!("the refusal names the members: {error}"));
        expected
            .split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect()
    }

    /// The job runtime documents the repository ships validate against
    /// the generated schema and load through the reader the compile path
    /// and the job host share.
    #[test]
    fn the_shipped_job_runtime_documents_pass_the_schema_and_the_reader() {
        let validator = validator();
        for relative in [
            "products/adapter/fixtures/corpus/base-job/job-runtime.yaml",
            "products/adapter/examples/kobotoolbox-job/job-runtime.example.yaml",
            "products/adapter/examples/odk-central-job/job-runtime.example.yaml",
        ] {
            let path = repository_file(relative);
            let document = yaml_as_json(&std::fs::read(&path).unwrap());
            let errors: Vec<String> = match validator.validate(&document) {
                Ok(()) => Vec::new(),
                Err(errors) => errors.map(|error| error.to_string()).collect(),
            };
            assert!(errors.is_empty(), "{relative} fails the schema: {errors:?}");
            JobRuntimeConfig::load(&path)
                .unwrap_or_else(|error| panic!("{relative} fails the reader: {error}"));
        }
    }

    /// A member neither the schema nor the reader knows refuses at both,
    /// and so does the facade's envelope.
    #[test]
    fn an_unknown_member_or_the_facade_envelope_refuses_at_both() {
        let validator = validator();
        let base = std::fs::read_to_string(repository_file(
            "products/adapter/fixtures/corpus/base-job/job-runtime.yaml",
        ))
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        for (label, text) in [
            (
                "an unknown member",
                format!("{base}listener:\n  port: 8080\n"),
            ),
            (
                "the facade envelope",
                base.replace(
                    "kind: AdapterJobRuntimeConfig",
                    "kind: AdapterRuntimeConfig",
                ),
            ),
        ] {
            assert!(
                validator.validate(&yaml_as_json(text.as_bytes())).is_err(),
                "the schema must refuse {label}"
            );
            let path = directory.path().join("runtime.yaml");
            std::fs::write(&path, &text).unwrap();
            assert!(
                JobRuntimeConfig::load(&path).is_err(),
                "the reader must refuse {label}"
            );
        }
    }

    /// Every member list the schema states for the job-only blocks is the
    /// reader's own, read from the reader's refusal of an unknown member,
    /// so a member the reader gains or drops fails here before the schema
    /// drifts.
    #[test]
    fn the_schema_member_lists_are_the_readers() {
        let schema = schema();
        let definitions = &schema["$defs"];
        let ca_bundle = definitions["SourceTls"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| variant["properties"]["type"]["const"] == "ca-bundle")
            .expect("the ca-bundle posture renders")
            .clone();
        let postgres = |tls: Value| {
            serde_json::json!({"postgres": {"source": {
                "host": "db.example.invalid",
                "database": "intake",
                "user": "reader",
                "passwordRef": "secret:env/SOURCE_PASSWORD",
                "namespace": "intake",
                "tls": tls,
            }}})
        };
        for (definition, schema_definition, probe) in [
            (
                "JobSources",
                definitions["JobSources"].clone(),
                serde_json::json!({"unknown": {}}),
            ),
            (
                "FileSource",
                definitions["FileSource"].clone(),
                serde_json::json!({"file": {"source": {"unknown": 1}}}),
            ),
            (
                "PostgresSource",
                definitions["PostgresSource"].clone(),
                serde_json::json!({"postgres": {"source": {"unknown": 1}}}),
            ),
            (
                "SourceTls ca-bundle",
                ca_bundle,
                postgres(serde_json::json!({"type": "ca-bundle", "unknown": 1})),
            ),
        ] {
            assert_eq!(
                schema_members(&schema_definition),
                reader_members(probe),
                "the {definition} members drifted from the reader"
            );
        }
        let tls_kinds: BTreeSet<String> = definitions["SourceTls"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|variant| {
                variant["properties"]["type"]["const"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(
            tls_kinds,
            reader_members(postgres(serde_json::json!({"type": "unknown"}))),
            "the TLS postures drifted from the reader"
        );
    }
}
