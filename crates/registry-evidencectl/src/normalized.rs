//! Filesystem adapter for the one normalized Evidence authoring compiler.
use crate::{authored, check::Checked};
use anyhow::{bail, Context as _, Result};
use registry_evidence_authoring::{
    compile::{self, CheckedPackRoute, CompiledProject},
    formats::finding_diagnostic,
    project::{self, EvidenceProject},
    target::{EvidenceTarget, TargetAssuranceProfile, TargetOutboundTls, TargetSigner},
};
use registry_platform_crypto::{canonicalize_json, domain_separated_sha256};
use registry_platform_yaml::Decoded;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

fn read_decoded(root: &Path) -> Result<(Decoded<EvidenceProject>, BTreeMap<String, String>)> {
    let file = if root.is_file() {
        root.to_path_buf()
    } else {
        root.join(project::PROJECT_FILE)
    };
    let directory = file
        .parent()
        .context("project file requires a parent directory")?;
    let bytes = authored::read_authored_file(&file, "Evidence project")?;
    let decoded = project::read_project(project::PROJECT_FILE, &bytes)?;
    let mut scripts = BTreeMap::new();
    for (index, function) in decoded.value.functions.iter().enumerate() {
        let path = safe_asset(directory, &function.source).map_err(|_| {
            let finding = registry_evidence_authoring::Finding {
                code: "asset-path",
                field: registry_evidence_authoring::FieldPath::root()
                    .key("functions")
                    .index(index)
                    .key("source"),
                message: "Function source must name a plain asset inside this project".to_owned(),
            };
            decoded.document.report_with([finding_diagnostic(
                &decoded.document,
                "project",
                &finding,
            )])
        })?;
        let bytes = authored::read_authored_file(&path, "reviewed Function asset")?;
        if bytes.len() > registry_evidence_authoring::layout::MAX_DERIVATION_BYTES as usize {
            bail!("Function exceeds the authored script size limit");
        }
        scripts.insert(
            function.source.clone(),
            String::from_utf8(bytes).context("Function asset must be UTF-8")?,
        );
    }
    let assets = decoded
        .value
        .assertion_definitions
        .values()
        .flat_map(|definition| {
            definition
                .outputs
                .values()
                .filter_map(|output| output.schema.as_deref())
        });
    let codelists = decoded
        .value
        .assertion_definitions
        .values()
        .flat_map(|definition| {
            definition
                .outputs
                .values()
                .filter_map(|output| output.codelist.as_deref())
        })
        .chain(
            decoded
                .value
                .selector_profiles
                .values()
                .flat_map(|profile| {
                    profile
                        .fields
                        .values()
                        .filter_map(|field| field.codelist().map(|(path, _)| path))
                }),
        );
    for asset in assets.chain(codelists) {
        let bytes =
            authored::read_authored_file(&safe_asset(directory, asset)?, "reviewed project asset")?;
        scripts.insert(
            asset.to_owned(),
            String::from_utf8(bytes).context("reviewed project asset must be UTF-8")?,
        );
    }
    Ok((decoded, scripts))
}

pub(crate) fn read(root: &Path) -> Result<(EvidenceProject, BTreeMap<String, String>)> {
    let (decoded, scripts) = read_decoded(root)?;
    Ok((decoded.value, scripts))
}

pub(crate) fn read_pack_routes(
    root: &Path,
    project: &EvidenceProject,
) -> Result<Vec<CheckedPackRoute>> {
    let root = if root.is_file() {
        root.parent()
            .context("project file requires a parent directory")?
    } else {
        root
    };
    let mut routes = BTreeMap::new();
    for source in project.sources.values() {
        let key = format!(
            "{}\0{}\0{}",
            source.pack.id, source.pack.version, source.route
        );
        if routes.contains_key(&key) {
            continue;
        }
        let pack_relative = format!("adapter-packs/{}/pack.yaml", source.pack.id);
        let pack_path = safe_asset(root, &pack_relative)?;
        let pack_bytes = authored::read_authored_file(&pack_path, "reviewed Adapter pack")?;
        let format = registry_platform_yaml::FormatSpec {
            kind: registry_adapter_core::ADAPTER_PACK_KIND,
            envelope: registry_platform_yaml::EnvelopeRule::ApiVersionKind {
                api_versions: &[registry_platform_yaml::ApiVersion::current(
                    registry_adapter_core::ADAPTER_PACK_API_VERSION,
                )],
                retired_api_versions: &[],
            },
            removed_keys: &[],
        };
        let pack = registry_platform_yaml::Reader::new(pack_relative.as_str())
            .decode::<registry_adapter_core::AdapterPack>(
                &pack_bytes,
                &registry_platform_yaml::Expect::one(&format),
            )
            .map_err(|_| {
                anyhow::anyhow!("Adapter pack must satisfy the current AdapterPack contract")
            })?
            .value;
        let document = serde_json::to_value(&pack).context("Adapter pack cannot be represented")?;
        let pack_root = pack_path
            .parent()
            .context("Adapter pack requires a parent directory")?;
        let mut references = BTreeMap::new();
        for reference in pack.pinned_files() {
            add_pack_reference(&mut references, &serde_json::to_value(reference)?)?;
        }
        let source_routes = document
            .get("sourceRoutes")
            .and_then(Value::as_array)
            .context("Adapter pack must declare sourceRoutes")?;
        let selected = source_routes
            .iter()
            .filter(|route| route.get("id").and_then(Value::as_str) == Some(source.route.as_str()))
            .collect::<Vec<_>>();
        if selected.len() != 1 {
            bail!("Adapter pack must declare the selected source route exactly once");
        }
        let evidence = selected[0]
            .get("evidence")
            .context("selected source route requires an Evidence contract")?;
        let input_path = evidence["inputsSchema"]["path"]
            .as_str()
            .context("Evidence inputsSchema path must be text")?;
        let facts_path = evidence["factsSchema"]["path"]
            .as_str()
            .context("Evidence factsSchema path must be text")?;
        let mut artifacts = BTreeMap::new();
        for path in references.keys() {
            artifacts.insert(
                path.clone(),
                authored::read_authored_file(
                    &safe_asset(pack_root, path)?,
                    "digest-pinned Adapter pack artifact",
                )?,
            );
        }
        let inputs_schema = serde_json::from_slice(
            artifacts
                .get(input_path)
                .context("selected Evidence inputs schema is missing")?,
        )
        .context("selected Evidence inputs schema must be JSON")?;
        let facts_schema = serde_json::from_slice(
            artifacts
                .get(facts_path)
                .context("selected Evidence facts schema is missing")?,
        )
        .context("selected Evidence facts schema must be JSON")?;
        routes.insert(
            key,
            CheckedPackRoute {
                pack: source.pack.clone(),
                route: source.route.clone(),
                digest: registry_platform_config::sha256_uri(&pack_bytes),
                inputs_schema,
                facts_schema,
                acquisition_posture: source.acquisition_posture,
                pack_bytes,
                artifacts,
            },
        );
    }
    Ok(routes.into_values().collect())
}

fn add_pack_reference(references: &mut BTreeMap<String, String>, reference: &Value) -> Result<()> {
    let path = reference
        .get("path")
        .and_then(Value::as_str)
        .context("Adapter pack reference path must be text")?;
    let digest = reference
        .get("digest")
        .and_then(Value::as_str)
        .context("Adapter pack reference digest must be text")?;
    if let Some(existing) = references.insert(path.to_owned(), digest.to_owned()) {
        if existing != digest {
            bail!("one Adapter pack artifact path has conflicting digest pins");
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PackRouteOperation {
    pub(crate) component: String,
    pub(crate) endpoint: String,
    pub(crate) http_method: Option<String>,
    pub(crate) path: Option<String>,
}

pub(crate) fn source_route_operations(
    root: &Path,
    source: &project::Source,
) -> Result<Vec<PackRouteOperation>> {
    let root = if root.is_file() {
        root.parent()
            .context("project file requires a parent directory")?
    } else {
        root
    };
    let relative = format!("adapter-packs/{}/pack.yaml", source.pack.id);
    let bytes =
        authored::read_authored_file(&safe_asset(root, &relative)?, "reviewed Adapter pack")?;
    let document = registry_platform_yaml::Reader::new(relative)
        .scan(&bytes)
        .map_err(|_| anyhow::anyhow!("Adapter pack must be one bounded YAML or JSON document"))?
        .context("Adapter pack must not be empty")?
        .to_json_value();
    let route = document
        .get("sourceRoutes")
        .and_then(Value::as_array)
        .and_then(|routes| {
            routes.iter().find(|route| {
                route.get("id").and_then(Value::as_str) == Some(source.route.as_str())
            })
        })
        .context("Adapter pack does not declare the selected source route")?;
    let mut direct_routes = BTreeMap::new();
    if let Some(routes) = document.get("routes").and_then(Value::as_array) {
        for route in routes {
            if let Some(id) = route.get("id").and_then(Value::as_str) {
                direct_routes.insert(id, route);
            }
        }
    }
    let mut operations = Vec::new();
    collect_route_operations(
        route.get("steps").unwrap_or(&Value::Null),
        &direct_routes,
        &mut BTreeSet::new(),
        &mut operations,
    )?;
    Ok(operations)
}

fn collect_route_operations<'a>(
    value: &'a Value,
    direct_routes: &BTreeMap<&'a str, &'a Value>,
    active: &mut BTreeSet<String>,
    operations: &mut Vec<PackRouteOperation>,
) -> Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_route_operations(value, direct_routes, active, operations)?;
            }
        }
        Value::Object(object) => {
            if let Some(uri) = object.get("uri").and_then(Value::as_str) {
                let (component, endpoint) = uri
                    .split_once(':')
                    .context("Adapter pack send URI must name a component and endpoint")?;
                if component == "direct" {
                    if !active.insert(endpoint.to_owned()) {
                        bail!("Adapter pack direct route cycle cannot be inspected");
                    }
                    let route = direct_routes
                        .get(endpoint)
                        .context("Adapter pack direct route is missing")?;
                    collect_route_operations(
                        route.get("steps").unwrap_or(&Value::Null),
                        direct_routes,
                        active,
                        operations,
                    )?;
                    active.remove(endpoint);
                } else {
                    let parameters = object.get("parameters");
                    operations.push(PackRouteOperation {
                        component: component.to_owned(),
                        endpoint: endpoint.to_owned(),
                        http_method: parameters
                            .and_then(|parameters| parameters.get("httpMethod"))
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        path: parameters
                            .and_then(|parameters| parameters.get("path"))
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    });
                }
                return Ok(());
            }
            for value in object.values() {
                collect_route_operations(value, direct_routes, active, operations)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn safe_asset(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.starts_with('/')
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("artifact must be a project-relative path without traversal");
    }
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        path.push(component);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspecting project asset {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("project assets cannot traverse symbolic links");
        }
    }
    Ok(path)
}
pub(crate) fn compile(root: &Path) -> Result<(EvidenceProject, CompiledProject)> {
    let (decoded, compiled) = compile_decoded(root)?;
    Ok((decoded.value, compiled))
}

fn compile_decoded(root: &Path) -> Result<(Decoded<EvidenceProject>, CompiledProject)> {
    compile_decoded_with_pack_root(root, root)
}

fn compile_decoded_with_pack_root(
    root: &Path,
    pack_root: &Path,
) -> Result<(Decoded<EvidenceProject>, CompiledProject)> {
    let (decoded, scripts) = read_decoded(root)?;
    let pack_routes = read_pack_routes(pack_root, &decoded.value)?;
    let compiled = compile::compile_with_pack_routes(&decoded.value, &scripts, &pack_routes)
        .map_err(|findings| {
            decoded.document.report_with(
                findings
                    .iter()
                    .map(|finding| finding_diagnostic(&decoded.document, "project", finding)),
            )
        })?;
    Ok((decoded, compiled))
}

pub(crate) fn inspect(root: &Path, target: Option<&Path>, command: &str) -> Result<Checked> {
    let target = target.map(crate::target::target_path);
    let snapshot = crate::project_snapshot::capture_project(root)?;
    let (decoded, mut compiled) = compile_decoded_with_pack_root(snapshot.root(), root)
        .map_err(|error| authored::project_refusal(error, snapshot.root(), root))?;
    let diagnostics = authored::rebase(decoded.document.warnings(), root);
    let project = decoded.value;
    for function in &mut compiled.functions {
        let path = function["source"]
            .as_str()
            .context("compiled Function source")?;
        let script = authored::read_authored_file(
            &safe_asset(snapshot.root(), path)?,
            "reviewed Function asset",
        )?;
        function["digest"] = json!(registry_platform_config::sha256_uri(&script));
    }
    let mut authority = Value::Null;
    if let Some(path) = target.as_deref() {
        let bytes = authored::read_authored_file(path, "Evidence target")?;
        let target =
            registry_evidence_authoring::target::read_target(&path.to_string_lossy(), &bytes)?
                .value;
        if target.project != project.id {
            bail!("target must name this EvidenceProject");
        }
        let authority_path = safe_asset(target_directory(path), &target.authority)?;
        let bytes = authored::read_authored_file(&authority_path, "governed target authority")?;
        let decoded = registry_evidence_authoring::target::read_authority(
            &authority_path.to_string_lossy(),
            &bytes,
            &project,
        )?;
        if decoded.value.target != target.id {
            bail!("target authority must name the selected target");
        }
        let document =
            registry_evidence_authoring::target::compile_authority(&decoded.value, &project)
                .map_err(|findings| {
                    authored::file_findings_report(
                        &authority_path.to_string_lossy(),
                        "authority",
                        findings,
                    )
                })?;
        // This is the same canonical compiled document used by activation.
        let mut body = document.clone();
        body.as_object_mut()
            .expect("authority object")
            .remove("apiVersion");
        body.as_object_mut()
            .expect("authority object")
            .remove("kind");
        let canonical = canonicalize_json(&body).context("canonicalizing target authority")?;
        let ceilings = compiled.model["requirements"].as_array().context("compiled definitions")?.iter().map(|definition| json!({"requirement":definition["uri"],"grantCeiling":definition["grantCeiling"],"purposes":definition["purposes"],"subjects":definition["subjectRoles"],"representations":definition["representations"],"subjectBinding":definition["subjectBinding"]})).collect::<Vec<_>>();
        let effective = canonicalize_json(
            &json!({"ceilings":ceilings,"accessProfiles":document["accessProfiles"]}),
        )
        .context("canonicalizing effective grants")?;
        authority = json!({"target":target.id,"effectiveGrantDigest":registry_platform_config::sha256_uri(&effective),"authorityRevision":format!("sha256:{}", hex::encode(domain_separated_sha256(b"registry.evidence.target-authority/v1\0", &canonical))),"digest":registry_platform_config::sha256_uri(&canonical),"accessProfiles":document["accessProfiles"],"effectiveCeilings":project.assertion_definitions.iter().map(|(id,d)| (id.as_str(),json!({"grantCeiling":d.grant_ceiling,"purpose":d.purpose,"subjects":d.subjects,"representations":d.representations,"subjectBinding":d.subject_binding}))).collect::<BTreeMap<_,_>>()});
    }
    let definitions = project.assertion_definitions.iter().map(|(id, definition)| json!({"id":id,"label":definition.label,"description":definition.description,"question":definition.question,"requirement":definition.semantics.requirement,"acquisition":definition.acquisition,"derive":definition.derive,"outputs":definition.outputs,"grantCeiling":definition.grant_ceiling,"representations":definition.representations,"subjectBinding":definition.subject_binding,"validitySeconds":definition.validity_seconds})).collect::<Vec<_>>();
    Ok(Checked {
        report: crate::report::success(
            command,
            "complete",
            json!({"project":root,"target":target.as_deref(),"proof":"authoring","diagnostics":diagnostics.to_json_value(),"projectPresentation":{"id":project.id,"label":project.label,"description":project.description},"selectorProfiles":project.selector_profiles,"capabilityCeilings":{"maximumHolderBoundBatchSize":project.maximum_holder_bound_batch_size},"assertionDefinitions":definitions,"sources":project.sources.iter().map(|(id,source)| json!({"id":id,"label":source.label,"description":source.description,"pack":source.pack,"route":source.route,"connection":source.connection,"inputs":source.inputs,"acquisitionPosture":source.acquisition_posture,"facts":compiled.source_facts.get(id.as_str())})).collect::<Vec<_>>(),"functions":compiled.functions,"authority":authority,"offline":true,"networkAccess":false,"secretResolution":false,"fixtureExecution":false}),
        ),
        diagnostics,
    })
}

#[derive(Debug, clap::Args)]
pub(crate) struct TypesArgs {
    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command needs an editable project holding evidence.yaml.
    #[arg(value_name = "PROJECT", default_value = ".")]
    pub(crate) project: PathBuf,
    /// Output language for generated declarations.
    #[arg(long, value_enum)]
    pub(crate) language: TypeLanguage,
    /// New generated declaration file to create.
    #[arg(long)]
    pub(crate) output: PathBuf,
}
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum TypeLanguage {
    Typescript,
    Python,
}
pub(crate) fn generate_types(
    args: TypesArgs,
    format: crate::OutputFormat,
) -> Result<std::process::ExitCode> {
    let (project, compiled) = compile(&args.project)?;
    let text = match args.language {
        TypeLanguage::Typescript => project::typescript(&project, &compiled),
        TypeLanguage::Python => project::python(&project, &compiled),
    };
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .context("creating generated type file; output must not exist")?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    if format == crate::OutputFormat::Json {
        crate::report::print(&crate::report::success(
            "types",
            "generated",
            json!({"project":args.project,"output":args.output}),
        ))?;
    } else {
        println!("Generated {}", args.output.display());
    }
    Ok(std::process::ExitCode::SUCCESS)
}

pub(crate) fn runtime_source_connections(
    source_root: &Path,
    target: &EvidenceTarget,
) -> Result<Value> {
    let connections = target
        .connections
        .iter()
        .map(|(id, connection)| {
            let outbound_tls = scoped_outbound_tls(
                target.outbound_tls.as_ref(),
                connection
                    .endpoints
                    .values()
                    .filter_map(|endpoint| endpoint.tls_trust_profile.as_deref()),
            );
            Ok((
                id.to_string(),
                connection.runtime_value(id, outbound_tls.as_ref())?,
            ))
        })
        .collect::<Result<serde_json::Map<_, _>>>()?;
    let mut connections = Value::Object(connections);
    for connection in connections
        .as_object_mut()
        .expect("source connections project as a mapping")
        .values_mut()
    {
        if let Some(outbound_tls) = connection.get_mut("outboundTls") {
            crate::build::rebase_outbound_tls(source_root, outbound_tls)?;
        }
    }
    Ok(connections)
}

/// Project the target's reviewed trust inventory into one runtime trust scope.
///
/// A reference that is absent from the inventory deliberately remains absent
/// from the projection. The endpoint or root authentication still names it,
/// so the runtime reports the existing unbound-profile refusal instead of the
/// tooling silently manufacturing trust.
fn scoped_outbound_tls<'a>(
    outbound_tls: Option<&TargetOutboundTls>,
    referenced_profiles: impl IntoIterator<Item = &'a str>,
) -> Option<TargetOutboundTls> {
    let outbound_tls = outbound_tls?;
    let referenced_profiles = referenced_profiles.into_iter().collect::<BTreeSet<_>>();
    let trust_profiles = outbound_tls
        .trust_profiles
        .iter()
        .filter(|(id, _)| referenced_profiles.contains(id.as_str()))
        .map(|(id, profile)| (id.clone(), profile.clone()))
        .collect();
    Some(TargetOutboundTls {
        system_roots: outbound_tls.system_roots,
        trust_profiles,
    })
}

/// Root owns issuer-key TLS. Profiles referenced only by source connections
/// belong to those connections. A profile referenced nowhere remains at root
/// so the runtime's existing unused-profile check still refuses the target.
pub(crate) fn root_runtime_outbound_tls(target: &EvidenceTarget) -> Option<TargetOutboundTls> {
    let outbound_tls = target.outbound_tls.as_ref()?;
    let referenced_profiles = target
        .authentication
        .oidc
        .tls_trust_profile
        .as_deref()
        .into_iter()
        .chain(
            target
                .connections
                .values()
                .flat_map(|connection| connection.endpoints.values())
                .filter_map(|endpoint| endpoint.tls_trust_profile.as_deref()),
        )
        .collect::<BTreeSet<_>>();
    let root_profiles = target
        .authentication
        .oidc
        .tls_trust_profile
        .as_deref()
        .into_iter()
        .chain(
            outbound_tls
                .trust_profiles
                .keys()
                .map(|id| id.as_str())
                .filter(|id| !referenced_profiles.contains(id)),
        );
    scoped_outbound_tls(Some(outbound_tls), root_profiles)
}

pub(crate) fn read_target_documents(path: &Path) -> Result<crate::build::TargetDocuments> {
    let path = crate::target::target_path(path);
    let source_root = target_directory(&path).canonicalize()?;
    let bytes = authored::read_authored_file(&path, "Evidence target")?;
    let target =
        registry_evidence_authoring::target::read_target(&path.to_string_lossy(), &bytes)?.value;
    let authority_path = safe_asset(&source_root, &target.authority)?;
    // Retain authority with the other target inputs before delegated tools run.
    let authority = authored::read_authored_file(&authority_path, "target authority")?;
    let stage = tempfile::Builder::new()
        .prefix("evidencectl-target-")
        .tempdir()?;
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(stage.path(), std::fs::Permissions::from_mode(0o700))?;
    let root = stage.path().canonicalize()?;
    let key = target.signer.public_jwk_file();
    let assurance_profile = target
        .assurance_profile
        .unwrap_or(TargetAssuranceProfile::Local);
    if assurance_profile == TargetAssuranceProfile::Local
        && !source_root.join(key).exists()
        && key == ".generated/secrets/signing-p256-public.jwk.json"
    {
        let default_signer = matches!(
            &target.signer,
            TargetSigner::LocalJwk { private_key_ref, .. }
                if private_key_ref.as_str() == "secret:file/signing-p256-private-jwk"
        );
        let default_file_root = target
            .secret_providers
            .file
            .as_ref()
            .is_some_and(|provider| provider.root == ".generated/secrets");
        if !default_signer || !default_file_root {
            return Err(crate::build::TargetDocumentDiagnostic {
                code: "evidence.target.signing-key-missing",
                path: format!("{}:/signer/publicJwkFile", path.display()),
                message: "automatic local signing keys require signer.type local-jwk, signer.privateKeyRef secret:file/signing-p256-private-jwk and secretProviders.file.root .generated/secrets; provide the matching public JWK for any explicit alternative binding".to_owned(),
            }.into());
        }
        crate::authoring::ensure_local_project_key_material(&source_root)?;
    }
    let key_bytes =
        authored::read_authored_file(&safe_asset(&source_root, key)?, "target public signing key")?;
    let public = registry_platform_crypto::PublicJwk::parse(
        std::str::from_utf8(&key_bytes).context("target public signing key must be UTF-8")?,
    )
    .context("target public signing key must be a valid public JWK")?;
    let thumbprint = public
        .jkt()
        .context("computing target public signing key thumbprint")?;
    if public.kid.as_deref() != Some(thumbprint.as_str()) {
        bail!("target public signing JWK kid must equal its RFC 7638 thumbprint");
    }
    let key_path = format!("public-keys/{thumbprint}.jwk.json");
    std::fs::create_dir(root.join("public-keys"))?;
    std::fs::write(root.join(&key_path), key_bytes)?;
    let mut governance = crate::authoring::local_target_governance(&key_path)?;
    governance["apiVersion"] = json!(crate::evidence_binary::EVIDENCE_BUNDLE_API_VERSION);
    governance["kind"] = json!(crate::evidence_binary::EVIDENCE_BUNDLE_KIND);
    governance["assuranceProfile"] = serde_json::to_value(assurance_profile)?;
    let (service, issuer) = target.service.governed_values()?;
    governance["service"] = service;
    governance["issuer"] = issuer;
    governance["authentication"] = target.authentication.governed_value()?;
    governance["subjectBinding"] = serde_json::to_value(&target.subject_binding)?;
    if let Some(signing) = &target.signing {
        governance["signing"]["maximumAssertionValiditySeconds"] =
            json!(signing.maximum_assertion_validity_seconds);
    }
    governance["audit"] = target.audit.governed_value();
    governance["rateLimits"] = target.rate_limits.governed_value()?;
    if let Some(formats) = &target.response_formats {
        governance["responseFormats"] = serde_json::to_value(formats)?;
    }
    if let Some(publication) = &target.publication {
        governance["publication"] = serde_json::to_value(publication)?;
    } else {
        governance
            .as_object_mut()
            .expect("governance object")
            .remove("publication");
    }
    let connections = target
        .connections
        .iter()
        .map(|(id, connection)| Ok((id.to_string(), connection.governed_value()?)))
        .collect::<Result<serde_json::Map<_, _>>>()?;
    governance["sourceConnections"] = json!(connections);
    governance["authorityProfiles"] = json!({});
    let mut runtime = json!({"apiVersion":crate::evidence_binary::EVIDENCE_RUNTIME_API_VERSION,"kind":crate::evidence_binary::EVIDENCE_RUNTIME_KIND,"package":&target.package,"listener":target.listener.runtime_value()?,"secretProviders":&target.secret_providers,"signer":target.signer.runtime_value()?,"audit":target.audit.runtime_value(),"authority":{"root":source_root.join(".generated/authority"),"target":&target.id}});
    for pointer in ["/package/root", "/secretProviders/file/root", "/audit/path"] {
        if let Some(value) = runtime.pointer_mut(pointer) {
            if let Some(path) = value.as_str() {
                if Path::new(path).is_relative() {
                    *value = json!(source_root.join(path));
                }
            }
        }
    }
    runtime["sourceConnections"] = runtime_source_connections(&source_root, &target)?;
    if let Some(source_acquisition) = &target.source_acquisition {
        runtime["sourceAcquisition"] = source_acquisition.runtime_value()?;
    }
    runtime["outboundTls"] = root_runtime_outbound_tls(&target)
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| json!({"systemRoots":true,"trustProfiles":{}}));
    crate::build::rebase_outbound_tls(&source_root, &mut runtime["outboundTls"])?;
    if let Some(extracts) = &target.extracts {
        let mut extracts = serde_json::to_value(extracts)?;
        let bindings = extracts
            .as_object_mut()
            .context("target extracts must be named bindings")?;
        for binding in bindings.values_mut() {
            let path = binding
                .get_mut("path")
                .context("extract binding requires path")?;
            let value = path.as_str().context("extract binding path must be text")?;
            if Path::new(value).is_relative() {
                *path = json!(source_root.join(value));
            }
        }
        runtime["sourceExtracts"] = extracts;
    }
    Ok(crate::build::TargetDocuments {
        root,
        runtime: authored::to_indented_yaml(&runtime)?.into_bytes(),
        governed_bundle: governance,
        normalized_target: Some(target),
        authority_path,
        authority,
        source_path: Some(path),
        _stage: Some(stage),
    })
}

pub(crate) fn compiled_authority(
    project: &EvidenceProject,
    target: &registry_evidence_authoring::target::EvidenceTarget,
    path: &Path,
    bytes: &[u8],
) -> Result<Value> {
    let decoded = registry_evidence_authoring::target::read_authority(
        &path.to_string_lossy(),
        bytes,
        project,
    )?;
    if decoded.value.target != target.id {
        bail!("authority must name the selected target");
    }
    registry_evidence_authoring::target::compile_authority(&decoded.value, project).map_err(
        |findings| {
            authored::file_findings_report(&path.to_string_lossy(), "authority", findings).into()
        },
    )
}

pub(crate) fn target_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
#[test]
fn invalid_asset_paths_are_refused_before_filesystem_lookup() {
    let temporary = tempfile::tempdir().unwrap();
    let missing_root = temporary.path().join("not-created");
    for relative in [
        "/outside.rhai",
        "missing/../outside.rhai",
        "functions/./answer.rhai",
        "functions//answer.rhai",
        "functions\\answer.rhai",
    ] {
        let error = safe_asset(&missing_root, relative).unwrap_err();
        assert_eq!(
            error.to_string(),
            "artifact must be a project-relative path without traversal"
        );
    }
    assert!(!missing_root.exists());
}

#[cfg(test)]
#[test]
fn relative_target_filename_uses_the_current_directory() {
    assert_eq!(
        target_directory(Path::new("local-target.yaml")),
        Path::new(".")
    );
    assert_eq!(
        target_directory(Path::new("targets/local.yaml")),
        Path::new("targets")
    );
}

#[cfg(test)]
fn projected_runtime_with_tls(
    oidc_profile: Option<&str>,
    connections: &[(&str, &str)],
    inventory: &[&str],
) -> Value {
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/examples/standalone");
    let root = tempfile::tempdir().expect("target root");
    let mut target =
        std::fs::read_to_string(example.join("local-target.yaml")).expect("standalone target");
    target = target.replace(
        "connections:\n  synthetic-register:\n    endpoints:\n      register:\n        origin: http://127.0.0.1:8081\n        authentication:\n          type: static-authorization\n          tokenRef: secret:file/synthetic-source-token\n",
        "connections:\n",
    );
    if let Some(profile) = oidc_profile {
        target = target.replace(
            "    issuer: http://127.0.0.1:8082\n",
            &format!("    issuer: https://issuer.invalid\n    tlsTrustProfile: {profile}\n"),
        );
        target = target.replace(
            "      uri: http://127.0.0.1:8082/oauth2/jwks\n",
            "      uri: https://issuer.invalid/oauth2/jwks\n",
        );
    }
    let mut authored_connections = String::new();
    for (connection, profile) in connections {
        authored_connections.push_str(&format!(
            "  {connection}:\n    endpoints:\n      register:\n        origin: https://{connection}.invalid\n        authentication:\n          type: static-authorization\n          tokenRef: secret:file/{connection}-token\n        tlsTrustProfile: {profile}\n"
        ));
    }
    target = target.replace(
        "connections:\nsecretProviders:\n",
        &format!("connections:\n{authored_connections}secretProviders:\n"),
    );
    let mut trust_profiles = String::new();
    for profile in inventory {
        let file = format!("{profile}.pem");
        std::fs::write(root.path().join(&file), "synthetic fixture CA").expect("fixture CA file");
        trust_profiles.push_str(&format!("    {profile}:\n      caBundleFile: {file}\n"));
    }
    target.push_str(&format!(
        "outboundTls:\n  systemRoots: true\n  trustProfiles:\n{trust_profiles}"
    ));
    std::fs::write(root.path().join("local-target.yaml"), target).expect("target");
    std::fs::copy(
        example.join("dev-authority.yaml"),
        root.path().join("dev-authority.yaml"),
    )
    .expect("authority");
    let documents =
        read_target_documents(&root.path().join("local-target.yaml")).expect("target documents");
    crate::build::runtime_value(&documents.runtime).expect("runtime YAML")
}

#[cfg(test)]
fn profile_names(value: &Value) -> Vec<&str> {
    value
        .get("trustProfiles")
        .and_then(Value::as_object)
        .expect("trust profile map")
        .keys()
        .map(String::as_str)
        .collect()
}

#[cfg(test)]
#[test]
fn source_only_private_ca_is_scoped_to_its_connection() {
    let runtime =
        projected_runtime_with_tls(None, &[("synthetic-register", "source-ca")], &["source-ca"]);
    assert!(profile_names(&runtime["outboundTls"]).is_empty());
    assert_eq!(
        profile_names(&runtime["sourceConnections"]["synthetic-register"]["outboundTls"]),
        vec!["source-ca"]
    );
}

#[cfg(test)]
#[test]
fn oidc_and_disjoint_source_connections_receive_only_their_own_cas() {
    let runtime = projected_runtime_with_tls(
        Some("oidc-ca"),
        &[
            ("synthetic-register", "source-a-ca"),
            ("second-register", "source-b-ca"),
        ],
        &["oidc-ca", "source-a-ca", "source-b-ca"],
    );
    assert_eq!(profile_names(&runtime["outboundTls"]), vec!["oidc-ca"]);
    assert_eq!(
        profile_names(&runtime["sourceConnections"]["synthetic-register"]["outboundTls"]),
        vec!["source-a-ca"]
    );
    assert_eq!(
        profile_names(&runtime["sourceConnections"]["second-register"]["outboundTls"]),
        vec!["source-b-ca"]
    );
}

#[cfg(test)]
#[test]
fn unused_ca_inventory_remains_visible_to_the_runtime_refusal() {
    let runtime = projected_runtime_with_tls(
        None,
        &[("synthetic-register", "source-ca")],
        &["source-ca", "unused-ca"],
    );
    assert_eq!(profile_names(&runtime["outboundTls"]), vec!["unused-ca"]);
    assert_eq!(
        profile_names(&runtime["sourceConnections"]["synthetic-register"]["outboundTls"]),
        vec!["source-ca"]
    );
}

#[cfg(test)]
#[test]
fn missing_source_ca_reference_remains_unbound_for_runtime_refusal() {
    let runtime = projected_runtime_with_tls(
        Some("oidc-ca"),
        &[("synthetic-register", "missing-ca")],
        &["oidc-ca"],
    );
    assert_eq!(
        runtime["sourceConnections"]["synthetic-register"]["endpoints"][0]["tlsTrustProfile"],
        "missing-ca"
    );
    assert!(
        profile_names(&runtime["sourceConnections"]["synthetic-register"]["outboundTls"])
            .is_empty()
    );
}

#[cfg(test)]
#[test]
fn filesystem_pack_closure_reaches_the_checked_compiler_without_conversion() {
    let root = tempfile::tempdir().unwrap();
    let pack_root = root.path().join("adapter-packs/synthetic-register");
    std::fs::create_dir_all(pack_root.join("schemas")).unwrap();
    let inputs = serde_json::to_vec(&json!({
        "type":"object","additionalProperties":false,"required":["recordId"],
        "properties":{"recordId":{"type":"string"}}
    }))
    .unwrap();
    let facts = serde_json::to_vec(&json!({
        "type":"object","additionalProperties":false,"required":["matched"],
        "properties":{"matched":{"type":"boolean"}}
    }))
    .unwrap();
    let pack = serde_json::to_vec(&json!({
        "apiVersion":registry_adapter_core::ADAPTER_PACK_API_VERSION,
        "kind":registry_adapter_core::ADAPTER_PACK_KIND,
        "id":"synthetic-register","version":"0.1.0",
        "testedVersions":[],
        "sourceRoutes":[{"id":"evidence-record","evidence":{
            "inputsSchema":{"path":"schemas/inputs.json","digest":registry_platform_config::sha256_uri(&inputs)},
            "factsSchema":{"path":"schemas/facts.json","digest":registry_platform_config::sha256_uri(&facts)}
        }}]
    }))
    .unwrap();
    std::fs::write(pack_root.join("pack.yaml"), pack).unwrap();
    std::fs::write(pack_root.join("schemas/inputs.json"), &inputs).unwrap();
    std::fs::write(pack_root.join("schemas/facts.json"), &facts).unwrap();
    let project: EvidenceProject = serde_json::from_value(json!({
        "id":"pack-bridge",
        "selectorProfiles":{"record-by-id":{"maximumAggregateBytes":64,"fields":{"record-id":{"type":"string","minimumBytes":1,"maximumBytes":64}}}},
        "functions":[{"id":"derive-record","interface":"assertion-derive/v1","source":"functions/derive.rhai"}],
        "sources":{"record":{"pack":{"id":"synthetic-register","version":"0.1.0"},"route":"evidence-record","connection":"register","inputs":{"recordId":{"selector":{"role":"subject","profile":"record-by-id","field":"record-id"}}},"acquisitionPosture":"record-transformed"}},
        "assertionDefinitions":{"record-match":{"question":"Does the record match?","semantics":{"requirement":"urn:example:requirement:record","kind":"criterion","evidenceType":"urn:example:evidence:record","referenceFrameworks":["urn:example:framework:record"]},"purpose":"record-check","grantCeiling":{"authorities":["organizational"],"actorKinds":["service"],"valueOrigins":["request"],"audiences":["urn:example:audience:consumer"]},"subjects":[{"role":"subject","selectors":["record-by-id"]}],"acquisition":{"source":"record"},"derive":{"function":"derive-record"},"outputs":{"matched":{"concept":"urn:example:concept:matched","type":"boolean"}},"validitySeconds":300,"subjectBinding":"audience-scoped","representations":["signed-jws"]}}
    }))
    .unwrap();
    let scripts = BTreeMap::from([(
        "functions/derive.rhai".to_owned(),
        "fn derive(facts, selectors, context) { [#{output: \"matched\", value: facts.matched}] }"
            .to_owned(),
    )]);
    let routes = read_pack_routes(root.path(), &project).unwrap();
    compile::compile_with_pack_routes(&project, &scripts, &routes)
        .expect("exact captured pack route compiles");

    std::fs::write(pack_root.join("schemas/facts.json"), b"{}").unwrap();
    let changed = read_pack_routes(root.path(), &project).unwrap();
    assert!(compile::compile_with_pack_routes(&project, &scripts, &changed).is_err());
}
