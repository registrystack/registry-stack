//! Filesystem adapter for the one normalized Evidence authoring compiler.
use crate::{authored, check::Checked};
use anyhow::{bail, Context as _, Result};
use registry_evidence_authoring::{
    compile::{self, CompiledProject},
    project::{self, EvidenceProject},
    target::TargetAssuranceProfile,
};
use registry_platform_crypto::{canonicalize_json, domain_separated_sha256};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(crate) fn read(root: &Path) -> Result<(EvidenceProject, BTreeMap<String, String>)> {
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
            let root = registry_platform_yaml::Reader::new(project::PROJECT_FILE)
                .scan(&bytes)
                .expect("the project was decoded")
                .expect("project document");
            authored::node_findings_report(
                project::PROJECT_FILE,
                "project",
                &root,
                vec![registry_evidence_authoring::Finding {
                    code: "asset-path",
                    field: registry_evidence_authoring::FieldPath::root()
                        .key("functions")
                        .index(index)
                        .key("source"),
                    message: "Function source must name a plain asset inside this project"
                        .to_owned(),
                }],
            )
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
        .sources
        .values()
        .filter_map(|source| source.request.get("statement").and_then(Value::as_str))
        .chain(
            decoded
                .value
                .assertion_definitions
                .values()
                .flat_map(|definition| {
                    definition
                        .outputs
                        .values()
                        .filter_map(|output| output.schema.as_deref())
                }),
        );
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
                        .filter_map(|field| field.get("codelist").and_then(Value::as_str))
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
    Ok((decoded.value, scripts))
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
        let metadata = std::fs::symlink_metadata(&path).context("inspecting project asset")?;
        if metadata.file_type().is_symlink() {
            bail!("project assets cannot traverse symbolic links");
        }
    }
    Ok(path)
}
pub(crate) fn compile(root: &Path) -> Result<(EvidenceProject, CompiledProject)> {
    let (project, scripts) = read(root)?;
    let compiled = compile::compile(&project, &scripts).map_err(|findings| {
        authored::file_findings_report(project::PROJECT_FILE, "project", findings)
    })?;
    Ok((project, compiled))
}
pub(crate) fn inspect(root: &Path, target: Option<&Path>, command: &str) -> Result<Checked> {
    let target = target.map(crate::target::target_path);
    let snapshot = crate::project_snapshot::capture_project(root)?;
    let (project, mut compiled) = compile(snapshot.root())
        .map_err(|error| authored::project_refusal(error, snapshot.root(), root))?;
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
    let definitions = project.assertion_definitions.iter().map(|(id, definition)| json!({"id":id,"label":definition.label,"description":definition.description,"question":definition.question,"requirement":definition.semantics.requirement,"acquisition":definition.acquisition,"derive":definition.derive,"outputs":definition.outputs,"grantCeiling":definition.grant_ceiling,"representations":definition.representations,"subjectBinding":definition.subject_binding})).collect::<Vec<_>>();
    Ok(Checked {
        report: crate::report::success(
            command,
            "complete",
            json!({"project":root,"target":target.as_deref(),"proof":"authoring","diagnostics":[],"projectPresentation":{"id":project.id,"label":project.label,"description":project.description},"selectorProfiles":project.selector_profiles,"capabilityCeilings":{"acquisitionCapabilities":project.acquisition_capabilities,"maximumHolderBoundBatchSize":project.maximum_holder_bound_batch_size},"assertionDefinitions":definitions,"sources":project.sources.iter().map(|(id,source)| json!({"id":id,"label":source.label,"description":source.description,"type":source.source_type,"connection":source.connection,"facts":source.facts,"response":source.response,"prepare":source.prepare,"resolvedPreparation":{"generated":source.prepare.is_none(),"script":compiled.model["sources"][id.as_str()]["request"]["prepareScript"],"limits":compiled.model["sources"][id.as_str()]["request"]["preparationLimits"]},"extract":source.extract,"limits":source.limits})).collect::<Vec<_>>(),"functions":compiled.functions,"authority":authority,"offline":true,"networkAccess":false,"secretResolution":false,"fixtureExecution":false}),
        ),
        diagnostics: registry_platform_yaml::Report::new(Vec::new()),
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

pub(crate) fn read_target_documents(path: &Path) -> Result<crate::build::TargetDocuments> {
    let path = crate::target::target_path(path);
    let source_root = target_directory(&path).canonicalize()?;
    let bytes = authored::read_authored_file(&path, "Evidence target")?;
    let target =
        registry_evidence_authoring::target::read_target(&path.to_string_lossy(), &bytes)?.value;
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
        let generated = source_root.join(".generated");
        if !generated.exists() {
            std::fs::create_dir(&generated)?;
            std::fs::set_permissions(&generated, std::fs::Permissions::from_mode(0o700))?;
        }
        crate::keygen::ensure_local_key_material(&generated.join("secrets"))?;
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
        .map(|(id, connection)| {
            Ok((id.to_string(), connection.governed_value()?))
        })
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
    runtime["acquisitionCapabilities"] = json!(target.acquisition_capabilities);
    runtime["outboundTls"] = target
        .outbound_tls
        .as_ref()
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
        source_root: Some(source_root),
        source_path: Some(path),
        _stage: Some(stage),
    })
}

pub(crate) fn compiled_authority(
    project: &EvidenceProject,
    target: &registry_evidence_authoring::target::EvidenceTarget,
    root: &Path,
) -> Result<Value> {
    let path = safe_asset(root, &target.authority)?;
    let bytes = authored::read_authored_file(&path, "target authority")?;
    let decoded = registry_evidence_authoring::target::read_authority(
        &path.to_string_lossy(),
        &bytes,
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
