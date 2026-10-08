// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use registry_manifest_cli::{
    check_metadata_file, check_profiles, manifest_digest, metadata_error_diagnostics, ReadManifest,
    CTL_REPORT_API_VERSION, CTL_REPORT_KIND,
};
use registry_manifest_core::{
    canonicalize_json, compile_manifest, render_base_dcat, render_breg_dcat_ap, render_catalog,
    render_cpsv_ap, render_dataset_policy_document, render_dcat_profile,
    render_entity_schema_draft_2020_12, render_evidence_offering, render_evidence_offerings,
    render_form_schema_draft_2020_12, render_ogc_records_items, render_policy_collection,
    render_shacl, sha256_uri, CompiledMetadata,
};
use registry_platform_yaml::{Diagnostic, Report};
use serde::Serialize;

/// The command line was incomplete, conflicting, or unsupported.
const USAGE_EXIT: u8 = 2;
/// A file or directory the command reads could not be read.
const UNAVAILABLE_EXIT: u8 = 3;
const USAGE_CODE: &str = "manifest.usage.invalid-arguments";
const USAGE_ACTION: &str =
    "Run registry-manifest --help, or the command with --help, and retry with the documented \
     arguments.";

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    ExitCode::from(run(&args))
}

/// Why a command stopped.
enum Failure {
    /// The arguments do not match the command's synopsis. The message never
    /// repeats an argument.
    Usage(&'static str),
    /// A refusal from rendering or publication.
    Refused(String),
    /// Findings from reading the manifest.
    Diagnostics {
        report: Report,
        exit: u8,
        sentence: &'static str,
    },
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::Refused(message)
    }
}

fn run(args: &[String]) -> u8 {
    let command = args.first().map(String::as_str);
    if matches!(
        command,
        Some("validate" | "validate-profiles" | "render" | "publish")
    ) && args[1..].iter().any(|arg| arg == "--help" || arg == "-h")
    {
        println!("{}", usage());
        return 0;
    }
    let result = match command {
        Some("--version") => {
            println!(
                "registry-manifest {}",
                registry_platform_buildinfo::DISPLAY_VERSION
            );
            Ok(0)
        }
        Some("--help" | "-h" | "help") => {
            println!("{}", usage());
            Ok(0)
        }
        Some("validate") => validate_command(&args[1..]),
        Some("validate-profiles") => validate_profiles_command(&args[1..]),
        Some("render") => render_command(&args[1..]).map(|()| 0),
        Some("publish") => publish_command(&args[1..]).map(|()| 0),
        Some(_) => Err(Failure::Usage(
            "the command is not one registry-manifest runs",
        )),
        None => Err(Failure::Usage("registry-manifest needs a command")),
    };
    match result {
        Ok(exit) => exit,
        Err(Failure::Usage(message)) => {
            let diagnostic = Diagnostic::error(USAGE_CODE, "", message, USAGE_ACTION);
            if machine_readable(args) {
                let mut report = Report::new(vec![diagnostic]);
                report.set_files_checked(0);
                write_report(&CtlReport::new("usage", USAGE_EXIT, &report));
            } else {
                eprint!("{}", diagnostic.render_human());
                eprintln!("{}", usage());
            }
            USAGE_EXIT
        }
        Err(Failure::Refused(message)) => {
            eprintln!("{message}");
            1
        }
        Err(Failure::Diagnostics {
            report,
            exit,
            sentence,
        }) => {
            eprintln!("{sentence}");
            eprint!("{}", report.render_human());
            exit
        }
    }
}

/// Whether a usage error is reported as JSON: `--format json` was asked of a
/// command whose `--format` selects the report format.
fn machine_readable(args: &[String]) -> bool {
    !matches!(args.first().map(String::as_str), Some("render" | "publish"))
        && args.iter().enumerate().any(|(index, arg)| {
            arg == "--format=json"
                || (arg == "--format" && args.get(index + 1).map(String::as_str) == Some("json"))
        })
}

/// The options `validate` and `validate-profiles` share.
struct CheckOptions {
    path: Option<String>,
    json: bool,
    deny_warnings: bool,
}

impl CheckOptions {
    fn parse(args: &[String]) -> Result<Self, Failure> {
        let mut options = Self {
            path: None,
            json: false,
            deny_warnings: false,
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let format = match arg.as_str() {
                "--deny-warnings" => {
                    options.deny_warnings = true;
                    continue;
                }
                "--format" => args.next().map(String::as_str),
                other => match other.strip_prefix("--format=") {
                    Some(value) => Some(value),
                    None if other.starts_with('-') => {
                        return Err(Failure::Usage("an option is not one this command accepts"))
                    }
                    None if options.path.is_some() => {
                        return Err(Failure::Usage("this command takes one path"))
                    }
                    None => {
                        options.path = Some(other.to_owned());
                        continue;
                    }
                },
            };
            options.json = match format {
                Some("json") => true,
                Some("human") => false,
                _ => return Err(Failure::Usage("--format accepts human or json")),
            };
        }
        Ok(options)
    }
}

/// The exit code for a finished check.
fn check_exit(report: &Report, unavailable: bool, deny_warnings: bool) -> u8 {
    if unavailable {
        UNAVAILABLE_EXIT
    } else if report.has_errors() || (deny_warnings && report.warning_count() > 0) {
        1
    } else {
        0
    }
}

/// The report `validate --format json` and `validate-profiles --format
/// json` write (`manifest/ctl-report`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CtlReport<'a> {
    ok: bool,
    command: &'a str,
    status: &'static str,
    api_version: &'static str,
    kind: &'static str,
    files_checked: usize,
    errors: usize,
    warnings: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_manifest_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profiles: Option<usize>,
    diagnostics: &'a [Diagnostic],
}

impl<'a> CtlReport<'a> {
    fn new(command: &'a str, exit: u8, report: &'a Report) -> Self {
        Self {
            ok: exit == 0,
            command,
            status: match exit {
                0 => "complete",
                USAGE_EXIT => "usage-error",
                UNAVAILABLE_EXIT => "operational-failure",
                _ => "domain-refusal",
            },
            api_version: CTL_REPORT_API_VERSION,
            kind: CTL_REPORT_KIND,
            files_checked: report.files_checked().unwrap_or(0),
            errors: report.error_count(),
            warnings: report.warning_count(),
            source_manifest_digest: None,
            profiles: None,
            diagnostics: report.diagnostics(),
        }
    }
}

fn write_report(report: &CtlReport<'_>) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{json}"),
        Err(_) => eprintln!("registry-manifest could not write its JSON report."),
    }
}

/// `validate`: check one metadata manifest offline (CFG-CHECK-1).
fn validate_command(args: &[String]) -> Result<u8, Failure> {
    let options = CheckOptions::parse(args)?;
    let path = options.path.ok_or(Failure::Usage(
        "validate needs the path of a metadata manifest",
    ))?;
    let check = check_metadata_file(Path::new(&path));
    let mut report = check.report;
    let digest = match check.manifest.as_ref().map(manifest_digest) {
        Some(Ok(digest)) => Some(digest),
        Some(Err(diagnostic)) => {
            report.push(*diagnostic);
            None
        }
        None => None,
    };
    let exit = check_exit(&report, check.unavailable, options.deny_warnings);
    if options.json {
        let mut written = CtlReport::new("validate", exit, &report);
        written.source_manifest_digest = digest.as_deref();
        write_report(&written);
    } else if exit == 0 {
        println!("metadata manifest valid: {path}");
        if let Some(digest) = &digest {
            println!("source_manifest_digest: {digest}");
        }
        print!("{}", report.render_human());
    } else {
        eprintln!(
            "{}",
            if check.unavailable {
                "registry-manifest validate could not read the manifest."
            } else {
                "registry-manifest validate refused the manifest."
            }
        );
        eprint!("{}", report.render_human());
    }
    Ok(exit)
}

/// `validate-profiles`: check every profile descriptor and the fixtures it
/// lists offline (CFG-CHECK-1).
fn validate_profiles_command(args: &[String]) -> Result<u8, Failure> {
    let options = CheckOptions::parse(args)?;
    let root = PathBuf::from(options.path.as_deref().unwrap_or("profiles"));
    let check = check_profiles(&root);
    let exit = check_exit(&check.report, check.unavailable, options.deny_warnings);
    if options.json {
        let mut written = CtlReport::new("validate-profiles", exit, &check.report);
        written.profiles = Some(check.profiles);
        write_report(&written);
    } else if exit == 0 {
        println!(
            "validated {} profile descriptors and fixtures",
            check.profiles
        );
        print!("{}", check.report.render_human());
    } else {
        eprintln!(
            "{}",
            if check.unavailable {
                "registry-manifest validate-profiles could not read every profile descriptor \
                 and fixture."
            } else {
                "registry-manifest validate-profiles refused a profile descriptor or fixture."
            }
        );
        eprint!("{}", check.report.render_human());
    }
    Ok(exit)
}

/// The manifest at `path`, read and validated, for `render` and `publish`.
/// Warnings go to standard error, so standard output carries only the
/// command's own output.
fn load_manifest(path: &str, sentences: Sentences) -> Result<ReadManifest, Failure> {
    let check = check_metadata_file(Path::new(path));
    let exit = check_exit(&check.report, check.unavailable, false);
    match check.manifest {
        Some(read) if exit == 0 => {
            if check.report.warning_count() > 0 {
                eprint!("{}", check.report.render_human());
            }
            Ok(read)
        }
        _ => Err(Failure::Diagnostics {
            report: check.report,
            exit,
            sentence: if check.unavailable {
                sentences.unreadable
            } else {
                sentences.refused
            },
        }),
    }
}

/// What `render` or `publish` says before the findings that stopped it.
#[derive(Clone, Copy)]
struct Sentences {
    refused: &'static str,
    unreadable: &'static str,
}

const RENDER: Sentences = Sentences {
    refused: "registry-manifest render refused the manifest.",
    unreadable: "registry-manifest render could not read the manifest.",
};

const PUBLISH: Sentences = Sentences {
    refused: "registry-manifest publish refused the manifest.",
    unreadable: "registry-manifest publish could not read the manifest.",
};

/// The compiled manifest, or the rules compilation refused, placed in the
/// manifest.
fn compile(read: &ReadManifest, sentences: Sentences) -> Result<CompiledMetadata, Failure> {
    compile_manifest(&read.manifest).map_err(|error| {
        let mut report = Report::new(metadata_error_diagnostics(&read.document, error));
        report.set_files_checked(1);
        Failure::Diagnostics {
            report,
            exit: 1,
            sentence: sentences.refused,
        }
    })
}

fn render_command(args: &[String]) -> Result<(), Failure> {
    let manifest_path = args.first().ok_or(Failure::Usage(
        "render needs the path of a metadata manifest",
    ))?;
    let format = option_value(args, "--format").ok_or(Failure::Usage(
        "render needs --format and the artifact to render",
    ))?;
    let profile = option_value(args, "--profile");
    let read = load_manifest(manifest_path, RENDER)?;
    let compiled = compile(&read, RENDER)?;
    let value = match format.as_str() {
        "catalog" => render_catalog(&compiled),
        "evidence-offerings" => render_evidence_offerings(&compiled),
        "evidence-offering" => {
            let offering = option_value(args, "--offering")
                .ok_or_else(|| "evidence-offering render requires --offering <id>".to_string())?;
            render_evidence_offering(&compiled, &offering)
                .ok_or_else(|| format!("evidence offering not found: {offering}"))?
        }
        "policies" => render_policy_collection(&compiled),
        "policy" => {
            let dataset = option_value(args, "--dataset")
                .ok_or_else(|| "policy render requires --dataset <id>".to_string())?;
            render_dataset_policy_document(&compiled, &dataset)
                .ok_or_else(|| format!("dataset not found: {dataset}"))?
        }
        "dcat" => {
            if let Some(profile) = profile.as_deref() {
                ensure_dcat_profile_available(&compiled, profile)?;
                render_dcat_profile(&compiled, profile)
                    .ok_or_else(|| format!("unsupported DCAT profile: {profile}"))?
            } else {
                render_base_dcat(&compiled)
            }
        }
        "bregdcat-ap" => {
            ensure_dcat_profile_available(&compiled, "bregdcat-ap")?;
            render_breg_dcat_ap(&compiled)
        }
        "cpsv-ap" => {
            ensure_dcat_profile_available(&compiled, "cpsv-ap")?;
            render_cpsv_ap(&compiled)
        }
        "shacl" => render_shacl(&compiled),
        "json-schema" => {
            let dataset = option_value(args, "--dataset").ok_or_else(|| {
                "json-schema render requires --dataset <id> and --entity <name>".to_string()
            })?;
            let entity = option_value(args, "--entity").ok_or_else(|| {
                "json-schema render requires --dataset <id> and --entity <name>".to_string()
            })?;
            render_entity_schema_draft_2020_12(&compiled, &dataset, &entity)
                .ok_or_else(|| format!("entity not found: {dataset}/{entity}"))?
        }
        "form-json-schema" => {
            let form = option_value(args, "--form")
                .ok_or_else(|| "form-json-schema render requires --form <id>".to_string())?;
            render_form_schema_draft_2020_12(&compiled, &form)
                .ok_or_else(|| format!("form not found: {form}"))?
        }
        "ogc-records" => render_ogc_records_items(&compiled),
        other => return Err(format!("unsupported render format: {other}").into()),
    };
    Ok(print_json(&value)?)
}

fn publish_command(args: &[String]) -> Result<(), Failure> {
    let manifest_path = args.first().ok_or(Failure::Usage(
        "publish needs the path of a metadata manifest",
    ))?;
    let out = option_value(args, "--out").unwrap_or_else(|| "public/metadata".to_string());
    let read = load_manifest(manifest_path, PUBLISH)?;
    let compiled = compile(&read, PUBLISH)?;
    let source_digest = manifest_digest(&read).map_err(|diagnostic| {
        let mut report = Report::new(vec![*diagnostic]);
        report.set_files_checked(1);
        Failure::Diagnostics {
            report,
            exit: 1,
            sentence: PUBLISH.refused,
        }
    })?;
    let out = PathBuf::from(out);
    let out_root = prepare_publish_root(&out, "metadata.publish.out_not_directory")?;
    let site_root = option_value(args, "--site-root")
        .map(PathBuf::from)
        .map(|site_root| {
            prepare_publish_root(&site_root, "metadata.publish.site_root_not_directory")
        })
        .transpose()?;
    create_contained_dir_all(&out_root, "schema")?;
    create_contained_dir_all(&out_root, "forms")?;
    create_contained_dir_all(&out_root, "profiles")?;
    create_contained_dir_all(&out_root, "evidence-offerings")?;
    create_contained_dir_all(&out_root, "policies")?;
    create_contained_dir_all(&out_root, "ogc-records")?;

    copy_contained(&out_root, "metadata.yaml", manifest_path)?;
    write_json(&out_root, "catalog.json", &render_catalog(&compiled))?;
    write_json(
        &out_root,
        "evidence-offerings.json",
        &render_evidence_offerings(&compiled),
    )?;
    write_json(
        &out_root,
        "policies.jsonld",
        &render_policy_collection(&compiled),
    )?;
    write_json(&out_root, "dcat.jsonld", &render_base_dcat(&compiled))?;
    let mut dcat_profiles = Vec::new();
    let mut service_catalogues = Vec::new();
    for profile in &compiled.catalog().application_profiles {
        if profile.id == "cpsv-ap" {
            let service_catalogue = render_cpsv_ap(&compiled);
            write_json(&out_root, "cpsv-ap", &service_catalogue)?;
            write_json(&out_root, "cpsv-ap.jsonld", &service_catalogue)?;
            service_catalogues.push(serde_json::json!({
                "id": profile.id,
                "version": profile.version,
                "url": "/metadata/cpsv-ap.jsonld",
                "aliases": ["/metadata/cpsv-ap"],
                "media_type": "application/ld+json",
            }));
            continue;
        }
        if let Some(document) = render_dcat_profile(&compiled, &profile.id) {
            let filename = format!("dcat.{}.jsonld", profile.id);
            write_json(&out_root, PathBuf::from(&filename), &document)?;
            dcat_profiles.push(serde_json::json!({
                "id": profile.id,
                "version": profile.version,
                "url": format!("/metadata/{filename}"),
            }));
        }
    }
    write_json(&out_root, "shacl.jsonld", &render_shacl(&compiled))?;
    write_json(
        &out_root,
        "ogc-records/items.json",
        &render_ogc_records_items(&compiled),
    )?;

    let mut schemas = Vec::new();
    let mut policy_documents = Vec::new();
    for dataset in compiled.datasets() {
        let policy_filename = format!("{}.jsonld", dataset.dataset_id);
        let policy =
            render_dataset_policy_document(&compiled, &dataset.dataset_id).ok_or_else(|| {
                format!(
                    "metadata.publish.compiled_renderer_missing: dataset policy for {}",
                    dataset.dataset_id
                )
            })?;
        write_json(
            &out_root,
            PathBuf::from("policies").join(&policy_filename),
            &policy,
        )?;
        policy_documents.push(serde_json::json!({
            "dataset": dataset.dataset_id,
            "url": format!("/metadata/policies/{policy_filename}"),
        }));

        let schema_dir = PathBuf::from("schema").join(&dataset.dataset_id);
        create_contained_dir_all(&out_root, &schema_dir)?;
        for entity in dataset.entities.values() {
            let entity_dir = schema_dir.join(&entity.name);
            create_contained_dir_all(&out_root, &entity_dir)?;
            let relative = format!(
                "/metadata/schema/{}/{}/schema.json",
                dataset.dataset_id, entity.name
            );
            let schema =
                render_entity_schema_draft_2020_12(&compiled, &dataset.dataset_id, &entity.name)
                    .ok_or_else(|| {
                        format!(
                            "metadata.publish.compiled_renderer_missing: entity schema for {}/{}",
                            dataset.dataset_id, entity.name
                        )
                    })?;
            write_json(&out_root, entity_dir.join("schema.json"), &schema)?;
            schemas.push(serde_json::json!({
                "dataset": dataset.dataset_id,
                "entity": entity.name,
                "url": relative,
            }));
        }
    }

    let mut form_schemas = Vec::new();
    for form in compiled.forms() {
        let form_dir = PathBuf::from("forms").join(&form.id);
        create_contained_dir_all(&out_root, &form_dir)?;
        let relative = format!("/metadata/forms/{}/schema.json", form.id);
        let schema = render_form_schema_draft_2020_12(&compiled, &form.id).ok_or_else(|| {
            format!(
                "metadata.publish.compiled_renderer_missing: form schema for {}",
                form.id
            )
        })?;
        write_json(&out_root, form_dir.join("schema.json"), &schema)?;
        form_schemas.push(serde_json::json!({
            "form": form.id,
            "url": relative,
        }));
    }

    let mut evidence_offerings = Vec::new();
    for offering in compiled.evidence_offerings() {
        let filename = format!("{}.json", offering.id);
        let document = render_evidence_offering(&compiled, &offering.id).ok_or_else(|| {
            format!(
                "metadata.publish.compiled_renderer_missing: evidence offering {}",
                offering.id
            )
        })?;
        write_json(
            &out_root,
            PathBuf::from("evidence-offerings").join(&filename),
            &document,
        )?;
        evidence_offerings.push(serde_json::json!({
            "id": offering.id,
            "dataset": offering.dataset_id,
            "url": format!("/metadata/evidence-offerings/{filename}"),
        }));
    }

    let mut profiles = Vec::new();
    for profile in compiled.profiles() {
        let filename = format!("{}.json", profile.id);
        write_json(
            &out_root,
            PathBuf::from("profiles").join(&filename),
            &serde_json::json!(profile),
        )?;
        profiles.push(serde_json::json!({
            "id": profile.id,
            "version": profile.version,
            "url": format!("/metadata/profiles/{filename}"),
        }));
    }
    let application_profiles = compiled
        .catalog()
        .application_profiles
        .iter()
        .map(|profile| {
            serde_json::json!({
                "id": profile.id,
                "version": profile.version,
            })
        })
        .collect::<Vec<_>>();
    let artifact_digests = collect_artifact_digests(&out_root)?;
    let package_digest = publication_package_digest(&source_digest, &artifact_digests)?;
    let index = serde_json::json!({
        "schema_version": "registry-manifest-index/v1",
        "source_manifest_digest": source_digest,
        "package_digest": package_digest,
        "artifacts": artifact_digests,
        "manifest": "/metadata/metadata.yaml",
        "catalog": "/metadata/catalog.json",
        "evidence_offerings": "/metadata/evidence-offerings.json",
        "evidence_offering_documents": evidence_offerings,
        "policies": "/metadata/policies.jsonld",
        "policy_documents": policy_documents,
        "dcat": "/metadata/dcat.jsonld",
        "dcat_profiles": dcat_profiles,
        "service_catalogues": service_catalogues,
        "shacl": "/metadata/shacl.jsonld",
        "ogc_records_items": "/metadata/ogc-records/items.json",
        "schemas": schemas,
        "form_schemas": form_schemas,
        "profiles": profiles,
        "application_profiles": application_profiles,
    });
    write_json(&out_root, "index.json", &index)?;
    let public_root = site_root.as_ref().unwrap_or(&out_root);
    write_well_known_discovery(public_root, &index)?;
    println!(
        "published metadata artifacts to {}",
        out_root.root.display()
    );
    Ok(())
}

fn write_well_known_discovery(
    public_root: &PublishRoot,
    index: &serde_json::Value,
) -> Result<(), String> {
    create_contained_dir_all(public_root, ".well-known")?;
    write_api_catalog(public_root, index)?;
    write_legacy_registry_manifest_discovery(public_root, index)
}

fn write_api_catalog(public_root: &PublishRoot, index: &serde_json::Value) -> Result<(), String> {
    let mut items = Vec::new();
    push_api_catalog_item(
        &mut items,
        index.get("catalog"),
        "Registry metadata catalog",
        "application/json",
        None,
    );
    push_api_catalog_item(
        &mut items,
        index.get("dcat"),
        "Base DCAT catalog",
        "application/ld+json",
        Some("http://www.w3.org/ns/dcat#"),
    );
    for entry in value_array(index, "dcat_profiles") {
        push_api_catalog_item(
            &mut items,
            entry.get("url"),
            &format!(
                "{} DCAT profile catalog",
                entry
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("profile")
            ),
            "application/ld+json",
            Some("http://www.w3.org/ns/dcat#"),
        );
    }
    for entry in value_array(index, "service_catalogues") {
        push_api_catalog_item(
            &mut items,
            entry.get("url"),
            &format!(
                "{} service catalogue",
                entry
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("service")
            ),
            entry
                .get("media_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("application/json"),
            None,
        );
    }
    push_api_catalog_item(
        &mut items,
        index.get("evidence_offerings"),
        "Evidence offerings",
        "application/json",
        None,
    );
    push_api_catalog_item(
        &mut items,
        index.get("policies"),
        "Policy metadata",
        "application/ld+json",
        None,
    );
    push_api_catalog_item(
        &mut items,
        index.get("shacl"),
        "SHACL shapes",
        "application/ld+json",
        None,
    );
    push_api_catalog_item(
        &mut items,
        index.get("ogc_records_items"),
        "OGC Records item collection",
        "application/geo+json",
        Some("https://ogcapi.ogc.org/records/"),
    );

    let api_catalog = serde_json::json!({
        "linkset": [
            {
                "anchor": "/.well-known/api-catalog",
                "describedby": [
                    {
                        "href": "/metadata/index.json",
                        "type": "application/json",
                        "title": "Registry Manifest metadata index"
                    }
                ],
                "item": items
            }
        ]
    });
    write_json(public_root, ".well-known/api-catalog", &api_catalog)
}

fn push_api_catalog_item(
    items: &mut Vec<serde_json::Value>,
    url: Option<&serde_json::Value>,
    title: &str,
    media_type: &str,
    profile: Option<&str>,
) {
    let Some(href) = url.and_then(serde_json::Value::as_str) else {
        return;
    };
    let mut item = serde_json::Map::new();
    item.insert("href".to_string(), serde_json::json!(href));
    item.insert("type".to_string(), serde_json::json!(media_type));
    item.insert("title".to_string(), serde_json::json!(title));
    if let Some(profile) = profile {
        item.insert("profile".to_string(), serde_json::json!(profile));
    }
    items.push(serde_json::Value::Object(item));
}

fn value_array<'a>(value: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn collect_artifact_digests(root: &PublishRoot) -> Result<Vec<serde_json::Value>, String> {
    let mut files = Vec::new();
    collect_artifact_paths(&root.root, Path::new(""), &mut files)?;
    files.sort();
    let mut artifacts = Vec::with_capacity(files.len());
    for relative in files {
        if relative == Path::new("index.json") || relative.starts_with(".well-known") {
            continue;
        }
        let full_path = root.root.join(&relative);
        let bytes = fs::read(&full_path).map_err(|error| error.to_string())?;
        let path = relative_path_string(&relative)?;
        artifacts.push(serde_json::json!({
            "path": path,
            "media_type": media_type_for_artifact(&relative),
            "sha256": sha256_uri(&bytes),
        }));
    }
    Ok(artifacts)
}

fn collect_artifact_paths(
    root: &Path,
    relative: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let dir = root.join(relative);
    for entry in fs::read_dir(&dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let child_relative = relative.join(name);
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            collect_artifact_paths(root, &child_relative, files)?;
        } else if metadata.is_file() {
            files.push(child_relative);
        }
    }
    Ok(())
}

fn relative_path_string(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "metadata.publish.path_escape: invalid generated path {}",
                    path.display()
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

fn media_type_for_artifact(path: &Path) -> &'static str {
    let path_string = path.to_string_lossy();
    if path_string.ends_with(".jsonld") || path == Path::new("cpsv-ap") {
        "application/ld+json"
    } else if path == Path::new("ogc-records/items.json") {
        "application/geo+json"
    } else if path_string.ends_with(".ttl") {
        "text/turtle"
    } else if path_string.ends_with(".yaml") || path_string.ends_with(".yml") {
        "application/yaml"
    } else {
        "application/json"
    }
}

fn publication_package_digest(
    source_manifest_digest: &str,
    artifacts: &[serde_json::Value],
) -> Result<String, String> {
    let package = serde_json::json!({
        "schema_version": "registry-manifest-package/v1",
        "source_manifest_digest": source_manifest_digest,
        "artifacts": artifacts,
    });
    let canonical = canonicalize_json(&package).map_err(|error| error.to_string())?;
    Ok(sha256_uri(&canonical))
}

fn write_legacy_registry_manifest_discovery(
    public_root: &PublishRoot,
    index: &serde_json::Value,
) -> Result<(), String> {
    let discovery = serde_json::json!({
        "schema_version": "registry-manifest-discovery/v1",
        "metadata_index": "/metadata/index.json",
        "manifest": index.get("manifest").cloned().unwrap_or(serde_json::Value::Null),
        "catalog": index.get("catalog").cloned().unwrap_or(serde_json::Value::Null),
        "dcat": index.get("dcat").cloned().unwrap_or(serde_json::Value::Null),
        "dcat_profiles": index.get("dcat_profiles").cloned().unwrap_or_else(|| serde_json::json!([])),
        "service_catalogues": index.get("service_catalogues").cloned().unwrap_or_else(|| serde_json::json!([])),
        "evidence_offerings": index.get("evidence_offerings").cloned().unwrap_or(serde_json::Value::Null),
        "application_profiles": index.get("application_profiles").cloned().unwrap_or_else(|| serde_json::json!([])),
    });
    write_json(
        public_root,
        ".well-known/registry-manifest.json",
        &discovery,
    )
}

fn option_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|window| (window[0] == name).then(|| window[1].clone()))
}

fn ensure_dcat_profile_available(
    compiled: &registry_manifest_core::CompiledMetadata,
    profile: &str,
) -> Result<(), String> {
    if matches!(profile, "dcat" | "dcat-ap") {
        return Ok(());
    }
    if compiled
        .catalog()
        .application_profiles
        .iter()
        .any(|candidate| candidate.id == profile)
    {
        Ok(())
    } else {
        Err(format!(
            "metadata.manifest.unsupported_application_profile: {profile}"
        ))
    }
}

struct PublishRoot {
    root: PathBuf,
    canonical: PathBuf,
}

fn prepare_publish_root(path: &Path, not_directory_code: &str) -> Result<PublishRoot, String> {
    if path.exists() && !path.is_dir() {
        return Err(format!("{not_directory_code}: {}", path.display()));
    }
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    Ok(PublishRoot {
        root: path.to_path_buf(),
        canonical,
    })
}

fn contained_path(root: &PublishRoot, relative: impl AsRef<Path>) -> Result<PathBuf, String> {
    let relative = relative.as_ref();
    if relative.is_absolute() {
        return Err(format!(
            "metadata.publish.path_escape: absolute generated path {}",
            relative.display()
        ));
    }

    let mut target = root.canonical.clone();
    for component in relative.components() {
        match component {
            Component::Normal(part) => target.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "metadata.publish.path_escape: parent traversal in generated path {}",
                    relative.display()
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "metadata.publish.path_escape: absolute generated path {}",
                    relative.display()
                ));
            }
        }
    }

    if target.starts_with(&root.canonical) {
        Ok(target)
    } else {
        Err(format!(
            "metadata.publish.path_escape: generated path escaped root {}",
            relative.display()
        ))
    }
}

fn create_contained_dir_all(root: &PublishRoot, relative: impl AsRef<Path>) -> Result<(), String> {
    let relative = relative.as_ref();
    let target = contained_path(root, relative)?;
    reject_existing_symlink_components(root, relative)?;
    fs::create_dir_all(target).map_err(|error| error.to_string())
}

fn write_contained_bytes(
    root: &PublishRoot,
    relative: impl AsRef<Path>,
    bytes: &[u8],
) -> Result<(), String> {
    let relative = relative.as_ref();
    let target = contained_path(root, relative)?;
    reject_existing_symlink_components(root, relative)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(target, bytes).map_err(|error| error.to_string())
}

fn reject_existing_symlink_components(root: &PublishRoot, relative: &Path) -> Result<(), String> {
    let mut current = root.canonical.clone();
    for component in relative.components() {
        match component {
            Component::Normal(part) => current.push(part),
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "metadata.publish.path_escape: invalid generated path {}",
                    relative.display()
                ));
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "metadata.publish.path_escape: symlink in generated path {}",
                    relative.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn copy_contained(
    root: &PublishRoot,
    relative: impl AsRef<Path>,
    source: impl AsRef<Path>,
) -> Result<(), String> {
    let bytes = fs::read(source).map_err(|error| error.to_string())?;
    write_contained_bytes(root, relative, &bytes)
}

fn write_json(
    root: &PublishRoot,
    relative: impl AsRef<Path>,
    value: &serde_json::Value,
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    write_contained_bytes(root, relative, &bytes)
}

fn print_json(value: &serde_json::Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn usage() -> String {
    "usage: registry-manifest validate <metadata.yaml> [--format human|json] [--deny-warnings] | validate-profiles [profiles-dir] [--format human|json] [--deny-warnings] | render <metadata.yaml> --format <catalog|evidence-offerings|evidence-offering|policies|policy|dcat|bregdcat-ap|cpsv-ap|shacl|json-schema|form-json-schema|ogc-records> [--profile <id>] [--dataset <id> --entity <name>] [--form <id>] [--offering <id>] | publish <metadata.yaml> --out <dir> [--site-root <dir>]".to_string()
}
