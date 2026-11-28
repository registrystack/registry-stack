// SPDX-License-Identifier: Apache-2.0
//! One local request to Render's authenticated seal route. The command constructs its own
//! runtime and credentials, keeps the router in-process, and gives the operator the public root.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use axum::body::{to_bytes, Body};
use axum::http::{header, Request};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use der::pem::{encode_string, LineEnding};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use registry_platform_config::package;
use registry_platform_crypto::{private_seal_key_json, seal_key_from_pkcs8_pem, PrivateJwk};
use serde_json::{json, Value};
use tempfile::Builder;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;
use zeroize::Zeroizing;

use crate::problem::{ProblemKind, RenderProblem};
use crate::render::{validate_data, RenderRequest, DEFAULT_MAX_OUTPUT_BYTES};
use crate::{runtime, server, Bundle};

const ISSUER: &str = "https://test-seal.invalid";
const CLIENT: &str = "render-test-seal";
const AUDIENCE: &str = "urn:registry-render:test-seal";

pub(crate) fn run(
    source: &Path,
    document: &str,
    request: &RenderRequest,
    output: &Path,
    declared: registry_platform_config::DeclaredPosture,
) -> Result<Value, RenderProblem> {
    server::mark_not_dumpable()?;
    match fs::symlink_metadata(output) {
        Ok(_) => {
            return Err(RenderProblem::new(
                ProblemKind::InvalidArgument,
                "choose a new output directory for this specimen",
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(io_problem(error)),
    }
    let (bundle, digest) = Bundle::load_for_authoring(source)?;
    let selected = bundle.document(document)?;
    if selected.spec.seal.is_none() {
        return Err(RenderProblem::new(ProblemKind::DocumentNotSealable,
            "the selected document has no seal; declare its issuing authority's seal in the bundle manifest"));
    }
    validate_data(selected, request)?;

    let scratch = Builder::new()
        .prefix("registry-render-test-seal-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .map_err(io_problem)?;
    let issued = (|| -> Result<_, RenderProblem> {
        let home = scratch.path().canonicalize().map_err(io_problem)?;
        let (package_path, package_digest) = local_package(&bundle, source, digest, &home)?;
        let root = write_test_chain(&home)?;
        let token = write_local_identity(&home)?;
        let runtime_path = write_runtime(&bundle, &home, &package_path, &package_digest)?;
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(io_problem)?;
        let (pdf, report) = executor.block_on(seal_request(
            &runtime_path,
            document,
            request,
            &token,
            &package_digest,
            declared,
        ))?;
        Ok((pdf, report, root))
    })();
    scratch.close().map_err(io_problem)?;
    let (pdf, report, root) = issued?;
    publish(output, &pdf, &root)?;
    Ok(report)
}

/// An existing package keeps its reviewed digest. Raw source is packaged from the loaded snapshot.
fn local_package(
    bundle: &Bundle,
    source: &Path,
    digest: Option<String>,
    home: &Path,
) -> Result<(PathBuf, String), RenderProblem> {
    if let Some(digest) = digest {
        return Ok((source.canonicalize().map_err(io_problem)?, digest));
    }
    crate::check::check_package_source(bundle, source)?;
    let path = home.join("package");
    let package = package::write_package(
        &path,
        &bundle.package_inputs(),
        None,
        &runtime::package_limits(),
        "registry-render test-seal",
    )
    .map_err(runtime::package_problem)?;
    Ok((path, package.digest().to_owned()))
}

fn params(name: &str, now: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(90);
    params
}

fn key() -> Result<KeyPair, RenderProblem> {
    KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|_| internal("could not generate an ephemeral development key"))
}

fn as_jwk(pair: &KeyPair) -> Result<PrivateJwk, RenderProblem> {
    let pem = Zeroizing::new(
        encode_string("PRIVATE KEY", LineEnding::LF, pair.serialized_der())
            .map_err(|_| internal("could not encode the ephemeral development key"))?,
    );
    seal_key_from_pkcs8_pem(pem.as_bytes(), None)
        .map_err(|_| internal("could not load the ephemeral development key"))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), RenderProblem> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(io_problem)
}

fn write_test_chain(home: &Path) -> Result<String, RenderProblem> {
    let now = OffsetDateTime::now_utc();
    let mut root = params("Registry Render Development Test CA", now);
    root.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = key()?;
    let ca = root
        .self_signed(&ca_key)
        .map_err(|_| internal("could not issue the public test root"))?;
    let issuer = Issuer::new(root, ca_key);

    let mut leaf = params("Registry Render Test Seal", now);
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ];
    leaf.use_authority_key_identifier_extension = true;
    let leaf_key = key()?;
    let certificate = leaf
        .signed_by(&leaf_key, &issuer)
        .map_err(|_| internal("could not issue the test signing certificate"))?;
    let pem = |der: &[u8]| {
        encode_string("CERTIFICATE", LineEnding::LF, der)
            .map_err(|_| internal("could not encode a public certificate"))
    };
    let public_root = pem(ca.der())?;
    let chain = pem(certificate.der())? + &public_root;
    write_private_file(&home.join("chain.pem"), chain.as_bytes())?;
    let secret = private_seal_key_json(&as_jwk(&leaf_key)?)
        .map_err(|_| internal("could not prepare the development signer"))?;
    write_private_file(&home.join("seal.jwk"), &secret)?;
    Ok(public_root)
}

/// The synthetic OIDC issuer uses a separate ephemeral key and grants only the seal scope.
fn write_local_identity(home: &Path) -> Result<Zeroizing<String>, RenderProblem> {
    let issuer_key = key()?;
    let mut public = as_jwk(&issuer_key)?.public();
    public.kid = Some(CLIENT.to_owned());
    write_private_file(
        &home.join("jwks.json"),
        json!({"keys":[public]}).to_string().as_bytes(),
    )?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some(CLIENT.to_owned());
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = json!({"iss":ISSUER, "sub":CLIENT, "client_id":CLIENT, "aud":AUDIENCE,
        "scope":"render:seal", "iat":now, "exp":now + 300});
    let key = jsonwebtoken::EncodingKey::from_ec_der(issuer_key.serialized_der());
    jsonwebtoken::encode(&header, &claims, &key)
        .map(Zeroizing::new)
        .map_err(|_| internal("could not authorize the local test request"))
}

fn write_runtime(
    bundle: &Bundle,
    home: &Path,
    package_root: &Path,
    digest: &str,
) -> Result<PathBuf, RenderProblem> {
    let seal = json!({
        "signer": {"type":"local-jwk", "privateKeyRef":"secret:file/seal.jwk"},
        "certificateChainFile":home.join("chain.pem"), "allowedClients":[CLIENT],
        "withoutTimestamp":"seal-stops-validating-when-certificate-expires"
    });
    let seals: BTreeMap<_, _> = bundle
        .documents
        .values()
        .filter_map(|doc| doc.spec.seal.as_deref().map(|id| (id, &seal)))
        .collect();
    let runtime = json!({
        "apiVersion":"id.registrystack.org/formats/render/runtime/v1alpha1", "kind":"RenderRuntimeConfig",
        "listener":{"bind":"127.0.0.1:8080"},
        "package":{"root":package_root,"expectedDigest":digest},
        "secretProviders":{"file":{"root":home}},
        "authentication":{"oidc":{"issuers":{"main":{"issuer":ISSUER,"audience":AUDIENCE,"allowedClients":[CLIENT],
            "jwksSource":{"type":"static","documentRef":"secret:file/jwks.json"}}}}},
        "audit":{"path":home.join("audit.jsonl")}, "assuranceProfile":"local", "signing":{"seals":seals}
    });
    let path = home.join("runtime.yaml");
    write_private_file(&path, runtime.to_string().as_bytes())?;
    Ok(path)
}

async fn seal_request(
    path: &Path,
    document: &str,
    request: &RenderRequest,
    token: &str,
    digest: &str,
    declared: registry_platform_config::DeclaredPosture,
) -> Result<(Vec<u8>, Value), RenderProblem> {
    let (runtime, _, service) = server::load_service(path, declared).await?;
    // The serving parent now holds the test signer. Remove its key file before any worker starts.
    fs::remove_file(path.with_file_name("seal.jwk")).map_err(io_problem)?;
    let body = json!({"data":request.data, "issuedAt":request.issued_at.to_rfc3339(),
        "assets":request.assets,"locale":request.locale})
    .to_string();
    if body.len() > runtime.limits.request_bytes() {
        return Err(RenderProblem::new(
            ProblemKind::BodyTooLarge,
            "the example request exceeds the local seal request limit",
        ));
    }
    let call = Request::post(format!("/v1/seal/{document}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .body(Body::from(body))
        .map_err(|_| internal("could not prepare the local test request"))?;
    let response = server::router(service)
        .oneshot(call)
        .await
        .expect("infallible router");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), DEFAULT_MAX_OUTPUT_BYTES * 2)
        .await
        .map_err(|_| internal("the test signing response exceeded its size limit"))?;
    let mut report: Value =
        serde_json::from_slice(&bytes).map_err(|_| internal("invalid test signing response"))?;
    if !status.is_success() {
        let code = report["code"]
            .as_str()
            .and_then(|s| s.strip_prefix("render."))
            .unwrap_or("internal");
        return Err(RenderProblem::new(
            ProblemKind::from_slug(code),
            report["detail"]
                .as_str()
                .unwrap_or("the seal route refused the local request"),
        ));
    }
    if report["seal"]["testOnly"] != true || report["packageDigest"] != digest {
        return Err(internal(
            "the seal response did not identify the requested local test package",
        ));
    }
    let encoded = report
        .as_object_mut()
        .and_then(|object| object.remove("pdfBase64"))
        .ok_or_else(|| internal("the test signing response omitted the PDF"))?;
    let pdf = STANDARD
        .decode(encoded.as_str().unwrap_or_default())
        .map_err(|_| internal("the test signing response contained an invalid PDF"))?;
    if !pdf.starts_with(b"%PDF-") || report["signedFileDigest"] != crate::hash::sha256_digest(&pdf)
    {
        return Err(internal(
            "the test-signed PDF did not match the returned digest",
        ));
    }
    Ok((pdf, report))
}

/// Readers see both public artifacts together. Concurrent runs cannot replace a prior specimen.
fn publish(output: &Path, pdf: &[u8], root: &str) -> Result<(), RenderProblem> {
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staged = Builder::new()
        .prefix(".registry-render-specimen-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .map_err(io_problem)?;
    write_private_file(&staged.path().join("document.pdf"), pdf)?;
    write_private_file(&staged.path().join("test-root.pem"), root.as_bytes())?;
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        use rustix::fs::{renameat_with, RenameFlags, CWD};
        renameat_with(CWD, staged.path(), CWD, output, RenameFlags::NOREPLACE)
            .map_err(|err| io_problem(err.into()))?;
        // The directory now belongs to the caller under its published name.
        let _ = staged.keep();
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    Err(internal(
        "atomic specimen publication is unavailable on this platform",
    ))
}

fn internal(detail: &'static str) -> RenderProblem {
    RenderProblem::new(ProblemKind::Internal, detail)
}
fn io_problem(error: std::io::Error) -> RenderProblem {
    RenderProblem::new(
        ProblemKind::InvalidArgument,
        format!("test-seal file operation: {error}"),
    )
}
