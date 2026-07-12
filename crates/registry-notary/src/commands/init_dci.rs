use crate::*;

#[derive(Debug)]
pub(crate) struct InitDciOptions {
    pub(crate) base_url: String,
    pub(crate) token_url: String,
    pub(crate) lookup_field: String,
    pub(crate) claim_id: String,
    pub(crate) claim_title: String,
    pub(crate) demo_issuer: bool,
    pub(crate) with_env_file: bool,
    pub(crate) force: bool,
    pub(crate) print_secrets: bool,
}

pub(crate) fn init_dci(
    output: &Path,
    options: InitDciOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_init_dci_options(&options)?;
    fs::create_dir_all(output)?;
    let api_key = random_secret("rn_api");
    let api_hash = sha256_hash(&api_key);
    let audit_secret = random_secret("rn_audit");
    let issuer_jwk = if options.demo_issuer {
        Some(demo_issuer_jwk("did:web:localhost#registry-notary-demo")?)
    } else {
        None
    };
    write_generated_file(
        &output.join("dci-notary.yaml"),
        &dci_config_yaml(&options),
        options.force,
        false,
    )?;
    write_generated_file(
        &output.join(".env.local.example"),
        &dci_env_example(options.demo_issuer),
        options.force,
        false,
    )?;
    if options.with_env_file {
        write_generated_file(
            &output.join(".env.local"),
            &dci_env_local(&api_key, &api_hash, &audit_secret, issuer_jwk.as_deref()),
            options.force,
            true,
        )?;
    }
    write_generated_file(
        &output.join("README.dci.md"),
        dci_readme(),
        options.force,
        false,
    )?;
    println!("Generated DCI starter files in {}", output.display());
    eprintln!(
        "WARN generated config uses temporary transitional_direct cutover scaffolding; it blocks the replacement beta and 1.0 release and must be replaced by a reviewed Relay profile"
    );
    if options.print_secrets {
        println!("REGISTRY_NOTARY_LOCAL_API_KEY={api_key}");
        println!("REGISTRY_NOTARY_API_KEY_HASH={api_hash}");
        println!("REGISTRY_NOTARY_AUDIT_HASH_SECRET={audit_secret}");
        if let Some(jwk) = issuer_jwk {
            println!("REGISTRY_NOTARY_ISSUER_JWK={jwk}");
        }
    } else if options.with_env_file {
        println!("Local secrets were written to .env.local and were not printed.");
    } else {
        println!(
            "Run `registry-notary hash-api-key --print-secret` to create local API credentials."
        );
    }
    Ok(())
}

pub(crate) fn validate_init_dci_options(
    options: &InitDciOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    for (name, value) in [
        ("base_url", options.base_url.as_str()),
        ("token_url", options.token_url.as_str()),
        ("lookup_field", options.lookup_field.as_str()),
        ("claim_id", options.claim_id.as_str()),
        ("claim_title", options.claim_title.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{name} must not be empty").into());
        }
        if value.contains(['\n', '\r']) {
            return Err(format!("{name} must not contain line breaks").into());
        }
    }
    reqwest::Url::parse(&options.base_url)
        .map_err(|err| format!("base_url must be an absolute URL: {err}"))?;
    reqwest::Url::parse(&options.token_url)
        .map_err(|err| format!("token_url must be an absolute URL: {err}"))?;
    Ok(())
}

pub(crate) fn write_generated_file(
    path: &Path,
    contents: &str,
    force: bool,
    secret: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() && !force {
        return Err(format!("{} exists; pass --force to overwrite", path.display()).into());
    }
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    if secret {
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents.as_bytes())?;
    Ok(())
}

pub(crate) fn dci_config_yaml(options: &InitDciOptions) -> String {
    let claim_id = yaml_string(&options.claim_id);
    let claim_title = yaml_string(&options.claim_title);
    let base_url = yaml_string(&options.base_url);
    let token_url = yaml_string(&options.token_url);
    let lookup_field = yaml_string(&options.lookup_field);
    let credential_profile = if options.demo_issuer {
        format!(
            r#"
  signing_keys:
    registry-notary-demo:
      provider: local_jwk_env
      private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
      alg: EdDSA
      kid: did:web:localhost#registry-notary-demo
      status: active
  credential_profiles:
    dci_record_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:localhost
      signing_key: registry-notary-demo
      vct: https://registry-notary.local/credentials/dci-record
      allowed_claims: [{claim_id}]
      holder_binding:
        mode: none
"#
        )
    } else {
        String::new()
    };
    let claim_profiles = if options.demo_issuer {
        "      credential_profiles: [dci_record_sd_jwt]\n"
    } else {
        ""
    };
    format!(
        r#"# TEMPORARY UNRELEASED CUTOVER SCAFFOLD: this file uses transitional_direct.
# It blocks the replacement beta and 1.0 release. Do not use it to start a new
# integration; replace it with a reviewed, hash-pinned Relay profile.
server:
  bind: 127.0.0.1:4255
auth:
  mode: api_key
  api_keys:
    - id: local-demo
      fingerprint:
        provider: env
        name: REGISTRY_NOTARY_API_KEY_HASH
      scopes: [dci:evidence_verification]
audit:
  sink: file
  path: ./dci-notary.audit.jsonl
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: dci-notary-demo
  source_connections:
    dci_registry:
      base_url: {base_url}
      source_auth:
        type: oauth2_client_credentials
        token_url: {token_url}
        client_id_env: DCI_CLIENT_ID
        client_secret_env: DCI_CLIENT_SECRET
        request_format: json
      dci:
        search_path: /registry/sync/search
        sender_id: registry-notary
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
{credential_profile}  claims:
    - id: {claim_id}
      title: {claim_title}
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      value:
        type: boolean
{claim_profiles}      source_bindings:
        record:
          connector: dci
          connection: dci_registry
          required_scope: dci:evidence_verification
          dataset: registry_records
          entity: record
          lookup:
            input: target.id
            field: {lookup_field}
            op: eq
            cardinality: one
          fields:
            id:
              field: id
              type: string
              required: false
      rule:
        type: exists
        source: record
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
        - application/dc+sd-jwt
"#
    )
}

pub(crate) fn yaml_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(crate) fn cli_fetch_url_policy(
    connection: &registry_notary_core::SourceConnectionConfig,
) -> FetchUrlPolicy {
    if connection.allow_insecure_private_network {
        FetchUrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: true,
            allow_http_private_network: true,
            deny_private_ranges: false,
            deny_cloud_metadata: true,
        }
    } else if connection.allow_insecure_localhost {
        FetchUrlPolicy::dev()
    } else {
        FetchUrlPolicy::strict()
    }
}

pub(crate) fn dci_env_example(demo_issuer: bool) -> String {
    let issuer = if demo_issuer {
        "REGISTRY_NOTARY_ISSUER_JWK=<generated by registry-notary demo-issuer-key>\n"
    } else {
        ""
    };
    format!(
        r#"# Copy to .env.local or run init with --with-env-file.
REGISTRY_NOTARY_API_KEY=<random local API key>
REGISTRY_NOTARY_API_KEY_HASH=sha256:<64 hex>
REGISTRY_NOTARY_AUDIT_HASH_SECRET=<random local audit secret>
DCI_CLIENT_ID=<DCI OAuth client id>
DCI_CLIENT_SECRET=<DCI OAuth client secret>
{issuer}"#
    )
}

pub(crate) fn dci_env_local(
    api_key: &str,
    api_hash: &str,
    audit_secret: &str,
    issuer_jwk: Option<&str>,
) -> String {
    let issuer = issuer_jwk
        .map(|jwk| format!("REGISTRY_NOTARY_ISSUER_JWK='{jwk}'\n"))
        .unwrap_or_default();
    format!(
        r#"REGISTRY_NOTARY_API_KEY={api_key}
REGISTRY_NOTARY_API_KEY_HASH={api_hash}
REGISTRY_NOTARY_AUDIT_HASH_SECRET={audit_secret}
DCI_CLIENT_ID=replace-me
DCI_CLIENT_SECRET=replace-me
{issuer}"#
    )
}

pub(crate) fn dci_readme() -> &'static str {
    r#"# DCI Registry Notary Starter

1. Fill `DCI_CLIENT_ID` and `DCI_CLIENT_SECRET` in `.env.local`.
2. Edit `dci-notary.yaml` for the DCI server's base URL, token URL, query type,
   registry filters, lookup field, and records path.
3. Run `registry-notary doctor --config dci-notary.yaml --env-file .env.local`.
4. Run `registry-notary doctor --config dci-notary.yaml --env-file .env.local --live`.
5. Start with `registry-notary --config dci-notary.yaml --env-file .env.local`.

The generated config uses explicit DCI config fields and generic
`source_auth.type = oauth2_client_credentials`. It does not depend on any
built-in registry-specific code path.
"#
}
#[cfg(test)]
#[path = "init_dci/tests.rs"]
mod tests;
