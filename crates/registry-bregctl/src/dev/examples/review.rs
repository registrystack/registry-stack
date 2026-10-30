// SPDX-License-Identifier: Apache-2.0
//! Optional local composition through the installed public CLIs and Casework HTTP API.
use super::*;
use std::{process::Command, time::Duration};
use zeroize::Zeroizing;

#[derive(Debug, Args)]
pub(super) struct ReviewArgs {
    /// Fresh destination for the facility and canonical Casework projects.
    directory: PathBuf,
    /// Explicitly record approval as the local synthetic Casework staff fixture.
    /// The decision uses Casework's ordinary claim, context and decision APIs.
    #[arg(long)]
    approve: bool,
    /// Casework authoring CLI from the same installation.
    #[arg(long)]
    caseworkctl_bin: Option<PathBuf>,
    /// Casework runtime executable; otherwise resolve casework on PATH.
    #[arg(long)]
    casework_bin: Option<PathBuf>,
    /// Base Registry Engine (BReg) runtime executable; otherwise resolve breg on PATH.
    #[arg(long)]
    breg_bin: Option<PathBuf>,
}

fn path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn ctl(binary: &Path, args: Vec<String>, logs: &Path) -> Result<Value> {
    let output = Command::new(binary)
        .args(["--format", "json"])
        .args(&args)
        .output()
        .with_context(|| format!("could not start {}", binary.display()))?;
    if output.stdout.len() > 2 * 1024 * 1024 || output.stderr.len() > 2 * 1024 * 1024 {
        bail!("local CLI report exceeded its bound");
    }
    if !output.status.success() {
        let log = logs.join(format!("{}.txt", uuid::Uuid::new_v4()));
        let mut bytes = output.stdout;
        bytes.extend(output.stderr);
        private::create(&log, &bytes)?;
        bail!(
            "local connection command failed; inspect private {}",
            log.display()
        );
    }
    let value = decode_exact_json(&output.stdout)?;
    if value["kind"] == "CaseworkReport" && (value["ok"] != true || value["status"] != "complete") {
        bail!("Casework command did not complete");
    }
    Ok(value)
}

fn authored(file: &Path) -> Result<Value> {
    let bytes = read_source(file)?;
    Ok(Reader::new(path(file))
        .scan(&bytes)?
        .context("authored project document is empty")?
        .to_json_value())
}
fn write(file: &Path, value: &Value) -> Result<()> {
    let original = read_source(file)?;
    let bytes = super::super::prepare_source::yaml_with_comments(value, &original)?;
    fs::write(file, bytes)?;
    Ok(())
}

/// Merge only local caller/transport settings. Policies and schema remain the
/// owner-authored templates written by the installed init commands.
fn local_clients(breg: &mut Value, casework: &mut Value, authority: &str) -> Result<()> {
    let source = breg["clients"]
        .as_array_mut()
        .context("BReg template has no clients")?;
    for target in casework["clients"]
        .as_array_mut()
        .context("Casework template has no clients")?
    {
        let id = target["id"]
            .as_str()
            .context("Casework client has no id")?
            .to_owned();
        if id == "staff" {
            let reviewer = source
                .iter_mut()
                .find(|client| client["id"] == "reviewer")
                .context("facility template has no reviewer fixture")?;
            reviewer["id"] = json!("staff");
            reviewer["scopes"]
                .as_array_mut()
                .context("reviewer has no scopes")?
                .push(json!("casework:staff"));
            target["claims"] = reviewer["claims"].clone();
            target["scopes"] = reviewer["scopes"].clone();
        } else {
            let claims = target.get("claims").cloned().unwrap_or_else(|| json!({}));
            source.push(
                json!({"id":id,"accessProfiles":[],"scopes":target["scopes"],
                "allowHumanFixture":claims["registry_actor_kind"] == "human", "claims":claims}),
            );
        }
    }
    source.push(
        json!({"id":"casework-service","accessProfiles":["casework-review-status"],
        "scopes":["registry:proposal:review-status"],"claims":{"registry_actor_kind":"service",
        "registry_principal":"synthetic-casework-service","registry_purpose":"facility-review"}}),
    );
    breg["reviewAuthorities"] = json!({"casework":{"endpoint":authority,"profile":"requester",
        "producerId":"facility-registry","recoveryDays":30,"client":"requester"}});
    Ok(())
}

fn bind_producer(project: &mut Value, identity: &Value) -> Result<()> {
    let trust = project["trustedProducers"]
        .as_object_mut()
        .context("canonical project has no trusted producers")?
        .get_mut("facility-registry")
        .context("canonical project has no facility review producer")?;
    trust["issuer"] = identity["issuer"].clone();
    trust["subject"] = identity["subject"].clone();
    if trust.get("trustedInitiatorIssuer").is_some() {
        trust["trustedInitiatorIssuer"] = identity["issuer"].clone();
    }
    Ok(())
}

fn bearer_from_header(header: &str) -> Result<Zeroizing<String>> {
    let mut bearers = header
        .lines()
        .filter_map(|line| line.strip_prefix("Authorization: Bearer "));
    let bearer = bearers
        .next()
        .filter(|bearer| !bearer.is_empty())
        .context("staff header has no bearer credential")?;
    if bearers.next().is_some() {
        bail!("staff header contains multiple bearer credentials");
    }
    Ok(Zeroizing::new(bearer.to_owned()))
}

fn observation_is_pending(report: &Value) -> bool {
    report["diagnostics"].as_array().is_some_and(|diagnostics| {
        diagnostics.len() == 1
            && diagnostics[0]["code"] == "examples.failed"
            && diagnostics[0]["message"]
                .as_str()
                .is_some_and(|message| message.ends_with(proposals::PENDING_OBSERVATION))
    })
}

pub(super) fn prepare(args: ReviewArgs) -> Result<Value> {
    // Resolve every rstack-managed helper before creating the destination, so
    // an absent component or a conflicting override has no local effects.
    let caseworkctl_bin = crate::selected_binary::resolve_managed(
        crate::selected_binary::CASEWORKCTL,
        args.caseworkctl_bin.as_deref(),
    )?
    .or(args.caseworkctl_bin)
    .unwrap_or_else(|| PathBuf::from("caseworkctl"));
    let breg_bin = crate::selected_binary::resolve_managed(
        crate::selected_binary::BREG,
        args.breg_bin.as_deref(),
    )?
    .or(args.breg_bin);
    let casework_bin = crate::selected_binary::resolve_managed(
        crate::selected_binary::CASEWORK,
        args.casework_bin.as_deref(),
    )?
    .or(args.casework_bin);
    let root = std::path::absolute(&args.directory)?;
    if root.exists() {
        bail!("review example requires a fresh destination; existing projects and sessions are preserved");
    }
    private::directory(&root)?;
    let root = root.canonicalize()?;
    let logs = root.join("logs");
    private::directory(&logs)?;
    let keys = root.join("keys");
    private::directory(&keys)?;
    let breg = root.join("facility");
    let casework = root.join("casework");
    let self_bin = std::env::current_exe()?;
    ctl(
        &self_bin,
        vec![
            "init".into(),
            path(&breg),
            "--template".into(),
            "facility-registry".into(),
        ],
        &logs,
    )?;
    ctl(
        &caseworkctl_bin,
        vec![
            "init".into(),
            path(&casework),
            "--template".into(),
            "canonical-review".into(),
        ],
        &logs,
    )?;
    let listeners: Vec<_> = (0..5)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<_>>()?;
    let ports: Vec<_> = listeners
        .iter()
        .map(|listener| listener.local_addr().map(|address| address.port()))
        .collect::<std::io::Result<_>>()?;
    let casework_url = format!("http://127.0.0.1:{}", ports[3]);
    let mut breg_clients = authored(&breg.join("dev-clients.yaml"))?;
    let mut casework_clients = authored(&casework.join("dev-clients.yaml"))?;
    local_clients(
        &mut breg_clients,
        &mut casework_clients,
        &format!("{casework_url}/"),
    )?;
    write(&breg.join("dev-clients.yaml"), &breg_clients)?;
    drop(listeners);
    let mut start = vec![
        "dev".into(),
        "start".into(),
        path(&breg),
        "--breg-port".into(),
        ports[0].to_string(),
        "--issuer-port".into(),
        ports[1].to_string(),
        "--database-port".into(),
        ports[2].to_string(),
    ];
    if let Some(binary) = &breg_bin {
        start.extend(["--breg-bin".into(), path(binary)]);
    }
    let source = ctl(&self_bin, start, &logs)?;
    let export = |id: &str| {
        ctl(
            &self_bin,
            vec![
                "dev".into(),
                "export-client".into(),
                path(&breg),
                "--client".into(),
                id.into(),
                "--client-id-file".into(),
                path(&keys.join(format!("{id}-id"))),
                "--assertion-key-file".into(),
                path(&keys.join(format!("{id}-key"))),
            ],
            &logs,
        )
    };
    let producer = export("requester")?;
    let status = export("casework-service")?;
    let mut project = authored(&casework.join("casework.yaml"))?;
    bind_producer(&mut project, &producer)?;
    write(&casework.join("casework.yaml"), &project)?;
    casework_clients["integrations"] = json!({"resource":producer["resource"],
        "contextProviders":{"facility-registry":{"baseUrl":status["bregUrl"],"statusProfile":"casework-review-status",
            "tokenEndpoint":status["tokenEndpoint"],"clientAssertionAudience":status["clientAssertionAudience"],
            "resource":status["resource"],"scopes":status["scopes"],"clientIdRef":"secret:file/breg-status-id",
            "clientAssertionKeyRef":"secret:file/breg-status-key"}},
        "secretFiles":{"breg-status-id":status["clientIdFile"],"breg-status-key":status["assertionKeyFile"]}});
    write(&casework.join("dev-clients.yaml"), &casework_clients)?;
    let package = PathBuf::from(
        source["stateFile"]
            .as_str()
            .context("source has no public state location")?,
    )
    .parent()
    .context("source state has no parent")?
    .join("build/package");
    ctl(
        &caseworkctl_bin,
        vec![
            "provider".into(),
            "pair".into(),
            path(&casework),
            "--provider-id".into(),
            "facility-proposal-context".into(),
            "--breg-package".into(),
            path(&package),
            "--action-id".into(),
            "correct-address".into(),
            "--bregctl-bin".into(),
            path(&self_bin),
            "--apply".into(),
        ],
        &logs,
    )?;
    ctl(
        &caseworkctl_bin,
        vec!["check".into(), path(&casework)],
        &logs,
    )?;
    let mut start = vec![
        "dev".into(),
        "start".into(),
        path(&casework),
        "--issuer-project".into(),
        path(&breg),
        "--casework-port".into(),
        ports[3].to_string(),
        "--database-port".into(),
        ports[4].to_string(),
    ];
    if let Some(binary) = &casework_bin {
        start.extend(["--casework-bin".into(), path(binary)]);
    }
    ctl(&caseworkctl_bin, start, &logs)?;
    let registration = ctl(
        &self_bin,
        vec![
            "examples".into(),
            "run".into(),
            "register-facility".into(),
            path(&breg),
        ],
        &logs,
    )?;
    let submission = ctl(
        &self_bin,
        vec![
            "examples".into(),
            "run".into(),
            "submit-address-correction".into(),
            path(&breg),
            "--from-attempt".into(),
            registration["attempt"]
                .as_str()
                .context("registration has no attempt")?
                .into(),
        ],
        &logs,
    )?;
    let observe = format!(
        "bregctl examples run observe-address-correction {} --from-attempt {}",
        shell_path(&breg),
        submission["attempt"]
            .as_str()
            .context("submission has no attempt")?
    );
    let mut report = json!({"ok":true,"command":"examples review","directory":root,"bregProject":breg,"caseworkProject":casework,
        "caseworkUrl":casework_url,"registration":registration,"submission":submission,"observeCommand":observe,
        "stopCommands":[format!("caseworkctl dev stop {}",shell_path(&casework)),format!("bregctl dev stop {}",shell_path(&breg))],
        "message":"Independent Casework is connected. Review the captured Proposal through its authorized staff profile, then observe source application."});
    private::create(
        &root.join("review-session.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    if args.approve {
        let credentials = ctl(
            &caseworkctl_bin,
            vec![
                "dev".into(),
                "token".into(),
                "staff".into(),
                path(&casework),
            ],
            &logs,
        )?;
        let header = Zeroizing::new(String::from_utf8(private::read(
            Path::new(
                credentials["headerFile"]
                    .as_str()
                    .context("staff token has no header file")?,
            ),
            65536,
        )?)?);
        let token = bearer_from_header(&header)?;
        let proposal: ProposalCapture =
            serde_json::from_value(submission["proposals"]["correction"].clone())
                .context("submission has no typed Proposal capture")?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(approve(&casework_url, &proposal, token.as_str()))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        loop {
            let output = Command::new(&self_bin)
                .args([
                    "--format",
                    "json",
                    "examples",
                    "run",
                    "observe-address-correction",
                ])
                .arg(&breg)
                .arg("--from-attempt")
                .arg(
                    submission["attempt"]
                        .as_str()
                        .context("submission has no attempt")?,
                )
                .output()?;
            if output.status.success() {
                report["observation"] = decode_exact_json(&output.stdout)?;
                break;
            }
            if !observation_is_pending(&decode_exact_json(&output.stdout)?) {
                let log = logs.join(format!("{}.txt", uuid::Uuid::new_v4()));
                let mut bytes = output.stdout;
                bytes.extend(output.stderr);
                private::create(&log, &bytes)?;
                bail!(
                    "source observation failed; inspect private {}. Resume with {observe}",
                    log.display()
                );
            }
            if std::time::Instant::now() >= deadline {
                bail!("independent decision was recorded; application is still pending. Resume with {observe}");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        report["message"] = json!("The explicitly requested synthetic human approved through Casework; the captured source submission applied.");
        private::replace(
            &root.join("review-session.json"),
            &serde_json::to_vec_pretty(&report)?,
        )?;
    }
    Ok(report)
}

fn review_request(
    http: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    token: &str,
    body: Option<Value>,
    revision: Option<i64>,
    key: &str,
) -> reqwest::RequestBuilder {
    let mut request = http
        .request(method, url)
        .bearer_auth(token)
        .header("Registry-Casework-Profile", "staff")
        .header("Registry-Source-Profile", "proposal-reviewer");
    if let Some(body) = body {
        request = request.json(&body);
    }
    if !key.is_empty() {
        request = request.header("Idempotency-Key", key);
    }
    if let Some(revision) = revision {
        request = request.header("If-Match", format!("\"{revision}\""));
    }
    request
}

async fn exchange(
    http: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    token: &str,
    body: Option<Value>,
    revision: Option<i64>,
    key: &str,
) -> Result<Value> {
    let response = review_request(http, method, url, token, body, revision, key)
        .send()
        .await?;
    if !response.status().is_success() {
        bail!(
            "Casework fixture request refused (HTTP {})",
            response.status().as_u16()
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > 512 * 1024)
    {
        bail!("Casework fixture response exceeds its bound");
    }
    let bytes = response.bytes().await?;
    if bytes.len() > 512 * 1024 {
        bail!("Casework fixture response exceeds its bound");
    }
    if bytes.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(decode_exact_json(&bytes)?)
    }
}

async fn approve(origin: &str, proposal: &ProposalCapture, token: &str) -> Result<()> {
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    let task = loop {
        let page = exchange(
            &http,
            reqwest::Method::GET,
            &format!("{origin}/v1/review-tasks?queue=facility-addresses&limit=25"),
            token,
            None,
            None,
            "",
        )
        .await?;
        if let Some(task) = page["items"].as_array().and_then(|items| {
            items
                .iter()
                .find(|task| task_matches(task, proposal) && task["state"] == "open")
        }) {
            break task.clone();
        }
        if std::time::Instant::now() >= deadline {
            bail!("the exact submitted Proposal did not reach an open Casework task");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let id = task["taskId"]
        .as_str()
        .filter(|id| uuid::Uuid::parse_str(id).is_ok())
        .context("Casework task has no UUID")?;
    let url = format!("{origin}/v1/review-tasks/{id}");
    exchange(
        &http,
        reqwest::Method::GET,
        &format!("{url}/context"),
        token,
        None,
        None,
        "",
    )
    .await?;
    exchange(
        &http,
        reqwest::Method::POST,
        &format!("{url}/claim"),
        token,
        None,
        task["revision"].as_i64(),
        &format!("example-{id}-claim"),
    )
    .await?;
    let current = exchange(&http, reqwest::Method::GET, &url, token, None, None, "").await?;
    exchange(
        &http,
        reqwest::Method::POST,
        &format!("{url}/decisions"),
        token,
        Some(json!({"decision":{"type":"approve","outcome":"approved"}})),
        current["revision"].as_i64(),
        &format!("example-{id}-approve"),
    )
    .await?;
    Ok(())
}

fn task_matches(task: &Value, proposal: &ProposalCapture) -> bool {
    let (Some(version), Some(digest)) = (
        proposal.submission_version,
        proposal.effect_digest.as_deref(),
    ) else {
        return false;
    };
    task["subject"]["id"].as_str() == Some(proposal.id.to_string().as_str())
        && task["subject"]["version"].as_str() == Some(version.to_string().as_str())
        && task["subject"]["digest"].as_str() == Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_casework_command_keeps_its_flat_report_payload() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("caseworkctl");
        fs::write(
            &binary,
            concat!(
                "#!/usr/bin/env bash\nset -euo pipefail\n",
                "printf '%s\\n' '{\"ok\":true,\"command\":\"check\",",
                "\"status\":\"complete\",\"kind\":\"CaseworkReport\",",
                "\"policyBindings\":[{\"policy\":\"permit-review\"}]}'\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();

        let report = ctl(&binary, vec!["check".into()], root.path()).unwrap();
        assert_eq!(report["policyBindings"][0]["policy"], "permit-review");
        assert!(report.get("data").is_none());
    }

    #[test]
    fn generated_review_yaml_keeps_schema_hints_notes_and_bindings() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().canonicalize().unwrap();
        let fixtures: [(&str, &[u8]); 3] = [
            (
                "breg-dev-clients.yaml",
                include_bytes!("../../../../../products/breg/examples/facility/dev-clients.yaml"),
            ),
            (
                "casework-dev-clients.yaml",
                include_bytes!(
                    "../../../../../products/casework/examples/canonical-review/dev-clients.yaml"
                ),
            ),
            (
                "casework.yaml",
                include_bytes!(
                    "../../../../../products/casework/examples/canonical-review/casework.yaml"
                ),
            ),
        ];
        for (name, bytes) in fixtures {
            fs::write(directory.join(name), bytes).unwrap();
        }
        let breg_file = directory.join(fixtures[0].0);
        let casework_file = directory.join(fixtures[1].0);
        let project_file = directory.join(fixtures[2].0);
        let mut breg = authored(&breg_file).unwrap();
        let mut casework = authored(&casework_file).unwrap();
        let mut project = authored(&project_file).unwrap();
        let original_project = project.clone();
        local_clients(&mut breg, &mut casework, "http://127.0.0.1:28096/").unwrap();
        bind_producer(
            &mut project,
            &json!({"issuer":"http://127.0.0.1:28093", "subject":"owner-requester"}),
        )
        .unwrap();
        for (file, value) in [
            (&breg_file, &breg),
            (&casework_file, &casework),
            (&project_file, &project),
        ] {
            let original = fs::read_to_string(file).unwrap();
            write(file, value).unwrap();
            let rendered = fs::read_to_string(file).unwrap();
            assert!(rendered.starts_with(original.lines().next().unwrap()));
            assert!(rendered.starts_with("# yaml-language-server: $schema="));
            assert!(rendered.contains("\napiVersion: "));
            assert_eq!(authored(file).unwrap(), *value);
            for comment in original.lines().filter(|line| line.trim().starts_with('#')) {
                assert!(rendered.lines().any(|line| line.trim() == comment.trim()));
            }
        }
        config::clients("dev-clients.yaml", &fs::read(&breg_file).unwrap()).unwrap();
        assert_eq!(breg["reviewAuthorities"]["casework"]["client"], "requester");
        assert_eq!(
            project["reviewPolicies"],
            original_project["reviewPolicies"]
        );
        assert_eq!(
            project["contextProviders"],
            original_project["contextProviders"]
        );
        assert_eq!(
            project["trustedProducers"]["requester"],
            original_project["trustedProducers"]["requester"]
        );
        assert_eq!(fs::read_dir(directory).unwrap().count(), fixtures.len());
    }

    #[test]
    fn observation_retries_only_an_explicit_pending_state() {
        let pending = json!({"diagnostics":[{"code":"examples.failed","message":proposals::PENDING_OBSERVATION}]});
        assert!(observation_is_pending(&pending));
        let retained = json!({"diagnostics":[{"code":"examples.failed","message":format!("example observe-address-correction attempt retained 0 confirmed steps; resume the original operation: {}",proposals::PENDING_OBSERVATION)}]});
        assert!(observation_is_pending(&retained));
        let refused = json!({"diagnostics":[{"code":"examples.failed","message":"example input must contain exactly the scenario's declared payload keys"}]});
        assert!(!observation_is_pending(&refused));
    }

    #[tokio::test]
    async fn claim_sends_an_empty_revision_fenced_idempotent_http_request() {
        let app = axum::Router::new().route(
            "/claim",
            axum::routing::post(
                |headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
                    assert!(body.is_empty());
                    assert_eq!(headers["if-match"], "\"7\"");
                    assert_eq!(headers["idempotency-key"], "example-claim");
                    assert_eq!(headers["registry-casework-profile"], "staff");
                    assert_eq!(headers["registry-source-profile"], "proposal-reviewer");
                    assert_eq!(headers["authorization"], "Bearer synthetic-token");
                    axum::Json(json!({"claimed":true}))
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/claim", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let token = bearer_from_header("Authorization: Bearer synthetic-token\nRegistry-Casework-Profile: staff\nRegistry-Review-Profile: staff\n").unwrap();
        let response = exchange(
            &http,
            reqwest::Method::POST,
            &url,
            token.as_str(),
            None,
            Some(7),
            "example-claim",
        )
        .await
        .unwrap();
        server.abort();
        assert_eq!(response, json!({"claimed":true}));
        assert!(
            bearer_from_header("Authorization: Bearer one\nAuthorization: Bearer two\n").is_err()
        );
    }

    #[test]
    fn local_connection_preserves_unrelated_trusted_producers() {
        let mut project = Reader::new("casework.yaml")
            .scan(include_bytes!(
                "../../../../../products/casework/examples/canonical-review/casework.yaml"
            ))
            .unwrap()
            .unwrap()
            .to_json_value();
        let unrelated = project["trustedProducers"]["requester"].clone();
        let identity = json!({"issuer":"http://127.0.0.1:28093", "subject":"owner-requester"});
        bind_producer(&mut project, &identity).unwrap();
        assert_eq!(project["trustedProducers"]["requester"], unrelated);
        let producer = &project["trustedProducers"]["facility-registry"];
        assert_eq!(producer["issuer"], identity["issuer"]);
        assert_eq!(producer["subject"], identity["subject"]);
        assert_eq!(producer["trustedInitiatorIssuer"], identity["issuer"]);
    }

    #[test]
    fn local_review_connection_reuses_authored_clients_and_exact_submission() {
        let mut breg = Reader::new("dev-clients.yaml")
            .scan(include_bytes!(
                "../../../../../products/breg/examples/facility/dev-clients.yaml"
            ))
            .unwrap()
            .unwrap()
            .to_json_value();
        let mut casework = Reader::new("dev-clients.yaml")
            .scan(include_bytes!(
                "../../../../../products/casework/examples/canonical-review/dev-clients.yaml"
            ))
            .unwrap()
            .unwrap()
            .to_json_value();
        local_clients(&mut breg, &mut casework, "http://127.0.0.1:28096/").unwrap();
        config::clients("dev-clients.yaml", &serde_json::to_vec(&breg).unwrap()).unwrap();
        let staff = breg["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|client| client["id"] == "staff")
            .unwrap();
        let reviewer = casework["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|client| client["id"] == "staff")
            .unwrap();
        assert_eq!(staff["claims"], reviewer["claims"]);
        assert_eq!(staff["scopes"], reviewer["scopes"]);
        let proposal = ProposalCapture {
            action: "correct-address".to_owned(),
            id: uuid::Uuid::new_v4(),
            submission_version: Some(1),
            effect_digest: Some(format!("sha256:{}", "a".repeat(64))),
            action_revision: None,
        };
        let mut task =
            json!({"subject":{"id":proposal.id,"version":"1","digest":proposal.effect_digest}});
        assert!(task_matches(&task, &proposal));
        task["subject"]["version"] = json!("2");
        assert!(!task_matches(&task, &proposal));
    }
}
