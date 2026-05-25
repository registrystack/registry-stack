#!/usr/bin/env python3
"""Narrated live-service stories for registry-lab."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "compose.yaml"
SERVICE_FIRST_DEPS = ROOT / "scripts" / "check-service-first-deps.sh"
PURPOSE = "https://demo.example.gov/purpose/live-service-stories"
CORRELATION_ID = os.environ.get("DEMO_CORRELATION_ID", "registry-lab-live-stories-001")
SERVICE_IRI = "https://demo.example.gov/services/health-linked-child-support"
STATIC_METADATA_URL = os.environ.get("STATIC_METADATA_URL", "http://127.0.0.1:4331")
STATIC_CPSV_PATH = "/metadata/cpsv-ap"


class StoryError(RuntimeError):
    pass


@dataclass
class HttpResult:
    status: int
    body: Any
    headers: dict[str, str]


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def env(name: str, values: dict[str, str], default: str | None = None) -> str:
    value = os.environ.get(name) or values.get(name) or default
    if not value:
        raise StoryError(f"missing required environment variable: {name}")
    return value


def run(cmd: list[str], *, cwd: Path = ROOT, env_updates: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    child_env = os.environ.copy()
    if env_updates:
        child_env.update(env_updates)
    result = subprocess.run(cmd, cwd=cwd, env=child_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        detail = stderr or stdout or f"exit status {result.returncode}"
        raise StoryError(f"command failed: {' '.join(cmd)}\n{detail}")
    return result


def compose(*args: str, env_updates: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return run(["docker", "compose", "-f", str(COMPOSE_FILE), *args], env_updates=env_updates)


def atlas_root() -> Path:
    return service_first_dependency_path("atlas")


def service_first_dependency_path(kind: str) -> Path:
    result = run([str(SERVICE_FIRST_DEPS), f"{kind}-path"])
    return Path(result.stdout.strip())


def require_service_first_dependencies() -> None:
    run([str(SERVICE_FIRST_DEPS), "all"])


def publish_static_metadata() -> None:
    run([str(ROOT / "scripts" / "publish-static-metadata.sh")])


def run_atlas_analyze(catalogue_path: Path) -> dict[str, Any]:
    atlas = atlas_root()
    result = run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "semantic-asset-discovery-cli",
            "--bin",
            "semantic-asset-discovery",
            "--",
            "analyze",
            "--entry-url",
            urllib.parse.urljoin(STATIC_METADATA_URL.rstrip("/") + "/", STATIC_CPSV_PATH.lstrip("/")),
            str(catalogue_path),
        ],
        cwd=atlas,
    )
    return json.loads(result.stdout)


def write_atlas_service_graph_helper(out: Path) -> Path:
    atlas = atlas_root()
    core_path = atlas / "crates" / "semantic-asset-discovery-core"
    if not core_path.exists():
        raise StoryError(f"Atlas semantic discovery core crate not found: {core_path}")
    helper = out / "_atlas-service-first-query"
    src = helper / "src"
    src.mkdir(parents=True, exist_ok=True)
    (helper / "Cargo.toml").write_text(
        "\n".join(
            [
                "[package]",
                'name = "registry-lab-atlas-service-first-query"',
                'version = "0.1.0"',
                'edition = "2021"',
                "",
                "[dependencies]",
                f"semantic-asset-discovery-core = {{ path = {json.dumps(str(core_path))} }}",
                'serde_json = "1"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (src / "main.rs").write_text(
        r'''
use semantic_asset_discovery_core::{
    DiscoveryEvidence, DiscoveryReport, RelationClaim, SemanticAsset, SemanticRelation,
    ServiceGraph,
};
use serde_json::{json, Value};
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let report_path = args.next().ok_or("missing report path")?;
    let service_iri = args.next().ok_or("missing service IRI")?;
    let report: DiscoveryReport = serde_json::from_str(&fs::read_to_string(report_path)?)?;
    let graph = ServiceGraph::from_report(&report)?;
    let service = graph.public_service(&service_iri)?;

    let requirements = service
        .requirements()
        .into_iter()
        .map(|requirement| {
            let evidence_options = requirement
                .evidence_options()
                .into_iter()
                .map(|option| {
                    let evidence_types = option
                        .evidence_types()
                        .into_iter()
                        .map(|evidence_type| {
                            json!({
                                "asset": asset_value(&graph, evidence_type.asset),
                                "relations": relation_values(evidence_type.relations()),
                                "claims": claim_values(evidence_type.claims()),
                                "source_evidence": evidence_values(evidence_type.evidence()),
                            })
                        })
                        .collect::<Vec<_>>();
                    let missing_evidence_types = option
                        .missing_evidence_types()
                        .into_iter()
                        .map(|evidence_type| asset_value(&graph, evidence_type.asset))
                        .collect::<Vec<_>>();
                    json!({
                        "asset": asset_value(&graph, option.asset),
                        "evidence_types": evidence_types,
                        "missing_evidence_types": missing_evidence_types,
                        "satisfiable": option.is_satisfiable(),
                        "relations": relation_values(option.relations()),
                        "claims": claim_values(option.claims()),
                        "source_evidence": evidence_values(option.evidence()),
                    })
                })
                .collect::<Vec<_>>();
            let accepted_evidence_types = requirement
                .accepted_evidence_types()
                .into_iter()
                .map(|evidence_type| {
                    json!({
                        "asset": asset_value(&graph, evidence_type.asset),
                        "relations": relation_values(evidence_type.relations()),
                        "claims": claim_values(evidence_type.claims()),
                        "source_evidence": evidence_values(evidence_type.evidence()),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "asset": asset_value(&graph, requirement.asset),
                "evidence_options": evidence_options,
                "accepted_evidence_types": accepted_evidence_types,
                "relations": relation_values(requirement.relations()),
                "claims": claim_values(requirement.claims()),
                "source_evidence": evidence_values(requirement.evidence()),
            })
        })
        .collect::<Vec<_>>();

    let accepted_evidence_types = service
        .accepted_evidence_types()
        .into_iter()
        .map(|evidence_type| {
            json!({
                "asset": asset_value(&graph, evidence_type.asset),
                "relations": relation_values(evidence_type.relations()),
                "claims": claim_values(evidence_type.claims()),
                "source_evidence": evidence_values(evidence_type.evidence()),
            })
        })
        .collect::<Vec<_>>();

    let evidence_provider_map = service
        .accepted_evidence_types()
        .into_iter()
        .map(|evidence_type| {
            let offerings = evidence_type
                .evidence_offerings()
                .into_iter()
                .map(|offering| {
                    let providers = offering
                        .providers()
                        .into_iter()
                        .map(|provider| {
                            json!({
                                "asset": asset_value(&graph, provider.asset),
                                "relations": relation_values(provider.relations()),
                                "claims": claim_values(provider.claims()),
                                "source_evidence": evidence_values(provider.evidence()),
                            })
                        })
                        .collect::<Vec<_>>();
                    let access_services = offering
                        .access_services()
                        .into_iter()
                        .map(|service| {
                            json!({
                                "asset": asset_value(&graph, service.asset),
                                "relations": relation_values(service.relations()),
                                "claims": claim_values(service.claims()),
                                "source_evidence": evidence_values(service.evidence()),
                            })
                        })
                        .collect::<Vec<_>>();
                    json!({
                        "asset": asset_value(&graph, offering.asset),
                        "providers": providers,
                        "access_services": access_services,
                        "relations": relation_values(offering.relations()),
                        "claims": claim_values(offering.claims()),
                        "source_evidence": evidence_values(offering.evidence()),
                    })
                })
                .collect::<Vec<_>>();
            let providers = evidence_type
                .providers()
                .into_iter()
                .map(|provider| {
                    json!({
                        "asset": asset_value(&graph, provider.asset),
                        "relations": relation_values(provider.relations()),
                        "claims": claim_values(provider.claims()),
                        "source_evidence": evidence_values(provider.evidence()),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "evidence_type": asset_value(&graph, evidence_type.asset),
                "providers": providers,
                "offerings": offerings,
            })
        })
        .collect::<Vec<_>>();

    let channels = service
        .channels()
        .into_iter()
        .map(|channel| {
            json!({
                "asset": asset_value(&graph, channel.asset),
                "relations": relation_values(channel.relations()),
                "claims": claim_values(channel.claims()),
                "source_evidence": evidence_values(channel.evidence()),
            })
        })
        .collect::<Vec<_>>();

    let forms = service
        .forms()
        .into_iter()
        .map(|form| {
            json!({
                "asset": asset_value(&graph, form.asset),
                "relations": relation_values(form.relations()),
                "claims": claim_values(form.claims()),
                "source_evidence": evidence_values(form.evidence()),
            })
        })
        .collect::<Vec<_>>();

    let routes = graph
        .routes_for_service(service.id())
        .into_iter()
        .map(|route| {
            json!({
                "route_kind": format!("{:?}", route.route_kind),
                "service": asset_value(&graph, route.service),
                "target": asset_value(&graph, route.target),
                "relations": relation_values(route.relations()),
                "claims": claim_values(route.claims()),
                "source_evidence": evidence_values(route.evidence()),
            })
        })
        .collect::<Vec<_>>();

    let gaps = service
        .gaps()
        .into_iter()
        .map(|gap| {
            json!({
                "asset_id": gap.asset_id,
                "predicate": gap.predicate,
                "message": gap.message,
            })
        })
        .collect::<Vec<_>>();

    let output = json!({
        "service": asset_value(&graph, service.asset),
        "channels": channels,
        "requirements": requirements,
        "accepted_evidence_types": accepted_evidence_types,
        "evidence_provider_map": evidence_provider_map,
        "forms": forms,
        "routes": routes,
        "gaps": gaps,
        "report": {
            "run_id": &report.run_id,
            "schema_version": &report.schema_version,
            "artifact_count": report.artifacts.len(),
            "asset_count": report.assets.len(),
            "relation_count": report.relations.len(),
            "relation_claim_count": report.relation_claims.len(),
        },
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn asset_value(graph: &ServiceGraph<'_>, asset: &SemanticAsset) -> Value {
    let endpoint = graph.endpoint_url_for_asset(&asset.id);
    json!({
        "id": &asset.id,
        "kind": &asset.kind,
        "uri": &asset.uri,
        "title": &asset.title,
        "description": &asset.description,
        "artifact_id": &asset.artifact_id,
        "endpoint_url": endpoint.as_ref().map(|item| item.url),
        "endpoint_relation_id": endpoint.as_ref().map(|item| item.relation_id),
        "conforms_to": &asset.conforms_to,
    })
}

fn relation_values(relations: &[&SemanticRelation]) -> Value {
    json!(relations)
}

fn claim_values(claims: Vec<&RelationClaim>) -> Value {
    json!(claims)
}

fn evidence_values(evidence: Vec<&DiscoveryEvidence>) -> Vec<Value> {
    evidence
        .into_iter()
        .map(|item| {
            json!({
                "location": item.location(),
                "evidence": item,
            })
        })
        .collect()
}

'''.lstrip(),
        encoding="utf-8",
    )
    return helper / "Cargo.toml"


def run_atlas_service_graph(out: Path, report_path: Path) -> dict[str, Any]:
    manifest = write_atlas_service_graph_helper(out)
    result = run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(manifest),
            "--",
            str(report_path),
            SERVICE_IRI,
        ],
    )
    return json.loads(result.stdout)


def output_dir() -> Path:
    path = Path(os.environ.get("DEMO_LIVE_OUTPUT_DIR", ROOT / "output" / "live-stories"))
    if path.exists():
        for child in path.iterdir():
            if child.name == ".gitignore":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    path.mkdir(parents=True, exist_ok=True)
    return path


def save(out: Path, index: int, label: str, payload: Any) -> Path:
    path = out / f"{index:02d}-{label}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"    artifact: {path}")
    return path


def save_named_json(out: Path, name: str, payload: Any) -> Path:
    path = out / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"    artifact: {path}")
    return path


def save_named_text(out: Path, name: str, payload: str) -> Path:
    path = out / name
    path.write_text(payload, encoding="utf-8")
    print(f"    artifact: {path}")
    return path


def explain(message: str = "") -> None:
    if message:
        print(f"  explain: {message}")
    else:
        print()


def show_query(method: str, base_url: str, path: str, *, purpose: bool = False, body: Any | None = None) -> None:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    print(f"  query: {method} {url}")
    print(f"    header: x-request-id={CORRELATION_ID}")
    if purpose:
        print(f"    header: Data-Purpose={PURPOSE}")
    if body is not None:
        print(f"    body: {json.dumps(body, sort_keys=True)}")


def show_status(result: HttpResult) -> None:
    print(f"    status: HTTP {result.status}")


def list_names(items: list[Any], key: str, limit: int = 5) -> str:
    values = [str(item.get(key)) for item in items if isinstance(item, dict) and item.get(key)]
    if len(values) > limit:
        return ", ".join(values[:limit]) + f", +{len(values) - limit} more"
    return ", ".join(values) if values else "none"


def summarize_postgres_metadata(metadata: Any) -> None:
    catalog = metadata.get("catalog", {}) if isinstance(metadata, dict) else {}
    datasets = catalog.get("datasets", []) if isinstance(catalog, dict) else []
    dataset = datasets[0] if datasets and isinstance(datasets[0], dict) else {}
    entities = dataset.get("entities", []) if isinstance(dataset, dict) else []
    entity = entities[0] if entities and isinstance(entities[0], dict) else {}
    fields = entity.get("fields", []) if isinstance(entity, dict) else []
    explain(
        "Relay published dataset "
        f"`{dataset.get('dataset_id')}` with entity `{entity.get('name')}` "
        f"and fields: {list_names(fields, 'name')}."
    )


def summarize_row_read(label: str, response: Any) -> int:
    rows = response.get("data", []) if isinstance(response, dict) else []
    count = len(rows) if isinstance(rows, list) else 0
    ids = list_names(rows, "id") if isinstance(rows, list) else "none"
    explain(f"{label}: Relay returned {count} declared row(s); visible ids: {ids}.")
    return count


def summarize_oidc_discovery(discovery: Any) -> None:
    if not isinstance(discovery, dict):
        explain("OIDC discovery returned a non-JSON body.")
        return
    explain(
        "Zitadel discovery returned issuer "
        f"`{discovery.get('issuer')}` and JWKS endpoint `{discovery.get('jwks_uri')}`."
    )


def summarize_oidc_claims(decoded: dict[str, Any]) -> None:
    claims = decoded.get("claims", {})
    audience = decoded.get("audience")
    if isinstance(audience, list):
        audience_text = ", ".join(str(item) for item in audience)
    else:
        audience_text = str(audience)
    explain(
        "The access token is decoded only for presentation: "
        f"issuer `{claims.get('iss')}`, audience `{audience_text}`, "
        f"subject `{decoded.get('subject')}`, alg `{decoded.get('header', {}).get('alg')}`."
    )


def summarize_openfn_discovery(discovery: Any) -> None:
    if not isinstance(discovery, dict):
        explain("Witness discovery returned a non-JSON body.")
        return
    formats = discovery.get("formats", [])
    format_ids = list_names(formats, "id") if isinstance(formats, list) else "none"
    explain(
        f"Witness `{discovery.get('service_id')}` advertises claims at "
        f"`{discovery.get('claims_url')}` and supports formats: {format_ids}."
    )


def summarize_claims(claims: Any) -> None:
    data = claims.get("data", []) if isinstance(claims, dict) else []
    explain(f"Claim discovery returned {len(data)} claim(s): {list_names(data, 'id')}.")


def summarize_openfn_evaluation(evaluation: Any) -> None:
    results = evaluation.get("results", []) if isinstance(evaluation, dict) else []
    result = results[0] if results and isinstance(results[0], dict) else {}
    provenance = result.get("provenance", {}) if isinstance(result, dict) else {}
    explain(
        "Witness evaluated the discovered claim "
        f"`{result.get('claim_id')}` with value `{result.get('value')}` "
        f"from {provenance.get('source_count')} sidecar-backed source(s)."
    )


def artifact_path(out: Path, label: str) -> Path | None:
    matches = sorted(out.glob(f"*-{label}.json"))
    return matches[0] if matches else None


def artifact_ref(out: Path, label: str) -> str:
    path = artifact_path(out, label)
    return path.name if path else f"missing:{label}"


def artifact_json(out: Path, label: str, default: Any = None) -> Any:
    path = artifact_path(out, label)
    if not path:
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def parse_body(raw: bytes) -> Any:
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def request(
    method: str,
    base_url: str,
    path: str,
    token: str | None = None,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> HttpResult:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    req_headers = {"Accept": "*/*", "x-request-id": CORRELATION_ID}
    if token:
        req_headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return HttpResult(resp.status, parse_body(resp.read()), dict(resp.headers))
    except urllib.error.HTTPError as exc:
        return HttpResult(exc.code, parse_body(exc.read()), dict(exc.headers))
    except urllib.error.URLError as exc:
        raise StoryError(f"{method} {url} failed: {exc}") from exc


def require(result: HttpResult, status: int, label: str) -> Any:
    if result.status != status:
        raise StoryError(f"{label} returned HTTP {result.status}, expected {status}: {result.body}")
    return result.body


def wait_for(label: str, fn, timeout: int = 180) -> None:
    deadline = time.time() + timeout
    last = "not attempted"
    while time.time() < deadline:
        try:
            fn()
            print(f"  ready: {label}")
            return
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
            time.sleep(2)
    raise StoryError(f"timed out waiting for {label}: {last}")


def fingerprint(raw: str) -> str:
    return "sha256:" + hashlib.sha256(raw.encode("ascii")).hexdigest()


def b64_json(segment: str) -> Any:
    padded = segment + ("=" * (-len(segment) % 4))
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


def decode_jwt(token: str) -> dict[str, Any]:
    header, payload, _signature = token.split(".", 2)
    claims = b64_json(payload)
    return {
        "header": b64_json(header),
        "claims": {key: claims[key] for key in sorted(claims) if key not in {"jti"}},
        "audience": claims.get("aud"),
        "subject": claims.get("sub"),
    }


def wait_zitadel_init(out: Path) -> Path:
    compose("up", "-d", "zitadel-init")
    deadline = time.time() + int(os.environ.get("ZITADEL_WAIT_SECONDS", "180"))
    while time.time() < deadline:
        cid = compose("ps", "-a", "-q", "zitadel-init").stdout.strip()
        if cid:
            state = run(["docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", cid]).stdout.strip()
            if state == "exited 0":
                env_path = out / "zitadel.env"
                subprocess.run(
                    ["docker", "compose", "-f", str(COMPOSE_FILE), "cp", "zitadel-init:/seed/zitadel.env", str(env_path)],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return env_path
            if state.startswith("exited ") and state != "exited 0":
                logs = compose("logs", "--no-color", "zitadel-init").stderr
                raise StoryError(f"zitadel-init failed ({state}): {logs}")
        time.sleep(2)
    raise StoryError("zitadel-init did not complete")


def mint_zitadel_token(zitadel_env: dict[str, str]) -> str:
    issuer = zitadel_env["OIDC_ISSUER"].rstrip("/")
    data = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": os.environ.get("OIDC_SCOPE", "openid")}).encode()
    req = urllib.request.Request(f"{issuer}/oauth/v2/token", data=data, method="POST")
    basic = base64.b64encode(f"{zitadel_env['OIDC_SA_CLIENT_ID']}:{zitadel_env['OIDC_SA_CLIENT_SECRET']}".encode()).decode()
    req.add_header("Authorization", f"Basic {basic}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=20) as resp:
        payload = json.loads(resp.read())
    return payload["access_token"]


def psql(sql: str) -> None:
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "registry_lab"],
        cwd=ROOT,
        input=sql,
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def start_relay(config_path: Path, log_path: Path, port: int, env_updates: dict[str, str]) -> subprocess.Popen[str]:
    relay_dir = Path(os.environ.get("REGISTRY_RELAY_SOURCE_DIR", ROOT / "vendor" / "registry-relay"))
    child_env = os.environ.copy()
    child_env.update(env_updates)
    log = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        ["cargo", "run", "--", "--config", str(config_path)],
        cwd=relay_dir,
        env=child_env,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    def check_health() -> None:
        if proc.poll() is not None:
            raise StoryError(f"Relay on {port} exited during startup; see {log_path}")
        require(request("GET", f"http://127.0.0.1:{port}", "/health"), 200, "relay health")

    wait_for(f"Relay on {port}", check_health, timeout=180)
    return proc


def stop_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def write_postgres_story_config(out: Path, port: int) -> Path:
    path = out / "postgres-live-relay.yaml"
    cache = out / "postgres-relay-cache"
    db_url_env = "POSTGRES_STORY_DATABASE_URL"
    path.write_text(
        f"""server:
  bind: 127.0.0.1:{port}
  cache_dir: {cache}

catalog:
  title: Postgres Source Relay (Registry Lab)
  base_url: http://127.0.0.1:{port}
  publisher: Social Protection Authority (Database Story)

vocabularies:
  demo: https://demo.example.gov/vocab/

auth:
  mode: api_key
  api_keys:
    - id: live_story_reader
      hash_env: POSTGRES_STORY_READER_HASH
      scopes:
        - postgres_registry:metadata
        - postgres_registry:rows

audit:
  sink: stdout
  format: jsonl
  hash_secret_env: REGISTRY_RELAY_AUDIT_HASH_SECRET

datasets:
  - id: postgres_registry
    title: Postgres-backed Registry
    description: Live database source used by the registry-lab story runner.
    owner: Social Protection Authority
    sensitivity: personal
    access_rights: restricted
    update_frequency: continuous
    defaults:
      refresh:
        mode: manual
    tables:
      - id: beneficiaries_live
        materialization: live
        source:
          type: postgres
          connection_env: {db_url_env}
          table:
            schema: demo_story
            name: beneficiaries
          query_timeout: 10s
          live_max_connections: 2
        primary_key: beneficiary_id
        schema:
          strict: true
          fields:
            - name: beneficiary_id
              type: integer
              nullable: false
            - name: national_id
              type: string
              nullable: false
              sensitive: true
            - name: program
              type: string
              nullable: false
            - name: amount
              type: number
              nullable: false
            - name: status
              type: string
              nullable: false
            - name: updated_at
              type: timestamp
              nullable: false
    entities:
      - name: beneficiary
        title: Benefit Case
        description: Live benefit case read from Postgres.
        table: beneficiaries_live
        concept_uri: demo:BenefitCase
        fields:
          - name: id
            from: beneficiary_id
          - name: national_id
          - name: program
          - name: amount
          - name: status
          - name: updated_at
        access:
          metadata_scope: postgres_registry:metadata
          aggregate_scope: postgres_registry:aggregate
          read_scope: postgres_registry:rows
          evidence_verification_scope: postgres_registry:evidence_verification
        api:
          default_limit: 25
          max_limit: 100
          require_purpose_header: true
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: national_id
              ops: [eq, in]
            - field: status
              ops: [eq, in]
""",
        encoding="utf-8",
    )
    return path


def write_oidc_story_config(out: Path, port: int, issuer: str, audience: list[str]) -> Path:
    path = out / "oidc-social-relay.yaml"
    cache = out / "oidc-relay-cache"
    audience_yaml = "\n".join(f"      - {json.dumps(value)}" for value in audience)
    path.write_text(
        f"""server:
  bind: 127.0.0.1:{port}
  cache_dir: {cache}

catalog:
  title: OIDC Social Protection Relay (Registry Lab)
  base_url: http://127.0.0.1:{port}
  publisher: Social Protection Authority (OIDC Story)

vocabularies:
  demo: https://demo.example.gov/vocab/

auth:
  mode: oidc
  oidc:
    issuer: {issuer}
    audience:
{audience_yaml}
    discovery_url: {issuer.rstrip("/")}/.well-known/openid-configuration
    algorithms: [RS256, ES256, EdDSA]
    jwks_cache_ttl: 10m
    leeway: 60s
    scope_claim: "urn:zitadel:iam:org:project:roles"
    scope_map:
      "social-registry-reader": "social_protection_registry:rows"
      "social-registry-aggregate": "social_protection_registry:aggregate"
    allowed_clients: []
    token_types: [JWT, at+jwt]

audit:
  sink: stdout
  format: jsonl
  hash_secret_env: REGISTRY_RELAY_AUDIT_HASH_SECRET

datasets:
  - id: social_protection_registry
    title: Social Protection Registry
    description: OIDC-protected slice of the registry-lab social protection fixture.
    owner: Social Protection Authority
    sensitivity: personal
    access_rights: restricted
    update_frequency: weekly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: households_table
        materialization: snapshot
        source:
          type: file
          path: {ROOT / "data" / "social-protection" / "social-protection.xlsx"}
          format:
            xlsx:
              sheet: Households
              header_row: 1
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
            - name: national_id
              type: string
              nullable: false
              sensitive: true
            - name: district
              type: string
              nullable: false
            - name: poverty_score
              type: number
              nullable: false
            - name: eligibility_band
              type: string
              nullable: false
    entities:
      - name: household
        title: Household
        description: OIDC-protected household projection.
        table: households_table
        concept_uri: demo:Household
        fields:
          - name: id
            from: household_id
          - name: national_id
          - name: district
          - name: poverty_score
          - name: eligibility_band
        access:
          metadata_scope: social_protection_registry:metadata
          aggregate_scope: social_protection_registry:aggregate
          read_scope: social_protection_registry:rows
          evidence_verification_scope: social_protection_registry:evidence_verification
        api:
          default_limit: 25
          max_limit: 100
          require_purpose_header: true
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: national_id
              ops: [eq, in]
""",
        encoding="utf-8",
    )
    return path


def service_graph_names(items: list[Any]) -> str:
    names = []
    for item in items:
        asset = item.get("asset", item) if isinstance(item, dict) else {}
        if isinstance(asset, dict):
            names.append(str(asset.get("title") or asset.get("uri") or asset.get("id")))
    return ", ".join(name for name in names if name and name != "None") or "none"


def summarize_service_graph(graph: dict[str, Any]) -> None:
    service = graph.get("service", {})
    explain(f"Atlas selected public service `{service.get('title')}` from `{service.get('uri')}`.")
    explain(f"Atlas found requirements: {service_graph_names(graph.get('requirements', []))}.")
    explain(f"Atlas found accepted evidence types: {service_graph_names(graph.get('accepted_evidence_types', []))}.")
    option_count = sum(len(req.get("evidence_options", [])) for req in graph.get("requirements", []))
    explain(f"Atlas preserved {option_count} CCCEV evidence option group(s).")
    provider_names = []
    for entry in graph.get("evidence_provider_map", []):
        for provider in entry.get("providers", []):
            asset = provider.get("asset", {})
            provider_names.append(str(asset.get("title") or asset.get("uri") or asset.get("id")))
    explain(f"Atlas resolved evidence providers: {', '.join(provider_names) if provider_names else 'none'}.")
    gaps = graph.get("gaps", [])
    explain(f"Atlas reported {len(gaps)} service graph gap(s).")


def requirement_evidence_map(graph: dict[str, Any]) -> list[dict[str, Any]]:
    entries = []
    for requirement in graph.get("requirements", []):
        requirement_asset = requirement.get("asset", {})
        entries.append(
            {
                "requirement": requirement_asset,
                "evidence_options": [
                    {
                        "option": option.get("asset", {}),
                        "satisfiable": option.get("satisfiable"),
                        "evidence_types": [
                            evidence_type.get("asset", {})
                            for evidence_type in option.get("evidence_types", [])
                        ],
                        "missing_evidence_types": option.get("missing_evidence_types", []),
                    }
                    for option in requirement.get("evidence_options", [])
                ],
                "accepted_evidence_types": [
                    evidence_type.get("asset", {})
                    for evidence_type in requirement.get("accepted_evidence_types", [])
                ],
                "source_evidence": requirement.get("source_evidence", []),
            }
        )
    return entries


def selected_evidence_type_iris(graph: dict[str, Any]) -> list[str]:
    selected: list[str] = []
    for requirement in graph.get("requirements", []):
        options = [
            option
            for option in requirement.get("evidence_options", [])
            if option.get("satisfiable") is True
        ]
        if options:
            option = sorted(options, key=lambda item: len(item.get("evidence_types", [])))[0]
            selected.extend(
                str(evidence_type.get("asset", {}).get("uri"))
                for evidence_type in option.get("evidence_types", [])
                if evidence_type.get("asset", {}).get("uri")
            )
            continue
        selected.extend(
            str(evidence_type.get("asset", {}).get("uri"))
            for evidence_type in requirement.get("accepted_evidence_types", [])
            if evidence_type.get("asset", {}).get("uri")
        )
    return list(dict.fromkeys(selected))


def form_schema_url(index: dict[str, Any], form_id: str) -> str | None:
    for entry in index.get("form_schemas", []):
        if isinstance(entry, dict) and entry.get("form") == form_id:
            return str(entry.get("url"))
    return None


def service_form_sample() -> dict[str, Any]:
    return {
        "supportType": "health_linked",
        "applicantNationalId": "NID-1001",
        "children": [{"childNationalId": "NID-2001"}],
        "healthDistrict": "central",
    }


def validate_sample_payload(schema: dict[str, Any], payload: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(payload, dict):
            return [f"{path} must be an object"]
        for name in schema.get("required", []):
            if name not in payload:
                errors.append(f"{path}.{name} is required")
        properties = schema.get("properties", {})
        for key in payload:
            if schema.get("additionalProperties") is False and key not in properties:
                errors.append(f"{path}.{key} is not allowed")
        for key, child_schema in properties.items():
            if key in payload and isinstance(child_schema, dict):
                errors.extend(validate_sample_payload(child_schema, payload[key], f"{path}.{key}"))
    elif expected_type == "array":
        if not isinstance(payload, list):
            return [f"{path} must be an array"]
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if isinstance(min_items, int) and len(payload) < min_items:
            errors.append(f"{path} must contain at least {min_items} item(s)")
        if isinstance(max_items, int) and len(payload) > max_items:
            errors.append(f"{path} must contain at most {max_items} item(s)")
        item_schema = schema.get("items", {})
        if isinstance(item_schema, dict):
            for index, item in enumerate(payload):
                errors.extend(validate_sample_payload(item_schema, item, f"{path}[{index}]"))
    elif expected_type == "string" and not isinstance(payload, str):
        errors.append(f"{path} must be a string")
    elif expected_type == "boolean" and not isinstance(payload, bool):
        errors.append(f"{path} must be a boolean")
    elif expected_type == "integer" and not isinstance(payload, int):
        errors.append(f"{path} must be an integer")
    elif expected_type == "number" and not isinstance(payload, (int, float)):
        errors.append(f"{path} must be a number")
    return errors


def witness_call_config(values: dict[str, str]) -> dict[str, dict[str, str]]:
    return {
        "https://demo.example.gov/evidence-types/civil-child-status": {
            "token": env("CIVIL_EVIDENCE_CLIENT_BEARER", values),
            "claim": "person-is-alive",
            "subject": "NID-1001",
            "route_label": "civil child status via civil Witness",
        },
        "https://demo.example.gov/evidence-types/household-support": {
            "token": env("SOCIAL_EVIDENCE_CLIENT_BEARER", values),
            "claim": "beneficiary-active",
            "subject": "NID-1001",
            "route_label": "household support via social protection Witness",
        },
        "https://demo.example.gov/evidence-types/health-service-availability": {
            "token": env("SHARED_EVIDENCE_CLIENT_BEARER", values),
            "claim": "health-service-available",
            "subject": "NID-1001",
            "route_label": "health service availability via shared Witness",
        },
        "https://demo.example.gov/evidence-types/combined-support": {
            "token": env("SHARED_EVIDENCE_CLIENT_BEARER", values),
            "claim": "eligible-for-combined-support",
            "subject": "NID-1001",
            "route_label": "combined support via shared Witness",
        },
    }


def host_access_url(discovered_url: str) -> str:
    parsed = urllib.parse.urlparse(discovered_url)
    compose_to_host = compose_access_translations()
    replacement = compose_to_host.get((parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)))
    if not replacement:
        return discovered_url.rstrip("/")
    return replacement.rstrip("/")


def compose_access_translations() -> dict[tuple[str, int], str]:
    return {
        ("civil-witness", 8080): os.environ.get("CIVIL_WITNESS_URL", "http://127.0.0.1:4321"),
        ("social-protection-witness", 8080): os.environ.get("SOCIAL_PROTECTION_WITNESS_URL", "http://127.0.0.1:4322"),
        ("shared-eligibility-witness", 8080): os.environ.get("SHARED_ELIGIBILITY_WITNESS_URL", "http://127.0.0.1:4323"),
    }


def discovered_witness_routes(graph: dict[str, Any], values: dict[str, str]) -> dict[str, dict[str, Any]]:
    config = witness_call_config(values)
    routes: dict[str, dict[str, Any]] = {}
    for entry in graph.get("evidence_provider_map", []):
        evidence_type = entry.get("evidence_type", {})
        evidence_iri = evidence_type.get("uri")
        if not evidence_iri or evidence_iri not in config:
            continue
        for offering in entry.get("offerings", []):
            for access_service in offering.get("access_services", []):
                endpoint_url = access_service.get("asset", {}).get("endpoint_url")
                if not endpoint_url:
                    continue
                routes[evidence_iri] = {
                    **config[evidence_iri],
                    "base_url": host_access_url(endpoint_url),
                    "discovered_endpoint_url": endpoint_url,
                    "offering": offering.get("asset", {}),
                    "access_service": access_service.get("asset", {}),
                    "providers": offering.get("providers", []),
                }
                break
            if evidence_iri in routes:
                break
    return routes


def discovered_access_service_endpoints(graph: dict[str, Any]) -> set[str]:
    endpoints: set[str] = set()
    for entry in graph.get("evidence_provider_map", []):
        for offering in entry.get("offerings", []):
            for access_service in offering.get("access_services", []):
                endpoint_url = access_service.get("asset", {}).get("endpoint_url")
                if endpoint_url:
                    endpoints.add(str(endpoint_url).rstrip("/"))
    return endpoints


def validate_service_first_route_provenance(graph: dict[str, Any], evaluations: list[dict[str, Any]]) -> dict[str, Any]:
    discovered_endpoints = discovered_access_service_endpoints(graph)
    if not discovered_endpoints:
        raise StoryError("service-first validation found no discovered access-service endpoints")

    checked: list[dict[str, Any]] = []
    known_host_ports = {"4321", "4322", "4323"}
    for item in evaluations:
        if item.get("status") != "evaluated":
            continue
        discovered = str(item.get("discovered_endpoint_url", "")).rstrip("/")
        host_url = str(item.get("host_access_url", "")).rstrip("/")
        if discovered not in discovered_endpoints:
            raise StoryError(
                "service-first validation rejected a Witness route that was not selected "
                f"from Atlas access-service discovery: {discovered}"
            )
        expected_host_url = host_access_url(discovered).rstrip("/")
        if host_url != expected_host_url:
            raise StoryError(
                "service-first validation rejected a hard-coded Witness host route: "
                f"{host_url} was used, but {expected_host_url} is derived from {discovered}"
            )
        parsed_discovered = urllib.parse.urlparse(discovered)
        if (parsed_discovered.hostname or "") in {"127.0.0.1", "localhost"} and str(parsed_discovered.port or "") in known_host_ports:
            raise StoryError(
                "service-first validation expected a discovered Compose access-service endpoint, "
                f"not a host-port URL: {discovered}"
            )
        checked.append(
            {
                "evidence_type": item.get("evidence_type", {}).get("uri"),
                "discovered_endpoint_url": discovered,
                "host_access_url": host_url,
                "translation": "compose-hostname-to-host-port" if discovered != host_url else "none",
            }
        )
    if not checked:
        raise StoryError("service-first validation found no evaluated Witness routes to check")
    return {
        "status": "passed",
        "checked_route_count": len(checked),
        "allowed_local_translation": "Compose service hostname to demo host port only",
        "checked_routes": checked,
    }


def story_service_first(out: Path, values: dict[str, str], step: int) -> int:
    print("\nStory 1. Service-first discovery through Atlas")
    explain("Publish the service catalogue, let Atlas analyze it, then use the Atlas service graph API to choose evidence routes.")
    require_service_first_dependencies()
    publish_static_metadata()
    compose(
        "up",
        "-d",
        "static-metadata-publisher",
        "civil-registry-relay",
        "social-protection-registry-relay",
        "health-registry-relay",
        "civil-witness",
        "social-protection-witness",
        "shared-eligibility-witness",
    )

    wait_for("static metadata index", lambda: require(request("GET", STATIC_METADATA_URL, "/metadata/index.json"), 200, "static metadata index"))
    wait_for("static CPSV-AP catalogue", lambda: require(request("GET", STATIC_METADATA_URL, STATIC_CPSV_PATH), 200, "static CPSV-AP catalogue"))

    show_query("GET", STATIC_METADATA_URL, "/metadata/index.json")
    index = require(request("GET", STATIC_METADATA_URL, "/metadata/index.json"), 200, "static metadata index")
    show_status(HttpResult(200, index, {}))
    save(out, step, "service-metadata-index", index)
    step += 1

    show_query("GET", STATIC_METADATA_URL, STATIC_CPSV_PATH)
    catalogue = require(request("GET", STATIC_METADATA_URL, STATIC_CPSV_PATH), 200, "static CPSV-AP catalogue")
    show_status(HttpResult(200, catalogue, {}))
    catalogue_path = save(out, step, "service-catalogue", catalogue)
    step += 1

    explain("Invoke the Atlas semantic discovery CLI over the CPSV-AP catalogue.")
    report = run_atlas_analyze(catalogue_path)
    report_path = save(out, step, "service-discovery-report", report)
    step += 1

    explain("Invoke the Atlas Rust ServiceGraph API over the discovery report.")
    graph = run_atlas_service_graph(out, report_path)
    summarize_service_graph(graph)
    save(out, step, "service-graph-excerpt", graph)
    step += 1

    req_map = requirement_evidence_map(graph)
    save(out, step, "service-requirement-evidence-map", req_map)
    step += 1

    schema_path = form_schema_url(index, "health_linked_child_support_form")
    if not schema_path:
        raise StoryError("metadata index does not publish the health-linked child support form schema")
    explain("Validate one sample service-form payload against the published JSON Schema.")
    show_query("GET", STATIC_METADATA_URL, schema_path)
    form_schema = require(
        request("GET", STATIC_METADATA_URL, schema_path),
        200,
        "service form JSON Schema",
    )
    form_payload = service_form_sample()
    form_errors = validate_sample_payload(form_schema, form_payload)
    if form_errors:
        raise StoryError("service form sample failed JSON Schema validation: " + "; ".join(form_errors))
    save(
        out,
        step,
        "service-form-validation",
        {
            "status": "valid",
            "schema_url": schema_path,
            "payload": form_payload,
            "schema": form_schema,
        },
    )
    step += 1

    provider_map = graph.get("evidence_provider_map", [])
    witness_routes = discovered_witness_routes(graph, values)
    for evidence_iri, route in witness_routes.items():
        wait_for(
            f"discovered witness route for {evidence_iri}",
            lambda route=route: require(
                request("GET", route["base_url"], "/.well-known/evidence-service", route["token"]),
                200,
                route["route_label"],
            ),
        )
    save(out, step, "service-evidence-provider-map", provider_map)
    step += 1

    route_status = {
        "service": graph.get("service", {}),
        "status": "declared_with_gaps" if graph.get("gaps") else "declared",
        "routes": graph.get("routes", []),
        "provider_routes": provider_map,
        "gaps": graph.get("gaps", []),
    }
    save(out, step, "service-route-status", route_status)
    step += 1

    evaluations = []
    selected_iris = selected_evidence_type_iris(graph)
    evidence_assets_by_iri = {
        item.get("asset", {}).get("uri"): item.get("asset", {})
        for item in graph.get("accepted_evidence_types", [])
        if item.get("asset", {}).get("uri")
    }
    for evidence_iri in selected_iris:
        asset = evidence_assets_by_iri.get(evidence_iri, {"uri": evidence_iri})
        route = witness_routes.get(evidence_iri)
        if not route:
            evaluations.append(
                {
                    "evidence_type": asset,
                    "status": "gap",
                    "gap": f"No lab Witness route configured for evidence type {evidence_iri}",
                }
            )
            continue
        payload = {
            "subject": {"id": route["subject"], "id_type": "national_id"},
            "claims": [route["claim"]],
            "disclosure": "predicate",
            "format": "application/vnd.registry-witness.claim-result+json",
        }
        explain(f"Call the discovered route for {route['route_label']}.")
        explain(f"Discovered endpoint `{route['discovered_endpoint_url']}` is used through host URL `{route['base_url']}`.")
        show_query("POST", route["base_url"], "/claims/evaluate", purpose=True, body=payload)
        response = require(
            request(
                "POST",
                route["base_url"],
                "/claims/evaluate",
                route["token"],
                payload,
                {"Data-Purpose": PURPOSE},
            ),
            200,
            route["route_label"],
        )
        show_status(HttpResult(200, response, {}))
        evaluations.append(
            {
                "evidence_type": asset,
                "route_label": route["route_label"],
                "claim": route["claim"],
                "subject": route["subject"],
                "discovered_endpoint_url": route["discovered_endpoint_url"],
                "host_access_url": route["base_url"],
                "offering": route.get("offering"),
                "access_service": route.get("access_service"),
                "providers": route.get("providers", []),
                "status": "evaluated",
                "response": response,
            }
        )

    save(out, step, "service-witness-evaluations", evaluations)
    step += 1
    evaluation_gaps = [item for item in evaluations if item.get("status") != "evaluated"]
    if evaluation_gaps:
        raise StoryError(
            "service-first story did not evaluate every Atlas-selected evidence type: "
            + json.dumps(evaluation_gaps, sort_keys=True)
        )
    route_validation = validate_service_first_route_provenance(graph, evaluations)
    save(out, step, "service-route-provenance-validation", route_validation)
    step += 1
    save(
        out,
        step,
        "service-first-story",
        {
            "story": "Service-first discovery through Atlas",
            "service_iri": SERVICE_IRI,
            "requirements": [entry.get("requirement", {}).get("uri") for entry in req_map],
            "selected_evidence_types": selected_iris,
            "accepted_evidence_types": [
                item.get("asset", {}).get("uri")
                for item in graph.get("accepted_evidence_types", [])
            ],
            "provider_route_count": sum(len(entry.get("providers", [])) for entry in provider_map),
            "witness_evaluation_count": len([item for item in evaluations if item.get("status") == "evaluated"]),
            "gap_count": len(graph.get("gaps", [])) + len(evaluation_gaps),
            "form_validation": "valid",
            "route_status": route_status["status"],
            "boundary": {
                "atlas_used_for_graph_navigation": True,
                "python_jsonld_graph_traversal": False,
                "witness_called_after_service_context": True,
                "witness_route_provenance_validated": True,
                "local_translation_limited_to_compose_hostnames": True,
            },
        },
    )
    return step + 1


def story_postgres(out: Path, values: dict[str, str], step: int) -> int:
    print("\nStory 2. Database-source cutover with live Postgres")
    explain("Start a Postgres-backed Relay from a generated config, then discover its published dataset before reading rows.")
    compose("up", "-d", "postgres")
    psql(
        """
DROP SCHEMA IF EXISTS demo_story CASCADE;
CREATE SCHEMA demo_story;
CREATE TABLE demo_story.beneficiaries (
  beneficiary_id bigint primary key,
  national_id text not null,
  program text not null,
  amount double precision not null,
  status text not null,
  updated_at timestamptz not null
);
INSERT INTO demo_story.beneficiaries VALUES
  (1, 'NID-1001', 'CHILD_SUPPORT', 85.50, 'active', '2026-01-10T00:00:00Z'),
  (2, 'NID-1002', 'CHILD_SUPPORT', 0.00, 'inactive', '2026-01-11T00:00:00Z');
"""
    )
    token = secrets.token_urlsafe(24)
    port = int(os.environ.get("REGISTRY_LAB_POSTGRES_STORY_PORT", "4315"))
    config = write_postgres_story_config(out, port)
    relay_env = {
        "POSTGRES_STORY_DATABASE_URL": f"postgres://postgres:postgres@127.0.0.1:{os.environ.get('REGISTRY_LAB_POSTGRES_PORT', '54329')}/registry_lab?sslmode=disable",
        "POSTGRES_STORY_READER_HASH": fingerprint(token),
        "REGISTRY_RELAY_AUDIT_HASH_SECRET": env("REGISTRY_RELAY_AUDIT_HASH_SECRET", values),
    }
    proc = start_relay(config, out / "postgres-live-relay.log", port, relay_env)
    try:
        base = f"http://127.0.0.1:{port}"
        show_query("GET", base, "/metadata")
        metadata = require(request("GET", base, "/metadata", token), 200, "postgres metadata")
        show_status(HttpResult(200, metadata, {}))
        summarize_postgres_metadata(metadata)
        save(out, step, "postgres-live-metadata", metadata)
        step += 1
        show_query("GET", base, "/datasets/postgres_registry/beneficiary?limit=10", purpose=True)
        before = require(
            request("GET", base, "/datasets/postgres_registry/beneficiary?limit=10", token, headers={"Data-Purpose": PURPOSE}),
            200,
            "postgres live row read before insert",
        )
        show_status(HttpResult(200, before, {}))
        before_count = summarize_row_read("Before the database change", before)
        save(out, step, "postgres-live-before-insert", before)
        step += 1
        explain("Insert one operational row directly into Postgres, without restarting Relay or changing Relay config.")
        psql("INSERT INTO demo_story.beneficiaries VALUES (3, 'NID-1004', 'CHILD_SUPPORT', 110.00, 'active', '2026-01-12T00:00:00Z');")
        show_query("GET", base, "/datasets/postgres_registry/beneficiary?limit=10", purpose=True)
        after = require(
            request("GET", base, "/datasets/postgres_registry/beneficiary?limit=10", token, headers={"Data-Purpose": PURPOSE}),
            200,
            "postgres live row read after insert",
        )
        show_status(HttpResult(200, after, {}))
        after_count = summarize_row_read("After the database change", after)
        explain(f"The row count changed from {before_count} to {after_count}; that proves Relay is reading the live source projection.")
        save(out, step, "postgres-live-after-insert", after)
        step += 1
        save(
            out,
            step,
            "postgres-live-story",
            {
                "story": "Database-source cutover with live Postgres",
                "before_count": len(before.get("data", [])),
                "after_count": len(after.get("data", [])),
                "boundary": {
                    "relay_materialization": "live",
                    "client_wrote_to_relay": False,
                    "database_change_visible_without_relay_restart": len(after.get("data", [])) > len(before.get("data", [])),
                },
            },
        )
        return step + 1
    finally:
        stop_process(proc)


def story_oidc(out: Path, values: dict[str, str], step: int) -> int:
    print("\nStory 3. Zitadel-issued JWT at a separate OIDC Relay node")
    explain("Use Zitadel as the issuer, show OIDC discovery, mint a token, then let Relay verify it before scope authorization.")
    zitadel_env_path = wait_zitadel_init(out)
    zitadel_env = parse_env_file(zitadel_env_path)
    issuer = zitadel_env["OIDC_ISSUER"]
    show_query("GET", issuer, "/.well-known/openid-configuration")
    issuer_discovery = require(request("GET", issuer, "/.well-known/openid-configuration"), 200, "zitadel OIDC discovery")
    show_status(HttpResult(200, issuer_discovery, {}))
    summarize_oidc_discovery(issuer_discovery)
    save(out, step, "oidc-issuer-discovery", issuer_discovery)
    step += 1
    explain("Request an OAuth2 client_credentials access token. The raw token is used for the HTTP call but never written to artifacts.")
    show_query("POST", issuer, "/oauth/v2/token")
    print("    header: Authorization=Basic <redacted>")
    print(f"    body: grant_type=client_credentials&scope={os.environ.get('OIDC_SCOPE', 'openid')}")
    token = mint_zitadel_token(zitadel_env)
    decoded = decode_jwt(token)
    summarize_oidc_claims(decoded)
    audience = decoded["audience"]
    if isinstance(audience, str):
        audience = [audience]
    if not audience:
        raise StoryError("Zitadel token did not include an audience")
    port = int(os.environ.get("REGISTRY_LAB_OIDC_STORY_PORT", "4316"))
    config = write_oidc_story_config(out, port, zitadel_env["OIDC_ISSUER"], audience)
    proc = start_relay(config, out / "oidc-social-relay.log", port, {"REGISTRY_RELAY_AUDIT_HASH_SECRET": env("REGISTRY_RELAY_AUDIT_HASH_SECRET", values)})
    try:
        base = f"http://127.0.0.1:{port}"
        save(out, step, "oidc-token-claims", decoded)
        step += 1
        show_query("GET", base, "/health")
        health = require(request("GET", base, "/health"), 200, "oidc relay health")
        show_status(HttpResult(200, health, {}))
        explain("Relay is running with the discovered issuer and accepted token audience.")
        save(out, step, "oidc-relay-health", health)
        step += 1
        show_query("GET", base, "/datasets/social_protection_registry/household?limit=1", purpose=True)
        row = request("GET", base, "/datasets/social_protection_registry/household?limit=1", token, headers={"Data-Purpose": PURPOSE})
        show_status(row)
        if row.status not in {200, 403}:
            raise StoryError(f"OIDC row read returned HTTP {row.status}, expected 200 or 403: {row.body}")
        if row.status == 200:
            summarize_row_read("OIDC-protected row read", row.body)
            explain("JWT verification and scope authorization both succeeded.")
        else:
            code = row.body.get("code") if isinstance(row.body, dict) else None
            explain(f"JWT verification succeeded, then local Relay authorization denied the row scope with problem code `{code}`.")
        save(out, step, "oidc-relay-row-attempt", {"status": row.status, "body": row.body})
        step += 1
        save(
            out,
            step,
            "oidc-story",
            {
                "story": "Zitadel-issued JWT at a separate OIDC Relay node",
                "auth_result": "jwt_verified_and_authorized" if row.status == 200 else "jwt_verified_scope_denied",
                "note": "A 403 is expected for Zitadel machine tokens that do not emit mapped role claims.",
            },
        )
        return step + 1
    finally:
        stop_process(proc)


def story_openfn(out: Path, values: dict[str, str], step: int) -> int:
    print("\nStory 4. OpenFn sidecar lookup behind Registry Witness")
    explain("Discover the Witness service, discover its advertised claim, then evaluate that claim through the private OpenFn sidecar.")
    sidecar_raw = env("OPENFN_SIDECAR_TOKEN_RAW", values)
    sidecar_hash = os.environ.get("OPENFN_SIDECAR_TOKEN_HASH") or values.get("OPENFN_SIDECAR_TOKEN_HASH") or fingerprint(sidecar_raw)
    openfn_env = {
        "REGISTRY_OPENFN_WITNESS_SOURCE_DIR": os.environ.get("REGISTRY_OPENFN_WITNESS_SOURCE_DIR", str(ROOT / ".." / "registry-witness")),
        "REGISTRY_WITNESS_SOURCE_DIR": os.environ.get("REGISTRY_WITNESS_SOURCE_DIR", str(ROOT / ".." / "registry-witness")),
        "REGISTRY_PLATFORM_SOURCE_DIR": os.environ.get("REGISTRY_PLATFORM_SOURCE_DIR", str(ROOT / "vendor" / "registry-platform")),
        "OPENFN_SIDECAR_TOKEN_RAW": sidecar_raw,
        "OPENFN_SIDECAR_TOKEN_HASH": sidecar_hash,
        "OPENFN_MOCK_REGISTRY_TOKEN_RAW": env("OPENFN_MOCK_REGISTRY_TOKEN_RAW", values),
    }
    compose(
        "up",
        "-d",
        "--force-recreate",
        "--remove-orphans",
        "openfn-mock-registry",
        "openfn-civil-sidecar",
        "openfn-civil-witness",
        env_updates=openfn_env,
    )
    base = os.environ.get("OPENFN_CIVIL_WITNESS_URL", "http://127.0.0.1:4324")
    token = env("CIVIL_EVIDENCE_CLIENT_BEARER", values)
    wait_for("OpenFn civil witness", lambda: require(request("GET", base, "/.well-known/evidence-service", token), 200, "openfn discovery"))
    show_query("GET", base, "/.well-known/evidence-service")
    discovery = require(request("GET", base, "/.well-known/evidence-service", token), 200, "openfn discovery")
    show_status(HttpResult(200, discovery, {}))
    summarize_openfn_discovery(discovery)
    save(out, step, "openfn-witness-discovery", discovery)
    step += 1
    show_query("GET", base, "/claims")
    claims = require(request("GET", base, "/claims", token), 200, "openfn claims")
    show_status(HttpResult(200, claims, {}))
    summarize_claims(claims)
    save(out, step, "openfn-witness-claims", claims)
    step += 1
    evaluation_payload = {
        "subject": {"id": "person-123", "id_type": "national_id"},
        "claims": ["date-of-birth"],
        "disclosure": "value",
        "format": "application/vnd.registry-witness.claim-result+json",
    }
    show_query("POST", base, "/claims/evaluate", purpose=True, body=evaluation_payload)
    evaluation = require(
        request(
            "POST",
            base,
            "/claims/evaluate",
            token,
            evaluation_payload,
            {"Data-Purpose": PURPOSE},
        ),
        200,
        "openfn date-of-birth evaluation",
    )
    show_status(HttpResult(200, evaluation, {}))
    summarize_openfn_evaluation(evaluation)
    save(out, step, "openfn-date-of-birth-evaluation", evaluation)
    step += 1
    result = (evaluation.get("results") or [{}])[0]
    save(
        out,
        step,
        "openfn-story",
        {
            "story": "OpenFn sidecar lookup behind Registry Witness",
            "claim_id": result.get("claim_id"),
            "value": result.get("value"),
            "source_count": result.get("provenance", {}).get("source_count"),
            "boundary": {
                "sidecar_private_to_compose_network": True,
                "client_called_witness_not_sidecar": True,
            },
        },
    )
    return step + 1


def write_case_file(out: Path, enabled: list[str]) -> dict[str, Any]:
    service_story = artifact_json(out, "service-first-story", {})
    service_graph = artifact_json(out, "service-graph-excerpt", {})
    service_evaluations = artifact_json(out, "service-witness-evaluations", [])
    service_route_validation = artifact_json(out, "service-route-provenance-validation", {})
    postgres_story = artifact_json(out, "postgres-live-story", {})
    oidc_story = artifact_json(out, "oidc-story", {})
    oidc_claims = artifact_json(out, "oidc-token-claims", {})
    oidc_row = artifact_json(out, "oidc-relay-row-attempt", {})
    openfn_story = artifact_json(out, "openfn-story", {})
    openfn_eval = artifact_json(out, "openfn-date-of-birth-evaluation", {})

    case_file = {
        "artifact_type": "registry-lab.live-service-case-file.v1",
        "title": "Live Service Assurance Case",
        "correlation_id": CORRELATION_ID,
        "purpose": PURPOSE,
        "case_summary": (
            "Demonstrates service-first discovery with Atlas, live database "
            "sources, OIDC-authenticated access, and adapter-backed evidence "
            "lookup without turning Relay into a write-back system."
        ),
        "actors": [
            {"id": "benefit_officer", "role": "Reviews a benefit case through governed APIs."},
            {"id": "registry_atlas", "role": "Discovers the service graph from CPSV-AP metadata."},
            {"id": "registry_relay", "role": "Publishes scoped registry data and metadata."},
            {"id": "registry_witness", "role": "Evaluates evidence claims without exposing source systems."},
            {"id": "zitadel", "role": "Issues and publishes verifiable OIDC access tokens."},
            {"id": "openfn_sidecar", "role": "Adapts an external HTTP registry into the evidence source contract."},
            {"id": "postgres", "role": "Holds a live operational source table."},
        ],
        "subject_refs": {
            "service_first_case": "NID-1001",
            "postgres_live_case": "NID-1001",
            "postgres_inserted_case": "NID-1004",
            "openfn_lookup_subject": "person-123",
            "oidc_principal": oidc_claims.get("subject"),
        },
        "story_results": {
            "service_first": {
                "enabled": "service_first" in enabled,
                "service_iri": service_story.get("service_iri"),
                "requirement_count": len(service_graph.get("requirements", [])) if isinstance(service_graph, dict) else None,
                "accepted_evidence_type_count": len(service_graph.get("accepted_evidence_types", [])) if isinstance(service_graph, dict) else None,
                "witness_evaluation_count": service_story.get("witness_evaluation_count"),
                "route_status": service_story.get("route_status"),
                "gap_count": service_story.get("gap_count"),
                "route_provenance_validation": service_route_validation.get("status"),
            },
            "postgres": {
                "enabled": "postgres" in enabled,
                "before_count": postgres_story.get("before_count"),
                "after_count": postgres_story.get("after_count"),
                "database_change_visible_without_relay_restart": postgres_story.get("boundary", {}).get("database_change_visible_without_relay_restart"),
            },
            "oidc": {
                "enabled": "oidc" in enabled,
                "auth_result": oidc_story.get("auth_result"),
                "row_attempt_status": oidc_row.get("status"),
                "issuer": oidc_claims.get("claims", {}).get("iss"),
                "audience": oidc_claims.get("audience"),
            },
            "openfn": {
                "enabled": "openfn" in enabled,
                "claim_id": openfn_story.get("claim_id"),
                "value": openfn_story.get("value"),
                "source_count": openfn_story.get("source_count"),
                "witness_result_count": len(openfn_eval.get("results", [])) if isinstance(openfn_eval, dict) else None,
            },
        },
        "trust_boundaries": [
            {
                "boundary": "client -> static metadata publisher -> Atlas",
                "credential": "public CPSV-AP metadata",
                "purpose_header": "not applicable",
                "data_returned": "service graph excerpt, requirements, evidence types, providers, and source evidence references",
                "data_not_returned": "personal registry rows or Witness secrets",
            },
            {
                "boundary": "service-first client -> Registry Witness",
                "credential": "Witness bearer tokens from lab environment",
                "purpose_header": PURPOSE,
                "data_returned": f"{len(service_evaluations) if isinstance(service_evaluations, list) else 0} service-context evidence evaluation response(s)",
                "dispatch": "Witness endpoint selected from discovered access-service metadata; local demo translates Compose hostnames to host ports only",
                "data_not_returned": "underlying Relay source credentials",
            },
            {
                "boundary": "client -> Postgres-backed Relay",
                "credential": "ephemeral API key generated by story runner",
                "purpose_header": PURPOSE,
                "data_returned": "beneficiary rows declared by Relay schema",
                "data_not_returned": "database credentials and undeclared database columns",
            },
            {
                "boundary": "Relay -> Postgres",
                "credential": "database connection string from environment",
                "purpose_header": "not forwarded to database",
                "data_returned": "declared live table projection",
                "data_not_returned": "write-back API, arbitrary caller SQL",
            },
            {
                "boundary": "client -> OIDC Relay",
                "credential": "Zitadel access token",
                "purpose_header": PURPOSE,
                "data_returned": "row data only if mapped scopes authorize access",
                "data_not_returned": "raw token, JWKS private key, unrelated claims",
            },
            {
                "boundary": "OIDC Relay -> Zitadel discovery/JWKS",
                "credential": "public OIDC metadata and public signing keys",
                "purpose_header": "not applicable",
                "data_returned": "issuer metadata and public verification keys",
                "data_not_returned": "client secret, user password",
            },
            {
                "boundary": "client -> OpenFn-backed Witness",
                "credential": "Witness bearer token",
                "purpose_header": PURPOSE,
                "data_returned": "claim result for date-of-birth",
                "data_not_returned": "sidecar token, mock registry token, full source payload",
            },
            {
                "boundary": "Witness -> OpenFn sidecar -> mock registry",
                "credential": "private sidecar bearer token and private mock registry token",
                "purpose_header": "Witness request purpose is represented in the evidence request context",
                "data_returned": "adapter-normalized field projection",
                "data_not_returned": "sidecar endpoint to host network",
            },
        ],
        "artifact_index": {
            "service_metadata_index": artifact_ref(out, "service-metadata-index"),
            "service_catalogue": artifact_ref(out, "service-catalogue"),
            "service_discovery_report": artifact_ref(out, "service-discovery-report"),
            "service_graph_excerpt": artifact_ref(out, "service-graph-excerpt"),
            "service_requirement_evidence_map": artifact_ref(out, "service-requirement-evidence-map"),
            "service_form_validation": artifact_ref(out, "service-form-validation"),
            "service_evidence_provider_map": artifact_ref(out, "service-evidence-provider-map"),
            "service_route_status": artifact_ref(out, "service-route-status"),
            "service_witness_evaluations": artifact_ref(out, "service-witness-evaluations"),
            "service_route_provenance_validation": artifact_ref(out, "service-route-provenance-validation"),
            "postgres_metadata": artifact_ref(out, "postgres-live-metadata"),
            "postgres_before": artifact_ref(out, "postgres-live-before-insert"),
            "postgres_after": artifact_ref(out, "postgres-live-after-insert"),
            "oidc_issuer_discovery": artifact_ref(out, "oidc-issuer-discovery"),
            "oidc_token_claims": artifact_ref(out, "oidc-token-claims"),
            "oidc_row_attempt": artifact_ref(out, "oidc-relay-row-attempt"),
            "openfn_discovery": artifact_ref(out, "openfn-witness-discovery"),
            "openfn_claims": artifact_ref(out, "openfn-witness-claims"),
            "openfn_evaluation": artifact_ref(out, "openfn-date-of-birth-evaluation"),
        },
    }
    save_named_json(out, "case-file.json", case_file)
    return case_file


def write_conformance_map(out: Path, enabled: list[str]) -> dict[str, Any]:
    entries = [
        {
            "standard_or_pattern": "CPSV-AP service catalogue",
            "demonstrated_by": "Service-first discovery through Atlas",
            "what_to_check": "The static metadata publisher exposes /metadata/cpsv-ap and Atlas discovers the public service from it.",
            "artifacts": [artifact_ref(out, "service-catalogue"), artifact_ref(out, "service-discovery-report")],
            "status": "demonstrated" if "service_first" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "Atlas ServiceGraph navigation API",
            "demonstrated_by": "Service-first discovery through Atlas",
            "what_to_check": "The story uses Atlas typed graph navigation for requirements, evidence types, providers, routes, gaps, and source evidence.",
            "artifacts": [artifact_ref(out, "service-graph-excerpt"), artifact_ref(out, "service-route-status")],
            "status": "demonstrated" if "service_first" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "Service-context evidence evaluation",
            "demonstrated_by": "Service-first discovery through Atlas",
            "what_to_check": "Witness calls happen after the public service, requirement, and evidence type context is established.",
            "artifacts": [artifact_ref(out, "service-requirement-evidence-map"), artifact_ref(out, "service-witness-evaluations")],
            "status": "demonstrated" if "service_first" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "Local form profile JSON Schema validation",
            "demonstrated_by": "Service-first discovery through Atlas",
            "what_to_check": "The service form declares a JSON Schema and the live story validates a sample payload against the published schema.",
            "artifacts": [artifact_ref(out, "service-form-validation")],
            "status": "demonstrated" if "service_first" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "Discovered access-service dispatch",
            "demonstrated_by": "Service-first discovery through Atlas",
            "what_to_check": "Witness endpoint dispatch is derived from Atlas access-service endpoints, with only Compose hostname to host-port translation for the local demo.",
            "artifacts": [artifact_ref(out, "service-evidence-provider-map"), artifact_ref(out, "service-route-provenance-validation")],
            "status": "demonstrated" if "service_first" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "PostgreSQL table source",
            "demonstrated_by": "Database-source cutover with live Postgres",
            "what_to_check": "Relay reads a live table projection and sees a new row without restart.",
            "artifacts": [artifact_ref(out, "postgres-live-before-insert"), artifact_ref(out, "postgres-live-after-insert")],
            "status": "demonstrated" if "postgres" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "HTTP Bearer token authentication",
            "demonstrated_by": "API-key and OIDC protected Relay/Witness requests",
            "what_to_check": "Clients present bearer credentials at the API boundary. Secrets are not written to artifacts.",
            "artifacts": [artifact_ref(out, "oidc-relay-row-attempt"), artifact_ref(out, "openfn-date-of-birth-evaluation")],
            "status": "demonstrated",
        },
        {
            "standard_or_pattern": "OAuth 2.0 client_credentials",
            "demonstrated_by": "Zitadel machine-user token minting",
            "what_to_check": "The story obtains an access token from Zitadel for machine-to-machine access.",
            "artifacts": [artifact_ref(out, "oidc-token-claims")],
            "status": "demonstrated" if "oidc" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "OpenID Connect Discovery and JWKS",
            "demonstrated_by": "OIDC Relay startup and token verification",
            "what_to_check": "Relay resolves issuer metadata and verifies the JWT using public keys.",
            "artifacts": [artifact_ref(out, "oidc-issuer-discovery"), artifact_ref(out, "oidc-token-claims"), artifact_ref(out, "oidc-story")],
            "status": "demonstrated" if "oidc" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "JWT access token validation",
            "demonstrated_by": "OIDC row attempt",
            "what_to_check": "Issuer and audience are accepted before the request reaches scope authorization.",
            "artifacts": [artifact_ref(out, "oidc-relay-row-attempt")],
            "status": "demonstrated" if "oidc" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "Problem Details style authorization failure",
            "demonstrated_by": "OIDC scope denial when machine token has no mapped row scope",
            "what_to_check": "A verified token can still fail authorization with a stable problem code.",
            "artifacts": [artifact_ref(out, "oidc-relay-row-attempt")],
            "status": "demonstrated" if "oidc" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "OpenFn adaptor pattern",
            "demonstrated_by": "OpenFn sidecar lookup behind Registry Witness",
            "what_to_check": "Witness calls a private sidecar, which adapts an HTTP registry lookup into a claim input.",
            "artifacts": [artifact_ref(out, "openfn-witness-discovery"), artifact_ref(out, "openfn-witness-claims"), artifact_ref(out, "openfn-date-of-birth-evaluation")],
            "status": "demonstrated" if "openfn" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "Registry Witness claim result JSON",
            "demonstrated_by": "OpenFn date-of-birth claim evaluation",
            "what_to_check": "The external lookup is returned as a normalized claim result with provenance count.",
            "artifacts": [artifact_ref(out, "openfn-date-of-birth-evaluation")],
            "status": "demonstrated" if "openfn" in enabled else "skipped",
        },
        {
            "standard_or_pattern": "Purpose-bound request pattern",
            "demonstrated_by": "Postgres, OIDC, and OpenFn story requests",
            "what_to_check": "Row/evidence requests carry a Data-Purpose header used for audit and policy context.",
            "artifacts": [artifact_ref(out, "postgres-live-after-insert"), artifact_ref(out, "openfn-date-of-birth-evaluation")],
            "status": "demonstrated",
        },
    ]
    conformance = {
        "artifact_type": "registry-lab.live-service-conformance-map.v1",
        "correlation_id": CORRELATION_ID,
        "scope": "Live-service story runner",
        "entries": entries,
    }
    save_named_json(out, "conformance-map.json", conformance)
    return conformance


def write_briefing(out: Path, case_file: dict[str, Any], conformance: dict[str, Any]) -> None:
    story_results = case_file["story_results"]
    standards = "\n".join(
        f"- {entry['standard_or_pattern']}: {entry['what_to_check']} Artifact(s): {', '.join(entry['artifacts'])}."
        for entry in conformance["entries"]
    )
    briefing = f"""# Registry Lab Live-Service Briefing

Correlation ID: `{CORRELATION_ID}`

## Presenter Summary

This run demonstrates four live-service patterns in one lab:

1. Atlas discovers a CPSV-AP public service, requirements, accepted evidence types, and provider routes.
2. A Registry Relay reads a live Postgres table and sees a new operational row without restart.
3. A separate Relay verifies a real Zitadel-issued JWT, then applies Relay scope authorization.
4. Registry Witness evaluates an evidence claim through a private OpenFn sidecar instead of exposing the adapter directly.

## Case Result

- Service-first route status: `{story_results['service_first'].get('route_status')}`
- Service-first witness evaluations: `{story_results['service_first'].get('witness_evaluation_count')}`
- Service-first route provenance validation: `{story_results['service_first'].get('route_provenance_validation')}`
- Postgres rows before insert: `{story_results['postgres'].get('before_count')}`
- Postgres rows after insert: `{story_results['postgres'].get('after_count')}`
- OIDC result: `{story_results['oidc'].get('auth_result')}`
- OIDC row attempt status: `{story_results['oidc'].get('row_attempt_status')}`
- OpenFn claim: `{story_results['openfn'].get('claim_id')}`
- OpenFn value: `{story_results['openfn'].get('value')}`
- OpenFn source count: `{story_results['openfn'].get('source_count')}`

## Topology

```mermaid
flowchart LR
  Client["Demo client"]
  Static["Static metadata :4331"]
  Atlas["Registry Atlas"]
  WitnessCore["Civil/social/shared Witness"]
  RelayPg["Postgres-backed Relay :4315"]
  Postgres["Postgres live table"]
  RelayOidc["OIDC Relay :4316"]
  Zitadel["Zitadel issuer/JWKS"]
  Witness["OpenFn-backed Witness :4324"]
  Sidecar["OpenFn sidecar"]
  Mock["Mock registry"]

  Client --> Static
  Static --> Atlas
  Atlas --> WitnessCore
  Client --> RelayPg
  RelayPg --> Postgres
  Client --> RelayOidc
  RelayOidc --> Zitadel
  Client --> Witness
  Witness --> Sidecar
  Sidecar --> Mock
```

## Sequence

```mermaid
sequenceDiagram
  participant C as Demo client
  participant P as Postgres Relay
  participant DB as Postgres
  participant O as OIDC Relay
  participant Z as Zitadel
  participant W as Witness
  participant S as OpenFn sidecar

  C->>P: GET beneficiary rows with Data-Purpose
  P->>DB: Read live table projection
  C->>DB: Insert demo row through setup script
  C->>P: GET beneficiary rows again
  C->>Z: OAuth2 client_credentials token request
  C->>O: GET protected row with Zitadel JWT
  O->>Z: OIDC discovery and JWKS fetch
  O-->>C: 200 or 403 after JWT verification
  C->>W: Evaluate date-of-birth claim
  W->>S: Private sidecar source lookup
  S-->>W: Normalized registry data
  W-->>C: Claim result JSON
```

## What To Point At

- `case-file.json`: the executive case summary, actors, subject references, trust boundaries, and artifact index.
- `conformance-map.json`: the standards and integration patterns demonstrated by each artifact.
- `{artifact_ref(out, 'service-route-provenance-validation')}`: proof that Witness dispatch used discovered access-service endpoints.
- `{artifact_ref(out, 'postgres-live-before-insert')}` and `{artifact_ref(out, 'postgres-live-after-insert')}`: the live database change.
- `{artifact_ref(out, 'oidc-issuer-discovery')}`, `{artifact_ref(out, 'oidc-token-claims')}`, and `{artifact_ref(out, 'oidc-relay-row-attempt')}`: issuer discovery, token verification, then authorization.
- `{artifact_ref(out, 'openfn-witness-discovery')}`, `{artifact_ref(out, 'openfn-witness-claims')}`, and `{artifact_ref(out, 'openfn-date-of-birth-evaluation')}`: Witness discovery, claim discovery, then OpenFn-backed evidence result.

## Trust Boundary Notes

- Relay reads from Postgres but does not expose database credentials or accept caller SQL.
- Zitadel signs the token, Relay verifies issuer, audience, type, and signature, then still applies local scope rules.
- OpenFn sidecar and mock registry stay on the private Compose network. The client calls Witness, not the sidecar.
- Artifacts intentionally avoid raw bearer tokens, client secrets, and database URLs.

## Standards And Patterns

{standards}
"""
    save_named_text(out, "briefing.md", briefing)


def html_escape(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def json_block(payload: Any) -> str:
    return html_escape(json.dumps(payload, indent=2, sort_keys=True))


def chip(label: str, value: Any, *, tone: str = "neutral", value_id: str | None = None) -> str:
    anchor = f' id="{html_escape(value_id)}"' if value_id else ""
    return (
        f'<span class="chip chip-{html_escape(tone)}"{anchor}>'
        f'<span>{html_escape(label)}</span><strong>{html_escape(value)}</strong></span>'
    )


def first_dataset_entity(metadata: Any) -> tuple[str, str, list[str]]:
    catalog = metadata.get("catalog", {}) if isinstance(metadata, dict) else {}
    datasets = catalog.get("datasets", []) if isinstance(catalog, dict) else []
    dataset = datasets[0] if datasets and isinstance(datasets[0], dict) else {}
    entities = dataset.get("entities", []) if isinstance(dataset, dict) else []
    entity = entities[0] if entities and isinstance(entities[0], dict) else {}
    fields = entity.get("fields", []) if isinstance(entity, dict) else []
    return (
        str(dataset.get("dataset_id", "")),
        str(entity.get("name", "")),
        [str(field.get("name")) for field in fields if isinstance(field, dict) and field.get("name")],
    )


def data_count(payload: Any) -> int:
    rows = payload.get("data", []) if isinstance(payload, dict) else []
    return len(rows) if isinstance(rows, list) else 0


def first_claim_id(claims: Any) -> str:
    data = claims.get("data", []) if isinstance(claims, dict) else []
    first = data[0] if data and isinstance(data[0], dict) else {}
    return str(first.get("id", ""))


def first_eval_result(evaluation: Any) -> dict[str, Any]:
    results = evaluation.get("results", []) if isinstance(evaluation, dict) else []
    return results[0] if results and isinstance(results[0], dict) else {}


def html_step(
    *,
    index: int,
    title: str,
    hypothesis: str,
    request_label: str,
    returns: list[str],
    used_next: str,
    proof: str,
    artifact: str,
    payload: Any,
    accent: str,
) -> str:
    returns_html = "\n".join(f"<li>{item}</li>" for item in returns)
    return f"""
      <article class="step-card" id="step-{index}" data-accent="{html_escape(accent)}">
        <div class="step-head">
          <span class="step-number">{index}</span>
          <div>
            <h3>{html_escape(title)}</h3>
            <p>{html_escape(hypothesis)}</p>
          </div>
        </div>
        <div class="request-line">{request_label}</div>
        <div class="step-grid">
          <section>
            <h4>Returned API Result</h4>
            <ul class="result-list">
              {returns_html}
            </ul>
          </section>
          <section>
            <h4>Used For Next Step</h4>
            <p>{used_next}</p>
            <h4>What This Proves</h4>
            <p>{proof}</p>
          </section>
        </div>
        <details>
          <summary>Show returned JSON from {html_escape(artifact)}</summary>
          <pre><code>{json_block(payload)}</code></pre>
        </details>
      </article>
"""


def write_interactive_story_html(out: Path, case_file: dict[str, Any], conformance: dict[str, Any]) -> None:
    service_catalogue = artifact_json(out, "service-catalogue", {})
    service_graph = artifact_json(out, "service-graph-excerpt", {})
    service_provider_map = artifact_json(out, "service-evidence-provider-map", [])
    service_evaluations = artifact_json(out, "service-witness-evaluations", [])
    service_route_validation = artifact_json(out, "service-route-provenance-validation", {})
    postgres_metadata = artifact_json(out, "postgres-live-metadata", {})
    postgres_before = artifact_json(out, "postgres-live-before-insert", {})
    postgres_after = artifact_json(out, "postgres-live-after-insert", {})
    oidc_discovery = artifact_json(out, "oidc-issuer-discovery", {})
    oidc_claims = artifact_json(out, "oidc-token-claims", {})
    oidc_attempt = artifact_json(out, "oidc-relay-row-attempt", {})
    openfn_discovery = artifact_json(out, "openfn-witness-discovery", {})
    openfn_claims = artifact_json(out, "openfn-witness-claims", {})
    openfn_evaluation = artifact_json(out, "openfn-date-of-birth-evaluation", {})

    dataset_id, entity_name, field_names = first_dataset_entity(postgres_metadata)
    before_count = data_count(postgres_before)
    after_count = data_count(postgres_after)
    claims = oidc_claims.get("claims", {}) if isinstance(oidc_claims, dict) else {}
    oidc_audience = oidc_claims.get("audience") if isinstance(oidc_claims, dict) else ""
    if isinstance(oidc_audience, list):
        oidc_audience_text = ", ".join(str(item) for item in oidc_audience)
    else:
        oidc_audience_text = str(oidc_audience)
    openfn_claim = first_claim_id(openfn_claims)
    openfn_result = first_eval_result(openfn_evaluation)
    openfn_provenance = openfn_result.get("provenance", {}) if isinstance(openfn_result, dict) else {}
    row_problem = oidc_attempt.get("body", {}).get("code") if isinstance(oidc_attempt.get("body"), dict) else None
    service = service_graph.get("service", {}) if isinstance(service_graph, dict) else {}
    service_requirements = len(service_graph.get("requirements", [])) if isinstance(service_graph, dict) else 0
    service_evidence_types = len(service_graph.get("accepted_evidence_types", [])) if isinstance(service_graph, dict) else 0
    service_provider_count = sum(len(entry.get("providers", [])) for entry in service_provider_map if isinstance(entry, dict))
    service_eval_count = len([item for item in service_evaluations if isinstance(item, dict) and item.get("status") == "evaluated"])
    service_catalogue_nodes = len(service_catalogue.get("@graph", [])) if isinstance(service_catalogue, dict) else 0
    checked_routes = service_route_validation.get("checked_routes", []) if isinstance(service_route_validation, dict) else []
    first_checked_route = checked_routes[0] if checked_routes and isinstance(checked_routes[0], dict) else {}
    first_service_eval = next((item for item in service_evaluations if isinstance(item, dict) and item.get("status") == "evaluated"), {})

    step_cards: list[tuple[int, str, str]] = []

    def add_step(index: int, nav_label: str, card: str) -> None:
        step_cards.append((index, nav_label, card))

    add_step(
        1,
        "Service catalogue",
        html_step(
            index=1,
            title="Start from the public service catalogue",
            hypothesis="The client begins with CPSV-AP service metadata, not a registry row endpoint.",
            request_label="GET http://127.0.0.1:4331/metadata/cpsv-ap",
            returns=[
                chip("graph nodes", service_catalogue_nodes, tone="blue")
                + " are published by the static metadata service.",
                chip("service", service.get("title"), tone="blue", value_id="value-service")
                + " is the selected public service.",
            ],
            used_next="The catalogue becomes the Atlas discovery input for service graph navigation.",
            proof="Service-first discovery has its own entry point before any Witness or Relay request is chosen.",
            artifact=artifact_ref(out, "service-catalogue"),
            payload=service_catalogue,
            accent="blue",
        ),
    )
    add_step(
        2,
        "Atlas graph",
        html_step(
            index=2,
            title="Resolve requirements and evidence with Atlas",
            hypothesis="Atlas should derive requirements, evidence types, providers, and access services from the catalogue.",
            request_label="semantic-asset-discovery analyze -> Atlas ServiceGraph",
            returns=[
                chip("requirements", service_requirements, tone="green")
                + " are linked with CCCEV evidence semantics.",
                chip("evidence types", service_evidence_types, tone="green")
                + " are accepted by the public service.",
                chip("providers", service_provider_count, tone="neutral")
                + " are associated with the accepted evidence.",
            ],
            used_next="The provider map supplies the evidence access services used by the Witness calls.",
            proof="The story relies on Atlas graph navigation instead of hand-walking JSON-LD in the demo script.",
            artifact=artifact_ref(out, "service-graph-excerpt"),
            payload=service_graph,
            accent="blue",
        ),
    )
    add_step(
        3,
        "Access services",
        html_step(
            index=3,
            title="Choose Witness endpoints from access services",
            hypothesis="Witness dispatch should come from discovered access-service endpoints, with only local Compose hostname translation for the demo.",
            request_label="Atlas evidence provider map -> access_service.endpoint_url",
            returns=[
                chip("checked routes", service_route_validation.get("checked_route_count"), tone="green")
                + " passed route provenance validation.",
                chip("discovered", first_checked_route.get("discovered_endpoint_url"), tone="blue")
                + " came from Atlas access-service discovery.",
                chip("host URL", first_checked_route.get("host_access_url"), tone="neutral")
                + " is the local demo translation used for HTTP.",
            ],
            used_next="The translated host URL is used only to reach the same discovered Witness endpoint from outside Compose.",
            proof="A hard-coded host-port Witness route fails validation unless it is derived from the discovered access-service endpoint.",
            artifact=artifact_ref(out, "service-route-provenance-validation"),
            payload={
                "provider_map": service_provider_map,
                "route_validation": service_route_validation,
            },
            accent="green",
        ),
    )
    add_step(
        4,
        "Witness evaluation",
        html_step(
            index=4,
            title="Evaluate evidence through the discovered route",
            hypothesis="The service context should lead to Witness evaluation after evidence type and access service selection.",
            request_label="POST {host_access_url}/claims/evaluate",
            returns=[
                chip("evaluations", service_eval_count, tone="green")
                + " were called through discovered access-service endpoints.",
                chip("claim", first_service_eval.get("claim"), tone="green")
                + " is the requested Witness claim.",
                chip("subject", first_service_eval.get("subject"), tone="neutral")
                + " is the service-review subject.",
            ],
            used_next="The evaluation count and validation result become the service-first assurance result.",
            proof="The demo dispatches to Witness only after the public service graph has selected the evidence route.",
            artifact=artifact_ref(out, "service-witness-evaluations"),
            payload=service_evaluations,
            accent="green",
        ),
    )
    add_step(
        5,
        "Postgres metadata",
        html_step(
            index=5,
            title="Discover the live Postgres Relay shape",
            hypothesis="Before reading data, the client discovers what dataset and entity the Relay publishes.",
            request_label="GET http://127.0.0.1:4315/metadata",
            returns=[
                chip("dataset_id", dataset_id, tone="blue", value_id="value-dataset")
                + " is returned by Relay metadata.",
                chip("entity", entity_name, tone="green", value_id="value-entity")
                + " names the row collection.",
                chip("fields", ", ".join(field_names[:5]) + (", ..." if len(field_names) > 5 else ""), tone="neutral")
                + " defines the declared projection.",
            ],
            used_next=(
                f"The next call composes <code>/datasets/{html_escape(dataset_id)}/{html_escape(entity_name)}</code> "
                "from the discovered dataset and entity values."
            ),
            proof="The client is not hard-coding a database table. It is following Relay metadata.",
            artifact=artifact_ref(out, "postgres-live-metadata"),
            payload=postgres_metadata,
            accent="blue",
        ),
    )
    add_step(
        6,
        "Row baseline",
        html_step(
            index=6,
            title="Read the discovered live entity",
            hypothesis="The discovered dataset/entity path should return the live table projection.",
            request_label=f"GET http://127.0.0.1:4315/datasets/{dataset_id}/{entity_name}?limit=10",
            returns=[
                chip("rows before insert", before_count, tone="blue", value_id="value-before")
                + " are returned through the Relay API.",
                chip("Data-Purpose", PURPOSE, tone="neutral")
                + " travels with the row request for audit context.",
            ],
            used_next="The row count becomes the baseline for proving whether a later source change is visible.",
            proof="Relay returns declared API rows, not database credentials or arbitrary SQL access.",
            artifact=artifact_ref(out, "postgres-live-before-insert"),
            payload=postgres_before,
            accent="blue",
        ),
    )
    add_step(
        7,
        "Live source proof",
        html_step(
            index=7,
            title="Prove the source is live",
            hypothesis="If Relay reads a live Postgres projection, a new source row appears without restarting Relay.",
            request_label=f"GET http://127.0.0.1:4315/datasets/{dataset_id}/{entity_name}?limit=10",
            returns=[
                chip("rows after insert", after_count, tone="green", value_id="value-after")
                + " are returned after inserting one operational row.",
                chip("delta", after_count - before_count, tone="green")
                + " links the database change to the API result.",
            ],
            used_next="The before/after delta feeds the case file conclusion for the Postgres story.",
            proof="The API view changes because the source changed, not because the demo rewrote Relay state.",
            artifact=artifact_ref(out, "postgres-live-after-insert"),
            payload=postgres_after,
            accent="green",
        ),
    )
    add_step(
        8,
        "OIDC discovery",
        html_step(
            index=8,
            title="Discover the OIDC issuer",
            hypothesis="Relay should validate tokens from issuer metadata and JWKS, not a copied signing key.",
            request_label="GET http://localhost:4380/.well-known/openid-configuration",
            returns=[
                chip("issuer", oidc_discovery.get("issuer"), tone="amber", value_id="value-issuer")
                + " identifies the token authority.",
                chip("jwks_uri", oidc_discovery.get("jwks_uri"), tone="amber", value_id="value-jwks")
                + " is where public verification keys are discovered.",
            ],
            used_next="The OIDC Relay config uses the issuer and discovery/JWKS metadata to verify the access token.",
            proof="The trust anchor is standard OIDC discovery, which is portable across compatible providers.",
            artifact=artifact_ref(out, "oidc-issuer-discovery"),
            payload=oidc_discovery,
            accent="amber",
        ),
    )
    add_step(
        9,
        "Token claims",
        html_step(
            index=9,
            title="Mint and inspect a non-secret token view",
            hypothesis="The access token should carry issuer and audience claims that Relay can verify.",
            request_label="POST http://localhost:4380/oauth/v2/token",
            returns=[
                chip("iss", claims.get("iss"), tone="amber")
                + " matches the discovered issuer.",
                chip("aud", oidc_audience_text, tone="amber", value_id="value-audience")
                + " becomes the accepted Relay audience.",
                chip("alg", oidc_claims.get("header", {}).get("alg") if isinstance(oidc_claims, dict) else "", tone="neutral")
                + " identifies the verification algorithm.",
            ],
            used_next="The raw token is sent to the OIDC Relay row endpoint, while only these non-secret claims are written to artifacts.",
            proof="The demo can explain token validation without exposing the bearer token or client secret.",
            artifact=artifact_ref(out, "oidc-token-claims"),
            payload=oidc_claims,
            accent="amber",
        ),
    )
    add_step(
        10,
        "Relay authorization",
        html_step(
            index=10,
            title="Use the token against Relay authorization",
            hypothesis="A valid JWT still needs local Relay scopes before data is released.",
            request_label="GET http://127.0.0.1:4316/datasets/social_protection_registry/household?limit=1",
            returns=[
                chip("status", oidc_attempt.get("status"), tone="rose", value_id="value-oidc-status")
                + " is returned by the protected Relay endpoint.",
                chip("problem code", row_problem, tone="rose")
                + " explains the authorization decision.",
            ],
            used_next="The status and problem code feed the assurance case: identity verification succeeded before row authorization denied scope.",
            proof="OIDC proves who issued the token. Relay still decides whether that principal can read this dataset.",
            artifact=artifact_ref(out, "oidc-relay-row-attempt"),
            payload=oidc_attempt,
            accent="rose",
        ),
    )
    add_step(
        11,
        "Witness discovery",
        html_step(
            index=11,
            title="Discover the OpenFn-backed Witness",
            hypothesis="The client should discover Witness capabilities before choosing a claim.",
            request_label="GET http://127.0.0.1:4324/.well-known/evidence-service",
            returns=[
                chip("service_id", openfn_discovery.get("service_id"), tone="green")
                + " identifies the Witness.",
                chip("claims_url", openfn_discovery.get("claims_url"), tone="green", value_id="value-claims-url")
                + " points to the next discovery call.",
            ],
            used_next=f"The next call follows the discovered claims URL: <code>{html_escape(openfn_discovery.get('claims_url'))}</code>.",
            proof="The client reaches the public Witness API, not the private OpenFn sidecar.",
            artifact=artifact_ref(out, "openfn-witness-discovery"),
            payload=openfn_discovery,
            accent="green",
        ),
    )
    add_step(
        12,
        "Claim discovery",
        html_step(
            index=12,
            title="Discover the claim to request",
            hypothesis="The client should request only claims the Witness advertises.",
            request_label="GET http://127.0.0.1:4324/claims",
            returns=[
                chip("claim id", openfn_claim, tone="green", value_id="value-claim")
                + " is advertised by the Witness.",
                chip("subject type", (openfn_claims.get("data") or [{}])[0].get("subject_type") if isinstance(openfn_claims, dict) else "", tone="neutral")
                + " constrains the request shape.",
            ],
            used_next=f"The evaluate request body uses <code>claims: [{html_escape(openfn_claim)}]</code> from discovery.",
            proof="The evidence request is driven by advertised capabilities, not a hidden sidecar contract.",
            artifact=artifact_ref(out, "openfn-witness-claims"),
            payload=openfn_claims,
            accent="green",
        ),
    )
    add_step(
        13,
        "Claim evaluation",
        html_step(
            index=13,
            title="Evaluate the discovered claim",
            hypothesis="Witness should use the private OpenFn sidecar to resolve the advertised claim value.",
            request_label="POST http://127.0.0.1:4324/claims/evaluate",
            returns=[
                chip("claim_id", openfn_result.get("claim_id"), tone="green")
                + " matches the discovered claim.",
                chip("value", openfn_result.get("value"), tone="green", value_id="value-dob")
                + " is the evidence result returned to the client.",
                chip("source_count", openfn_provenance.get("source_count"), tone="neutral")
                + " shows one sidecar-backed source contributed.",
            ],
            used_next="The claim value and provenance feed the final case result and conformance map.",
            proof="The client obtains evidence through Witness while the sidecar and mock registry remain private.",
            artifact=artifact_ref(out, "openfn-date-of-birth-evaluation"),
            payload=openfn_evaluation,
            accent="green",
        ),
    )
    steps_html = "\n".join(card for _, _, card in step_cards)
    nav_html = "\n".join(
        f'<button type="button" data-step="{index}">{index} {html_escape(label)}</button>'
        for index, label, _ in step_cards
    )
    standards_html = "\n".join(
        f"<li><strong>{html_escape(entry.get('standard_or_pattern'))}</strong>: {html_escape(entry.get('what_to_check'))}</li>"
        for entry in conformance.get("entries", [])
    )
    case_summary = case_file.get("case_summary", "")
    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Registry Lab Live-Service Walkthrough</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --ink: #17202a;
      --muted: #5a6573;
      --line: #d9dee7;
      --blue: #1f6feb;
      --green: #13795b;
      --amber: #a45f00;
      --rose: #b42318;
      --code: #101828;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.45;
    }}
    header {{
      background: linear-gradient(135deg, #102030, #204b57 52%, #6e4a13);
      color: #fff;
      padding: 32px clamp(18px, 4vw, 52px);
    }}
    header h1 {{
      margin: 0;
      font-size: clamp(2rem, 4vw, 4.25rem);
      letter-spacing: 0;
    }}
    header p {{ max-width: 980px; margin: 12px 0 0; color: #e4edf2; font-size: 1.05rem; }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(220px, 280px) minmax(0, 1fr);
      gap: 24px;
      max-width: 1440px;
      margin: 0 auto;
      padding: 24px;
    }}
    nav {{
      position: sticky;
      top: 16px;
      align-self: start;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
    }}
    nav h2 {{ font-size: .86rem; margin: 4px 4px 10px; color: var(--muted); text-transform: uppercase; }}
    nav button {{
      display: flex;
      width: 100%;
      align-items: center;
      gap: 8px;
      border: 0;
      border-radius: 6px;
      background: transparent;
      color: var(--ink);
      padding: 9px 8px;
      text-align: left;
      cursor: pointer;
      font: inherit;
    }}
    nav button:hover, nav button.active {{ background: #eef2f7; }}
    main {{ min-width: 0; }}
    .summary {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 18px;
    }}
    .summary h2, .step-card h3, .step-card h4 {{ margin-top: 0; }}
    .step-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-left: 6px solid var(--blue);
      border-radius: 8px;
      margin-bottom: 18px;
      padding: 18px;
      scroll-margin-top: 16px;
      box-shadow: 0 12px 30px rgba(16, 24, 40, .05);
    }}
    .step-card[data-accent="green"] {{ border-left-color: var(--green); }}
    .step-card[data-accent="amber"] {{ border-left-color: var(--amber); }}
    .step-card[data-accent="rose"] {{ border-left-color: var(--rose); }}
    .step-head {{ display: flex; gap: 12px; align-items: flex-start; }}
    .step-number {{
      flex: 0 0 auto;
      display: inline-grid;
      place-items: center;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: #17202a;
      color: #fff;
      font-weight: 700;
    }}
    .step-head h3 {{ margin-bottom: 4px; }}
    .step-head p {{ margin: 0; color: var(--muted); }}
    .request-line {{
      margin: 16px 0;
      padding: 10px 12px;
      border-radius: 6px;
      background: #101828;
      color: #eff8ff;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-x: auto;
      white-space: nowrap;
    }}
    .step-grid {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(260px, .8fr); gap: 18px; }}
    .result-list {{ padding-left: 20px; }}
    .result-list li {{ margin: 10px 0; }}
    .chip {{
      display: inline-flex;
      max-width: 100%;
      align-items: center;
      gap: 6px;
      margin-right: 6px;
      padding: 3px 8px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #f6f8fb;
      vertical-align: middle;
      font-size: .92rem;
    }}
    .chip strong {{
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: .84rem;
    }}
    .chip-blue {{ border-color: #8bb8ff; background: #eef5ff; }}
    .chip-green {{ border-color: #88cbb8; background: #edf8f4; }}
    .chip-amber {{ border-color: #e2b66c; background: #fff7e8; }}
    .chip-rose {{ border-color: #ef9a93; background: #fff1f0; }}
    details {{ margin-top: 16px; border-top: 1px solid var(--line); padding-top: 12px; }}
    summary {{ cursor: pointer; color: var(--muted); font-weight: 700; }}
    pre {{
      max-height: 420px;
      overflow: auto;
      background: var(--code);
      color: #e6edf3;
      border-radius: 6px;
      padding: 14px;
      font-size: .84rem;
    }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .chain {{
      display: grid;
      grid-template-columns: repeat(5, minmax(120px, 1fr));
      gap: 8px;
      margin-top: 14px;
    }}
    .chain span {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfcfe;
      font-weight: 700;
      text-align: center;
    }}
    .standards li {{ margin: 8px 0; }}
    @media (max-width: 900px) {{
      .layout {{ grid-template-columns: 1fr; padding: 14px; }}
      nav {{ position: static; }}
      .step-grid, .chain {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Registry Lab Live-Service Walkthrough</h1>
    <p>{html_escape(case_summary)}</p>
    <p>Correlation ID: <code>{html_escape(CORRELATION_ID)}</code></p>
  </header>
  <div class="layout">
    <nav aria-label="Story steps">
      <h2>Steps</h2>
      {nav_html}
    </nav>
    <main>
      <section class="summary">
        <h2>How To Read This</h2>
        <p>Each card shows a live API result, the value extracted from that result, and how that value is used by the next request. Open the JSON panels to inspect the full returned payloads.</p>
        <div class="chain" aria-label="Evidence chain">
          <span>Discover</span>
          <span>Extract value</span>
          <span>Use next</span>
          <span>Call API</span>
          <span>Prove boundary</span>
        </div>
      </section>
      {steps_html}
      <section class="summary">
        <h2>Standards And Patterns Demonstrated</h2>
        <ul class="standards">{standards_html}</ul>
      </section>
    </main>
  </div>
  <script>
    const buttons = document.querySelectorAll('nav button[data-step]');
    const cards = [...document.querySelectorAll('.step-card')];
    buttons.forEach((button) => {{
      button.addEventListener('click', () => {{
        const card = document.getElementById(`step-${{button.dataset.step}}`);
        card?.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
      }});
    }});
    const observer = new IntersectionObserver((entries) => {{
      entries.forEach((entry) => {{
        if (!entry.isIntersecting) return;
        buttons.forEach((button) => button.classList.toggle('active', button.dataset.step === entry.target.id.replace('step-', '')));
      }});
    }}, {{ rootMargin: '-20% 0px -65% 0px' }});
    cards.forEach((card) => observer.observe(card));
  </script>
</body>
</html>
"""
    save_named_text(out, "index.html", html_doc)


def write_explainability_artifacts(out: Path, enabled: list[str]) -> None:
    case_file = write_case_file(out, enabled)
    conformance = write_conformance_map(out, enabled)
    write_briefing(out, case_file, conformance)
    write_interactive_story_html(out, case_file, conformance)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-service-first", action="store_true")
    parser.add_argument("--skip-postgres", action="store_true")
    parser.add_argument("--skip-oidc", action="store_true")
    parser.add_argument("--skip-openfn", action="store_true")
    args = parser.parse_args()

    values = parse_env_file(ROOT / ".env")
    if not args.skip_service_first:
        env("CIVIL_EVIDENCE_CLIENT_BEARER", values)
        env("SOCIAL_EVIDENCE_CLIENT_BEARER", values)
        env("SHARED_EVIDENCE_CLIENT_BEARER", values)
    if not args.skip_postgres:
        env("REGISTRY_RELAY_AUDIT_HASH_SECRET", values)
    if not args.skip_oidc:
        env("REGISTRY_RELAY_AUDIT_HASH_SECRET", values)
    if not args.skip_openfn:
        env("OPENFN_SIDECAR_TOKEN_RAW", values)
        env("OPENFN_MOCK_REGISTRY_TOKEN_RAW", values)
        env("CIVIL_EVIDENCE_CLIENT_BEARER", values)

    out = output_dir()
    print("Registry Lab live-service stories")
    print(f"  correlation id: {CORRELATION_ID}")
    print(f"  artifacts: {out}")

    step = 1
    enabled: list[str] = []
    if not args.skip_service_first:
        enabled.append("service_first")
        step = story_service_first(out, values, step)
    if not args.skip_postgres:
        enabled.append("postgres")
        step = story_postgres(out, values, step)
    if not args.skip_oidc:
        enabled.append("oidc")
        step = story_oidc(out, values, step)
    if not args.skip_openfn:
        enabled.append("openfn")
        step = story_openfn(out, values, step)
    write_explainability_artifacts(out, enabled)

    save(
        out,
        step,
        "live-stories-summary",
        {
            "correlation_id": CORRELATION_ID,
            "stories": [
                "Service-first discovery through Atlas",
                "Database-source cutover with live Postgres",
                "Zitadel-issued JWT at a separate OIDC Relay node",
                "OpenFn sidecar lookup behind Registry Witness",
            ],
            "artifacts_dir": str(out),
        },
    )
    print("\nLive-service stories complete.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except StoryError as exc:
        print(f"demo-live-stories: {exc}", file=sys.stderr)
        raise SystemExit(1)
