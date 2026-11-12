"""Shared configuration, business calls, and framework factories for a portal."""

import base64
import binascii
from dataclasses import dataclass
import html
import json
import math
import os
from pathlib import Path
import re
import tomllib
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit
import uuid

from registry_client import portal_fastapi, portal_flask
from registry_client.portal import (
    AuthlibOIDCClient,
    GrantPolicy,
    PortalConfig,
    PortalSessions,
)
from registry_client.portal_postgres import PortalEncryptionKeys, PostgresSessionStore
from registry_client.portal_products import bind_person
from registry_client.portal_verifier import NativeGrantVerifier


_ENV = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9:+._-]{0,255}\Z")
_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class GrantSettings:
    name: str
    resource: str
    scopes: tuple[str, ...]
    profile: str
    required_claims: Mapping[str, str]
    forward_resource: str | None = None


@dataclass(frozen=True)
class ServiceSettings:
    persona: str
    client_id: str
    client_secret_env: str
    origin: str
    redirect_uri: str
    switch_redirect_uri: str
    breg_profile: str
    casework_profile: str
    session_seconds: float
    pending_seconds: float
    request_seconds: float
    same_site: str
    grants: tuple[GrantSettings, ...]


@dataclass(frozen=True)
class OperatorConfig:
    issuer: Mapping[str, Any]
    products: Mapping[str, Any]
    session_store: Mapping[str, Any]
    services: Mapping[str, ServiceSettings]


@dataclass(frozen=True)
class Runtime:
    service: ServiceSettings
    sessions: Any
    store: Any
    person_factory: Callable[[Any], Any]


def _obj(value: Any, path: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{path} must contain exactly the documented fields")
    return value


def _text(value: Any, path: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError(f"{path} must be bounded text")
    return value


def _token(value: Any, path: str) -> str:
    value = _text(value, path)
    if not _TOKEN.fullmatch(value):
        raise ValueError(f"{path} must be a token")
    return value


def _url(value: Any, path: str) -> str:
    value = _text(value, path)
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as error:
        raise ValueError(f"{path} must be an HTTPS URL") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{path} must be an HTTPS URL")
    return value


def _origin(value: Any, path: str) -> str:
    value = _url(value, path)
    if urlsplit(value).path or value.endswith("/"):
        raise ValueError(f"{path} must be an HTTPS origin without a trailing slash")
    return value


def _resource(value: Any, path: str) -> str:
    value = _text(value, path)
    parsed = urlsplit(value)
    if (
        not parsed.scheme
        or not parsed.path
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or any(char.isspace() for char in value)
    ):
        raise ValueError(f"{path} must be an absolute resource URI")
    return value


def _env(value: Any, path: str) -> str:
    value = _text(value, path)
    if not _ENV.fullmatch(value):
        raise ValueError(f"{path} must name an environment variable")
    return value


def _duration(value: Any, path: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{path} must be finite and positive")
    return float(value)


def _positive_integer(value: Any, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{path} must be a positive integer")
    return value


def _grant(name: str, value: Any, path: str) -> GrantSettings:
    if (
        not isinstance(value, dict)
        or not {"resource", "scopes", "profile", "requiredClaims"} <= set(value)
        or set(value)
        - {"resource", "scopes", "profile", "requiredClaims", "forwardResource"}
    ):
        raise ValueError(f"{path} has incomplete or unsupported fields")
    scopes = value["scopes"]
    if (
        not isinstance(scopes, list)
        or not scopes
        or len(scopes) > 32
        or len(set(scopes)) != len(scopes)
    ):
        raise ValueError(f"{path}.scopes must be distinct scope tokens")
    claims = value["requiredClaims"]
    if not isinstance(claims, dict) or not claims:
        raise ValueError(f"{path}.requiredClaims must name exact claims")
    return GrantSettings(
        name,
        _resource(value["resource"], f"{path}.resource"),
        tuple(_token(scope, f"{path}.scopes") for scope in scopes),
        _token(value["profile"], f"{path}.profile"),
        MappingProxyType(
            {
                _token(claim, f"{path}.requiredClaims"): _text(
                    expected, f"{path}.requiredClaims"
                )
                for claim, expected in claims.items()
            }
        ),
        _resource(value["forwardResource"], f"{path}.forwardResource")
        if "forwardResource" in value
        else None,
    )


def _service(persona: str, value: Any) -> ServiceSettings:
    path = f"services.{persona}"
    value = _obj(
        value,
        path,
        {
            "clientId",
            "clientSecretEnv",
            "origin",
            "redirectUri",
            "switchRedirectUri",
            "bregProfile",
            "caseworkProfile",
            "sessionSeconds",
            "pendingSeconds",
            "requestSeconds",
            "sameSite",
            "grants",
        },
    )
    raw_grants = _obj(value["grants"], f"{path}.grants", {"breg", "casework"})
    grants = tuple(
        _grant(name, raw_grants[name], f"{path}.grants.{name}")
        for name in ("breg", "casework")
    )
    origin = _origin(value["origin"], f"{path}.origin")
    redirect_uri = _url(value["redirectUri"], f"{path}.redirectUri")
    switch_uri = _url(value["switchRedirectUri"], f"{path}.switchRedirectUri")
    if (
        urlsplit(redirect_uri).path != "/auth/callback"
        or urlsplit(switch_uri).path != "/auth/login"
        or not redirect_uri.startswith(f"{origin}/")
        or not switch_uri.startswith(f"{origin}/")
    ):
        raise ValueError(f"{path} redirects must use the registered auth routes")
    breg_profile = _token(value["bregProfile"], f"{path}.bregProfile")
    casework_profile = _token(value["caseworkProfile"], f"{path}.caseworkProfile")
    if grants[0].profile != breg_profile or grants[1].profile != casework_profile:
        raise ValueError(f"{path} profiles must match their grant profiles")
    if (
        grants[0].forward_resource is not None
        or (persona == "holder" and grants[1].forward_resource is not None)
        or (
            persona == "staff"
            and (
                grants[1].forward_resource != grants[0].resource
                or not set(grants[0].scopes).issubset(grants[1].scopes)
                or any(
                    grants[1].required_claims.get(name) != expected
                    for name, expected in grants[0].required_claims.items()
                )
            )
        )
    ):
        raise ValueError(f"{path} forwarded Casework grant must include BReg authority")
    if value["sameSite"] not in ("Lax", "Strict"):
        raise ValueError(f"{path}.sameSite is unsupported")
    return ServiceSettings(
        persona,
        _token(value["clientId"], f"{path}.clientId"),
        _env(value["clientSecretEnv"], f"{path}.clientSecretEnv"),
        origin,
        redirect_uri,
        switch_uri,
        breg_profile,
        casework_profile,
        _duration(value["sessionSeconds"], f"{path}.sessionSeconds"),
        _duration(value["pendingSeconds"], f"{path}.pendingSeconds"),
        _duration(value["requestSeconds"], f"{path}.requestSeconds"),
        value["sameSite"],
        grants,
    )


def load_config(path: str | Path) -> OperatorConfig:
    selected = Path(path)
    try:
        contents = selected.read_bytes()
    except OSError as error:
        raise ValueError("operator configuration is unavailable") from error
    if len(contents) > 1_048_576:
        raise ValueError("operator configuration exceeds the size limit")
    try:
        document = tomllib.loads(contents.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("operator configuration is invalid TOML") from error
    return _parse_config(document)


def _parse_config(document: Any) -> OperatorConfig:
    document = _obj(
        document,
        "configuration",
        {
            "issuer",
            "products",
            "sessionStore",
            "services",
        },
    )
    issuer = _obj(
        document["issuer"],
        "issuer",
        {
            "url",
            "authorizationEndpoint",
            "tokenEndpoint",
            "endSessionEndpoint",
            "jwksUri",
            "algorithm",
            "accessTokenType",
            "maximumAccessTokenLifetimeSeconds",
            "maximumIdTokenLifetimeSeconds",
        },
    )
    issuer = MappingProxyType(
        {
            "url": _url(issuer["url"], "issuer.url"),
            "authorization_endpoint": _url(
                issuer["authorizationEndpoint"], "issuer.authorizationEndpoint"
            ),
            "token_endpoint": _url(issuer["tokenEndpoint"], "issuer.tokenEndpoint"),
            "end_session_endpoint": _url(
                issuer["endSessionEndpoint"], "issuer.endSessionEndpoint"
            ),
            "jwks_uri": _url(issuer["jwksUri"], "issuer.jwksUri"),
            "algorithm": _token(issuer["algorithm"], "issuer.algorithm"),
            "access_token_type": _token(
                issuer["accessTokenType"], "issuer.accessTokenType"
            ),
            "maximum_access_token_lifetime_seconds": _positive_integer(
                issuer["maximumAccessTokenLifetimeSeconds"],
                "issuer.maximumAccessTokenLifetimeSeconds",
            ),
            "maximum_id_token_lifetime_seconds": _positive_integer(
                issuer["maximumIdTokenLifetimeSeconds"],
                "issuer.maximumIdTokenLifetimeSeconds",
            ),
        }
    )
    products = _obj(
        document["products"],
        "products",
        {
            "recordsUrl",
            "reviewsUrl",
            "recordRoute",
            "recordFields",
            "reviewQueue",
            "reviewActionId",
            "reviewRecordInput",
            "reviewSubjectSource",
            "reviewSubjectType",
        },
    )
    fields = products["recordFields"]
    if (
        not isinstance(fields, list)
        or not fields
        or len(fields) > 32
        or len(set(fields)) != len(fields)
    ):
        raise ValueError("products.recordFields must be distinct field identifiers")
    products = MappingProxyType(
        {
            "records_url": _url(products["recordsUrl"], "products.recordsUrl"),
            "reviews_url": _url(products["reviewsUrl"], "products.reviewsUrl"),
            "record_route": _token(products["recordRoute"], "products.recordRoute"),
            "record_fields": tuple(
                _token(field, "products.recordFields") for field in fields
            ),
            "review_queue": _token(products["reviewQueue"], "products.reviewQueue"),
            "review_action_id": _token(
                products["reviewActionId"], "products.reviewActionId"
            ),
            "review_record_input": _token(
                products["reviewRecordInput"], "products.reviewRecordInput"
            ),
            "review_subject_source": _token(
                products["reviewSubjectSource"], "products.reviewSubjectSource"
            ),
            "review_subject_type": _token(
                products["reviewSubjectType"], "products.reviewSubjectType"
            ),
        }
    )
    store = _obj(
        document["sessionStore"],
        "sessionStore",
        {"databaseUrlEnv", "primaryKeyId", "encryptionKeyEnvs"},
    )
    key_envs = store["encryptionKeyEnvs"]
    if not isinstance(key_envs, dict) or not key_envs:
        raise ValueError("sessionStore.encryptionKeyEnvs must not be empty")
    store = MappingProxyType(
        {
            "database_url_env": _env(
                store["databaseUrlEnv"], "sessionStore.databaseUrlEnv"
            ),
            "primary_key_id": _token(
                store["primaryKeyId"], "sessionStore.primaryKeyId"
            ),
            "key_envs": MappingProxyType(
                {
                    _token(key_id, "sessionStore.encryptionKeyEnvs"): _env(
                        env_name, "sessionStore.encryptionKeyEnvs"
                    )
                    for key_id, env_name in key_envs.items()
                }
            ),
        }
    )
    if store["primary_key_id"] not in store["key_envs"]:
        raise ValueError("sessionStore.primaryKeyId needs a declared key reference")
    raw_services = _obj(document["services"], "services", {"holder", "staff"})
    services = {
        persona: _service(persona, raw_services[persona])
        for persona in ("holder", "staff")
    }
    if (
        services["holder"].client_id == services["staff"].client_id
        or services["holder"].origin == services["staff"].origin
        or services["holder"].client_secret_env == services["staff"].client_secret_env
    ):
        raise ValueError("holder and staff need distinct service registrations")
    return OperatorConfig(issuer, products, store, MappingProxyType(services))


def _environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required operator secret {name} is unavailable")
    return value


def build_store(config: OperatorConfig) -> PostgresSessionStore:
    keys = {}
    for key_id, environment_name in config.session_store["key_envs"].items():
        try:
            material = base64.b64decode(_environment(environment_name), validate=True)
        except (ValueError, binascii.Error):
            raise RuntimeError(
                f"operator encryption key {environment_name} is invalid"
            ) from None
        if len(material) != 32:
            raise RuntimeError(f"operator encryption key {environment_name} is invalid")
        keys[key_id] = material
    encryption = PortalEncryptionKeys(
        primary_key_id=config.session_store["primary_key_id"], keys=keys
    )
    database_url = _environment(config.session_store["database_url_env"])
    import psycopg

    return PostgresSessionStore(lambda: psycopg.connect(database_url), encryption)


def build_runtime(
    config: OperatorConfig, persona: str, *, store: Any | None = None
) -> Runtime:
    try:
        service = config.services[persona]
    except KeyError:
        raise ValueError("persona must be holder or staff") from None
    grants = tuple(
        GrantPolicy(
            grant.name,
            grant.resource,
            grant.scopes,
            grant.profile,
            grant.required_claims,
            grant.forward_resource,
        )
        for grant in service.grants
    )
    verifier = NativeGrantVerifier.from_native(
        issuer=config.issuer["url"],
        client_id=service.client_id,
        persona=service.persona,
        grants=grants,
        algorithm=config.issuer["algorithm"],
        access_token_type=config.issuer["access_token_type"],
        maximum_access_token_lifetime_seconds=config.issuer[
            "maximum_access_token_lifetime_seconds"
        ],
        maximum_id_token_lifetime_seconds=config.issuer[
            "maximum_id_token_lifetime_seconds"
        ],
        jwks_uri=config.issuer["jwks_uri"],
    )
    oidc = AuthlibOIDCClient(
        client_id=service.client_id,
        client_secret=_environment(service.client_secret_env),
        redirect_uri=service.redirect_uri,
        authorization_endpoint=config.issuer["authorization_endpoint"],
        token_endpoint=config.issuer["token_endpoint"],
        end_session_endpoint=config.issuer["end_session_endpoint"],
        switch_redirect_uri=service.switch_redirect_uri,
        verify_token=verifier,
    )
    portal_config = PortalConfig(
        issuer=config.issuer["url"],
        client_id=service.client_id,
        redirect_uri=service.redirect_uri,
        origin=service.origin,
        persona=service.persona,
        grants=grants,
        session_seconds=service.session_seconds,
        pending_seconds=service.pending_seconds,
    )
    selected_store = store if store is not None else build_store(config)
    sessions = PortalSessions(portal_config, oidc, selected_store)

    def person_factory(context):
        return bind_person(
            context,
            persona=service.persona,
            breg_url=config.products["records_url"],
            casework_url=config.products["reviews_url"],
            casework_profile=service.casework_profile,
        )

    return Runtime(service, sessions, selected_store, person_factory)


def _complete(result: Any, operation: str) -> Any:
    if (
        not isinstance(result, dict)
        or result.get("kind") != "complete"
        or "value" not in result
    ):
        raise RuntimeError(f"{operation} did not return a complete result")
    return result["value"]


def _person_service(
    person: Any, config: OperatorConfig, persona: str
) -> ServiceSettings:
    service = config.services.get(person.persona)
    if service is None or service.persona != persona:
        raise PermissionError(f"this operation requires the {persona} service")
    return service


def _uuid_identifier(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise ValueError(f"{name} must be a canonical UUID") from None
    if str(parsed) != value:
        raise ValueError(f"{name} must be a canonical UUID")
    return value


def _idempotency_key(value: Any) -> str:
    value = _token(value, "idempotencyKey")
    if len(value.encode("utf-8")) > 180:
        raise ValueError("idempotencyKey is too long")
    return value


def _revision(value: Any) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 9_007_199_254_740_991
    ):
        raise ValueError("revision must be a non-negative safe integer")
    return value


def _request_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def dashboard(person: Any, config: OperatorConfig) -> dict[str, Any]:
    service = config.services.get(person.persona)
    if service is None:
        raise RuntimeError("the signed-in persona is not configured")
    if service.persona == "holder":
        applications = _complete(
            person.breg.list_records(
                config.products["record_route"],
                top=10,
                select=list(config.products["record_fields"]),
                access_profile=service.breg_profile,
            ),
            "record list",
        )
        reviews = []
    else:
        applications = []
        reviews = _complete(
            person.casework.review_tasks(
                {"queue": config.products["review_queue"]},
                source_profile=service.breg_profile,
            ),
            "review task list",
        )
    return {
        "persona": person.persona,
        "subject": person.subject,
        "principal": person.principal,
        "csrfToken": person.csrf_token,
        "applications": applications,
        "reviews": reviews,
    }


def holder_submit_review(
    person: Any,
    config: OperatorConfig,
    record_identifier: str,
    inputs: dict[str, Any],
    idempotency_key: str,
) -> dict[str, Any]:
    service = _person_service(person, config, "holder")
    record_identifier = _uuid_identifier(record_identifier, "record identifier")
    inputs = dict(_request_object(inputs, "inputs"))
    record_input = config.products["review_record_input"]
    if inputs.get(record_input) != record_identifier:
        raise ValueError("inputs must bind the selected record")
    if inputs.get("status") != "submitted":
        raise ValueError("inputs.status must be submitted")
    key = _idempotency_key(idempotency_key)
    record = _complete(
        person.breg.get_record(
            config.products["record_route"],
            record_identifier,
            select=list(config.products["record_fields"]),
            access_profile=service.breg_profile,
        ),
        "record read",
    )
    metadata = person.breg.registry_contract(service.breg_profile)
    binding = metadata.select_action(
        config.products["review_action_id"], service.breg_profile
    )
    draft = person.breg.start_proposal(binding, inputs, f"{key}:draft")
    prepared = person.breg.prepare_proposal(draft, "submit", {}, f"{key}:submit")
    submitted = person.breg.execute_proposal(prepared)
    return {"record": record, "proposal": submitted.document}


def holder_review_history(
    person: Any, config: OperatorConfig, request_identifier: str
) -> Any:
    _person_service(person, config, "holder")
    request_identifier = _uuid_identifier(
        request_identifier, "review request identifier"
    )
    return _complete(
        person.casework.review_history(request_identifier), "review history"
    )


def staff_review_task(
    person: Any, config: OperatorConfig, task_identifier: str
) -> dict[str, Any]:
    service = _person_service(person, config, "staff")
    task_identifier = _uuid_identifier(task_identifier, "task identifier")
    task = _complete(
        person.casework.review_task(
            task_identifier, source_profile=service.breg_profile
        ),
        "review task",
    )
    context = _complete(
        person.casework.review_task_context(
            task_identifier, source_profile=service.breg_profile
        ),
        "review task context",
    )
    subject = task.get("subject") if isinstance(task, dict) else None
    if (
        not isinstance(subject, dict)
        or subject.get("source") != config.products["review_subject_source"]
        or subject.get("type") != config.products["review_subject_type"]
    ):
        raise RuntimeError("review task does not identify the configured source")
    source_identifier = _uuid_identifier(subject.get("id"), "review subject identifier")
    metadata = person.breg.registry_contract(service.breg_profile)
    binding = metadata.select_proposal_review_context(
        service.breg_profile, config.products["review_action_id"]
    )
    source = _complete(
        person.breg.read_proposal_review_by_id(binding, source_identifier),
        "review source read",
    )
    if (
        not isinstance(source, dict)
        or source.get("id") != source_identifier
        or source.get("actionId") != config.products["review_action_id"]
        or source.get("effectDigest") != subject.get("digest")
    ):
        raise RuntimeError("review source does not match the Casework task")
    return {"task": task, "context": context, "source": source}


def staff_claim_task(
    person: Any,
    config: OperatorConfig,
    task_identifier: str,
    revision: int,
    idempotency_key: str,
) -> Any:
    service = _person_service(person, config, "staff")
    return _complete(
        person.casework.claim_review_task(
            _uuid_identifier(task_identifier, "task identifier"),
            _revision(revision),
            _idempotency_key(idempotency_key),
            source_profile=service.breg_profile,
        ),
        "review task claim",
    )


def staff_release_task(
    person: Any,
    config: OperatorConfig,
    task_identifier: str,
    revision: int,
    idempotency_key: str,
) -> Any:
    _person_service(person, config, "staff")
    return _complete(
        person.casework.release_review_task(
            _uuid_identifier(task_identifier, "task identifier"),
            _revision(revision),
            _idempotency_key(idempotency_key),
        ),
        "review task release",
    )


def staff_decide_task(
    person: Any,
    config: OperatorConfig,
    task_identifier: str,
    revision: int,
    idempotency_key: str,
    decision: dict[str, Any],
) -> dict[str, str]:
    service = _person_service(person, config, "staff")
    _complete(
        person.casework.decide_review_task(
            _uuid_identifier(task_identifier, "task identifier"),
            _revision(revision),
            _idempotency_key(idempotency_key),
            _request_object(decision, "decision"),
            source_profile=service.breg_profile,
        ),
        "review task decision",
    )
    return {"status": "accepted"}


def staff_own_decisions(
    person: Any, config: OperatorConfig, query: dict[str, Any]
) -> Any:
    service = _person_service(person, config, "staff")
    return _complete(
        person.casework.own_review_decisions(
            _request_object(query, "decision query"),
            source_profile=service.breg_profile,
        ),
        "own review decisions",
    )


def staff_review_history(
    person: Any, config: OperatorConfig, request_identifier: str
) -> Any:
    service = _person_service(person, config, "staff")
    return _complete(
        person.casework.review_history(
            _uuid_identifier(request_identifier, "review request identifier"),
            source_profile=service.breg_profile,
        ),
        "review history",
    )


def _frontend(csrf_token: str, initial: Any) -> str:
    template = (_ROOT / "frontend.html").read_text(encoding="utf-8")
    payload = json.dumps(initial, sort_keys=True, separators=(",", ":"))
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e")
    return template.replace(
        "__REGISTRY_CSRF__", html.escape(csrf_token, quote=True)
    ).replace("__REGISTRY_DASHBOARD__", payload)


def _headers(content_type: str) -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "Content-Security-Policy": (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        ),
        "Content-Type": content_type,
        "X-Content-Type-Options": "nosniff",
    }


def create_flask_app(config: OperatorConfig, runtime: Runtime):
    from flask import Flask, Response, g, jsonify, request

    app = Flask(__name__)

    @app.get("/")
    def index():
        person = g.registry_person
        return Response(
            _frontend(person.csrf_token, dashboard(person, config)),
            headers=_headers("text/html; charset=utf-8"),
        )

    @app.get("/portal.js")
    def script():
        return Response(
            (_ROOT / "portal.js").read_text(encoding="utf-8"),
            headers=_headers("text/javascript; charset=utf-8"),
        )

    @app.get("/reviews/<identifier>")
    def review_page(identifier: str):
        person = g.registry_person
        if person.persona == "holder":
            value = holder_review_history(person, config, identifier)
        else:
            value = staff_review_task(person, config, identifier)
        return Response(
            _frontend(person.csrf_token, {"review": value}),
            headers=_headers("text/html; charset=utf-8"),
        )

    def api_response(value: Any):
        response = jsonify(value)
        response.headers.update(_headers("application/json"))
        return response

    @app.errorhandler(ValueError)
    def invalid_request(_error):
        return api_response({"code": "request.invalid"}), 400

    @app.errorhandler(PermissionError)
    def wrong_persona(_error):
        return api_response({"code": "authorization.persona-refused"}), 403

    @app.post("/api/applications/<identifier>/reviews")
    def submit_review(identifier: str):
        body = _request_object(request.get_json(), "request body")
        return api_response(
            holder_submit_review(
                g.registry_person,
                config,
                identifier,
                body.get("inputs"),
                body.get("idempotencyKey"),
            )
        )

    @app.get("/api/review-requests/<identifier>/history")
    def review_history(identifier: str):
        person = g.registry_person
        if person.persona == "holder":
            value = holder_review_history(person, config, identifier)
        else:
            value = staff_review_history(person, config, identifier)
        return api_response(value)

    @app.get("/api/tasks/<identifier>")
    def task(identifier: str):
        return api_response(staff_review_task(g.registry_person, config, identifier))

    @app.post("/api/tasks/<identifier>/claim")
    def claim_task(identifier: str):
        body = _request_object(request.get_json(), "request body")
        return api_response(
            staff_claim_task(
                g.registry_person,
                config,
                identifier,
                body.get("revision"),
                body.get("idempotencyKey"),
            )
        )

    @app.post("/api/tasks/<identifier>/release")
    def release_task(identifier: str):
        body = _request_object(request.get_json(), "request body")
        return api_response(
            staff_release_task(
                g.registry_person,
                config,
                identifier,
                body.get("revision"),
                body.get("idempotencyKey"),
            )
        )

    @app.post("/api/tasks/<identifier>/decisions")
    def decide_task(identifier: str):
        body = _request_object(request.get_json(), "request body")
        return api_response(
            staff_decide_task(
                g.registry_person,
                config,
                identifier,
                body.get("revision"),
                body.get("idempotencyKey"),
                {"decision": body.get("decision")},
            )
        )

    @app.get("/api/decisions")
    def decisions():
        limit = request.args.get("limit", default=10, type=int)
        return api_response(
            staff_own_decisions(g.registry_person, config, {"limit": limit})
        )

    portal_flask.install(
        app,
        runtime.sessions,
        origin=runtime.service.origin,
        persona=runtime.service.persona,
        person_factory=runtime.person_factory,
        request_seconds=runtime.service.request_seconds,
        same_site=runtime.service.same_site,
    )
    return app


def create_fastapi_app(config: OperatorConfig, runtime: Runtime):
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response

    app = FastAPI()

    @app.exception_handler(ValueError)
    async def invalid_request(_request: Request, _error: ValueError):
        return JSONResponse(
            {"code": "request.invalid"},
            status_code=400,
            headers=_headers("application/json"),
        )

    @app.exception_handler(PermissionError)
    async def wrong_persona(_request: Request, _error: PermissionError):
        return JSONResponse(
            {"code": "authorization.persona-refused"},
            status_code=403,
            headers=_headers("application/json"),
        )

    @app.get("/")
    def index(request: Request):
        return HTMLResponse(
            _frontend(request.state.registry_person.csrf_token, None),
            headers=_headers("text/html; charset=utf-8"),
        )

    @app.get("/portal.js")
    def script():
        return Response(
            (_ROOT / "portal.js").read_text(encoding="utf-8"),
            headers=_headers("text/javascript; charset=utf-8"),
        )

    @app.get("/api/dashboard")
    def api_dashboard(request: Request):
        return JSONResponse(
            dashboard(request.state.registry_person, config),
            headers=_headers("application/json"),
        )

    @app.post("/api/applications/{identifier}/reviews")
    def submit_review(identifier: str, body: dict[str, Any], request: Request):
        return JSONResponse(
            holder_submit_review(
                request.state.registry_person,
                config,
                identifier,
                body.get("inputs"),
                body.get("idempotencyKey"),
            ),
            headers=_headers("application/json"),
        )

    @app.get("/api/review-requests/{identifier}/history")
    def review_history(identifier: str, request: Request):
        person = request.state.registry_person
        if person.persona == "holder":
            value = holder_review_history(person, config, identifier)
        else:
            value = staff_review_history(person, config, identifier)
        return JSONResponse(value, headers=_headers("application/json"))

    @app.get("/api/tasks/{identifier}")
    def task(identifier: str, request: Request):
        return JSONResponse(
            staff_review_task(request.state.registry_person, config, identifier),
            headers=_headers("application/json"),
        )

    @app.post("/api/tasks/{identifier}/claim")
    def claim_task(identifier: str, body: dict[str, Any], request: Request):
        return JSONResponse(
            staff_claim_task(
                request.state.registry_person,
                config,
                identifier,
                body.get("revision"),
                body.get("idempotencyKey"),
            ),
            headers=_headers("application/json"),
        )

    @app.post("/api/tasks/{identifier}/release")
    def release_task(identifier: str, body: dict[str, Any], request: Request):
        return JSONResponse(
            staff_release_task(
                request.state.registry_person,
                config,
                identifier,
                body.get("revision"),
                body.get("idempotencyKey"),
            ),
            headers=_headers("application/json"),
        )

    @app.post("/api/tasks/{identifier}/decisions")
    def decide_task(identifier: str, body: dict[str, Any], request: Request):
        return JSONResponse(
            staff_decide_task(
                request.state.registry_person,
                config,
                identifier,
                body.get("revision"),
                body.get("idempotencyKey"),
                {"decision": body.get("decision")},
            ),
            headers=_headers("application/json"),
        )

    @app.get("/api/decisions")
    def decisions(request: Request, limit: int = 10):
        return JSONResponse(
            staff_own_decisions(
                request.state.registry_person, config, {"limit": limit}
            ),
            headers=_headers("application/json"),
        )

    portal_fastapi.install(
        app,
        runtime.sessions,
        origin=runtime.service.origin,
        persona=runtime.service.persona,
        person_factory=runtime.person_factory,
        request_seconds=runtime.service.request_seconds,
        same_site=runtime.service.same_site,
    )
    return app
