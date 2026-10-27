"""G2P disbursement and P2G collection profiles; simulator controls are CLI-only."""

import asyncio
import hmac
import json
import sqlite3
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import Response
from pydantic import ValidationError

from .models import (
    Acknowledgement,
    ApiError,
    BatchAccepted,
    BatchRequest,
    LookupResult,
    Problem,
    RegisterRequest,
    Transaction,
    UpdateRequest,
    invalid,
)
from .p2g_models import CollectionAccepted, CollectionRequest, CollectionStatus
from .store import Scope, dumps

BODY_LIMIT = 65536


@dataclass(frozen=True)
class Settings:
    token_file: Path = Path(".state/token")
    producer: str = "registry"
    tenants: tuple[str, ...] = ("pilot",)
    institutions: tuple[str, ...] = ("ministry",)
    source_id: str = "registry"
    programs: tuple[str, ...] = ("cash-support",)
    payer_accounts: tuple[str, ...] = ("programme-account",)
    billers: tuple[str, ...] = ("ministry",)
    callback_urls: tuple[str, ...] = (
        "https://programme.example.test/callback",
        "https://programme.example.test/api/v1/batch",
    )
    currencies: dict[str, int] = field(default_factory=lambda: {"USD": 2})
    modes: tuple[str, ...] = ("00",)
    manual: bool = False

    def token(self):
        with self.token_file.open("rb") as file:
            token = file.read(4097).rstrip(b"\r\n")
        if not 16 <= len(token) <= 4096 or any(byte <= 32 or byte >= 127 for byte in token):
            raise ValueError("token file must contain one ASCII bearer token of 16–4096 characters")
        return token


def json_response(value, status=200, *, problem=False):
    content = dumps(value, separators=(",", ":")).encode()
    if len(content) > BODY_LIMIT:
        raise ApiError(503, "service.unavailable", "Response exceeds profile limit")
    return Response(
        content,
        status_code=status,
        media_type="application/problem+json" if problem else "application/json",
    )


def header(request, name, limit, *, required=True):
    values = request.headers.getlist(name)
    if not values and not required:
        return None
    if len(values) != 1 or not 1 <= len(values[0]) <= limit:
        raise invalid(name)
    return values[0]


def queries(request, allowed):
    if any(
        key not in allowed or len(request.query_params.getlist(key)) != 1
        for key in request.query_params
    ):
        raise invalid()
    return request.query_params


def text_query(params, name, limit, *, default=None):
    value = params.get(name, default)
    if value is None or not 1 <= len(value) <= limit:
        raise invalid(name)
    return value


def integer_query(params, name, default, minimum, maximum):
    value = params.get(name, str(default))
    if not value.isascii() or not value.isdecimal() or len(value) > 10:
        raise invalid(name)
    number = int(value)
    if not minimum <= number <= maximum:
        raise invalid(name)
    return number


def authenticated(
    request,
    settings,
    *,
    institution_header=None,
    submission=False,
    callback=False,
    tenant_header="Platform-TenantId",
):
    values = request.headers.getlist("Authorization")
    try:
        expected = settings.token()
    except (OSError, ValueError):
        expected = None
    if (
        len(values) != 1
        or not values[0].startswith("Bearer ")
        or expected is None
        or not hmac.compare_digest(values[0][7:].encode(), expected)
    ):
        raise ApiError(401, "auth.required", "Bearer authentication required")
    tenant = header(request, tenant_header, 20)
    institution = header(request, institution_header, 12) if institution_header else ""
    program = header(request, "X-Program-Id", 20) if submission else ""
    receiver = header(request, "X-Callback-URL", 100) if callback else ""
    if (
        tenant not in settings.tenants
        or (institution_header and institution not in settings.institutions)
        or (submission and program not in settings.programs)
        or (callback and receiver not in settings.callback_urls)
    ):
        raise ApiError(403, "auth.forbidden", "Requested scope is not permitted")
    return Scope(settings.producer, tenant, institution, program, receiver)


async def body(request, model):
    if header(request, "Content-Type", 200).split(";", 1)[0].strip().lower() != "application/json":
        raise ApiError(415, "request.media-type", "Use application/json")
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > BODY_LIMIT:
            raise ApiError(413, "request.too-large", "Request exceeds profile limit")
        raw.extend(chunk)

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite number")

    try:
        value = json.loads(
            raw, parse_float=Decimal, parse_constant=constant, object_pairs_hook=pairs
        )
        # Reject lone Unicode surrogates before storing or serializing any field.
        dumps(value).encode("utf-8")
        entries = (
            value
            if isinstance(value, list)
            else (
                value.get("Beneficiaries", value.get("beneficiaries"))
                if isinstance(value, dict)
                else None
            )
        )
        if isinstance(entries, list) and len(entries) > 100:
            raise ApiError(413, "request.too-large", "Entry count exceeds profile limit")
        return model.model_validate(value)
    except (ValueError, RecursionError, UnicodeError, ValidationError):
        # Never echo Pydantic input/error contexts: they can contain addresses or credentials.
        raise invalid() from None


def parameter(name, location="header", *, required=True, maximum=20, **schema):
    return {
        "name": name,
        "in": location,
        "required": required,
        "schema": schema or {"type": "string", "minLength": 1, "maxLength": maximum},
    }


def operation(*parameters, model=None, tenant_header="Platform-TenantId"):
    result = {
        "security": [{"BearerAuth": []}],
        "parameters": [parameter(tenant_header), *parameters],
    }
    if model:
        result["requestBody"] = {
            "required": True,
            "content": {
                "application/json": {"schema": {"$ref": f"#/components/schemas/{model.__name__}"}}
            },
        }
    return result


def create_app(settings=None, store=None):
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        async def worker():
            while True:
                await asyncio.sleep(0.2)
                try:
                    store.advance()
                except sqlite3.OperationalError:
                    # A local CLI transaction may temporarily hold the write lock.
                    continue

        task = asyncio.create_task(worker()) if store and not settings.manual else None
        try:
            yield
        finally:
            if task:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(
        title="Payment Simulator",
        version="0.1.0",
        description="Synthetic local G2P disbursement and P2G collection profiles. "
        "No real payment rails or callback delivery. See SPEC.md and P2G-SPEC.md "
        "for GovStack differences.",
        redirect_slashes=False,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def mark_synthetic(request, call_next):
        response = await call_next(request)
        response.headers["X-Payment-Simulator"] = "synthetic"
        return response

    problems = {
        status: {
            "model": Problem,
            "content": {
                "application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}
            },
        }
        for status in (400, 401, 403, 404, 409, 413, 415, 503)
    }
    institution = parameter("X-Registering-Institution-ID", maximum=12)
    callback = parameter("X-Callback-URL", maximum=100)

    @app.exception_handler(ApiError)
    async def api_error(_, exc):
        return json_response(
            exc.problem.model_dump(exclude_none=True), exc.problem.status, problem=True
        )

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, exc):
        return await api_error(request, ApiError(503, "service.unavailable", "State unavailable"))

    @app.get("/healthz", include_in_schema=False)
    async def health():
        return {"status": "ready"}

    @app.post(
        "/identityAccountMapper/beneficiary",
        response_model=Acknowledgement,
        responses=problems,
        openapi_extra=operation(institution, callback, model=RegisterRequest),
    )
    async def register(request: Request):
        scope = authenticated(
            request, settings, institution_header="X-Registering-Institution-ID", callback=True
        )
        queries(request, set())
        value = await body(request, RegisterRequest)
        return json_response(store.write_mapping(scope, value))

    @app.put(
        "/identityAccountMapper/beneficiary",
        response_model=Acknowledgement,
        responses=problems,
        openapi_extra=operation(institution, model=UpdateRequest),
    )
    async def update(request: Request):
        scope = authenticated(request, settings, institution_header="X-Registering-Institution-ID")
        queries(request, set())
        value = await body(request, UpdateRequest)
        if value.sourceBBID != settings.source_id:
            raise ApiError(403, "auth.forbidden", "Source is not permitted")
        return json_response(store.write_mapping(scope, value, update=True))

    @app.get(
        "/beneficiary/",
        response_model=LookupResult,
        responses=problems,
        openapi_extra=operation(
            parameter("registeringInstitutionId", maximum=12),
            parameter("payeeIdentity", "query"),
            parameter("requestId", "query", maximum=12),
        ),
    )
    async def lookup(request: Request):
        scope = authenticated(request, settings, institution_header="registeringInstitutionId")
        params = queries(request, {"payeeIdentity", "requestId"})
        return json_response(
            store.lookup(
                scope, text_query(params, "payeeIdentity", 20), text_query(params, "requestId", 12)
            )
        )

    @app.post(
        "/batchtransactions",
        response_model=BatchAccepted,
        status_code=202,
        responses=problems,
        openapi_extra=operation(
            institution,
            callback,
            parameter("X-CorrelationID", maximum=12),
            parameter("X-Program-Id"),
            parameter("type", "query", type="string", enum=["raw"]),
            model=BatchRequest,
        ),
    )
    async def submit(request: Request):
        scope = authenticated(
            request,
            settings,
            institution_header="X-Registering-Institution-ID",
            submission=True,
            callback=True,
        )
        correlation = header(request, "X-CorrelationID", 12)
        params = queries(request, {"type"})
        if params.get("type") != "raw":
            raise invalid("type")
        value = await body(request, BatchRequest)
        for item in value.root:
            if item.debitParty[0].value not in settings.payer_accounts:
                raise ApiError(403, "auth.forbidden", "Payer account is not permitted")
        return json_response(
            store.accept(scope, correlation, value, settings.currencies, settings.modes), 202
        )

    @app.get(
        "/api/v1/batch/detail",
        response_model=list[Transaction],
        responses=problems,
        openapi_extra=operation(
            parameter("batchId", "query", maximum=50),
            parameter(
                "pageNo",
                "query",
                required=False,
                type="integer",
                minimum=0,
                maximum=2147483647,
                default=0,
            ),
            parameter(
                "pageSize",
                "query",
                required=False,
                type="integer",
                minimum=1,
                maximum=50,
                default=10,
            ),
            parameter("X-CorrelationID", "query", required=False, maximum=12),
            parameter("direction", "query", required=False, type="string", enum=["OUTGOING"]),
        ),
    )
    async def details(request: Request):
        scope = authenticated(request, settings)
        params = queries(request, {"batchId", "pageNo", "pageSize", "X-CorrelationID", "direction"})
        if "direction" in params and params["direction"] != "OUTGOING":
            raise invalid("direction")
        correlation = (
            text_query(params, "X-CorrelationID", 12) if "X-CorrelationID" in params else None
        )
        return json_response(
            store.details(
                scope,
                text_query(params, "batchId", 50),
                correlation,
                integer_query(params, "pageNo", 0, 0, 2147483647),
                integer_query(params, "pageSize", 10, 1, 50),
                settings.institutions,
                settings.programs,
                settings.payer_accounts,
            )
        )

    def collection_scope(request, *, callback=False):
        scope = authenticated(
            request, settings, tenant_header="X-Platform-TenantId", callback=callback
        )
        biller = header(request, "X-billerId", 20)
        if biller not in settings.billers:
            raise ApiError(403, "auth.forbidden", "Biller is not permitted")
        return Scope(scope.producer, scope.tenant, institution=biller, callback=scope.callback)

    @app.post(
        "/rtpRequest",
        response_model=CollectionAccepted,
        responses=problems,
        openapi_extra=operation(
            parameter("X-billerId"),
            parameter("X-CorrelationID", maximum=12),
            callback,
            model=CollectionRequest,
            tenant_header="X-Platform-TenantId",
        ),
    )
    async def request_collection(request: Request):
        scope = collection_scope(request, callback=True)
        correlation = header(request, "X-CorrelationID", 12)
        queries(request, set())
        value = await body(request, CollectionRequest)
        if correlation != value.requestId:
            raise invalid("X-CorrelationID")
        return json_response(store.request_collection(scope, value, settings.currencies))

    @app.get(
        "/transferRequests/{transferRequestId}",
        response_model=CollectionStatus,
        responses=problems,
        openapi_extra=operation(
            parameter("transferRequestId", "path", maximum=50),
            parameter("X-billerId"),
            parameter("X-CorrelationID"),
            tenant_header="X-Platform-TenantId",
        ),
    )
    async def collection_status(request: Request):
        scope = collection_scope(request)
        correlation = header(request, "X-CorrelationID", 20)
        queries(request, set())
        async for chunk in request.stream():
            if chunk:
                raise invalid()
        transfer_id = request.path_params["transferRequestId"]
        if not 1 <= len(transfer_id) <= 50:
            raise invalid("transferRequestId")
        response = json_response(store.collection_status(scope, transfer_id))
        response.headers["X-CorrelationID"] = correlation
        return response

    def openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title, version=app.version, description=app.description, routes=app.routes
        )
        components = schema.setdefault("components", {})
        components["securitySchemes"] = {"BearerAuth": {"type": "http", "scheme": "bearer"}}
        definitions = components.setdefault("schemas", {})
        for model in (RegisterRequest, UpdateRequest, BatchRequest, CollectionRequest):
            definition = model.model_json_schema(ref_template="#/components/schemas/{model}")
            definitions.update(definition.pop("$defs", {}))
            definitions[model.__name__] = definition
        for path in schema["paths"].values():
            for entry in path.values():
                entry["responses"].pop("422", None)
                for status, response in entry["responses"].items():
                    if int(status) >= 400:
                        response["content"].pop("application/json", None)
        app.openapi_schema = schema
        return schema

    app.openapi = openapi
    return app
