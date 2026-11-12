"""Explicit workload bindings for ordinary Python scripts and services."""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit


API_VERSION = "id.registrystack.org/formats/platform/python-connection/v1alpha1"
CONNECTION_ENV = "REGISTRY_STACK_CONNECTION"
_REFERENCE = re.compile(
    r"secret:(?:file/[a-z][a-z0-9._-]{0,127}|env/[A-Z][A-Z0-9_]{0,127})\Z"
)
_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_SUPPORTED_PRODUCTS = frozenset(("breg", "messaging"))
_RESERVED_AUTHORITY_CLAIMS = frozenset(
    (
        "iss",
        "aud",
        "sub",
        "client_id",
        "azp",
        "exp",
        "iat",
        "nbf",
        "jti",
        "scope",
        "registry_principal",
        "registry_assertion_issuer",
    )
)


class ConnectionError(ValueError):
    """A connection cannot select the declared workload authority."""

    def __init__(self, message: str, *, diagnostics: tuple[Mapping[str, Any], ...] = ()):
        super().__init__(message)
        self.diagnostics = tuple(diagnostics)


class UnsupportedOperationError(AttributeError):
    """A product method is outside the supported token-free surface."""

    code = "client.operation-not-supported"

    def __init__(self, product: str, operation: str):
        self.product = product
        self.operation = operation
        super().__init__(f"{self.code}: {product}.{operation}")


def _object(
    value: Any, path: str, allowed: set[str], required: set[str]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConnectionError(f"{path} must be an object")
    unexpected = set(value) - allowed
    missing = required - set(value)
    if unexpected:
        raise ConnectionError(f"{path}.{sorted(unexpected)[0]} is unsupported")
    if missing:
        raise ConnectionError(f"{path}.{sorted(missing)[0]} is required")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ConnectionError(f"{path} must be a nonempty string")
    return value


def _url(value: Any, path: str) -> str:
    value = _string(value, path)
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ConnectionError(
            f"{path} must be a credential-free HTTPS or loopback URL"
        ) from exc
    if (
        not (
            parsed.scheme == "https"
            or (
                parsed.scheme == "http"
                and parsed.hostname in ("localhost", "127.0.0.1", "::1")
            )
        )
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or any(ord(char) < 33 or char == "\\" for char in value)
    ):
        raise ConnectionError(f"{path} must be a credential-free HTTPS or loopback URL")
    return value


def _resource(value: Any, path: str) -> str:
    value = _string(value, path)
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ConnectionError(f"{path} must be an absolute resource URI") from exc
    if (
        not parsed.scheme
        or not parsed.path
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or any(char.isspace() or ord(char) < 33 for char in value)
    ):
        raise ConnectionError(f"{path} must be an absolute resource URI")
    return value


def _reference(value: Any, path: str, providers: Mapping[str, Any]) -> str:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ConnectionError(f"{path} must be a secret:file or secret:env reference")
    provider = value[7:].split("/", 1)[0]
    declared = "environment" if provider == "env" else provider
    if declared not in providers:
        raise ConnectionError(f"{path} needs the declared {declared} secret provider")
    return value


def _claims(value: Any, path: str) -> dict[str, Any]:
    """Validate and copy declared, non-secret additional token claims."""
    if not isinstance(value, dict) or len(value) > 64:
        raise ConnectionError(f"{path} must be an object with at most 64 claims")
    for name in value:
        if (
            not isinstance(name, str)
            or not name
            or len(name.encode("utf-8")) > 512
            or any(ord(character) < 33 or ord(character) == 127 for character in name)
            or name in _RESERVED_AUTHORITY_CLAIMS
            or name.startswith("registry_grant_")
        ):
            raise ConnectionError(f"{path} contains an unsupported claim name")
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ConnectionError(f"{path} must contain JSON values") from exc
    if len(encoded.encode("utf-8")) > 16_384:
        raise ConnectionError(f"{path} exceeds the 16384-byte limit")
    return json.loads(encoded)


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({name: _freeze_json(member) for name, member in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(member) for member in value)
    return value


def _providers(value: Any) -> Mapping[str, Any]:
    value = _object(value, "secretProviders", {"file", "environment"}, set())
    if not value:
        raise ConnectionError("secretProviders needs at least one provider")
    if "file" in value:
        file = _object(value["file"], "secretProviders.file", {"root"}, {"root"})
        root = Path(_string(file["root"], "secretProviders.file.root"))
        if not root.is_absolute():
            raise ConnectionError("secretProviders.file.root must be absolute")
    if "environment" in value:
        _object(value["environment"], "secretProviders.environment", set(), set())
    return MappingProxyType(value)


@dataclass(frozen=True)
class WorkloadAuthority:
    """Declared non-secret authority metadata for one product binding."""

    fingerprint: str
    product: str
    issuer: str = dataclass_field(repr=False)
    subject: str = dataclass_field(repr=False)
    client_id: str
    profile: str
    resource: str
    scopes: tuple[str, ...]
    claims: Mapping[str, Any] = dataclass_field(repr=False)


@dataclass(frozen=True)
class _Binding:
    name: str
    product: str
    url: str
    credential: Mapping[str, Any]
    default: bool


def _binding(value: Any, index: int, providers: Mapping[str, Any]) -> _Binding:
    path = f"bindings[{index}]"
    value = _object(
        value,
        path,
        {"name", "product", "url", "default", "credential"},
        {"name", "product", "url", "default", "credential"},
    )
    name = _string(value["name"], f"{path}.name")
    if not _NAME.fullmatch(name):
        raise ConnectionError(f"{path}.name must be kebab-case")
    product = _string(value["product"], f"{path}.product")
    if product not in _SUPPORTED_PRODUCTS:
        raise ConnectionError(f"{path}.product {product!r} is unsupported")
    if not isinstance(value["default"], bool):
        raise ConnectionError(f"{path}.default must be a boolean")
    raw_credential = value["credential"]
    if not isinstance(raw_credential, dict):
        raise ConnectionError(f"{path}.credential must be an object")
    credential_type = raw_credential.get("type")
    if credential_type == "private-key-jwt":
        fields = {
            "type", "issuer", "subject", "tokenEndpoint", "clientId", "profile",
            "clientKeyRef", "resource", "scopes", "claims",
        }
        credential = _object(raw_credential, f"{path}.credential", fields, fields)
        _url(credential["issuer"], f"{path}.credential.issuer")
        _url(credential["tokenEndpoint"], f"{path}.credential.tokenEndpoint")
        for field_name in ("subject", "clientId", "profile"):
            _string(credential[field_name], f"{path}.credential.{field_name}")
        _reference(credential["clientKeyRef"], f"{path}.credential.clientKeyRef", providers)
    elif credential_type == "runner-token":
        fields = {"type", "tokenRef", "runId", "binding", "issuer", "subject",
                  "clientId", "profile", "resource", "scopes", "claims", "runExpiresAt"}
        credential = _object(raw_credential, f"{path}.credential", fields, fields)
        reference = _reference(credential["tokenRef"], f"{path}.credential.tokenRef", providers)
        if not reference.startswith("secret:file/"):
            raise ConnectionError(f"{path}.credential.tokenRef must be a runner file reference")
        for field in ("runId", "binding", "issuer", "subject", "clientId", "profile"):
            _string(credential[field], f"{path}.credential.{field}")
        if credential["binding"] != name:
            raise ConnectionError(f"{path}.credential.binding must match the named binding")
        _url(credential["issuer"], f"{path}.credential.issuer")
        if (not isinstance(credential["runExpiresAt"], int)
                or isinstance(credential["runExpiresAt"], bool)
                or credential["runExpiresAt"] <= 0):
            raise ConnectionError(f"{path}.credential.runExpiresAt must be a positive epoch second")
    else:
        raise ConnectionError(f"{path}.credential.type is unsupported")
    _resource(credential["resource"], f"{path}.credential.resource")
    scopes = credential["scopes"]
    if (
        not isinstance(scopes, list)
        or not scopes
        or len(scopes) > 32
        or any(
            not isinstance(scope, str)
            or not scope
            or len(scope) > 128
            or any(char.isspace() for char in scope)
            for scope in scopes
        )
        or len(set(scopes)) != len(scopes)
    ):
        raise ConnectionError(f"{path}.credential.scopes must be distinct scope tokens")
    normalized_credential = dict(credential)
    normalized_credential["claims"] = _claims(
        credential["claims"], f"{path}.credential.claims"
    )
    return _Binding(
        name,
        product,
        _url(value["url"], f"{path}.url"),
        MappingProxyType(normalized_credential),
        value["default"],
    )


def _machine_admission(value: Any, audience: str) -> Mapping[str, Any]:
    if audience != "service":
        raise ConnectionError("connection.admission is valid only for a service audience")
    required = {"issuer", "resource", "clientId", "profile", "requiredScopes",
                "requiredClaims", "algorithm", "accessTokenType",
                "maximumAccessTokenLifetimeSeconds"}
    optional = {"jwksUri", "clockSkewSeconds", "allowInsecureHttp"}
    value = _object(value, "connection.admission", required | optional, required)
    _url(value["issuer"], "connection.admission.issuer")
    _resource(value["resource"], "connection.admission.resource")
    for field in ("clientId", "profile", "accessTokenType"):
        _string(value[field], f"connection.admission.{field}")
    if value["algorithm"] not in ("EdDSA", "ES256", "ES384", "RS256", "RS384"):
        raise ConnectionError("connection.admission.algorithm is unsupported")
    lifetime = value["maximumAccessTokenLifetimeSeconds"]
    if not isinstance(lifetime, int) or isinstance(lifetime, bool) or not 1 <= lifetime <= 7200:
        raise ConnectionError("connection.admission.maximumAccessTokenLifetimeSeconds must be 1..7200")
    scopes = value["requiredScopes"]
    if (not isinstance(scopes, list) or not scopes
            or any(not isinstance(scope, str) or not scope or len(scope) > 128
                   or any(char.isspace() for char in scope) for scope in scopes)
            or len(set(scopes)) != len(scopes)):
        raise ConnectionError("connection.admission.requiredScopes must be distinct scope tokens")
    claims = value["requiredClaims"]
    if (not isinstance(claims, dict) or not claims
            or any(not isinstance(name, str) or not name or not isinstance(expected, str)
                   or not expected for name, expected in claims.items())):
        raise ConnectionError("connection.admission.requiredClaims must name exact claim values")
    if "jwksUri" in value:
        _url(value["jwksUri"], "connection.admission.jwksUri")
    if "clockSkewSeconds" in value:
        skew = value["clockSkewSeconds"]
        if not isinstance(skew, int) or isinstance(skew, bool) or not 0 <= skew <= 300:
            raise ConnectionError("connection.admission.clockSkewSeconds must be 0..300")
    if "allowInsecureHttp" in value and not isinstance(value["allowInsecureHttp"], bool):
        raise ConnectionError("connection.admission.allowInsecureHttp must be boolean")
    return MappingProxyType(value)


def _secret(reference: str, providers: Mapping[str, Any]) -> str:
    kind, name = reference[7:].split("/", 1)
    if kind == "env":
        value = os.environ.get(name)
        if not value:
            raise ConnectionError("the declared environment secret is unavailable")
        return value
    root = Path(providers["file"]["root"])
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root_metadata = os.fstat(directory)
            if (not stat.S_ISDIR(root_metadata.st_mode)
                    or root_metadata.st_uid != os.getuid()
                    or root_metadata.st_mode & 0o077):
                raise ConnectionError("the file secret root must be a private directory")
            entry_metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(entry_metadata.st_mode):
                raise ConnectionError("the declared file secret must be a private regular file")
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(descriptor, "r", encoding="utf-8") as secret_file:
                metadata = os.fstat(secret_file.fileno())
                if (not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or metadata.st_uid != os.getuid()
                        or metadata.st_mode & 0o177):
                    raise ConnectionError(
                        "the declared file secret must be a private regular file"
                    )
                value = secret_file.read(1_048_577)
                if len(value) > 1_048_576:
                    raise ConnectionError("the declared file secret exceeds the size limit")
                return value
        finally:
            os.close(directory)
    except OSError as exc:
        raise ConnectionError("the declared file secret is unavailable") from exc


class BoundConnection:
    def __init__(self, owner: Connection, binding: _Binding):
        self._owner = owner
        self._binding = binding

    @property
    def breg(self):
        return self._owner._client(self._binding, "breg")

    @property
    def messaging(self):
        return self._owner._client(self._binding, "messaging")

    @property
    def authority(self) -> WorkloadAuthority:
        return self._owner._authority(self._binding)


class Connection:
    """Immutable declarations; native clients are constructed lazily after fork."""

    def __init__(
        self,
        bindings: Mapping[str, _Binding],
        defaults: Mapping[str, str],
        providers: Mapping[str, Any],
        audience: str,
        admission: Mapping[str, Any] | None,
    ):
        self._bindings = MappingProxyType(dict(bindings))
        self._defaults = MappingProxyType(dict(defaults))
        self._providers = providers
        self._audience = audience
        self._admission_config = admission
        self._admission = None
        self._clients: dict[str, Any] = {}
        self._pid = os.getpid()
        self._lock = threading.Lock()

    def using(self, name: str) -> BoundConnection:
        binding = self._bindings.get(name)
        if binding is None:
            raise ConnectionError("unknown workload binding")
        return BoundConnection(self, binding)

    def authority(self, product: str) -> WorkloadAuthority:
        """Describe the default binding's declared non-secret authority."""
        name = self._defaults.get(product)
        if name is None:
            raise ConnectionError(f"no default {product} binding")
        return self._authority(self._bindings[name])

    def admit(self, request_values: Mapping[str, Any]):
        """Verify a service-audience caller without changing workload identity."""
        if self._audience != "service" or self._admission_config is None:
            raise ConnectionError("machine admission is not configured for this service")
        if os.getpid() != self._pid:
            if self._clients or self._admission is not None:
                raise ConnectionError("construct the connection after the server forks")
            self._pid = os.getpid()
            self._lock = threading.Lock()
        with self._lock:
            if self._admission is None:
                from .oidc import AccessTokenVerifier
                from .machine import MachineAdmission

                config = self._admission_config
                verifier = AccessTokenVerifier(
                    config["issuer"], config["resource"], config["clientId"],
                    algorithm=config["algorithm"],
                    access_token_type=config["accessTokenType"],
                    maximum_access_token_lifetime_seconds=config["maximumAccessTokenLifetimeSeconds"],
                    clock_skew_seconds=config.get("clockSkewSeconds", 60),
                    claim_names=tuple(config["requiredClaims"]),
                    jwks_uri=config.get("jwksUri"),
                    allow_insecure_http=config.get("allowInsecureHttp", False),
                )
                self._admission = MachineAdmission(
                    verifier,
                    issuer=config["issuer"],
                    resource=config["resource"],
                    client_id=config["clientId"],
                    profile=config["profile"],
                    required_scopes=tuple(config["requiredScopes"]),
                    required_claims=config["requiredClaims"],
                )
            admission = self._admission
        return admission.admit(request_values)

    @property
    def breg(self):
        return self._default("breg")

    @property
    def messaging(self):
        return self._default("messaging")

    def _default(self, product: str):
        name = self._defaults.get(product)
        if name is None:
            raise ConnectionError(f"no default {product} binding")
        return self._client(self._bindings[name], product)

    @staticmethod
    def _authority(binding: _Binding) -> WorkloadAuthority:
        credential = binding.credential
        scopes = tuple(sorted(credential["scopes"]))
        identity = {
            "claims": credential["claims"],
            "clientId": credential["clientId"],
            "issuer": credential["issuer"],
            "product": binding.product,
            "profile": credential["profile"],
            "resource": credential["resource"],
            "scopes": scopes,
            "subject": credential["subject"],
        }
        encoded = json.dumps(
            identity,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return WorkloadAuthority(
            fingerprint=hashlib.sha256(
                b"registry-stack-workload-authority/v1\0" + encoded
            ).hexdigest(),
            product=binding.product,
            issuer=credential["issuer"],
            subject=credential["subject"],
            client_id=credential["clientId"],
            profile=credential["profile"],
            resource=credential["resource"],
            scopes=scopes,
            claims=_freeze_json(credential["claims"]),
        )

    def _client(self, binding: _Binding, product: str):
        if binding.product != product:
            raise ConnectionError(
                f"binding {binding.name!r} does not provide {product}"
            )
        if os.getpid() != self._pid:
            if self._clients:
                raise ConnectionError("construct the connection after the server forks")
            self._pid = os.getpid()
            self._lock = threading.Lock()
        with self._lock:
            existing = self._clients.get(binding.name)
            if existing is not None:
                return existing
            if binding.credential["type"] == "runner-token":
                from .runner import RotatingNativeBReg, RunnerTokenSource
                source = RunnerTokenSource(binding, self._providers)
                if product == "breg":
                    from .workload_breg import BRegWorkload
                    client = BRegWorkload(RotatingNativeBReg(binding.url, source))
                else:
                    from . import messaging
                    from .workload import MessagingWorkload
                    client = MessagingWorkload(messaging.MessagingClient(binding.url), source)
                self._clients[binding.name] = client
                return client
            try:
                key = json.loads(
                    _secret(binding.credential["clientKeyRef"], self._providers)
                )
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise ConnectionError(
                    "the declared client key is not a JWK object"
                ) from exc
            if not isinstance(key, dict):
                raise ConnectionError("the declared client key is not a JWK object")
            native_config = {
                "token_endpoint": binding.credential["tokenEndpoint"],
                "client_id": binding.credential["clientId"],
                "client_key": key,
                "resource": binding.credential["resource"],
                "scopes": binding.credential["scopes"],
            }
            if product == "breg":
                from . import breg
                from .workload_breg import BRegWorkload

                client = BRegWorkload(
                    breg.BaseRegistryClient(
                        binding.url, authorization={"private_key_jwt": native_config}
                    )
                )
            else:
                from . import breg, messaging
                from .workload import MessagingWorkload

                provider = breg.PrivateKeyJwt(native_config)
                client = MessagingWorkload(
                    messaging.MessagingClient(binding.url), provider
                )
            self._clients[binding.name] = client
            return client


def connect(*, path: str | Path | None = None) -> Connection:
    """Load the configured service's declared workload bindings."""
    selected = path if path is not None else os.environ.get(CONNECTION_ENV)
    if not selected:
        raise ConnectionError(f"set {CONNECTION_ENV} or pass path")
    try:
        contents = Path(selected).read_bytes()
    except OSError as exc:
        raise ConnectionError(
            "the connection file is unavailable"
        ) from exc
    from .yaml import ConfigReadError, read_document  # pyright: ignore[reportMissingImports]

    try:
        document = read_document(
            contents, file=os.fspath(selected), api_version=API_VERSION,
            kind="PlatformPythonConnection",
        )
    except ConfigReadError as exc:
        raise ConnectionError(
            "the connection document was refused",
            diagnostics=exc.diagnostics,
        ) from None
    document = _object(
        document,
        "connection",
        {"apiVersion", "kind", "service", "audience", "secretProviders", "bindings", "admission"},
        {"apiVersion", "kind", "service", "audience", "secretProviders", "bindings"},
    )
    _string(document["service"], "connection.service")
    if document["audience"] not in ("service", "holder", "staff"):
        raise ConnectionError("connection.audience must be service, holder or staff")
    providers = _providers(document["secretProviders"])
    values = document["bindings"]
    if not isinstance(values, list):
        raise ConnectionError("connection.bindings must be a list")
    bindings: dict[str, _Binding] = {}
    defaults: dict[str, str] = {}
    for index, value in enumerate(values):
        binding = _binding(value, index, providers)
        if binding.name in bindings:
            raise ConnectionError(f"duplicate binding name {binding.name!r}")
        bindings[binding.name] = binding
        if binding.default:
            if binding.product in defaults:
                raise ConnectionError(f"duplicate default {binding.product} binding")
            defaults[binding.product] = binding.name
    for product in {binding.product for binding in bindings.values()} - set(defaults):
        raise ConnectionError(f"missing default {product} binding")
    admission = (
        _machine_admission(document["admission"], document["audience"])
        if "admission" in document else None
    )
    return Connection(bindings, defaults, providers, document["audience"], admission)
