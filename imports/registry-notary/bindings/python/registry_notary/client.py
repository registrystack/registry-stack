"""Dictionary-friendly Registry Notary client."""

from __future__ import annotations

import asyncio
import datetime
import email.utils
import json
import socket
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from http.client import HTTPResponse
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .errors import NotaryError, NotaryProblemError, NotaryTransportError

CLAIM_RESULT_JSON = "application/vnd.registry-notary.claim-result+json"
APPLICATION_JWT = "application/jwt"
JSON = "application/json"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
JWKS_TTL_SECONDS = 10 * 60


@dataclass(frozen=True)
class _Response:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class RetryPolicy:
    """Route-aware retry configuration.

    Retries are applied to GET requests and batch evaluation requests that
    include an Idempotency-Key. Non-deduplicated POST routes are never retried.
    """

    max_attempts: int = 1
    base_delay: float = 0.05
    max_delay: float = 1.0
    retry_transport_errors: bool = False
    retry_rate_limited: bool = False
    retry_unavailable: bool = False


class RegistryNotaryClient:
    """Synchronous and asyncio-friendly Registry Notary HTTP client."""

    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str | None = None,
        api_key: str | None = None,
        default_purpose: str | None = None,
        timeout: float = 30.0,
        user_agent: str | None = None,
        retry_policy: RetryPolicy | Mapping[str, Any] | None = None,
        transport: Any | None = None,
        allow_insecure_internal_http: bool = False,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise NotaryError(kind="build", code="build.invalid_url", title="Invalid base URL")
        if (
            parsed.scheme == "http"
            and not _is_loopback_host(parsed.hostname)
            and not allow_insecure_internal_http
        ):
            raise NotaryError(
                kind="build",
                code="build.insecure_base_url",
                title=(
                    "Base URL must use https unless the host is loopback or "
                    "allow_insecure_internal_http is enabled"
                ),
            )
        if bearer_token and api_key:
            raise NotaryError(
                kind="build",
                code="build.multiple_auth_modes",
                title="Only one authentication mode can be configured",
            )
        self._base_url = base_url.rstrip("/")
        self._bearer_token = bearer_token
        self._api_key = api_key
        self._default_purpose = default_purpose
        self._timeout = timeout
        self._user_agent = user_agent
        self._retry_policy = _coerce_retry_policy(retry_policy)
        self._transport = transport
        self._jwks_cache: tuple[float, dict[str, Any]] | None = None

    def __repr__(self) -> str:
        return (
            "RegistryNotaryClient("
            f"base_url={self._base_url!r}, "
            f"default_purpose={self._default_purpose!r}, "
            f"timeout={self._timeout!r})"
        )

    def evaluate(
        self,
        *,
        target_id: str,
        identifier_scheme: str,
        claims: Iterable[str | Mapping[str, Any]],
        target_type: str = "Person",
        purpose: str | None = None,
        request_id: str | None = None,
        traceparent: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate claims for one identifier target using Pythonic argument names."""

        request = {
            "target": {
                "type": target_type,
                "identifiers": [{"scheme": identifier_scheme, "value": target_id}],
            },
            "claims": _claim_list(claims),
        }
        return self.evaluate_request(
            request,
            purpose=purpose,
            request_id=request_id,
            traceparent=traceparent,
            accept=accept,
        )

    async def aevaluate(
        self,
        *,
        target_id: str,
        identifier_scheme: str,
        claims: Iterable[str | Mapping[str, Any]],
        target_type: str = "Person",
        purpose: str | None = None,
        request_id: str | None = None,
        traceparent: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        """Async counterpart to :meth:`evaluate`."""

        request = {
            "target": {
                "type": target_type,
                "identifiers": [{"scheme": identifier_scheme, "value": target_id}],
            },
            "claims": _claim_list(claims),
        }
        return await self.aevaluate_request(
            request,
            purpose=purpose,
            request_id=request_id,
            traceparent=traceparent,
            accept=accept,
        )

    def evaluate_request(
        self,
        request: Mapping[str, Any],
        *,
        purpose: str | None = None,
        request_id: str | None = None,
        traceparent: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        """Send canonical snake_case evaluate JSON without case conversion."""

        effective_purpose = self._effective_purpose(request, purpose)
        response = self._post_json(
            "/v1/evaluations",
            request,
            purpose=effective_purpose,
            request_id=request_id,
            traceparent=traceparent,
            accept=accept or CLAIM_RESULT_JSON,
            retry_kind="post_no_retry",
        )
        return self._decode_json_response(response)

    def batch_evaluate_request(
        self,
        request: Mapping[str, Any],
        *,
        purpose: str | None = None,
        request_id: str | None = None,
        traceparent: str | None = None,
        idempotency_key: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        """Send canonical snake_case batch evaluate JSON."""

        effective_purpose = self._effective_purpose(request, purpose)
        response = self._post_json(
            "/v1/batch-evaluations",
            request,
            purpose=effective_purpose,
            request_id=request_id,
            traceparent=traceparent,
            idempotency_key=idempotency_key,
            accept=accept or CLAIM_RESULT_JSON,
            retry_kind="post_batch",
        )
        return self._decode_json_response(response)

    def render_request(
        self,
        request: Mapping[str, Any],
        *,
        request_id: str | None = None,
        traceparent: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        """Render evidence from canonical snake_case JSON.

        ``evaluation_id`` is required in the request mapping and is used as the
        route path parameter. It is not sent in the request body.
        """

        if not isinstance(request, Mapping):
            raise NotaryError(
                kind="client",
                code="request.invalid_type",
                title="request must be a mapping",
            )
        evaluation_id = request.get("evaluation_id")
        if not isinstance(evaluation_id, str) or not evaluation_id:
            raise NotaryError(
                kind="client",
                code="request.missing_evaluation_id",
                title="render request requires evaluation_id",
            )
        body = dict(request)
        body.pop("evaluation_id", None)
        response = self._post_json(
            f"/v1/evaluations/{quote(evaluation_id, safe='')}/render",
            body,
            purpose=None,
            request_id=request_id,
            traceparent=traceparent,
            idempotency_key=None,
            accept=accept or JSON,
            retry_kind="post_no_retry",
        )
        return self._decode_json_response(response)

    def issue_credential_request(
        self,
        request: Mapping[str, Any],
        *,
        request_id: str | None = None,
        traceparent: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        """Issue a credential from canonical snake_case JSON."""

        response = self._post_json(
            "/v1/credentials",
            request,
            purpose=None,
            request_id=request_id,
            traceparent=traceparent,
            idempotency_key=None,
            accept=accept or JSON,
            retry_kind="post_no_retry",
        )
        return self._decode_json_response(response)

    def list_claims(self, *, request_id: str | None = None) -> dict[str, Any]:
        return self._decode_json_response(self._get("/v1/claims", request_id=request_id))

    def get_claim(self, claim_id: str, *, request_id: str | None = None) -> dict[str, Any]:
        return self._decode_json_response(
            self._get(f"/v1/claims/{quote(claim_id, safe='')}", request_id=request_id)
        )

    def credential_status(
        self,
        credential_id: str,
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._decode_json_response(
            self._get(
                f"/v1/credentials/{quote(credential_id, safe='')}/status",
                request_id=request_id,
            )
        )

    def service_document(self, *, request_id: str | None = None) -> dict[str, Any]:
        return self._decode_json_response(
            self._get("/.well-known/evidence-service", request_id=request_id)
        )

    def issuer_jwks(self, *, request_id: str | None = None) -> dict[str, Any]:
        if request_id is None and self._jwks_cache is not None:
            expires_at, body = self._jwks_cache
            if expires_at > time.monotonic():
                return body
        return self.refresh_jwks(request_id=request_id)

    def refresh_jwks(self, *, request_id: str | None = None) -> dict[str, Any]:
        body = self.raw_issuer_jwks(request_id=request_id)
        self._jwks_cache = (time.monotonic() + JWKS_TTL_SECONDS, body)
        return body

    def raw_issuer_jwks(self, *, request_id: str | None = None) -> dict[str, Any]:
        return self._decode_json_response(
            self._get("/.well-known/evidence/jwks.json", request_id=request_id)
        )

    def get_jwk(self, kid: str, *, request_id: str | None = None) -> dict[str, Any] | None:
        jwks = self.issuer_jwks(request_id=request_id)
        found = _find_jwk(jwks, kid)
        if found is not None:
            return found
        return _find_jwk(self.refresh_jwks(request_id=request_id), kid)

    def oid4vci_issuer_metadata(self, *, request_id: str | None = None) -> dict[str, Any]:
        return self._decode_json_response(
            self._get("/.well-known/openid-credential-issuer", request_id=request_id),
            error_kind="oid4vci",
        )

    def oid4vci_credential_offer(
        self,
        credential_configuration_id: str | None = None,
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        path = "/oid4vci/credential-offer"
        if credential_configuration_id is not None:
            path = (
                "/oid4vci/credential-offer?credential_configuration_id="
                f"{quote(credential_configuration_id, safe='')}"
            )
        return self._decode_json_response(self._get(path, request_id=request_id), error_kind="oid4vci")

    def oid4vci_nonce(
        self,
        request: Mapping[str, Any] | None = None,
        *,
        request_id: str | None = None,
        traceparent: str | None = None,
    ) -> dict[str, Any]:
        response = self._post_json(
            "/oid4vci/nonce",
            request or {"credential_configuration_id": None},
            purpose=None,
            request_id=request_id,
            traceparent=traceparent,
            accept=JSON,
            retry_kind="post_no_retry",
        )
        return self._decode_json_response(response, error_kind="oid4vci")

    def oid4vci_credential(
        self,
        request: Mapping[str, Any],
        *,
        request_id: str | None = None,
        traceparent: str | None = None,
    ) -> dict[str, Any]:
        response = self._post_json(
            "/oid4vci/credential",
            request,
            purpose=None,
            request_id=request_id,
            traceparent=traceparent,
            accept=JSON,
            retry_kind="post_no_retry",
        )
        return self._decode_json_response(response, error_kind="oid4vci")

    def federation_evaluate_jws(
        self,
        compact_jws: str,
        *,
        request_id: str | None = None,
        traceparent: str | None = None,
    ) -> str:
        response = self._post_raw(
            "/federation/v1/evaluations",
            compact_jws.encode("utf-8"),
            content_type=APPLICATION_JWT,
            accept=APPLICATION_JWT,
            request_id=request_id,
            traceparent=traceparent,
            retry_kind="post_no_retry",
        )
        return self._decode_text_response(response)

    async def aevaluate_request(
        self,
        request: Mapping[str, Any],
        *,
        purpose: str | None = None,
        request_id: str | None = None,
        traceparent: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        """Async counterpart to :meth:`evaluate_request`."""

        return await asyncio.to_thread(
            self.evaluate_request,
            request,
            purpose=purpose,
            request_id=request_id,
            traceparent=traceparent,
            accept=accept,
        )

    async def abatch_evaluate_request(
        self,
        request: Mapping[str, Any],
        *,
        purpose: str | None = None,
        request_id: str | None = None,
        traceparent: str | None = None,
        idempotency_key: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self.batch_evaluate_request,
            request,
            purpose=purpose,
            request_id=request_id,
            traceparent=traceparent,
            idempotency_key=idempotency_key,
            accept=accept,
        )

    async def arender_request(
        self,
        request: Mapping[str, Any],
        *,
        request_id: str | None = None,
        traceparent: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self.render_request,
            request,
            request_id=request_id,
            traceparent=traceparent,
            accept=accept,
        )

    async def aissue_credential_request(
        self,
        request: Mapping[str, Any],
        *,
        request_id: str | None = None,
        traceparent: str | None = None,
        accept: str | None = None,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self.issue_credential_request,
            request,
            request_id=request_id,
            traceparent=traceparent,
            accept=accept,
        )

    def _post_json(
        self,
        path: str,
        body: Mapping[str, Any],
        *,
        purpose: str | None,
        request_id: str | None,
        traceparent: str | None,
        accept: str = JSON,
        idempotency_key: str | None = None,
        retry_kind: str,
    ) -> _Response:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": accept,
            "Content-Type": JSON,
        }
        self._add_common_headers(
            headers,
            purpose=purpose,
            request_id=request_id,
            traceparent=traceparent,
        )
        return self._send_with_retry(
            retry_kind,
            idempotency_key,
            lambda: self._send_once("POST", path, headers, payload, idempotency_key),
        )

    def _post_raw(
        self,
        path: str,
        body: bytes,
        *,
        content_type: str,
        accept: str,
        request_id: str | None,
        traceparent: str | None,
        retry_kind: str,
    ) -> _Response:
        headers = {
            "Accept": accept,
            "Content-Type": content_type,
        }
        self._add_common_headers(
            headers,
            purpose=None,
            request_id=request_id,
            traceparent=traceparent,
        )

        return self._send_with_retry(
            retry_kind,
            None,
            lambda: self._send_once("POST", path, headers, body, None),
        )

    def _send_once(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        idempotency_key: str | None,
    ) -> _Response:
        headers = dict(headers)
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        try:
            if self._transport is not None:
                return self._transport.request(
                    method,
                    f"{self._base_url}{path}",
                    headers=headers,
                    body=body,
                    timeout=self._timeout,
                )
            if method == "GET":
                return _stdlib_get(f"{self._base_url}{path}", headers, self._timeout)
            return _stdlib_post(f"{self._base_url}{path}", headers, body or b"", self._timeout)
        except NotaryError:
            raise
        except (HTTPError, URLError, OSError, TimeoutError, socket.timeout) as exc:
            raise NotaryTransportError(title="Transport error") from exc

    def _get(self, path: str, *, request_id: str | None = None) -> _Response:
        headers = {"Accept": JSON}
        self._add_common_headers(
            headers,
            purpose=None,
            request_id=request_id,
            traceparent=None,
        )

        return self._send_with_retry(
            "get",
            None,
            lambda: self._send_once("GET", path, headers, None, None),
        )

    def _add_common_headers(
        self,
        headers: dict[str, str],
        *,
        purpose: str | None,
        request_id: str | None,
        traceparent: str | None,
    ) -> None:
        if self._user_agent:
            headers["User-Agent"] = self._user_agent
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        if self._api_key:
            headers["X-Api-Key"] = self._api_key
        if purpose:
            headers["data-purpose"] = purpose
        if request_id:
            headers["x-request-id"] = request_id
        if traceparent:
            headers["traceparent"] = traceparent

    def _send_with_retry(
        self,
        retry_kind: str,
        idempotency_key: str | None,
        send_once: Any,
    ) -> _Response:
        attempts = _allowed_attempts(self._retry_policy, retry_kind, idempotency_key)
        attempt = 0
        while True:
            attempt += 1
            try:
                response = send_once()
                if response.status < 400:
                    return response
                error = _problem_error_from_response(
                    response,
                    _header(response.headers, "x-request-id"),
                )
                if attempt < attempts and _should_retry(self._retry_policy, error):
                    time.sleep(_retry_delay(self._retry_policy, attempt, error.retry_after))
                    continue
                return response
            except NotaryTransportError as exc:
                if attempt < attempts and _should_retry(self._retry_policy, exc):
                    time.sleep(_retry_delay(self._retry_policy, attempt, None))
                    continue
                raise

    def _decode_json_response(
        self,
        response: _Response,
        *,
        error_kind: str = "problem",
    ) -> dict[str, Any]:
        request_id = _header(response.headers, "x-request-id")
        if response.status >= 400:
            raise _problem_error_from_response(response, request_id, error_kind=error_kind)
        try:
            decoded = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NotaryProblemError(
                kind="decode",
                status=response.status,
                code="decode.failed",
                title="Failed to decode response body",
                retryable=False,
                request_id=request_id,
            ) from exc
        if not isinstance(decoded, dict):
            raise NotaryProblemError(
                kind="decode",
                status=response.status,
                code="decode.failed",
                title="Failed to decode response body",
                retryable=False,
                request_id=request_id,
            )
        return decoded

    def _decode_text_response(self, response: _Response) -> str:
        request_id = _header(response.headers, "x-request-id")
        if response.status >= 400:
            raise _problem_error_from_response(response, request_id)
        try:
            return response.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NotaryProblemError(
                kind="decode",
                status=response.status,
                code="decode.failed",
                title="Failed to decode response body",
                retryable=False,
                request_id=request_id,
            ) from exc

    def _effective_purpose(self, request: Mapping[str, Any], purpose: str | None) -> str | None:
        body_purpose = request.get("purpose")
        if body_purpose is not None and not isinstance(body_purpose, str):
            raise NotaryError(
                kind="build",
                code="request.invalid_purpose",
                title="Request purpose must be a string",
            )
        effective = purpose if purpose is not None else self._default_purpose
        if effective is None:
            effective = body_purpose
        if body_purpose is not None and effective != body_purpose:
            raise NotaryError(
                kind="build",
                code="request.purpose_conflict",
                title="Request purpose conflicts with request body purpose",
            )
        return effective


def _stdlib_post(
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout: float,
) -> _Response:
    request = Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            return _response_from_stdlib(response)
    except HTTPError as exc:
        try:
            return _Response(
                status=exc.code,
                headers=dict(exc.headers.items()),
                body=_read_bounded(exc, exc.code, dict(exc.headers.items())),
            )
        finally:
            exc.close()


def _stdlib_get(
    url: str,
    headers: Mapping[str, str],
    timeout: float,
) -> _Response:
    request = Request(url, headers=dict(headers), method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            return _response_from_stdlib(response)
    except HTTPError as exc:
        try:
            return _Response(
                status=exc.code,
                headers=dict(exc.headers.items()),
                body=_read_bounded(exc, exc.code, dict(exc.headers.items())),
            )
        finally:
            exc.close()


def _response_from_stdlib(response: HTTPResponse) -> _Response:
    headers = dict(response.headers.items())
    return _Response(
        status=int(response.status),
        headers=headers,
        body=_read_bounded(response, int(response.status), headers),
    )


def _read_bounded(
    response: HTTPResponse | HTTPError,
    status: int,
    headers: Mapping[str, str],
) -> bytes:
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise NotaryProblemError(
            kind="body_too_large",
            status=status,
            code="body.too_large",
            title="Response body exceeded configured size limit",
            retryable=False,
            request_id=_header(headers, "x-request-id"),
        )
    return body


def _problem_error_from_response(
    response: _Response,
    request_id: str | None,
    *,
    error_kind: str = "problem",
) -> NotaryProblemError:
    problem: dict[str, Any] = {}
    try:
        decoded = json.loads(response.body.decode("utf-8"))
        if isinstance(decoded, dict):
            problem = decoded
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    if error_kind == "oid4vci":
        kind = "oid4vci"
        code = _optional_str(problem.get("error")) or f"http.{response.status}"
        title = "OID4VCI request failed"
    else:
        kind = str(problem.get("kind") or "problem")
        code = _optional_str(problem.get("code")) or f"http.{response.status}"
        title = _optional_str(problem.get("title")) or "Registry Notary problem"
    retryable = (
        bool(problem.get("retryable"))
        if "retryable" in problem
        else response.status in {429, 503}
    )
    return NotaryProblemError(
        kind=kind,
        status=response.status,
        code=code,
        title=title,
        retryable=retryable,
        request_id=request_id,
        retry_after=_parse_retry_after(response.headers),
    )


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _is_loopback_host(hostname: str | None) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1"}


def _coerce_retry_policy(policy: RetryPolicy | Mapping[str, Any] | None) -> RetryPolicy:
    if policy is None:
        return RetryPolicy()
    if isinstance(policy, RetryPolicy):
        return policy
    return RetryPolicy(**dict(policy))


def _claim_list(claims: Iterable[str | Mapping[str, Any]]) -> list[str | Mapping[str, Any]]:
    if isinstance(claims, str) or isinstance(claims, Mapping):
        raise NotaryError(
            kind="client",
            code="request.invalid_claims",
            title="claims must be an iterable of claim strings or claim reference mappings",
        )
    return list(claims)


def _allowed_attempts(policy: RetryPolicy, retry_kind: str, idempotency_key: str | None) -> int:
    if retry_kind == "get":
        return max(1, policy.max_attempts)
    if retry_kind == "post_batch" and idempotency_key:
        return max(1, policy.max_attempts)
    return 1


def _should_retry(policy: RetryPolicy, error: NotaryError) -> bool:
    if isinstance(error, NotaryTransportError):
        return policy.retry_transport_errors
    if isinstance(error, NotaryProblemError):
        return (
            error.status == 429
            and policy.retry_rate_limited
            or error.status == 503
            and policy.retry_unavailable
        )
    return False


def _retry_delay(policy: RetryPolicy, attempt: int, retry_after: float | None) -> float:
    if isinstance(retry_after, (int, float)):
        return min(float(retry_after), policy.max_delay)
    delay = policy.base_delay * (2 ** max(0, attempt - 1))
    return min(delay, policy.max_delay)


def _parse_retry_after(headers: Mapping[str, str]) -> float | None:
    value = _header(headers, "retry-after")
    if value is None:
        return None
    stripped = value.strip()
    if stripped.isdigit():
        return float(stripped)
    try:
        parsed = email.utils.parsedate_to_datetime(stripped)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None

    ref_value = _header(headers, "date")
    ref_parsed = None
    if ref_value:
        try:
            ref_parsed = email.utils.parsedate_to_datetime(ref_value.strip())
        except (TypeError, ValueError):
            ref_parsed = None

    ref_dt = ref_parsed or datetime.datetime.now(datetime.timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    if ref_dt.tzinfo is None:
        ref_dt = ref_dt.replace(tzinfo=datetime.timezone.utc)
    return max(0.0, (parsed - ref_dt).total_seconds())


def _find_jwk(jwks: Mapping[str, Any], kid: str) -> dict[str, Any] | None:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return None
    for key in keys:
        if isinstance(key, dict) and key.get("kid") == kid:
            return key
    return None
