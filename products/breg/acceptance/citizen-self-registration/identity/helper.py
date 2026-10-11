"""Native ThunderID identity helper for the citizen registration acceptance journey.

The helper drives ThunderID's public OAuth and flow APIs.  It does not mint,
alter, or log tokens.  ``bootstrap`` installs declarative resources only while
the retained development issuer is stopped because ThunderID 1.0.1 correctly
refuses API mutation of declaratively managed applications.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

_CITIZEN_CLIENT_ID = "citizen-portal"
_CITIZEN_REDIRECT_URI = "http://127.0.0.1:3000/callback"
_CITIZEN_SCOPES = ("registration:self", "registration:read")
_STAFF_CLIENT_ID = "registration-console"
_STAFF_REDIRECT_URI = "http://127.0.0.1:3001/callback"
_STAFF_SCOPES = frozenset(
    ("registration:review", "registry:steward", "registration:casework-admin")
)
_STAFF_ONLY_SCOPES = _STAFF_SCOPES
_SCOPE_PROBE = "registration:casework-admin"
_EXPECTED_SCOPE_REFUSALS = frozenset(("invalid_scope", "unauthorized_scope"))
_INVALID_OTP_ERROR = "FET-1008"
_HUMAN_ACTOR_KIND = "human"
_AUTH_FLOW_ID = "01990000-0000-7000-8000-000000000061"
_REGISTRATION_FLOW_ID = "01990000-0000-7000-8000-000000000064"
_TEMPLATE_DESTINATIONS = {
    "citizen-user-type.yaml": "user_types/citizen.yaml",
    "citizen-applicant-role.yaml": "roles/citizen-applicant.yaml",
    "citizen-sms-otp-template.yaml": "templates/citizen-sms-otp.yaml",
    "citizen-registration-flow.yaml": "flows/citizen-registration.yaml",
    "citizen-authentication-flow.yaml": "flows/citizen-authentication.yaml",
}
_BOOTSTRAP_TEMPLATE_DESTINATIONS = {
    "citizen-sms-gateway.yaml": "connections/citizen-sms-gateway.yaml",
}


class IdentityError(RuntimeError):
    """The native identity setup or OAuth exchange failed."""


class IdentityFlowError(IdentityError):
    """ThunderID refused or did not complete a native user flow."""

    def __init__(self, message: str, *, step: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.step = dict(step) if step is not None else None


class _OAuthAuthorizationRefusal(IdentityError):
    """An OAuth error returned through the registered redirect URI."""

    def __init__(self, code: str):
        super().__init__(f"OAuth authorization was refused ({code})")
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class NativeIdentity:
    """Install and drive the acceptance journey's native ThunderID identities."""

    def __init__(
        self,
        issuer: str,
        project: Path,
        secret_root: Path,
        sms_sink_url: str,
        audience: str,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.project = Path(project).resolve()
        self.secret_root = Path(secret_root).resolve()
        self.sms_sink_url = sms_sink_url
        self.audience = audience
        self._opener = urllib.request.build_opener(_NoRedirect)

        parsed_issuer = urllib.parse.urlparse(self.issuer)
        if parsed_issuer.scheme not in {"http", "https"} or not parsed_issuer.netloc:
            raise ValueError("issuer must be an absolute HTTP(S) URL")
        parsed_sink = urllib.parse.urlparse(self.sms_sink_url)
        if (
            parsed_sink.scheme != "http"
            or parsed_sink.hostname != "host.docker.internal"
            or not parsed_sink.port
            or not parsed_sink.path.startswith("/")
        ):
            raise ValueError(
                "sms_sink_url must be an absolute host-only "
                "http://host.docker.internal:<port>/... URL"
            )
        if not self.audience:
            raise ValueError("audience must not be empty")

    def bootstrap(self) -> None:
        """Install the native citizen resources into retained, stopped issuer state."""
        issuer_state = self.project / ".breg" / "dev" / "issuer"
        resources = issuer_state / "resources"
        registry_schema = issuer_state / "registry-schema"
        if not resources.is_dir():
            raise IdentityError(
                "issuer state is absent; run the owner bregctl dev session once, stop it "
                "without reset, then call bootstrap"
            )
        if not registry_schema.is_dir():
            raise IdentityError("issuer registry-schema directory is absent")
        if self._issuer_is_reachable():
            raise IdentityError("stop the retained ThunderID dev issuer before bootstrap")

        application_path, application = self._find_application(resources, _CITIZEN_CLIENT_ID)
        resource_server_id = self._find_resource_server(resources, self.audience)
        ou_handle = application.get("ouHandle")
        if not isinstance(ou_handle, str) or not ou_handle:
            raise IdentityError("citizen-portal declarative application has no ouHandle")

        application["authFlowId"] = _AUTH_FLOW_ID
        application["registrationFlowId"] = _REGISTRATION_FLOW_ID
        application["isRegistrationFlowEnabled"] = True
        application["isRecoveryFlowEnabled"] = False
        application["allowedUserTypes"] = ["Citizen"]
        self._ensure_human_token_attribute(application)
        self._atomic_yaml(application_path, application)

        substitutions = {
            "__OU_HANDLE__": ou_handle,
            "__RESOURCE_SERVER_ID__": resource_server_id,
            "__SMS_SINK_URL__": self.sms_sink_url,
        }
        template_root = Path(__file__).with_name("templates")
        for template_name, relative_destination in _TEMPLATE_DESTINATIONS.items():
            document = self._load_yaml(template_root / template_name)
            rendered = self._substitute(document, substitutions)
            self._atomic_yaml(resources / relative_destination, rendered)
        # ThunderID 1.0.1 selects the notification sender's file store only
        # through the global declarative_resources flag. The owner issuer keeps
        # that flag disabled and uses narrow per-service composite stores, so a
        # connection under resources/connections is parsed but is invisible to
        # SMSExecutor. Install the sender through the supported bootstrap
        # importer so it is present in the mutable notification store instead.
        for template_name, relative_destination in _BOOTSTRAP_TEMPLATE_DESTINATIONS.items():
            document = self._load_yaml(template_root / template_name)
            rendered = self._substitute(document, substitutions)
            # bootstrap.loadBundle inserts its own YAML document separator.
            # A leading `---` here would create an empty document, which the
            # pinned importer rejects because its root is not a mapping.
            self._atomic_yaml(
                registry_schema / relative_destination,
                rendered,
                explicit_start=False,
            )
        (resources / "connections" / "citizen-sms-gateway.yaml").unlink(missing_ok=True)

    def signup(self, phone: str, otp_for: Callable[[str], str]) -> dict[str, str]:
        """Register ``phone`` through native SMS OTP and return its bearer and subject."""
        token = self._citizen_token(phone, otp_for, action="action_signup")
        return {"access_token": token["access_token"], "sub": token["sub"]}

    def login(self, phone: str, otp_for: Callable[[str], str]) -> dict[str, str]:
        """Authenticate an existing citizen through native SMS OTP."""
        token = self._citizen_token(phone, otp_for, action="action_login")
        return {"access_token": token["access_token"], "sub": token["sub"]}

    def refuses_staff_scope(self, phone: str, otp_for: Callable[[str], str]) -> bool:
        """Ask the issuer for a staff scope as a citizen and inspect its real grant."""
        try:
            token = self._citizen_token(
                phone,
                otp_for,
                action="action_login",
                _scope_probe=(_SCOPE_PROBE,),
            )
        except _OAuthAuthorizationRefusal as exc:
            if exc.code in _EXPECTED_SCOPE_REFUSALS:
                return True
            raise
        granted = set(token["granted_scopes"])
        return _SCOPE_PROBE not in granted and not granted.intersection(_STAFF_ONLY_SCOPES)

    def staff_login(self, username: str, password: str, scopes: Iterable[str]) -> str:
        """Use the generated native password account and console OAuth client."""
        requested = tuple(dict.fromkeys(scopes))
        if not requested or not set(requested).issubset(_STAFF_SCOPES):
            raise ValueError("staff scopes must be a non-empty subset of the configured staff scopes")
        auth = self._start_authorization(
            client_id=_STAFF_CLIENT_ID,
            redirect_uri=_STAFF_REDIRECT_URI,
            scopes=requested,
        )
        initial = self._flow(auth["execution_id"], stage="staff initial prompt")
        complete = self._flow(
            auth["execution_id"],
            inputs={"username": username, "password": password},
            action="action_001",
            challenge_token=self._challenge(initial),
            stage="staff credential verification",
        )
        return self._finish_authorization(
            auth,
            complete,
            client_id=_STAFF_CLIENT_ID,
            redirect_uri=_STAFF_REDIRECT_URI,
            requested_scopes=requested,
        )["access_token"]

    def _citizen_token(
        self,
        phone: str,
        otp_for: Callable[[str], str],
        *,
        action: str,
        _scope_probe: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        if not callable(otp_for):
            raise TypeError("otp_for must be callable")
        requested_scopes = _scope_probe if _scope_probe is not None else _CITIZEN_SCOPES
        auth = self._start_authorization(
            client_id=_CITIZEN_CLIENT_ID,
            redirect_uri=_CITIZEN_REDIRECT_URI,
            scopes=requested_scopes,
        )
        initial = self._flow(auth["execution_id"], stage="citizen initial prompt")
        mode = self._flow(
            auth["execution_id"],
            action=action,
            challenge_token=self._challenge(initial),
            stage="citizen flow selection",
        )
        phone_inputs = {"mobile_number": phone}
        if action == "action_signup":
            # The caller cannot select actor kind. The native flow and user schema
            # independently constrain this hidden field to the same fixed value.
            phone_inputs["registry_actor_kind"] = _HUMAN_ACTOR_KIND
        otp_prompt = self._flow(
            auth["execution_id"],
            inputs=phone_inputs,
            action="action_send_otp",
            challenge_token=self._challenge(mode),
            stage="citizen OTP generation and delivery",
        )
        otp = otp_for(phone)
        if not isinstance(otp, str) or not otp:
            raise IdentityFlowError("otp_for returned no OTP")
        complete = self._flow(
            auth["execution_id"],
            inputs={"otp": otp},
            action="action_verify_otp",
            challenge_token=self._challenge(otp_prompt),
            stage="citizen OTP verification",
        )
        self._raise_invalid_otp(complete)
        token = self._finish_authorization(
            auth,
            complete,
            client_id=_CITIZEN_CLIENT_ID,
            redirect_uri=_CITIZEN_REDIRECT_URI,
            requested_scopes=requested_scopes,
            require_exact_scopes=_scope_probe is None,
        )
        return token

    def _start_authorization(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scopes: Iterable[str],
    ) -> dict[str, str]:
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state = secrets.token_urlsafe(24)
        query = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": " ".join(scopes),
                "state": state,
                "resource": self.audience,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        status, headers, _ = self._request("GET", f"/oauth2/authorize?{query}", redirect=False)
        if status not in {302, 303, 307, 308}:
            raise IdentityError(f"authorization endpoint returned HTTP {status}")
        location = headers.get("Location")
        if not location:
            raise IdentityError("authorization endpoint returned no redirect")
        values = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        refusal = self._optional_query(values, "error")
        if refusal is not None:
            if self._optional_query(values, "state") != state:
                raise IdentityError("OAuth authorization error state did not match")
            raise _OAuthAuthorizationRefusal(refusal)
        if "authId" not in values:
            raise IdentityError("OAuth authorization redirect omitted authId without an error code")
        if "executionId" not in values:
            raise IdentityError("OAuth authorization redirect omitted executionId without an error code")
        auth_id = self._one_query(values, "authId")
        execution_id = self._one_query(values, "executionId")
        return {
            "auth_id": auth_id,
            "execution_id": execution_id,
            "state": state,
            "verifier": verifier,
        }

    def _finish_authorization(
        self,
        auth: Mapping[str, str],
        complete: Mapping[str, Any],
        *,
        client_id: str,
        redirect_uri: str,
        requested_scopes: Iterable[str],
        require_exact_scopes: bool = True,
    ) -> dict[str, Any]:
        if complete.get("flowStatus") != "COMPLETE" or not complete.get("assertion"):
            raise IdentityFlowError(self._flow_error(complete), step=complete)
        callback = self._json_request(
            "POST",
            "/oauth2/auth/callback",
            {"authId": auth["auth_id"], "assertion": complete["assertion"]},
        )
        redirect = callback.get("redirect_uri")
        if not isinstance(redirect, str):
            raise IdentityError("authorization callback returned no redirect_uri")
        query = urllib.parse.parse_qs(urllib.parse.urlparse(redirect).query)
        if self._one_query(query, "state") != auth["state"]:
            raise IdentityError("authorization callback state did not match")
        code = self._one_query(query, "code")
        secret = self._read_client_secret(client_id)
        token = self._form_request(
            "/oauth2/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": auth["verifier"],
                "client_id": client_id,
                "client_secret": secret,
                "resource": self.audience,
            },
        )
        bearer = token.get("access_token")
        if not isinstance(bearer, str) or not bearer:
            raise IdentityError("token endpoint returned no access_token")
        claims = self._decode_jwt_unverified(bearer)
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise IdentityError("access token has no subject")
        if claims.get("registry_actor_kind") != _HUMAN_ACTOR_KIND:
            raise IdentityError("access token is missing the fixed human actor marker")
        token_client = claims.get("client_id", claims.get("azp"))
        if token_client != client_id:
            raise IdentityError("access token client does not match the requested OAuth client")
        audiences = claims.get("aud")
        if isinstance(audiences, str):
            audiences = [audiences]
        if not isinstance(audiences, list) or self.audience not in audiences:
            raise IdentityError("access token audience does not match the BReg resource")
        granted = set(self._scope_values(claims.get("scope")))
        if "scope" in token and set(self._scope_values(token["scope"])) != granted:
            raise IdentityError("token response scope does not match the access token")
        requested = set(requested_scopes)
        if require_exact_scopes and granted != requested:
            raise IdentityError("issuer did not return the exact requested scopes")
        if client_id == _CITIZEN_CLIENT_ID and granted & _STAFF_ONLY_SCOPES and require_exact_scopes:
            raise IdentityError("citizen token unexpectedly contains a staff scope")
        return {"access_token": bearer, "sub": subject, "granted_scopes": tuple(sorted(granted))}

    def _flow(
        self,
        execution_id: str,
        *,
        inputs: Mapping[str, str] | None = None,
        action: str | None = None,
        challenge_token: str | None = None,
        stage: str,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"executionId": execution_id}
        if inputs:
            body["inputs"] = dict(inputs)
        if action:
            body["action"] = action
        if challenge_token:
            body["challengeToken"] = challenge_token
        try:
            return self._json_request("POST", "/flow/execute", body)
        except IdentityError as exc:
            raise IdentityFlowError(f"{stage} failed: {exc}") from exc

    def _json_request(self, method: str, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        raw = json.dumps(body, separators=(",", ":")).encode()
        status, _, response = self._request(
            method,
            path,
            data=raw,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        if status != 200:
            raise IdentityError(f"ThunderID returned HTTP {status} for {path}")
        try:
            decoded = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IdentityError(f"ThunderID returned invalid JSON for {path}") from exc
        if not isinstance(decoded, dict):
            raise IdentityError(f"ThunderID returned an invalid object for {path}")
        return decoded

    def _form_request(self, path: str, body: Mapping[str, str]) -> dict[str, Any]:
        status, _, response = self._request(
            "POST",
            path,
            data=urllib.parse.urlencode(body).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        if status != 200:
            raise IdentityError(f"ThunderID returned HTTP {status} for {path}")
        try:
            decoded = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IdentityError(f"ThunderID returned invalid JSON for {path}") from exc
        if not isinstance(decoded, dict):
            raise IdentityError(f"ThunderID returned an invalid object for {path}")
        return decoded

    def _request(
        self,
        method: str,
        path: str,
        *,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        redirect: bool = True,
    ) -> tuple[int, Mapping[str, str], bytes]:
        request = urllib.request.Request(
            urllib.parse.urljoin(f"{self.issuer}/", path.lstrip("/")),
            data=data,
            headers=dict(headers or {}),
            method=method,
        )
        opener = urllib.request.build_opener() if redirect else self._opener
        try:
            with opener.open(request, timeout=10) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read()
            if not redirect and exc.code in {301, 302, 303, 307, 308}:
                return exc.code, exc.headers, body
            raise IdentityError(f"ThunderID returned HTTP {exc.code} for {path}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise IdentityError(f"ThunderID request failed for {path}") from exc

    def _read_client_secret(self, client_id: str) -> str:
        path = self.secret_root / f"application-{client_id}"
        try:
            info = path.stat(follow_symlinks=False)
        except FileNotFoundError as exc:
            raise IdentityError(f"generated client secret is absent for {client_id}") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise IdentityError(f"generated client secret is not an owner-only regular file for {client_id}")
        secret = path.read_text(encoding="utf-8").strip()
        if len(secret) < 16:
            raise IdentityError(f"generated client secret is invalid for {client_id}")
        return secret

    def _issuer_is_reachable(self) -> bool:
        request = urllib.request.Request(f"{self.issuer}/health/liveness", method="GET")
        try:
            with self._opener.open(request, timeout=1):
                return True
        except urllib.error.HTTPError:
            return True
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (ConnectionRefusedError, ConnectionResetError)):
                return False
            raise IdentityError("could not establish whether the issuer is stopped") from exc
        except TimeoutError as exc:
            raise IdentityError("issuer health probe timed out; stop it before bootstrap") from exc

    @staticmethod
    def _find_application(resources: Path, client_id: str) -> tuple[Path, dict[str, Any]]:
        matches: list[tuple[Path, dict[str, Any]]] = []
        for path in sorted((resources / "applications").glob("*.yaml")):
            document = NativeIdentity._load_yaml(path)
            if not isinstance(document, dict):
                continue
            for inbound in document.get("inboundAuthConfig", []):
                if not isinstance(inbound, dict):
                    continue
                config = inbound.get("config")
                if isinstance(config, dict) and config.get("clientId") == client_id:
                    matches.append((path, document))
        if len(matches) != 1:
            raise IdentityError(f"expected exactly one declarative application for {client_id}")
        return matches[0]

    @staticmethod
    def _find_resource_server(resources: Path, audience: str) -> str:
        matches: list[str] = []
        for path in sorted((resources / "resource_servers").glob("*.yaml")):
            document = NativeIdentity._load_yaml(path)
            if isinstance(document, dict) and document.get("identifier") == audience:
                identifier = document.get("id")
                if isinstance(identifier, str) and identifier:
                    matches.append(identifier)
        if len(matches) != 1:
            raise IdentityError("expected exactly one issuer resource server for the BReg audience")
        return matches[0]

    @staticmethod
    def _ensure_human_token_attribute(application: dict[str, Any]) -> None:
        inbound = application.get("inboundAuthConfig")
        if not isinstance(inbound, list) or len(inbound) != 1 or not isinstance(inbound[0], dict):
            raise IdentityError("citizen-portal has an unexpected inboundAuthConfig")
        config = inbound[0].get("config")
        if not isinstance(config, dict):
            raise IdentityError("citizen-portal has no OAuth configuration")
        token = config.setdefault("token", {})
        access = token.setdefault("accessToken", {})
        user = access.setdefault("userConfig", {})
        attributes = user.setdefault("attributes", [])
        if not isinstance(attributes, list):
            raise IdentityError("citizen-portal token attribute configuration is invalid")
        if "registry_actor_kind" not in attributes:
            attributes.append("registry_actor_kind")

    @staticmethod
    def _load_yaml(path: Path) -> Any:
        try:
            return yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise IdentityError(f"could not read native resource {path.name}") from exc

    @staticmethod
    def _atomic_yaml(path: Path, document: Any, *, explicit_start: bool = True) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        rendered = yaml.safe_dump(document, sort_keys=False, explicit_start=explicit_start)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    @staticmethod
    def _substitute(value: Any, substitutions: Mapping[str, str]) -> Any:
        if isinstance(value, str):
            return substitutions.get(value, value)
        if isinstance(value, list):
            return [NativeIdentity._substitute(item, substitutions) for item in value]
        if isinstance(value, dict):
            return {key: NativeIdentity._substitute(item, substitutions) for key, item in value.items()}
        return value

    @staticmethod
    def _challenge(step: Mapping[str, Any]) -> str | None:
        value = step.get("challengeToken")
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _flow_error(step: Mapping[str, Any]) -> str:
        error = step.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, dict) and isinstance(message.get("defaultValue"), str):
                return message["defaultValue"]
            if isinstance(error.get("code"), str):
                return error["code"]
        return f"native flow did not complete ({step.get('flowStatus', 'unknown status')})"

    @staticmethod
    def _raise_invalid_otp(step: Mapping[str, Any]) -> None:
        error = step.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        if code != _INVALID_OTP_ERROR:
            return
        if step.get("flowStatus") != "INCOMPLETE" or step.get("assertion"):
            raise IdentityError("native invalid-OTP response was not an incomplete assertion-free step")
        raise IdentityFlowError(NativeIdentity._flow_error(step), step=step)

    @staticmethod
    def _optional_query(values: Mapping[str, list[str]], key: str) -> str | None:
        found = values.get(key)
        if found is None:
            return None
        if len(found) != 1 or not found[0]:
            raise IdentityError(f"OAuth response has no unambiguous {key}")
        return found[0]

    @staticmethod
    def _one_query(values: Mapping[str, list[str]], key: str) -> str:
        found = values.get(key)
        if not found or len(found) != 1 or not found[0]:
            raise IdentityError(f"OAuth response has no unambiguous {key}")
        return found[0]

    @staticmethod
    def _decode_jwt_unverified(token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise IdentityError("access token is not a JWT")
        try:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(payload))
        except (ValueError, json.JSONDecodeError) as exc:
            raise IdentityError("access token payload is invalid") from exc
        if not isinstance(decoded, dict):
            raise IdentityError("access token payload is not an object")
        return decoded

    @staticmethod
    def _scope_values(value: Any) -> tuple[str, ...]:
        if isinstance(value, str):
            return tuple(part for part in value.split() if part)
        if isinstance(value, list) and all(isinstance(part, str) for part in value):
            return tuple(value)
        return ()
