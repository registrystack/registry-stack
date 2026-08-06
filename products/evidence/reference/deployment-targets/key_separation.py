#!/usr/bin/env python3
"""Validate public-key shape and separation in the reference targets."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import pathlib
import re
import stat
import sys
from collections.abc import Iterable
from typing import Any

try:
    import yaml
except ImportError as error:  # pragma: no cover - depends on the operator host
    raise SystemExit(
        "PyYAML is required to check deployment target client keys"
    ) from error


MAX_CLIENT_FILE_BYTES = 256 * 1024
PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
P256_PRIME = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


class CheckError(ValueError):
    """A target key document violates the checked public-key contract."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader which also rejects duplicate mapping members."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a duplicate mapping key",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _decode_base64url(
    value: Any, member: str, expected_bytes: int | None = None
) -> bytes:
    if not isinstance(value, str) or not BASE64URL.fullmatch(value):
        raise CheckError(f"{member} is not unpadded base64url")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise CheckError(f"{member} is not unpadded base64url") from error
    encoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if encoded != value:
        raise CheckError(f"{member} is not canonical base64url")
    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise CheckError(f"{member} has the wrong public-coordinate length")
    return decoded


def _required_string(key: dict[str, Any], member: str) -> str:
    value = key.get(member)
    if not isinstance(value, str) or not value:
        raise CheckError(f"{member} must be a non-empty string")
    return value


def _validate_kid(key: dict[str, Any]) -> str:
    kid = _required_string(key, "kid")
    if len(kid.encode("utf-8")) > 256 or kid.strip() != kid:
        raise CheckError("kid must be 1..=256 non-whitespace bytes")
    if any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in kid
    ):
        raise CheckError("kid contains a control character")
    return kid


def _validate_optional_algorithm(key: dict[str, Any], expected: str) -> None:
    algorithm = key.get("alg")
    if algorithm is not None and algorithm != expected:
        raise CheckError(f"alg must be {expected} when present")


def public_material(key: Any) -> tuple[str, dict[str, str]]:
    """Return kid and complete RFC 7638 public material for a supported client key."""
    if not isinstance(key, dict) or not all(isinstance(member, str) for member in key):
        raise CheckError("a client key must be a mapping with string members")
    if PRIVATE_MEMBERS.intersection(key):
        raise CheckError("client key contains private key material")
    kid = _validate_kid(key)
    key_type = _required_string(key, "kty")

    if key_type == "OKP":
        if key.get("crv") != "Ed25519" or any(
            member in key for member in ("y", "n", "e")
        ):
            raise CheckError("OKP client key must be an Ed25519 public JWK")
        _validate_optional_algorithm(key, "EdDSA")
        _decode_base64url(key.get("x"), "x", 32)
        material = {"crv": "Ed25519", "kty": "OKP", "x": key["x"]}
    elif key_type == "EC":
        if key.get("crv") != "P-256" or any(member in key for member in ("n", "e")):
            raise CheckError("EC client key must be a P-256 public JWK")
        _validate_optional_algorithm(key, "ES256")
        x_bytes = _decode_base64url(key.get("x"), "x", 32)
        y_bytes = _decode_base64url(key.get("y"), "y", 32)
        x_coordinate = int.from_bytes(x_bytes, "big")
        y_coordinate = int.from_bytes(y_bytes, "big")
        if not (x_coordinate < P256_PRIME and y_coordinate < P256_PRIME):
            raise CheckError("EC public coordinate is outside P-256")
        if (
            pow(y_coordinate, 2, P256_PRIME)
            != (pow(x_coordinate, 3, P256_PRIME) - 3 * x_coordinate + P256_B)
            % P256_PRIME
        ):
            raise CheckError("EC public coordinates are not a P-256 point")
        material = {"crv": "P-256", "kty": "EC", "x": key["x"], "y": key["y"]}
    elif key_type == "RSA":
        if any(member in key for member in ("crv", "x", "y")):
            raise CheckError("RSA client key contains another key type's members")
        _validate_optional_algorithm(key, "RS256")
        modulus = _decode_base64url(key.get("n"), "n")
        exponent = _decode_base64url(key.get("e"), "e")
        if not modulus or modulus[0] == 0 or not exponent or exponent[0] == 0:
            raise CheckError(
                "RSA public integers must be nonzero and minimally encoded"
            )
        exponent_value = int.from_bytes(exponent, "big")
        if exponent_value < 3 or exponent_value % 2 == 0:
            raise CheckError(
                "RSA public exponent must be an odd integer of at least three"
            )
        material = {"e": key["e"], "kty": "RSA", "n": key["n"]}
    else:
        raise CheckError("client key type is not Ed25519, P-256, or RSA")

    return kid, material


def material_fingerprint(material: dict[str, str]) -> str:
    canonical = json.dumps(material, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return (
        base64.urlsafe_b64encode(hashlib.sha256(canonical).digest())
        .rstrip(b"=")
        .decode()
    )


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        pairs = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=list)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CheckError(f"{path}: service JWK is unreadable or malformed") from error
    if not isinstance(pairs, list) or any(
        not isinstance(pair, tuple) for pair in pairs
    ):
        raise CheckError(f"{path}: service JWK must be an object")
    result: dict[str, Any] = {}
    for member, value in pairs:
        if member in result:
            raise CheckError(f"{path}: service JWK has a duplicate member")
        result[member] = value
    return result


def _read_client(path: pathlib.Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise CheckError(f"{path}: client registration is not a regular file")
        if metadata.st_size > MAX_CLIENT_FILE_BYTES:
            raise CheckError(f"{path}: client registration exceeds its byte limit")
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except CheckError:
        raise
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise CheckError(
            f"{path}: client registration YAML is unreadable or malformed"
        ) from error
    if not isinstance(document, dict):
        raise CheckError(f"{path}: client registration must be a mapping")
    return document


def _remember(
    seen: dict[str, pathlib.Path], fingerprint: str, path: pathlib.Path
) -> None:
    previous = seen.get(fingerprint)
    if previous is not None:
        raise CheckError(f"{path}: public key material reused from {previous}")
    seen[fingerprint] = path


def check_client_file(path: pathlib.Path, seen: dict[str, pathlib.Path]) -> None:
    document = _read_client(path)
    keys = document.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= 8:
        raise CheckError(f"{path}: between one and eight client keys are required")
    kids: set[str] = set()
    for key in keys:
        try:
            kid, material = public_material(key)
        except CheckError as error:
            raise CheckError(f"{path}: {error}") from error
        if kid in kids:
            raise CheckError(
                f"{path}: client key ids must be unique within one registration"
            )
        kids.add(kid)
        _remember(seen, material_fingerprint(material), path)


def _service_keys(path: pathlib.Path) -> Iterable[pathlib.Path]:
    keys = sorted(path.glob("*.jwk.json"))
    if not keys:
        raise CheckError(
            f"{path}: at least one governed service public key is required"
        )
    return keys


def check_targets(root: pathlib.Path) -> None:
    environments_root = root / "environments"
    try:
        environments = sorted(
            path for path in environments_root.iterdir() if path.is_dir()
        )
    except OSError as error:
        raise CheckError("deployment target environments are unavailable") from error
    if not environments:
        raise CheckError("at least one complete deployment environment is required")

    seen: dict[str, pathlib.Path] = {}
    for environment in environments:
        for service in ("evidence", "mint"):
            public_keys = environment / service / "public-keys"
            for path in _service_keys(public_keys):
                key = _read_json(path)
                if set(key) != {"kty", "crv", "alg", "kid", "x", "y"}:
                    raise CheckError(f"{path}: service JWK is not exact public ES256")
                try:
                    kid, material = public_material(key)
                except CheckError as error:
                    raise CheckError(
                        f"{path}: service JWK is invalid: {error}"
                    ) from error
                if (key["kty"], key["crv"], key["alg"]) != ("EC", "P-256", "ES256"):
                    raise CheckError(f"{path}: service JWK is not EC P-256 ES256")
                thumbprint = material_fingerprint(material)
                if kid != thumbprint or path.name != f"{thumbprint}.jwk.json":
                    raise CheckError(
                        f"{path}: kid or filename is not its RFC 7638 thumbprint"
                    )
                _remember(seen, thumbprint, path)

        client_directory = environment / "mint" / "clients"
        client_files = sorted(client_directory.glob("*.yaml"))
        if not client_files:
            raise CheckError(
                f"{client_directory}: at least one client registration is required"
            )
        for path in client_files:
            check_client_file(path, seen)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: key_separation.py <deployment-target-root>", file=sys.stderr)
        return 2
    try:
        check_targets(pathlib.Path(argv[1]))
    except CheckError as error:
        print(error, file=sys.stderr)
        return 1
    print(
        "Deployment target service and client public keys are distinct and correctly identified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
