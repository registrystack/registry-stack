#!/usr/bin/env python3
"""Seed the local MOSIP eSignet stack for the Registry Lab citizen flow."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


CLIENT_ID = "registry-lab-live-client"
CLIENT_KEY_ID = "registry-lab-live-client-key-1"
RELYING_PARTY_ID = "registry-lab"
CLIENT_DETAIL_CACHE_KEY = f"esignet:clientdetails::{CLIENT_ID}"
DEMO_PIN = "545411"
DEMO_USERS = [
    ("NID-1001", "Miguel", "Santos", "2016/01/15", "Male", "north"),
    ("NID-1002", "Maria", "Dela Cruz", "2018/01/15", "Female", "south"),
    ("NID-1003", "Cara", "Okafor", "1957/02/14", "Female", "central"),
    ("NID-1004", "Rafael", "Aquino", "2019/01/15", "Male", "east"),
    ("NID-1005", "Rosalie", "Bautista", "2013/01/15", "Female", "west"),
    ("NID-1006", "Miguel", "Martinez", "2014/01/15", "Male", "north"),
    ("NID-1007", "Lola", "Santos", "1958/01/15", "Female", "north"),
    ("NID-1008", "Rosa", "Garcia", "1954/01/15", "Female", "west"),
    ("NID-1009", "Ana", "Mendoza", "1998/01/15", "Female", "east"),
    ("NID-2001", "Maria", "Santos", "1984/01/15", "Female", "north"),
]


def run(args: list[str], *, input_text: str | None = None, capture: bool = False) -> str:
    result = subprocess.run(
        args,
        input=input_text,
        text=True,
        check=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout if capture else ""


def psql(database: str, sql: str, *, capture: bool = False) -> str:
    return run(
        [
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            database,
            "-At",
        ],
        input_text=sql,
        capture=capture,
    )


def wait_for_table(database: str, table_name: str) -> None:
    deadline = time.time() + 180
    query = f"select to_regclass('{table_name}') is not null;\n"
    while time.time() < deadline:
        try:
            if psql(database, query, capture=True).strip() == "t":
                return
        except subprocess.CalledProcessError:
            pass
        time.sleep(2)
    raise RuntimeError(f"timed out waiting for {database}.{table_name}")


def read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    size = first & 0x7F
    length = int.from_bytes(data[offset : offset + size], "big")
    return length, offset + size


def read_der_tlv(data: bytes, offset: int, expected_tag: int | None = None) -> tuple[int, bytes, int]:
    tag = data[offset]
    if expected_tag is not None and tag != expected_tag:
        raise ValueError(f"expected ASN.1 tag {expected_tag:#x}, got {tag:#x}")
    length, value_offset = read_der_length(data, offset + 1)
    end = value_offset + length
    return tag, data[value_offset:end], end


def read_der_int(data: bytes, offset: int) -> tuple[int, int]:
    _, value, end = read_der_tlv(data, offset, 0x02)
    return int.from_bytes(value.lstrip(b"\x00"), "big"), end


def public_jwk(private_key: Path) -> str:
    der = subprocess.check_output(
        ["openssl", "rsa", "-in", str(private_key), "-pubout", "-outform", "DER"],
        stderr=subprocess.DEVNULL,
    )
    _, spki, _ = read_der_tlv(der, 0, 0x30)
    _, _, offset = read_der_tlv(spki, 0, 0x30)
    _, bit_string, _ = read_der_tlv(spki, offset, 0x03)
    if bit_string[0] != 0:
        raise ValueError("unsupported subject public key bit string")
    _, rsa_public_key, _ = read_der_tlv(bit_string[1:], 0, 0x30)
    modulus, offset = read_der_int(rsa_public_key, 0)
    exponent, _ = read_der_int(rsa_public_key, offset)

    def b64url_int(value: int) -> str:
        width = max(1, (value.bit_length() + 7) // 8)
        raw = value.to_bytes(width, "big")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    jwk = {
        "kty": "RSA",
        "kid": CLIENT_KEY_ID,
        "use": "sig",
        "alg": "RS256",
        "n": b64url_int(modulus),
        "e": b64url_int(exponent),
    }
    return json.dumps(jwk, separators=(",", ":"))


def ensure_private_key() -> tuple[Path, str, str]:
    key_file = Path(os.environ.get("ESIGNET_CLIENT_PRIVATE_KEY_FILE", "/output/client-private.pem"))
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if not key_file.exists():
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key_file)])
        key_file.chmod(0o600)
    jwk = public_jwk(key_file)
    key_hash = hashlib.sha256(jwk.encode("utf-8")).hexdigest()
    return key_file, jwk, key_hash


def sql_literal(value: object) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, separators=(",", ":"))
    return "'" + value.replace("'", "''") + "'"


def seed_esignet(jwk: str, key_hash: str) -> None:
    client_name = {"@none": "Registry Lab Live eSignet Client"}
    additional_config = {
        "userinfo_response_type": "JWS",
        "purpose": {"type": "verify"},
        "signup_banner_required": False,
        "forgot_pwd_link_required": False,
        "consent_expire_in_mins": 20,
    }
    sql = f"""
insert into esignet.client_detail (
  id, name, rp_id, logo_uri, redirect_uris, claims, acr_values, public_key,
  public_key_hash, grant_types, auth_methods, status, additional_config,
  cr_dtimes, upd_dtimes
) values (
  {sql_literal(CLIENT_ID)},
  {sql_literal(client_name)},
  {sql_literal(RELYING_PARTY_ID)},
  'https://example.invalid/logo.png',
  {sql_literal([
      "http://127.0.0.1:4325/callback",
      "http://localhost:5000/callback",
      "http://localhost:5000/**",
      "http://localhost:8765/callback",
      "http://localhost:8765/**",
      "http://localhost:8766/callback",
      "http://localhost:8766/**",
  ])},
  {sql_literal(["individual_id", "name", "email", "gender", "phone_number", "picture", "birthdate"])},
  {sql_literal(["mosip:idp:acr:generated-code", "mosip:idp:acr:password", "mosip:idp:acr:linked-wallet"])},
  {sql_literal(jwk)},
  {sql_literal(key_hash)},
  {sql_literal(["authorization_code"])},
  {sql_literal(["private_key_jwt"])},
  'ACTIVE',
  {sql_literal(additional_config)},
  now(),
  now()
)
on conflict (id) do update set
  public_key = excluded.public_key,
  public_key_hash = excluded.public_key_hash,
  redirect_uris = excluded.redirect_uris,
  claims = excluded.claims,
  acr_values = excluded.acr_values,
  grant_types = excluded.grant_types,
  auth_methods = excluded.auth_methods,
  status = excluded.status,
  additional_config = excluded.additional_config,
  upd_dtimes = now();
"""
    psql("mosip_esignet", sql)


def clear_esignet_client_cache() -> None:
    redis_host = os.environ.get("ESIGNET_REDIS_HOST")
    if not redis_host:
        return
    redis_port = int(os.environ.get("ESIGNET_REDIS_PORT", "6379"))
    command = redis_command("DEL", CLIENT_DETAIL_CACHE_KEY)
    with socket.create_connection((redis_host, redis_port), timeout=10) as connection:
        connection.sendall(command)
        response = connection.recv(128)
    if not response.startswith((b":0", b":1")):
        raise RuntimeError(f"failed to clear eSignet client cache: {response!r}")


def redis_command(*parts: str) -> bytes:
    encoded = [part.encode("utf-8") for part in parts]
    payload = [f"*{len(encoded)}\r\n".encode("ascii")]
    for part in encoded:
        payload.append(f"${len(part)}\r\n".encode("ascii"))
        payload.append(part)
        payload.append(b"\r\n")
    return b"".join(payload)


def demo_identity(user: tuple[str, str, str, str, str, str]) -> dict[str, object]:
    individual_id, given_name, family_name, date_of_birth, gender, region = user
    full_name = f"{given_name} {family_name}"
    return {
        "individualId": individual_id,
        "pin": DEMO_PIN,
        "password": DEMO_PIN,
        "email": f"{individual_id.lower()}@example.test",
        "phone": "+919427357934",
        "fullName": [{"language": "eng", "value": full_name}],
        "givenName": [{"language": "eng", "value": given_name}],
        "familyName": [{"language": "eng", "value": family_name}],
        "preferredUsername": [{"language": "eng", "value": full_name.lower().replace(" ", ".")}],
        "gender": [{"language": "eng", "value": gender}],
        "dateOfBirth": date_of_birth,
        "region": [{"language": "eng", "value": region}],
        "preferredLang": "eng",
        "locale": "eng",
    }


def seed_mock_identities() -> None:
    values = ",\n".join(
        f"({sql_literal(individual_id)}, {sql_literal(demo_identity(user))})"
        for user in DEMO_USERS
        for individual_id in [user[0]]
    )
    sql = f"""
insert into mockidentitysystem.mock_identity (individual_id, identity_json)
values
{values}
on conflict (individual_id) do update set identity_json = excluded.identity_json;
"""
    psql("mosip_mockidentitysystem", sql)


def main() -> int:
    key_file, jwk, key_hash = ensure_private_key()
    wait_for_table("mosip_esignet", "esignet.client_detail")
    wait_for_table("mosip_mockidentitysystem", "mockidentitysystem.mock_identity")
    seed_esignet(jwk, key_hash)
    clear_esignet_client_cache()
    seed_mock_identities()
    print(f"Seeded eSignet lab client {CLIENT_ID}.")
    print(f"Cleared eSignet client cache key {CLIENT_DETAIL_CACHE_KEY}.")
    print(f"Seeded {len(DEMO_USERS)} mock identities: {', '.join(user[0] for user in DEMO_USERS)}.")
    print(f"Client private key: {key_file}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"seed-esignet-live.py: {exc}", file=sys.stderr)
        raise
