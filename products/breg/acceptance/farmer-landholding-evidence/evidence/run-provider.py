#!/usr/bin/env python3
"""Run the synthetic farmer source, token issuer and actual Evidence binary.

All tokens, keys, source requests and logs stay in the owner-only output tree.
Write a newline to stdin (or close it) to stop the service and its source.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import ProxyHandler, Request, build_opener

urlopen = build_opener(ProxyHandler({})).open

import yaml


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def command(*args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


def der_value(data, offset=0):
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 128:
        count = length & 127
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def make_key(root, name):
    pem = root / (name + ".pem")
    command("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(pem))
    private_der = command("openssl", "ec", "-in", str(pem), "-outform", "DER")
    _, sequence, _ = der_value(private_der)
    _, _, end = der_value(sequence)
    _, scalar, _ = der_value(sequence, end)
    public_der = command("openssl", "ec", "-in", str(pem), "-pubout", "-outform", "DER")
    point = public_der[-65:]
    assert point[0] == 4 and len(scalar) == 32
    public = {"kty": "EC", "crv": "P-256", "x": b64(point[1:33]), "y": b64(point[33:])}
    kid = b64(hashlib.sha256(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).digest())
    public.update(alg="ES256", kid=kid)
    return pem, public, dict(public, d=b64(scalar))


def sign_token(pem, public, claims):
    header = {"alg": "ES256", "kid": public["kid"], "typ": "at+jwt"}
    data = (b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())).encode()
    signature = command("openssl", "dgst", "-sha256", "-sign", str(pem), data=data)
    _, sequence, _ = der_value(signature)
    _, r, end = der_value(sequence)
    _, s, _ = der_value(sequence, end)
    raw = int.from_bytes(r, "big").to_bytes(32, "big") + int.from_bytes(s, "big").to_bytes(32, "big")
    return data.decode() + "." + b64(raw)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "ready.json").exists():
        raise RuntimeError("use a fresh output directory")
    secrets = output / "secrets"
    secrets.mkdir()
    bundle = output / "bundle"
    shutil.copytree(Path(__file__).parent / "provider", bundle)
    issuer_pem, issuer_public, _ = make_key(secrets, "issuer")
    _, signing_public, signing_private = make_key(secrets, "signer")
    write_json(secrets / "signing-key", signing_private)
    write_json(output / "jwks.json", {"keys": [signing_public]})
    for name in ("audit-hash-key", "subject-binding-key", "source-a-token"):
        (secrets / name).write_text(b64(os.urandom(32)))
    source_token = (secrets / "source-a-token").read_text()
    control_path = output / "control.json"
    write_json(control_path, {"active": True, "category": "smallholder", "mode": "match"})
    requests_path = output / "requests.jsonl"
    requests_path.touch()
    request_lock = threading.Lock()

    class Source(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send_json(self, code, value):
            encoded = json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            if self.path == "/.well-known/jwks.json":
                self.send_json(200, {"keys": [issuer_public]})
            else:
                self.send_json(404, {})

        def do_POST(self):
            if self.path != "/v1/facts" or self.headers.get("Authorization") != "Bearer " + source_token:
                self.send_json(403, {})
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                self.send_json(400, {})
                return
            request = json.loads(self.rfile.read(length))
            with request_lock:
                with requests_path.open("a") as log:
                    log.write(json.dumps(request) + "\n")
            control = json.loads(control_path.read_text())
            if request.get("reference") not in ("TH-00042", "TH-00043") or control.get("mode") == "missing":
                self.send_json(200, {"total": 0})
                return
            if control.get("mode") == "ambiguous":
                self.send_json(200, {"total": 2})
                return
            reference = "TH-99999" if control.get("mode") == "mismatch" else request["reference"]
            self.send_json(200, {"total": 1, "reference": reference, "active": control["active"] and request["reference"] != "TH-00043", "category": control["category"]})

    source = ThreadingHTTPServer(("127.0.0.1", 0), Source)
    threading.Thread(target=source.serve_forever, daemon=True).start()
    issuer = "http://127.0.0.1:" + str(source.server_port)
    reservation = socket.socket()
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    origin = "http://127.0.0.1:" + str(port)
    config = yaml.safe_load((bundle / "evidence.yaml").read_text())
    config["service"]["publicOrigin"] = origin
    config["authentication"]["issuer"] = issuer
    config["authentication"]["jwksUri"] = issuer + "/.well-known/jwks.json"
    for source_config in config["sources"].values():
        source_config["baseUrl"] = issuer
    for path in (bundle / "public-keys").iterdir():
        path.unlink()
    public_path = "public-keys/" + signing_public["kid"] + ".jwk.json"
    write_json(bundle / public_path, signing_public)
    config["signing"]["activePublicJwkFile"] = public_path
    (bundle / "evidence.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
    runtime = {"version": 1, "bundleDirectory": str(bundle), "listener": {
        "bindHost": "127.0.0.1", "port": port, "tlsTermination": "operator-controlled-upstream", "trustProxyIdentityHeaders": False,
        "maximumRequestBytes": 65536, "maximumConcurrentRequests": 16, "requestTimeoutMilliseconds": 10000, "shutdownGraceMilliseconds": 1000},
        "secretProviders": {"file": {"root": str(secrets)}}, "signer": {"kind": "local-jwk", "privateKeyRef": "secret:file/signing-key"},
        "auditStorage": {"path": str(output / "audit.jsonl"), "maximumFileBytes": 10485760}, "outboundTls": {"systemRoots": True, "trustProfiles": {}}}
    runtime_path = output / "runtime.yaml"
    runtime_path.write_text(yaml.safe_dump(runtime, sort_keys=False))
    runtime_path.chmod(0o444)
    for path in bundle.rglob("*"):
        if path.is_file():
            path.chmod(0o444)
    for path in sorted(bundle.rglob("*"), reverse=True):
        if path.is_dir():
            path.chmod(0o555)
    bundle.chmod(0o555)
    now = int(time.time())
    claims = {"iss": issuer, "aud": "farmer-evidence-trial", "sub": "registered-breg-procedure", "iat": now - 1, "exp": now + 299,
              "evidence_tags": ["breg-farmer-procedure"], "evidence_audience": "urn:example:landholding"}
    token = sign_token(issuer_pem, issuer_public, claims)
    token_path = output / "token"
    token_path.write_text(token)
    unauthorized_path = output / "unauthorized-token"
    unauthorized_path.write_text(sign_token(issuer_pem, issuer_public, dict(claims, evidence_tags=[])))
    reservation.close()
    stop = threading.Event()
    def finish(*_args):
        stop.set()
    signal.signal(signal.SIGTERM, finish)
    signal.signal(signal.SIGINT, finish)
    def stdin_stop():
        sys.stdin.readline()
        stop.set()
    threading.Thread(target=stdin_stop, daemon=True).start()
    with (output / "service.log").open("wb") as log:
        process = subprocess.Popen([str(args.evidence.resolve()), "--runtime", str(runtime_path), "serve"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Evidence startup failed; inspect protected service.log")
                try:
                    with urlopen(origin + "/ready", timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Evidence readiness deadline expired")
                    time.sleep(0.05)
            request = Request(origin + "/v1/evidence-definitions", headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
            with urlopen(request, timeout=5) as response:
                definitions = json.load(response)
            contracts = {key: definitions[key] for key in ("assuranceProfile", "audience", "issuedBy", "providedBy", "definitions")}
            contracts["schema"] = "registry.evidence-client-contracts/v1"
            contracts_path = output / "contracts.json"
            write_json(contracts_path, contracts)
            write_json(output / "ready.json", {"baseUrl": origin, "contractsFile": str(contracts_path), "tokenFile": str(token_path),
                "unauthorizedTokenFile": str(unauthorized_path), "jwksFile": str(output / "jwks.json"), "requestsFile": str(requests_path), "controlFile": str(control_path)})
            stop.wait()
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            source.shutdown()
            source.server_close()
            # The service has exited; allow the owning test to remove its temporary tree.
            bundle.chmod(0o700)
            for path in bundle.rglob("*"):
                path.chmod(0o700 if path.is_dir() else 0o600)


if __name__ == "__main__":
    main()
