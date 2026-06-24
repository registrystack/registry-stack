#!/usr/bin/env python3
"""Validate the committed public Bruno API workspace."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


COLLECTION_PATH = Path("requests/registry-lab")
HOMEPAGE_ENV_PATH = Path("config/lab-homepage/public-demo-credentials.env")
DOCS_INDEX_PATH = Path("docs/README.md")
SPEC_PATH = Path("docs/public-api-workspace.md")

REQUIRED_FOLDERS = (
    "00 - Start Here",
    "10 - Relay Metadata",
    "20 - Relay Access Boundaries",
    "30 - Notary Evaluation",
)

FORBIDDEN_NAME_RE = re.compile(
    "|".join(
        [
            r"\b[A-Z0-9_]*SOURCE_RAW\b",
            r"\bOPENFN_SIDECAR_TOKEN_RAW\b",
            r"\bREGISTRY_NOTARY_ISSUER_JWK\b",
            r"\bREGISTRY_NOTARY_ACCESS_TOKEN_JWK\b",
            r"\bREGISTRY_NOTARY_ESIGNET_RP_JWK\b",
            r"\b[A-Z0-9_]*PRIVATE_KEY[A-Z0-9_]*\b",
            r"\b[A-Z0-9_]*CLIENT_SECRET[A-Z0-9_]*\b",
            r"\b[A-Z0-9_]*SHA_SECRET[A-Z0-9_]*\b",
            r"\b[A-Z0-9_]*DB_PASSWORD[A-Z0-9_]*\b",
            r"\b[A-Z0-9_]*POSTGRES_PASSWORD[A-Z0-9_]*\b",
            r"\b[A-Z0-9_]*REDIS[A-Z0-9_]*\b",
            r"\b[A-Z0-9_]*COOLIFY[A-Z0-9_]*\b",
            r"\b[A-Z0-9_]*WEBHOOK[A-Z0-9_]*\b",
            r"\b[A-Z0-9_]*SSH[A-Z0-9_]*\b",
            r"\bOPENFN_DHIS2_USERNAME\b",
            r"\bOPENFN_DHIS2_PASSWORD\b",
            r"\bZITADEL_MASTERKEY\b",
            r"\bOPENCRVS_DCI_CLIENT_ID\b",
            r"\bOPENCRVS_DCI_CLIENT_SECRET\b",
            r"\bOPENCRVS_DCI_SHA_SECRET\b",
        ]
    )
)


@dataclass(frozen=True)
class Issue:
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: [{self.code}] {self.message}"


def parse_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def parse_bru_vars(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    in_vars = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "vars {":
            in_vars = True
            continue
        if in_vars and line == "}":
            break
        if not in_vars or not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def validate_workspace(root: Path | str = Path(".")) -> list[Issue]:
    root = Path(root)
    issues: list[Issue] = []
    collection = root / COLLECTION_PATH
    hosted_env = collection / "environments" / "Hosted Lab.bru"
    local_env = collection / "environments" / "Local Compose.bru"

    issues.extend(validate_required_files(root, collection, hosted_env, local_env))
    issues.extend(validate_public_token_parity(root, hosted_env))
    issues.extend(validate_environment_urls(hosted_env, local_env))
    issues.extend(validate_forbidden_names(collection))
    issues.extend(validate_request_files(collection))
    issues.extend(validate_readme(root, collection))
    return issues


def validate_required_files(
    root: Path,
    collection: Path,
    hosted_env: Path,
    local_env: Path,
) -> list[Issue]:
    checks = [
        (collection / "bruno.json", "missing-bruno-json", "collection must include bruno.json"),
        (collection / "collection.bru", "missing-collection-bru", "collection must include collection.bru"),
        (collection / "README.md", "missing-collection-readme", "collection must include README.md"),
        (hosted_env, "missing-hosted-env", "collection must include a Hosted Lab environment"),
        (local_env, "missing-local-env", "collection must include a Local Compose environment"),
        (root / HOMEPAGE_ENV_PATH, "missing-public-credential-env", "public homepage credential env is missing"),
        (root / SPEC_PATH, "missing-api-workspace-spec", "public API workspace spec is missing"),
    ]
    issues = [
        Issue(code, relative(path, root), message)
        for path, code, message in checks
        if not path.exists()
    ]
    for folder in REQUIRED_FOLDERS:
        path = collection / folder
        if not path.is_dir():
            issues.append(
                Issue(
                    "missing-required-folder",
                    relative(path, root),
                    f"collection must include required folder {folder!r}",
                )
            )
        elif not list(path.glob("*.bru")):
            issues.append(
                Issue(
                    "missing-required-request",
                    relative(path, root),
                    f"required folder {folder!r} must contain at least one request",
                )
            )
    return issues


def validate_public_token_parity(root: Path, hosted_env: Path) -> list[Issue]:
    public_tokens = parse_dotenv(root / HOMEPAGE_ENV_PATH)
    hosted_vars = parse_bru_vars(hosted_env)
    issues: list[Issue] = []
    for key, expected in sorted(public_tokens.items()):
        if key not in hosted_vars:
            issues.append(
                Issue(
                    "hosted-token-missing",
                    relative(hosted_env, root),
                    f"Hosted Lab environment is missing public credential {key}",
                )
            )
        elif hosted_vars[key] != expected:
            issues.append(
                Issue(
                    "hosted-token-mismatch",
                    relative(hosted_env, root),
                    f"Hosted Lab value for {key} does not match public homepage credentials",
                )
            )
    return issues


def validate_environment_urls(hosted_env: Path, local_env: Path) -> list[Issue]:
    issues: list[Issue] = []
    hosted_vars = parse_bru_vars(hosted_env)
    local_vars = parse_bru_vars(local_env)
    hosted_url_values = [value for key, value in hosted_vars.items() if key.endswith("_url")]
    if not hosted_url_values:
        issues.append(
            Issue("missing-hosted-url-vars", str(hosted_env), "Hosted Lab environment must define hosted URL variables")
        )
    for value in hosted_url_values:
        if "://lab.registrystack.org" not in value and ".lab.registrystack.org" not in value:
            issues.append(
                Issue("hosted-url-not-lab-domain", str(hosted_env), f"hosted URL {value!r} is not under the lab domain")
            )
    local_url_values = [value for key, value in local_vars.items() if key.endswith("_url")]
    if not local_url_values:
        issues.append(
            Issue("missing-local-url-vars", str(local_env), "Local Compose environment must define local URL variables")
        )
    for value in local_url_values:
        if not value.startswith("http://127.0.0.1:"):
            issues.append(
                Issue("local-url-not-loopback", str(local_env), f"local URL {value!r} must target 127.0.0.1")
            )
    return issues


def validate_forbidden_names(collection: Path) -> list[Issue]:
    issues: list[Issue] = []
    if not collection.exists():
        return issues
    for path in sorted(collection.rglob("*")):
        if path.suffix not in {".bru", ".json"}:
            continue
        text = path.read_text(encoding="utf-8")
        for match in FORBIDDEN_NAME_RE.finditer(text):
            issues.append(
                Issue(
                    "forbidden-bruno-secret-name",
                    relative(path, collection.parent.parent),
                    f"committed Bruno file references forbidden secret name {match.group(0)!r}",
                )
            )
    return issues


def validate_request_files(collection: Path) -> list[Issue]:
    issues: list[Issue] = []
    if not collection.exists():
        return issues
    for path in sorted(collection.rglob("*.bru")):
        if path.parent.name == "environments" or path.name == "collection.bru" or path.name == "folder.bru":
            continue
        text = path.read_text(encoding="utf-8")
        if "script:post-response" not in text:
            issues.append(Issue("missing-post-response-tests", str(path), "request must include Bruno post-response tests"))
            continue
        if "res.getStatus()" not in text:
            issues.append(Issue("missing-status-test", str(path), "request must assert expected HTTP status"))
        if text.count("test(") < 2:
            issues.append(
                Issue(
                    "missing-behavior-test",
                    str(path),
                    "request must include a behavior-specific response invariant in addition to status",
                )
            )
        if "{{" not in text:
            issues.append(Issue("missing-environment-variable", str(path), "request must use environment variables"))
    return issues


def validate_readme(root: Path, collection: Path) -> list[Issue]:
    issues: list[Issue] = []
    collection_readme = collection / "README.md"
    if collection_readme.exists():
        text = collection_readme.read_text(encoding="utf-8")
        required_fragments = [
            "config/lab-homepage/public-demo-credentials.env",
            "Hosted Lab",
            "Local Compose",
        ]
        for fragment in required_fragments:
            if fragment not in text:
                issues.append(
                    Issue(
                        "collection-readme-missing-guidance",
                        relative(collection_readme, root),
                        f"collection README must mention {fragment!r}",
                    )
                )
    docs_index = root / DOCS_INDEX_PATH
    if docs_index.exists():
        text = docs_index.read_text(encoding="utf-8")
        if "public-api-workspace.md" not in text:
            issues.append(
                Issue(
                    "docs-index-missing-spec-link",
                    relative(docs_index, root),
                    "docs index must link to the public API workspace spec",
                )
            )
        if "requests/registry-lab" not in text:
            issues.append(
                Issue(
                    "docs-index-missing-collection-link",
                    relative(docs_index, root),
                    "docs index must link to the Bruno collection",
                )
            )
    return issues


def relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root to validate")
    args = parser.parse_args(argv)

    issues = validate_workspace(args.root)
    if issues:
        for issue in issues:
            print(issue, file=sys.stderr)
        return 1
    print("public API workspace validation OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
