#!/usr/bin/env python3
"""Package the Registry Stack theme as ThunderID API and declarative resources."""

import argparse
import json
from pathlib import Path
import shutil
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
BRANDING = json.loads((ROOT / "branding.json").read_text())
DEFAULT_ASSET_BASE = BRANDING["assetBasePath"]
THEME_ID = BRANDING["themeId"]
LAYOUT_ID = BRANDING["layoutId"]
PIN_PATH = ROOT.parents[3] / "crates/registry-thunderid-tooling/thunderid-version.json"


def resource_yaml(resource: dict) -> str:
    # ThunderID 1.0.1 selects combined-file documents by scanning for a literal
    # resource_type: header before parsing YAML. A wholly JSON document is valid
    # YAML but is silently skipped by that loader. JSON remains valid for values.
    lines = [f"resource_type: {resource['resource_type']}"]
    lines.extend(
        f"{key}: " + json.dumps(value, indent=2).replace("\n", "\n  ")
        for key, value in resource.items()
        if key != "resource_type"
    )
    return "\n".join(lines) + "\n"


def build(output: Path, asset_base: str) -> None:
    if output.resolve().is_relative_to(ROOT):
        raise ValueError("output must be outside the branding source directory")
    parsed = urlsplit(asset_base)
    if "?" in asset_base or "#" in asset_base or parsed.username or parsed.password:
        raise ValueError("asset base must not contain credentials, a query, or a fragment")
    if not (asset_base.startswith("/") and not asset_base.startswith("//")) and not (
        parsed.scheme == "https" and parsed.netloc
    ):
        raise ValueError("asset base must be a root-relative path or an HTTPS URL")
    if any(character in asset_base for character in "\"'()\\\n\r<>"):
        raise ValueError("asset base contains a character that cannot be used in CSS URLs")

    theme = json.loads((ROOT / "theme.json").read_text())
    stylesheet = (ROOT / "registry-stack.css").read_text().replace(
        DEFAULT_ASSET_BASE + "/", asset_base.rstrip("/") + "/"
    )
    layout = {
        "handle": "registry-stack",
        "displayName": "Registry Stack",
        "layout": {
            "head": {
                "stylesheets": [
                    {"id": "registry-stack", "type": "inline", "content": stylesheet}
                ]
            }
        },
    }
    pin = json.loads(PIN_PATH.read_text())
    output.mkdir(parents=True, exist_ok=False)
    for name, content in (("theme.json", theme), ("layout.json", layout)):
        (output / name).write_text(json.dumps(content, indent=2) + "\n")
    (output / "registry-stack.css").write_text(stylesheet)
    shutil.copytree(ROOT / "assets", output / "assets")
    # Keep one source for the stylesheet and both native resource formats.
    resources = [
        {"resource_type": "theme", "id": THEME_ID, **theme},
        {"resource_type": "layout", "id": LAYOUT_ID, **layout},
    ]
    (output / "resources.yaml").write_text(
        "---\n".join(resource_yaml(resource) for resource in resources)
    )
    for resource in resources:
        directory = output / "resources" / (resource["resource_type"] + "s")
        directory.mkdir(parents=True)
        (directory / (resource["id"] + ".yaml")).write_text(
            resource_yaml(resource)
        )
    # The image is an assets-only extension of the shared upstream pin.
    # Environment-owned resources and deployment settings stay with the
    # environment, so a resource-directory mount cannot hide this branding.
    (output / "Dockerfile").write_text(
        f'FROM {pin["image"]}\n'
        "COPY assets/ /opt/thunderid/apps/gate/assets/registry-stack/\n"
    )
    (output / "branding.json").write_text(
        json.dumps({**BRANDING, "assetBaseUrl": asset_base.rstrip("/")}, indent=2) + "\n"
    )
    print(f"Created theme, layout, stylesheet and assets in {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    parser.add_argument("--asset-base-url", default=DEFAULT_ASSET_BASE)
    args = parser.parse_args()
    try:
        build(args.output, args.asset_base_url)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Cannot build branding: {error}\n")


if __name__ == "__main__":
    main()
