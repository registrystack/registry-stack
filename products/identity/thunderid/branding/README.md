# Registry Stack branding for ThunderID

A theme and stylesheet for the hosted sign-in, registration, and recovery
screens in the ThunderID 1.0.1 version pinned by
[`registry-thunderid-tooling`](../../../../crates/registry-thunderid-tooling/thunderid-version.json).
The package uses ThunderID's existing Design resources and application metadata.

The light palette follows `registrystack-brand/tokens.json`: Registry blue
`#173b7a`, ink `#161616`, white, and ledger paper `#eef2ec`. Public Sans,
square corners, fine rules, and hard-edged shadows match the public website.
The dark palette follows Registry Stack's documentation site. Both palettes
keep form labels, validation messages, keyboard focus, and disabled states.
A small **Powered by ThunderID** line sits below the card, with Registry Stack
remaining the primary brand. The stylesheet supplies this display-only
attribution because the pinned Gate version does not render layout footer slots.

## Files

| File | Purpose |
| --- | --- |
| `branding.json` | Shared theme/layout IDs and the default same-origin asset path. |
| `theme.json` | Request body for `POST /design/themes`; theme tokens and component styles. |
| `registry-stack.css` | Layout stylesheet, including a same-origin Public Sans font face. |
| `assets/` | Public Sans, its OFL licence, and the plain-text wordmark rendered as SVG paths. |
| `build.py` | Packages API payloads, an importable YAML bundle, CSS, and static assets. Python 3.9 or later; no dependencies. |
| `generate-wordmark.py` | Reproduces the wordmark from the included font; optional for ordinary use. |
| `test_build.py` | Unit tests for `build.py`'s asset base URL handling; CI runs them on every pull request. |

## Build

From the Registry Stack repository root, choose a new output directory:

```sh
python3 products/identity/thunderid/branding/build.py \
  --output /tmp/registry-stack-thunderid-branding
```

The output contains `theme.json`, `layout.json`, `resources.yaml`,
`resources/themes/`, `resources/layouts/`, `registry-stack.css`, `assets/`,
`branding.json`, and a `Dockerfile`. The layout embeds the stylesheet, so
there is no separate stylesheet request and no generated CSS copy to maintain.
Editing the source CSS and rebuilding updates the importable layout.

The default asset URL is `/gate/assets/registry-stack`. For a different
same-origin static mount, supply its root-relative path:

```sh
python3 products/identity/thunderid/branding/build.py \
  --asset-base-url /identity-assets/registry-stack \
  --output /tmp/registry-stack-thunderid-branding-custom
```

An absolute HTTPS asset URL is also accepted. Another origin needs explicit
CSP permission for fonts and images, plus appropriate font CORS headers.
Same-origin hosting works with ThunderID's default CSP.

## Install

Installing the package into a ThunderID deployment, selecting it on applications, the
wordmark and custom flow notes, compatibility and removal are in
[Connect an OIDC issuer](https://docs.registrystack.org/operate/advanced/connect-an-oidc-issuer/#brand-the-thunderid-sign-in-screens).

## Regenerate the wordmark

Ordinary builds use the committed SVG. To regenerate it after an intentional
font update, use Python 3.10 or later and the generator's pinned dependencies:

```sh
uv run --with 'fonttools[woff]==4.67.0' --with 'uharfbuzz==0.56.3' \
  products/identity/thunderid/branding/generate-wordmark.py
```

The generator verifies the source font's checksum. The included font and
derived wordmark are covered by `assets/fonts/OFL-public-sans.txt`.
