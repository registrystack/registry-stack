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

## Docker and environment integration

Keep one branding package across environments. The issuer URL, credentials,
redirect URIs, and application policies belong to each environment.

### CLI development sessions

`registry-thunderid-tooling` embeds these source files. Newly rendered local
sessions with interactive applications select the theme and layout automatically,
write the public assets under their state directory, and mount those assets
read-only into the pinned ThunderID image. This includes browser applications
provisioned through `bregctl dev`, such as App Kit's local deployment.

There is no Python requirement at runtime and no administrator API call on
startup. Machine-only sessions need no branding resources. Existing retained
sessions keep their configuration and state; adopting a new CLI build does not
reset or silently rewrite them.

### Docker Compose

For an environment that owns its ThunderID configuration, merge the generated
theme and layout documents from `resources/` into its existing native resource
directory, or append `resources.yaml` through its existing resource assembler.
Keep the other application, flow, role, and user documents.

Configure these two stores in the environment's existing `deployment.yaml`:

```yaml
theme:
  store: composite
layout:
  store: composite
```

Add the asset directory to the existing ThunderID service. For example, this
Compose override assumes the built package is beside the Compose file:

```yaml
services:
  thunderid:
    volumes:
      - ./registry-stack-branding/assets:/opt/thunderid/apps/gate/assets/registry-stack:ro
```

Keep the environment's existing image, database, certificate, resource, network,
and configuration mounts. Select the theme/layout IDs and set the logo URL on
each intended browser application using the fields below. Use that environment's
public issuer origin for the logo URL.

The maintained Solmara Base Registries environment vendors the public package,
includes its documents in its existing resource assembler, and mounts the assets
read-only. Its four officer, supervisor, and casework browser applications select
the same IDs. Normal operation does not need a Registry Stack checkout.

### An image with the assets included

The generated `Dockerfile` takes its base image from the shared
`thunderid-version.json` pin and copies only the public font, licence, and wordmark:

```sh
docker build --tag registry-stack-thunderid:1.0.1 \
  /tmp/registry-stack-thunderid-branding
```

Use this image in place of the stock image when a bind mount is inconvenient.
Load the theme/layout documents and select them on applications as above.
The image contains no environment configuration, keys, credentials, or startup
administrator script. An external asset URL still requires serving the assets
at that URL; this image serves the default `/gate/assets/registry-stack` path.

Use either native files or the import API for these fixed resource IDs. A
deployment that already imported the resources can keep its API-managed copies;
loading duplicate IDs from native files as well can prevent a composite store
from starting.

## Install into an existing API-managed deployment

1. Serve the contents of the output's `assets/` directory at
   `/gate/assets/registry-stack/` on the identity server. For the pinned Docker
   image, mount that directory read-only at
   `/opt/thunderid/apps/gate/assets/registry-stack`. This adds static assets
   without replacing the Gate application.
2. Import `resources.yaml` through the Console's YAML import workflow. It
   contains only a theme and a layout, both named **Registry Stack**. The
   `/import` API accepts the same file as its `content` string, with
   `options.upsert: true` for subsequent updates.
3. Open the intended application and select **Registry Stack** for both its
   theme and layout under **Customization**. Set its application logo to the
   absolute, same-origin URL of `registry-stack-wordmark.svg`.
4. Start a fresh sign-in through that application's normal OAuth/OIDC entry
   point. Check registration and recovery if the application enables them.

The equivalent fields for an existing declarative application are:

```yaml
themeId: 019a05b7-1000-7000-8000-000000000001
layoutId: 019a05b7-1000-7000-8000-000000000002
logoUrl: https://identity.example.org/gate/assets/registry-stack/registry-stack-wordmark.svg
```

Keep the application's other fields, authentication flows, grants, and redirect
URIs. These are fields to merge into its definition, not a complete application
or a replacement `PUT /applications/{id}` body. The fixed resource IDs belong
to this package; avoid assigning them to another theme or layout.

For deployments that load resources at startup, append the generated documents
to the existing resource bundle and configure the theme and layout stores as
`composite` or `declarative`, following the deployment's existing resource
loading convention. Do not replace an existing bundle with this branding-only
file: ThunderID's explicit resources-file mode ignores other resource sources.

### Wordmark and custom flows

The stock Default Authentication Flow already renders `application.logoUrl`.
For the Console-specific flow and custom flows that omit the supplied image,
the stylesheet displays **Registry Stack** as text above the form. It omits
that fallback when the supplied wordmark image is present, so the name appears
once without changing authentication flows.

A flow that explicitly renders the application logo should use:

```yaml
type: IMAGE
src: "{{ meta(application.logoUrl) }}"
alt: Registry Stack
```

Set the existing image's alternative text to **Registry Stack** as well when
using this wordmark. Keep that change in the application's own flow; shared
translation overrides can affect other applications.

The SVG is the name set in Public Sans 700, not a new logo. It uses paths so
it renders correctly in an image element without external fonts. Its original
blue is retained in light mode; the stylesheet renders it white in dark mode.
Provider logos, QR codes, and other flow images are not recoloured or resized.

## Compatibility

- ThunderID 1.0.1 consumes `layout.head.stylesheets` on the hosted Gate screens.
  The package does not rely on layout `screens`, header slots, or footer slots,
  which that Gate version does not render.
- Invite acceptance is outside the page-and-card stylesheet's scope in 1.0.1:
  that route omits the component variant classes used by the other Gate screens.
  It can inherit theme tokens, but its layout and wordmark need a separate
  integration.
- Selectors use the public component class suffixes, so a custom product-name
  prefix is supported. Generated Emotion class names are not used.
- Inline CSS uses the CSP nonce supplied by ThunderID. Fonts are self-hosted;
  there are no Google Fonts, CDN imports, or JavaScript injections.
- The stylesheet includes the font-family override needed by Gate 1.0.1's
  `FontImporter`, which otherwise can fall back to its system font.
- Native error, MFA, consent, and recovery content remains in the flow.
  Styling does not enable any authentication method or registration policy.
- Upgrades should repeat a browser check of the real Gate screens, especially
  if component class names, the font importer, or the CSP changes.

To remove the branding, restore the application's previous theme, layout, and
logo selections. Remove the resources only after all applications stop using
them.

## Regenerate the wordmark

Ordinary builds use the committed SVG. To regenerate it after an intentional
font update, use Python 3.10 or later and the generator's pinned dependencies:

```sh
uv run --with 'fonttools[woff]==4.67.0' --with 'uharfbuzz==0.56.3' \
  products/identity/thunderid/branding/generate-wordmark.py
```

The generator verifies the source font's checksum. The included font and
derived wordmark are covered by `assets/fonts/OFL-public-sans.txt`.
