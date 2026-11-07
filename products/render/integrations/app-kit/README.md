# App Kit integration

Add document rendering through an app-owned host route. App Kit provides the
`createAppHost(config, caseworkClient?, { routes })` seam, `HostRoute`, and
`RouteContext` from `@registrystack/app-server`. Its maintained guide is
`project/docs/customization.md`, “Add a host route”. Repository access is
currently private and must be granted by Registry Stack maintainers.

App Kit has no built-in documents configuration block. Keep Render destinations and credentials in app-owned server configuration;
the closed host configuration schema does not accept arbitrary extensions.

## Decide the disclosure

Agree the fields printed on each document type, the wording beside its QR,
the public check URL, and who reviews each template package version before
writing the template. Paper remains readable after the caller's session ends.

The check is answered by Registry Evidence's public check route and a static
page; see `products/evidence/examples/public-check/README.md`. The app or issuing
workflow generates a check code at issuance, stores it on the record, and
supplies the QR URL (`https://check.example.org/#n=<number>&c=<code>`). Print
the check origin as text beside the QR code. A scanned URL or a Render hash
grants no registry access. Render only prints the app-supplied URL and performs
no work when the QR is scanned.

## Author and package

Author templates, schemas, labels, and vendored assets under
`project/deployment/render/bundle/`. Run `registry-render package` with that
source and a separate output directory,
`project/deployment/render/package/`. The latter is the verified runtime
package carrying `SHA256SUMS` and optional `REVISION`; configure Render's
`package.root` to that directory. Never serve the authored `bundle/` directly.

Supervise `registry-render serve` beside the app through the app's deployment
configuration. Bind its listener to a private address behind the operator's TLS proxy. Keep the package
read-only and the audit destination durable.

## Render from the app

A session-authorized POST host route, for example
`/api/documents/{type}/render`, reads permitted BReg fields with the end user's
authority and assembles the Render request. Preserve the host's session, CSRF,
and Origin checks. Use the app-owned server credential for the selected Render deployment,
call `POST /v1/render/{type}`, and stream the PDF to the browser, or attach it
to the owning Record and retain `pdfDigest` and `dataDigest` alongside it.

The check page is not an app route: the static page and Evidence's public check
route answer the scan. App Kit's public GET/HEAD host-route option remains for
other public pages; its context intentionally excludes the authenticated
session and host config. A signed POST receiver needs a separate authenticated
server endpoint.

## Verify the complete journey

Exercise a staff print from an authorized Record, read back the attachment and
stored hashes, then scan the QR and confirm the static page shows Evidence's
answer with the printed fields. Confirm that a wrong number and a wrong check
code give the same not-found message, and test an unauthorized print. The
host-route seam alone does not prove this journey has run.
