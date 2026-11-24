# Verify a fictional Population extract

This example issues a test-signed PDF for Ada Example and lets someone look up the
printed document reference. Each issuance gets a fresh reference, even for the same
person. The QR code carries the verifier address and the document reference.

From this directory, use Node 24 and a `registry-render` build with `test-seal` on
your path. You can also set `REGISTRY_RENDER_BIN` to its absolute path.

```sh
node issue.mjs --registry ./specimens --origin http://127.0.0.1:4371
node serve.mjs --registry ./specimens --host 127.0.0.1 --port 4371
```

Open the PDF at the path printed by the first command. Click its QR code, or open
the printed lookup address and enter the document reference. For a phone on the
same Wi-Fi, use the computer's private IPv4 address in both `--origin` and
`--host` when issuing and serving. Keep the service at the printed address and
keep its specimen directory so earlier references continue to resolve.

The issuer adds `reference` and `verify-url` to the fictional fixture. It
stages the pinned Zebra QR package from Render's certificate bundle and calls
`registry-render test-seal`. After checking the returned test marker and signed
file digest, it publishes the PDF, its public test certificate and a receipt
together. A failed signing run leaves the reference unavailable.

The lookup displays the receipt's issuance time and the SHA-256 of the signed
file. The person number and personal details stay off the verification page.
Use the Render offline validator with the paired `test-root.pem` to check
the PDF signature. The example represents fictional issuance only.

## Publish a fictional example on the docs site

The [public lookup](https://docs.registrystack.org/dev/examples/population-extract/verify/)
uses the reference printed on the PDF. You can also compare a copy of the PDF
on your device. Give the issuer that address before signing the sample.

```sh
node issue.mjs --registry ./specimens \
  --verification-page https://docs.registrystack.org/dev/examples/population-extract/verify/
```

Review the fictional PDF and validate its signature with its public test root.
Copy only `document.pdf`, `test-root.pem` and `receipt.json` into the docs site's
`public/examples/population-extract/issued/<reference>/` directory. Submit the
three files together. The page checks the reference and PDF digest at build
time. The QR starts resolving after the main docs site deploys.

Keep each published reference and its files. Issue a fresh specimen to demonstrate
signature validation after its 90-day test certificate expires. Earlier references
continue to identify the exact file originally published.

Run the example tests from this directory. The last command renders the actual
signed page, decodes its QR with ZXing, and follows the decoded link. It also
scans every specimen published with the docs site.

```sh
node --test issue.test.mjs serve.test.mjs
uv run --python 3.13 --script test_scan.py
```
