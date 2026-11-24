#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { defaultPort, isLocalIPv4 } from './origin.mjs';
import { normalizeReference } from './reference.mjs';

const RECEIPT_FIELDS = ['issuedAt', 'reference', 'signedFileDigest'];
const MAX_RECEIPT_BYTES = 16 * 1024;

const CSS = `
:root {
  color-scheme: light;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #17242f;
  background: #eef3f1;
  font-synthesis: none;
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; }
body::before {
  content: "";
  display: block;
  height: .35rem;
  background: linear-gradient(90deg, #0a604f, #2e8470, #e0a22b);
}
main { width: min(100% - 2rem, 42rem); margin: 0 auto; padding: 2.5rem 0 4rem; }
.eyebrow { margin: 0 0 .55rem; color: #0a604f; font-size: .76rem; font-weight: 750; letter-spacing: .11em; text-transform: uppercase; }
h1 { margin: 0; max-width: 17ch; font-family: ui-serif, Georgia, serif; font-size: clamp(2rem, 8vw, 3.25rem); line-height: 1.03; letter-spacing: -.025em; }
.card { margin-top: 1.75rem; padding: clamp(1.2rem, 5vw, 2rem); border: 1px solid #d5dfdb; border-radius: 1.1rem; background: #fff; box-shadow: 0 .8rem 2.5rem rgb(28 55 45 / 8%); }
label { display: block; margin-bottom: .55rem; font-weight: 700; }
.hint, .fine { color: #617079; font-size: .9rem; line-height: 1.45; }
input[type="text"], input[type="file"] { width: 100%; font: inherit; }
input[type="text"] { padding: .85rem .9rem; border: 1px solid #aab8b3; border-radius: .6rem; color: #17242f; background: #fff; text-transform: uppercase; }
input:focus-visible, button:focus-visible { outline: 3px solid #e0a22b; outline-offset: 2px; }
button { width: 100%; margin-top: 1rem; padding: .85rem 1rem; border: 0; border-radius: .6rem; color: #fff; background: #0a604f; font: inherit; font-weight: 750; cursor: pointer; }
button:hover { background: #084e41; }
.result { border-left: .38rem solid #0a604f; }
.result-error { border-left-color: #b13a2f; }
h2, h3 { margin: 0; }
h2 { font-size: 1.55rem; }
h3 { font-size: 1.05rem; }
.result p { line-height: 1.5; }
dl { display: grid; grid-template-columns: minmax(7rem, .7fr) minmax(0, 1.5fr); gap: .6rem 1rem; margin: 1.5rem 0; }
dt { color: #64737b; }
dd { margin: 0; font-weight: 650; overflow-wrap: anywhere; }
code { font: .85em ui-monospace, SFMono-Regular, Consolas, monospace; }
.local-check { margin-top: 1.5rem; padding-top: 1.4rem; border-top: 1px solid #dfe6e3; }
.local-check code { display: block; margin-top: .45rem; overflow-wrap: anywhere; }
.comparison { margin-top: .7rem; font-weight: 700; }
[hidden] { display: none !important; }
@media (max-width: 30rem) {
  main { width: min(100% - 1.2rem, 42rem); padding-top: 1.7rem; }
  dl { grid-template-columns: 1fr; gap: .12rem; }
  dd { margin-bottom: .65rem; }
}
@media (prefers-reduced-motion: no-preference) {
  .card { animation: arrive .25s ease-out; }
  @keyframes arrive { from { opacity: 0; transform: translateY(.25rem); } }
}
`;

const JS = `
const panel = document.querySelector('[data-file-check]');
if (panel && window.isSecureContext && globalThis.crypto?.subtle) {
  const controls = panel.querySelector('[data-webcrypto]');
  const fallback = panel.querySelector('[data-checksum-fallback]');
  const input = panel.querySelector('input[type="file"]');
  const output = panel.querySelector('[data-comparison]');
  const expected = panel.dataset.expectedDigest;
  fallback.hidden = true;
  controls.hidden = false;
  let latestSelection = 0;
  input.addEventListener('change', async () => {
    latestSelection += 1;
    const mine = latestSelection;
    const file = input.files?.[0];
    if (!file) {
      output.textContent = '';
      return;
    }
    output.textContent = 'Comparing on this device…';
    try {
      const bytes = await file.arrayBuffer();
      const digest = await crypto.subtle.digest('SHA-256', bytes);
      const actual = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
      if (mine !== latestSelection) return;
      output.textContent = actual === expected
        ? 'Exact file match. This file has the receipt digest.'
        : 'Different file. Its SHA-256 does not match this receipt.';
    } catch {
      if (mine === latestSelection) output.textContent = 'This browser could not compare the file.';
    }
  });
}
`;

export function parseArguments(args) {
  const options = { registry: null, host: '127.0.0.1', port: defaultPort };
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (value === undefined) throw new Error(`missing value for ${name}`);
    if (name === '--registry') options.registry = value;
    else if (name === '--host') options.host = value;
    else if (name === '--port') options.port = Number(value);
    else throw new Error(`unknown argument: ${name}`);
  }
  if (options.registry === null || options.registry.length === 0) {
    throw new Error('--registry <dir> is required');
  }
  if (!isLocalIPv4(options.host)) {
    throw new Error('--host must be a loopback or private LAN IPv4 address; wildcard and public binds are refused');
  }
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535) {
    throw new Error('--port must be an integer from 0 to 65535');
  }
  return options;
}

function securityHeaders(contentType) {
  return {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'Content-Type': contentType,
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), geolocation=(), microphone=()',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  };
}

function send(response, method, status, body, contentType = 'text/plain; charset=utf-8', extra = {}) {
  response.writeHead(status, { ...securityHeaders(contentType), ...extra });
  response.end(method === 'HEAD' ? undefined : body);
}

function page(result = '') {
  const checkHeading = result === '' ? 'Check a reference' : 'Check another reference';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0a604f">
  <title>Verify a population register extract</title>
  <link rel="stylesheet" href="/assets/verify.css">
</head>
<body>
  <main>
    <header>
      <p class="eyebrow">Synthetic Population Office · Development</p>
      <h1>Verify a population register extract</h1>
    </header>
    ${result}
    <section class="card" aria-labelledby="check-title">
      <h2 id="check-title">${checkHeading}</h2>
      <p class="hint">Use the code printed beside the QR. Letter case, spaces, and hyphens do not matter.</p>
      <form method="get" action="/verify">
        <label for="ref">Reference</label>
        <input id="ref" name="ref" type="text" inputmode="text" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="TEST-XXXX-XXXX-XXXX-XXXX-XXXX" maxlength="64" required>
        <button type="submit">Check reference</button>
      </form>
    </section>
  </main>
  <script src="/assets/verify.js" defer></script>
</body>
</html>`;
}

function foundResult(receipt) {
  const digest = receipt.signedFileDigest.slice('sha256:'.length);
  const issued = new Date(receipt.issuedAt);
  const issuedLabel = new Intl.DateTimeFormat('en-GB', {
    day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit',
    timeZone: 'UTC', timeZoneName: 'short',
  }).format(issued);
  return `<section class="card result" aria-live="polite" aria-labelledby="result-title">
  <h2 id="result-title">Reference found</h2>
  <p>The Synthetic Population Office recorded this test extract on <time datetime="${issued.toISOString()}">${issuedLabel}</time>. The stored PDF matches the receipt digest.</p>
  <dl>
    <dt>Document type</dt><dd>Population register extract</dd>
    <dt>Reference</dt><dd><code>${receipt.reference}</code></dd>
  </dl>
  <section class="local-check" data-file-check data-expected-digest="${digest}">
    <h3>Compare a file on this device</h3>
    <p class="fine" data-checksum-fallback>Compare the original PDF using this SHA-256 fingerprint.<code>${receipt.signedFileDigest}</code></p>
    <div data-webcrypto hidden>
      <label for="local-file">Choose the PDF you received</label>
      <p class="fine">Your browser compares the PDF on this device.</p>
      <input id="local-file" type="file" accept="application/pdf,.pdf">
      <p class="comparison" data-comparison aria-live="polite"></p>
    </div>
  </section>
</section>`;
}

function errorResult(heading, explanation) {
  return `<section class="card result result-error" aria-live="polite" aria-labelledby="result-title">
  <h2 id="result-title">${heading}</h2>
  <p>${explanation}</p>
</section>`;
}

async function readBoundedJson(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const file = await handle.stat();
    if (!file.isFile() || file.size > MAX_RECEIPT_BYTES) throw new Error('invalid receipt file');
    return JSON.parse(await handle.readFile('utf8'));
  } finally {
    await handle.close();
  }
}

function validateReceipt(receipt, reference) {
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) return false;
  const fields = Object.keys(receipt).sort();
  if (fields.length !== RECEIPT_FIELDS.length
    || fields.some((field, index) => field !== RECEIPT_FIELDS[index])) return false;
  return receipt.reference === reference
    && typeof receipt.issuedAt === 'string'
    && /^\d{4}-\d{2}-\d{2}T/.test(receipt.issuedAt)
    && Number.isFinite(Date.parse(receipt.issuedAt))
    && typeof receipt.signedFileDigest === 'string'
    && /^sha256:[0-9a-f]{64}$/.test(receipt.signedFileDigest);
}

async function sha256File(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const file = await handle.stat();
    if (!file.isFile()) throw new Error('invalid PDF file');
    const hash = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk);
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

async function lookup(registry, reference) {
  const expectedDirectory = join(registry, reference);
  let directory;
  try {
    directory = await realpath(expectedDirectory);
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return { kind: 'unknown' };
    throw error;
  }
  if (directory !== expectedDirectory) throw new Error('specimen directory must not be a symbolic link');

  let receipt;
  try {
    receipt = await readBoundedJson(join(directory, 'receipt.json'));
  } catch (error) {
    if (error?.code === 'ENOENT') return { kind: 'unknown' };
    throw error;
  }
  if (!validateReceipt(receipt, reference)) return { kind: 'invalid' };

  const actualDigest = await sha256File(join(directory, 'document.pdf'));
  if (receipt.signedFileDigest !== `sha256:${actualDigest}`) return { kind: 'mismatch' };
  return { kind: 'found', receipt };
}

async function handleVerify(request, response, registry, url) {
  const references = url.searchParams.getAll('ref');
  if (references.length === 0) {
    send(response, request.method, 200, page(), 'text/html; charset=utf-8');
    return;
  }
  const reference = references.length === 1 ? normalizeReference(references[0]) : null;
  if (reference === null) {
    const result = errorResult(
      'Could not read reference',
      'Enter TEST followed by five groups of four hexadecimal characters.',
    );
    send(response, request.method, 400, page(result), 'text/html; charset=utf-8');
    return;
  }

  try {
    const outcome = await lookup(registry, reference);
    if (outcome.kind === 'found') {
      send(response, request.method, 200, page(foundResult(outcome.receipt)), 'text/html; charset=utf-8');
    } else if (outcome.kind === 'unknown') {
      const result = errorResult(
        'Unknown reference',
        'No receipt with this reference exists in the local synthetic registry.',
      );
      send(response, request.method, 404, page(result), 'text/html; charset=utf-8');
    } else {
      const explanation = outcome.kind === 'mismatch'
        ? 'The stored specimen did not match its receipt. Ask the development issuer to regenerate it.'
        : 'The local specimen registry entry could not be verified.';
      send(
        response,
        request.method,
        500,
        page(errorResult('Verification error', explanation)),
        'text/html; charset=utf-8',
      );
    }
  } catch {
    send(
      response,
      request.method,
      500,
      page(errorResult('Verification error', 'The local specimen registry entry could not be verified.')),
      'text/html; charset=utf-8',
    );
  }
}

export async function createVerificationServer({ registry }) {
  const registryRoot = await realpath(resolve(registry));
  return createServer((request, response) => {
    const route = async () => {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        send(response, request.method, 405, 'Method not allowed\n', undefined, { Allow: 'GET, HEAD' });
        return;
      }
      let url;
      try {
        url = new URL(request.url, 'http://verification.local');
      } catch {
        send(response, request.method, 400, 'Bad request\n');
        return;
      }
      if (url.pathname === '/verify') {
        await handleVerify(request, response, registryRoot, url);
      } else if (url.pathname === '/assets/verify.css') {
        send(response, request.method, 200, CSS, 'text/css; charset=utf-8');
      } else if (url.pathname === '/assets/verify.js') {
        send(response, request.method, 200, JS, 'text/javascript; charset=utf-8');
      } else {
        send(response, request.method, 404, 'Not found\n');
      }
    };
    route().catch(() => {
      if (response.headersSent) {
        response.destroy();
      } else {
        send(response, request.method, 500, 'Verification error\n');
      }
    });
  });
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const server = await createVerificationServer(options);
  server.listen(options.port, options.host, () => {
    const address = server.address();
    const origin = `http://${options.host}:${address.port}`;
    process.stdout.write(`${origin}/verify\n`);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`serve.mjs: ${error.message}\n`);
    process.exitCode = 1;
  });
}
