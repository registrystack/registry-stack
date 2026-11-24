// SPDX-License-Identifier: Apache-2.0

const REFERENCE_PATTERN = /^TEST[0-9A-F]{20}$/;
const PUBLIC_FILES = new Set(['document.pdf', 'test-root.pem']);

export function normalizePublicReference(input) {
  if (typeof input !== 'string' || input.length > 64) return null;
  const compact = input.toUpperCase().replaceAll(/[ -]/g, '');
  if (!REFERENCE_PATTERN.test(compact)) return null;
  return `TEST-${compact.slice(4).match(/.{4}/g).join('-')}`;
}

export function lookupRecord(records, input) {
  if (input === null) return { kind: 'manual' };
  const reference = normalizePublicReference(input);
  if (reference === null) return { kind: 'malformed' };
  const record = records.find((candidate) => candidate.reference === reference);
  return record === undefined ? { kind: 'unknown', reference } : { kind: 'found', record };
}

export function lookupQuery(records, search) {
  const references = new URLSearchParams(search).getAll('ref');
  if (references.length === 0) return { kind: 'manual' };
  if (references.length !== 1) return { kind: 'malformed' };
  return lookupRecord(records, references[0]);
}

export function historyPath(href, input) {
  const url = new URL(href);
  const reference = normalizePublicReference(input);
  if (reference === null) url.searchParams.delete('ref');
  else url.searchParams.set('ref', reference);
  return `${url.pathname}${url.search}`;
}

export function assetHref(reference, file) {
  if (normalizePublicReference(reference) !== reference || !PUBLIC_FILES.has(file)) {
    throw new Error('invalid public specimen asset');
  }
  return `../issued/${reference}/${file}`;
}

export function formatIssuedAt(timestamp) {
  return new Date(timestamp).toLocaleString('en-GB', {
    dateStyle: 'long', timeStyle: 'medium', timeZone: 'UTC',
  });
}

export async function sha256Hex(bytes) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function parseRecords(root) {
  const parsed = JSON.parse(root.dataset.records ?? '[]');
  return Array.isArray(parsed) ? parsed : [];
}

export function startVerifier(document, location, history) {
  const root = document.querySelector('[data-verifier]');
  if (root === null) return;
  const records = parseRecords(root);
  const form = document.getElementById('reference-form');
  const input = document.getElementById('reference');
  const formTitle = document.getElementById('form-title');
  const result = document.getElementById('result');
  const states = [...result.querySelectorAll('[data-result]')];
  const foundReference = document.getElementById('found-reference');
  const issuedAt = document.getElementById('issued-at');
  const digest = document.getElementById('signed-digest');
  const pdfLink = document.getElementById('pdf-link');
  const rootLink = document.getElementById('root-link');
  const fileInput = document.getElementById('original-file');
  const comparison = document.getElementById('comparison');
  let activeRecord = null;
  let latestSelection = 0;

  const render = (outcome, focus = false) => {
    latestSelection += 1;
    activeRecord = outcome.kind === 'found' ? outcome.record : null;
    fileInput.value = '';
    comparison.textContent = '';
    delete comparison.dataset.match;
    for (const state of states) state.hidden = state.dataset.result !== outcome.kind;
    result.hidden = outcome.kind === 'manual';
    formTitle.textContent = outcome.kind === 'manual' ? 'Check a reference' : 'Check another reference';
    if (outcome.kind === 'found') {
      foundReference.textContent = outcome.record.reference;
      issuedAt.textContent = formatIssuedAt(outcome.record.issuedAt);
      issuedAt.dateTime = outcome.record.issuedAt;
      digest.textContent = outcome.record.signedFileDigest;
      pdfLink.href = assetHref(outcome.record.reference, 'document.pdf');
      rootLink.href = assetHref(outcome.record.reference, 'test-root.pem');
    }
    if (focus && !result.hidden) result.focus();
  };

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const outcome = lookupRecord(records, input.value);
    history.replaceState(null, '', historyPath(location.href, input.value));
    render(outcome, true);
  });

  fileInput.addEventListener('change', async () => {
    latestSelection += 1;
    const mine = latestSelection;
    const file = fileInput.files?.[0];
    if (file === undefined || activeRecord === null) {
      comparison.textContent = '';
      delete comparison.dataset.match;
      return;
    }
    comparison.textContent = 'Comparing on this device…';
    delete comparison.dataset.match;
    try {
      const actual = await sha256Hex(await file.arrayBuffer());
      if (mine !== latestSelection) return;
      const expected = activeRecord.signedFileDigest.slice('sha256:'.length);
      comparison.textContent = actual === expected
        ? 'Exact file match. This PDF has the recorded SHA-256.'
        : 'Different file. This PDF does not have the recorded SHA-256.';
      comparison.dataset.match = actual === expected ? 'yes' : 'no';
    } catch {
      if (mine === latestSelection) {
        comparison.textContent = 'This browser could not compare the file.';
        comparison.dataset.match = 'error';
      }
    }
  });

  const references = new URLSearchParams(location.search).getAll('ref');
  if (references.length === 1) input.value = references[0];
  render(lookupQuery(records, location.search));
}

if (typeof document !== 'undefined') {
  startVerifier(document, window.location, window.history);
}
