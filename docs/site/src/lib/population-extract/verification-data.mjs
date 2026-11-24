// SPDX-License-Identifier: Apache-2.0

import { createHash, X509Certificate } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

import { normalizeReference } from '../../../../../products/render/examples/specimen-verification/reference.mjs';

const RECORD_FILES = ['document.pdf', 'receipt.json', 'test-root.pem'];
const RECEIPT_FIELDS = ['issuedAt', 'reference', 'signedFileDigest'];
const MAX_RECEIPT_BYTES = 16 * 1024;

async function regularFile(path, label) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file`);
  }
  return metadata;
}

async function readReceipt(directory, reference) {
  const path = join(directory, 'receipt.json');
  const metadata = await regularFile(path, `${reference}/receipt.json`);
  if (metadata.size > MAX_RECEIPT_BYTES) {
    throw new Error(`${reference}/receipt.json exceeds ${MAX_RECEIPT_BYTES} bytes`);
  }
  let receipt;
  try {
    receipt = JSON.parse(await readFile(path, 'utf8'));
  } catch {
    throw new Error(`${reference}/receipt.json is not valid JSON`);
  }
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new Error(`${reference}/receipt.json must be an object`);
  }
  const fields = Object.keys(receipt).sort();
  if (fields.length !== RECEIPT_FIELDS.length
    || fields.some((field, index) => field !== RECEIPT_FIELDS[index])) {
    throw new Error(`${reference}/receipt.json must contain exactly reference, issuedAt, signedFileDigest`);
  }
  if (normalizeReference(receipt.reference) !== receipt.reference) {
    throw new Error(`${reference}/receipt.json has an invalid reference`);
  }
  if (receipt.reference !== reference) {
    throw new Error(`${reference} directory name must equal receipt reference`);
  }
  if (typeof receipt.issuedAt !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T/.test(receipt.issuedAt)
    || !Number.isFinite(Date.parse(receipt.issuedAt))) {
    throw new Error(`${reference}/receipt.json has an invalid issuedAt`);
  }
  if (typeof receipt.signedFileDigest !== 'string'
    || !/^sha256:[0-9a-f]{64}$/.test(receipt.signedFileDigest)) {
    throw new Error(`${reference}/receipt.json has an invalid signedFileDigest`);
  }
  return receipt;
}

async function validatePublicCertificate(directory, reference) {
  const path = join(directory, 'test-root.pem');
  await regularFile(path, `${reference}/test-root.pem`);
  const pem = (await readFile(path, 'utf8')).trim();
  const certificates = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  if (certificates.length !== 1 || certificates[0] !== pem) {
    throw new Error(`${reference}/test-root.pem must contain one public CERTIFICATE and nothing else`);
  }
  try {
    new X509Certificate(pem);
  } catch {
    throw new Error(`${reference}/test-root.pem must contain a valid public CERTIFICATE`);
  }
}

async function loadRecord(issuedDirectory, entry) {
  const reference = entry.name;
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw new Error(`${reference} must be a record directory`);
  }
  if (normalizeReference(reference) !== reference) {
    throw new Error(`${reference} is not a canonical specimen reference`);
  }
  const directory = join(issuedDirectory, reference);
  const files = (await readdir(directory)).sort();
  if (files.length !== RECORD_FILES.length
    || files.some((file, index) => file !== RECORD_FILES[index])) {
    throw new Error(`${reference} must contain exactly document.pdf, receipt.json, test-root.pem`);
  }

  const receipt = await readReceipt(directory, reference);
  await validatePublicCertificate(directory, reference);
  await regularFile(join(directory, 'document.pdf'), `${reference}/document.pdf`);
  const pdf = await readFile(join(directory, 'document.pdf'));
  const digest = `sha256:${createHash('sha256').update(pdf).digest('hex')}`;
  if (digest !== receipt.signedFileDigest) {
    throw new Error(`${reference}/document.pdf digest does not match receipt.json`);
  }
  return receipt;
}

export async function loadIssuedSpecimens(issuedDirectory) {
  let entries;
  try {
    entries = await readdir(issuedDirectory, { withFileTypes: true });
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new Error('issued specimen directory is missing');
    }
    throw error;
  }
  if (entries.length === 0) throw new Error('issued specimen directory must contain at least one record');
  const records = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    records.push(await loadRecord(issuedDirectory, entry));
  }
  return records;
}
