// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs';
import * as path from 'node:path';

// Product-owned markers mirror root discovery in registry-language-server.
// A registry.yaml root must declare a Base Registry Engine project.
export const EVIDENCE_MARKER_FILE = 'evidence-project.yaml';
export const EVIDENCE_OPENAPI_FILE = 'source.openapi.yaml';
export const EVIDENCE_QUESTIONS_DIRECTORY = 'questions';

const PRODUCT_MARKERS = [
  ['registry.yaml', 'kind', 'RegistryProject', 'apiVersion', 'registry.registrystack.org/v1alpha1', true],
  ['casework.yaml', 'kind', 'CaseworkProject', 'apiVersion', 'registry.registrystack.org/casework/'],
  ['scheduling.yaml', 'kind', 'SchedulingProject', 'apiVersion', 'id.registrystack.org/formats/scheduling/project/'],
  ['messaging.yaml', 'kind', 'MessagingProject', 'apiVersion', 'id.registrystack.org/formats/messaging/project/'],
  ['origins.yaml', '', '', 'schemaVersion', 'registry-discovery/origins/'],
  ['manifest.yaml', 'kind', 'RenderBundle', 'apiVersion', 'id.registrystack.org/formats/render/bundle/'],
  ['metadata.yaml', '', '', 'schema_version', 'registry-manifest/v1', true],
] as const;

// Product discriminators are top-level keys. Match the language server's
// authored-document ceiling before reading a marker or declared document.
const MAX_MARKER_BYTES = 1024 * 1024;

export function isProjectRoot(directory: string): boolean {
  if (
    declaresProduct(directory) ||
    declaresExplicitProduct(directory)
  ) {
    return true;
  }
  if (isFile(path.join(directory, EVIDENCE_MARKER_FILE))) {
    return true;
  }
  return (
    isFile(path.join(directory, EVIDENCE_OPENAPI_FILE)) &&
    isDirectory(path.join(directory, EVIDENCE_QUESTIONS_DIRECTORY))
  );
}

function declaresProduct(directory: string): boolean {
  return PRODUCT_MARKERS.some(([file, kindKey, kind, versionKey, version, exact]) => {
    const text = readMarker(path.join(directory, file));
    if (text === undefined) {
      return false;
    }
    const declaredVersion = topLevelScalar(text, versionKey);
    return (
      (kindKey !== '' && topLevelScalar(text, kindKey) === kind) ||
      (declaredVersion !== undefined &&
        (exact ? declaredVersion === version : declaredVersion.startsWith(version)))
    );
  });
}

function readMarker(candidate: string): string | undefined {
  if (!isFile(candidate)) {
    return undefined;
  }
  try {
    const handle = fs.openSync(candidate, fs.constants.O_RDONLY);
    try {
      if (fs.fstatSync(handle).size > MAX_MARKER_BYTES) {
        return undefined;
      }
      const buffer = Buffer.alloc(MAX_MARKER_BYTES);
      const read = fs.readSync(handle, buffer, 0, MAX_MARKER_BYTES, 0);
      return buffer.subarray(0, read).toString('utf8');
    } finally {
      fs.closeSync(handle);
    }
  } catch {
    return undefined;
  }
}

// Manifest and wallet-delivery configuration can have adopter-chosen names.
// The shared editor configurator records the product explicitly rather than
// guessing from a generic runtime.yaml shared by several products.
function declaresExplicitProduct(directory: string): boolean {
  const markerDirectory = path.join(directory, '.registry-stack-editor');
  if (!isDirectory(markerDirectory)) {
    return false;
  }
  const text = readMarker(path.join(markerDirectory, 'project.json'));
  if (text === undefined) {
    return false;
  }
  try {
    const marker = JSON.parse(text);
    if (
      marker === null ||
      (marker.product !== 'manifest' && marker.product !== 'evidence-oid4vci') ||
      typeof marker.document !== 'string' ||
      marker.document.includes('\\') ||
      path.isAbsolute(marker.document) ||
      !['.yaml', '.yml'].includes(path.extname(marker.document))
    ) {
      return false;
    }
    const components = marker.document.split('/');
    if (components.some((component: string) => component === '' || component === '.' || component === '..')) {
      return false;
    }
    let parent = directory;
    for (const component of components.slice(0, -1)) {
      parent = path.join(parent, component);
      if (!isDirectory(parent)) {
        return false;
      }
    }
    return readMarker(path.join(directory, marker.document)) !== undefined;
  } catch {
    return false;
  }
}

// The value of one top-level key, when the document writes it as a plain or
// quoted scalar on the key's own line. Only the top level counts: a `kind`
// nested under another key names something else, and a document whose
// discriminator is written in a form this does not read is one the client
// leaves to the family that can read it.
function topLevelScalar(text: string, key: string): string | undefined {
  const prefix = `${key}:`;
  for (const line of text.split('\n')) {
    if (!line.startsWith(prefix)) {
      continue;
    }
    return unquote(line.slice(prefix.length).trim());
  }
  return undefined;
}

// A scalar as it is written: quoted with its delimiters removed, plain with
// any trailing comment removed. YAML starts a comment on a plain scalar's line
// only at whitespace before the `#`, so a `#` inside a value stays in it.
function unquote(written: string): string {
  for (const quote of ['"', "'"]) {
    if (written.startsWith(quote)) {
      const end = written.indexOf(quote, quote.length);
      return end === -1 ? written.slice(quote.length) : written.slice(quote.length, end);
    }
  }
  return written.split(/\s+#/)[0].trimEnd();
}

// A symbolic link declares nothing, at either marker: it is how a directory
// borrows a shape it does not have, and a borrowed shape must not anchor a
// project root the client will then start a language server against.
// fs.lstatSync reports the link itself rather than following it, so a link
// never reads as a file or a directory here, whatever it points at.
function isFile(candidate: string): boolean {
  try {
    return fs.lstatSync(candidate).isFile();
  } catch {
    return false;
  }
}

function isDirectory(candidate: string): boolean {
  try {
    return fs.lstatSync(candidate).isDirectory();
  } catch {
    return false;
  }
}
