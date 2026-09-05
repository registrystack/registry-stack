// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs';
import * as path from 'node:path';

// Relay V2 is a governed project family with its own contract marker.
export const RELAY_V2_MARKER_FILE = 'registry.yaml';
// The two keys a governed contract declares itself by. registry.yaml is also
// what the Base Registry Engine calls its project document, so the file name
// alone says nothing about which product wrote the directory, and a client
// that started Relay's language server over a Base Registry Engine project
// would fill the author's editor with sentences about a grammar their build
// never applies. This mirrors declares_root() in
// crates/registry-language-server/src/relay_v2/index.rs, including the rule
// that either key is enough: an author part way through writing a contract may
// have typed one and not the other.
export const RELAY_V2_API_VERSION_PREFIX = 'relay.registrystack.org/';
export const RELAY_V2_CONTRACT_KIND = 'RegistryContract';
// Evidence project root: the marker written by newer projects, or the
// pre-marker pair of an OpenAPI description and a questions directory. This
// mirrors declares_root() in crates/registry-language-server/src/evidence/mod.rs.
export const EVIDENCE_MARKER_FILE = 'evidence-project.yaml';
export const EVIDENCE_OPENAPI_FILE = 'source.openapi.yaml';
export const EVIDENCE_QUESTIONS_DIRECTORY = 'questions';

// How much of a registry.yaml is read to find its discriminator. The two keys
// are written at the top of the document, and this is the same ceiling the
// language server holds one project document to.
const MAX_MARKER_BYTES = 1024 * 1024;

export function isProjectRoot(directory: string): boolean {
  if (declaresRelayV2(path.join(directory, RELAY_V2_MARKER_FILE))) {
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

// Whether the file at this path is a governed contract. Anything the client
// cannot read as one reads as "not this family": a file that is not there, one
// past the ceiling, one that is not text, one naming neither key. Declaring a
// root on a document the client could not read is what produced the false
// diagnostics this check removes.
function declaresRelayV2(candidate: string): boolean {
  if (!isFile(candidate)) {
    return false;
  }
  let text: string;
  try {
    const handle = fs.openSync(candidate, fs.constants.O_RDONLY);
    try {
      if (fs.fstatSync(handle).size > MAX_MARKER_BYTES) {
        return false;
      }
      const buffer = Buffer.alloc(MAX_MARKER_BYTES);
      const read = fs.readSync(handle, buffer, 0, MAX_MARKER_BYTES, 0);
      text = buffer.subarray(0, read).toString('utf8');
    } finally {
      fs.closeSync(handle);
    }
  } catch {
    return false;
  }
  const kind = topLevelScalar(text, 'kind');
  const apiVersion = topLevelScalar(text, 'apiVersion');
  return (
    kind === RELAY_V2_CONTRACT_KIND ||
    (apiVersion !== undefined && apiVersion.startsWith(RELAY_V2_API_VERSION_PREFIX))
  );
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
