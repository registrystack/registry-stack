// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs';
import * as path from 'node:path';

// Relay project root: a single manifest file.
export const RELAY_MARKER_FILE = 'registry-stack.yaml';
// Evidence project root: the marker written by newer projects, or the
// pre-marker pair of an OpenAPI description and a questions directory. This
// mirrors declares_root() in crates/registry-language-server/src/evidence/mod.rs.
export const EVIDENCE_MARKER_FILE = 'evidence-project.yaml';
export const EVIDENCE_OPENAPI_FILE = 'source.openapi.yaml';
export const EVIDENCE_QUESTIONS_DIRECTORY = 'questions';

export function isProjectRoot(directory: string): boolean {
  if (isFile(path.join(directory, RELAY_MARKER_FILE))) {
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
