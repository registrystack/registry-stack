import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import YAML from 'yaml';

const docsDir = 'src/content/docs';
const required = [
  'title',
  'description',
  'status',
  'owner',
  'source_repos',
  'last_reviewed',
  'doc_type',
  'locale',
  'standards_referenced',
];
const validStatus = new Set(['draft', 'current', 'historical', 'deprecated']);
const validDocTypes = new Set(['tutorial', 'how-to', 'explanation', 'reference', 'decision', 'specification']);
// Formal specification layer axes (see spec/RS-DOC). category is the document's
// role; evidence is how true it is against shipped code. doc_id is the stable
// citable identifier and must be unique across the specification register.
const validCategory = new Set(['normative', 'informative']);
const validEvidence = new Set(['aspirational', 'partial', 'verified']);
// Section 2 declaration vocabularies (see spec/RS-TERMS Section 6). Both keys are
// optional and only validated when present; layer enumerates the stack's real
// layers, audience the reader roles.
const validLayer = new Set(['metadata', 'consultation', 'evaluation', 'credential', 'federation', 'administration', 'operations']);
const validAudience = new Set(['integrator', 'operator', 'maintainer', 'specification editor', 'tooling', 'auditor', 'decision-maker']);
const docIdPattern = /^RS-[A-Z0-9]+(-[A-Z0-9]+)*$/;
const seenDocIds = new Map();
const standardsRegister = YAML.parse(await readFile('src/data/standards.yaml', 'utf8'));
if (!Array.isArray(standardsRegister) || standardsRegister.length === 0) {
  console.error('src/data/standards.yaml did not parse to a non-empty list; cannot validate standards_referenced ids.');
  process.exit(1);
}
const knownStandards = new Set(standardsRegister.map((entry) => entry.id));

async function files(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const found = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...await files(path));
    if (entry.isFile() && /\.(md|mdx)$/.test(entry.name)) found.push(path);
  }
  return found;
}

function frontmatter(text, file) {
  if (!text.startsWith('---\n')) {
    throw new Error(`${file} is missing YAML frontmatter`);
  }
  const end = text.indexOf('\n---\n', 4);
  if (end === -1) {
    throw new Error(`${file} has unterminated YAML frontmatter`);
  }
  return YAML.parse(text.slice(4, end));
}

const errors = [];
for (const file of await files(docsDir)) {
  try {
    const data = frontmatter(await readFile(file, 'utf8'), file);
    for (const key of required) {
      if (data[key] === undefined || data[key] === null || data[key] === '') {
        errors.push(`${relative('.', file)} missing ${key}`);
      }
    }
    if (!validStatus.has(data.status)) errors.push(`${relative('.', file)} has invalid status`);
    if (!validDocTypes.has(data.doc_type)) errors.push(`${relative('.', file)} has invalid doc_type`);
    if (data.locale !== 'en') errors.push(`${relative('.', file)} must have locale: en`);
    if (!Array.isArray(data.source_repos)) {
      errors.push(`${relative('.', file)} source_repos must be a list`);
    }
    if (!Array.isArray(data.standards_referenced)) {
      errors.push(`${relative('.', file)} standards_referenced must be a list`);
    } else {
      for (const id of data.standards_referenced) {
        if (!knownStandards.has(id)) {
          errors.push(`${relative('.', file)} standards_referenced id "${id}" is not in src/data/standards.yaml`);
        }
      }
    }
    if (data.layer !== undefined) {
      if (!Array.isArray(data.layer)) {
        errors.push(`${relative('.', file)} layer must be a list`);
      } else {
        for (const value of data.layer) {
          if (!validLayer.has(value)) errors.push(`${relative('.', file)} has invalid layer "${value}"`);
        }
      }
    }
    if (data.audience !== undefined) {
      if (!Array.isArray(data.audience)) {
        errors.push(`${relative('.', file)} audience must be a list`);
      } else {
        for (const value of data.audience) {
          if (!validAudience.has(value)) errors.push(`${relative('.', file)} has invalid audience "${value}"`);
        }
      }
    }
    if (data.doc_type === 'specification') {
      const rel = relative('.', file);
      if (data.doc_id === undefined || data.doc_id === null || data.doc_id === '') {
        errors.push(`${rel} (specification) missing doc_id`);
      } else if (!docIdPattern.test(data.doc_id)) {
        errors.push(`${rel} has invalid doc_id "${data.doc_id}" (expected e.g. RS-PR-NOTARY)`);
      } else if (seenDocIds.has(data.doc_id)) {
        errors.push(`${rel} reuses doc_id "${data.doc_id}" already used by ${seenDocIds.get(data.doc_id)}`);
      } else {
        seenDocIds.set(data.doc_id, rel);
      }
      if (!validCategory.has(data.category)) {
        errors.push(`${rel} (specification) has missing or invalid category (normative or informative)`);
      }
      if (!validEvidence.has(data.evidence)) {
        errors.push(`${rel} (specification) has missing or invalid evidence (aspirational, partial, or verified)`);
      }
    }
  } catch (error) {
    errors.push(error.message);
  }
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log('Frontmatter check passed.');
