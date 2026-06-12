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
const validDocTypes = new Set(['tutorial', 'how-to', 'explanation', 'reference', 'decision']);
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
  } catch (error) {
    errors.push(error.message);
  }
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log('Frontmatter check passed.');
