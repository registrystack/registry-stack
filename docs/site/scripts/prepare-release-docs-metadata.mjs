import { readFile, writeFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import YAML from 'yaml';
import { docEntryAppliesToDocset } from './docsets.mjs';

function parse(source, name) {
  const document = YAML.parseDocument(source);
  if (document.errors.length) throw new Error(`${name}: ${document.errors[0].message}`);
  return document;
}

function calendarDate(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    !Number.isNaN(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
}

function fragment(value, indent) {
  const document = new YAML.Document(value);
  YAML.visit(document, {
    Pair(_, pair) {
      if (['docsets', 'standards_referenced'].includes(pair.key.value)) pair.value.flow = true;
    },
  });
  return document.toString({ lineWidth: 0 }).split('\n').map((line) =>
    line ? ' '.repeat(indent) + line : line).join('\n');
}

function insertions(source, edits) {
  return edits.sort((a, b) => b.offset - a.offset).reduce(
    (result, edit) => result.slice(0, edit.offset) + edit.text + result.slice(edit.offset), source,
  );
}

// Insert fragments at YAML node boundaries. Existing comments, scalar styles,
// flow lists and historical records remain byte-for-byte unchanged.
export async function prepareReleaseDocsMetadata({
  siteRoot = process.cwd(), version, releaseId, date, write = true,
}) {
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version ?? '')) {
    throw new Error('version must be an unprefixed stable semantic version');
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(releaseId ?? '')) {
    throw new Error('release-id must be a release identifier of 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or digit');
  }
  if (!calendarDate(date)) throw new Error('date must be a valid YYYY-MM-DD calendar date');
  const repoRoot = resolve(siteRoot, '../..');
  const docsetId = `v${version}`;
  const manifestPath = resolve(repoRoot, `release/manifests/registry-stack-${releaseId}.yaml`);
  const manifest = parse(await readFile(manifestPath, 'utf8'), manifestPath).toJS();
  if (manifest.stack?.version !== version || manifest.stack?.release !== releaseId ||
      manifest.stack?.source_tag !== docsetId || manifest.artifacts?.['registry-docs'] !== version) {
    throw new Error('selected manifest must match version, release-id, source_tag and registry-docs artifact');
  }
  if (!manifest.external || typeof manifest.external !== 'object' || Array.isArray(manifest.external)) {
    throw new Error('selected manifest external must be a map');
  }
  const docsetsPath = resolve(siteRoot, 'src/data/docsets.yaml');
  const repoDocsPath = resolve(siteRoot, 'src/data/repo-docs.yaml');
  const [docsetsSource, repoDocsSource, lockSource] = await Promise.all([
    readFile(docsetsPath, 'utf8'), readFile(repoDocsPath, 'utf8'),
    readFile(resolve(siteRoot, 'src/data/archive-lock.yaml'), 'utf8').catch((error) => {
      if (error.code === 'ENOENT') return 'archives: {}';
      throw error;
    }),
  ]);
  const docsetsDocument = parse(docsetsSource, docsetsPath);
  const repoDocsDocument = parse(repoDocsSource, repoDocsPath);
  const docsets = docsetsDocument.toJS();
  const current = docsets.docsets.find((entry) => entry.id === docsets.current);
  if (!current?.products || current.status !== 'current') throw new Error('current docset must declare its products');
  const products = {};
  const sourceRef = manifest.stack.source_ref ?? docsetId;
  for (const productId of Object.keys(current.products)) {
    if (Object.hasOwn(manifest.external, productId)) continue;
    products[productId] = { version: docsetId, ref: sourceRef };
  }
  for (const [productId, external] of Object.entries(manifest.external)) {
    if (!external?.ref) throw new Error(`external product ${productId} must declare ref`);
    products[productId] = { version: external.version ?? external.ref, ref: external.ref };
  }
  const candidate = {
    id: docsetId, label: docsetId, path: `/v/${version}/`, status: 'archived',
    availability: 'candidate', source: `registry-stack-${docsetId}`,
    repo_docs_source: 'monorepo', published_at: date,
    description: `Registry Stack ${docsetId} ${releaseId} candidate documentation set.`, products,
  };
  const matches = docsets.docsets.filter((entry) => entry.id === docsetId);
  if (matches.length > 1) throw new Error(`duplicate docset ${docsetId}`);
  if (matches.length && !isDeepStrictEqual(matches[0], candidate)) {
    throw new Error(`conflicting existing candidate metadata for ${docsetId}`);
  }
  const docsetsEdits = [];
  if (!matches.length) {
    const sequence = docsetsDocument.get('docsets', true);
    if (!YAML.isSeq(sequence) || sequence.flow) throw new Error('docsets must be a block sequence');
    const currentNode = sequence.items.find((node) => node.get('id') === docsets.current);
    docsetsEdits.push({ offset: currentNode.range[2], text: fragment([candidate], 2) });
  }
  const repoEdits = [];
  const reposNode = repoDocsDocument.get('repos', true);
  if (!YAML.isMap(reposNode)) throw new Error('repo-docs.yaml must declare repos');
  for (const repoPair of reposNode.items) {
    const entries = repoPair.value.get('docs', true);
    if (!entries) continue;
    if (!YAML.isSeq(entries) || entries.flow) throw new Error('repo docs must be a block sequence');
    for (const entryNode of entries.items) {
      const entry = entryNode.toJSON();
      if (!docEntryAppliesToDocset(entry, candidate)) continue;
      if (!Object.hasOwn(products, repoPair.key.value)) {
        throw new Error(`candidate is missing active repo product ${repoPair.key.value}`);
      }
      if (!(entry.last_reviewed === 'unreviewed' || calendarDate(entry.last_reviewed)) ||
          !Array.isArray(entry.standards_referenced) ||
          entry.standards_referenced.some((value) => typeof value !== 'string' || !value.trim())) {
        throw new Error(`${entry.src}: current review and standards metadata must be explicit`);
      }
      const snapshot = { standards_referenced: entry.standards_referenced, last_reviewed: entry.last_reviewed };
      const existing = (entry.docset_overrides ?? []).filter((override) => override.docsets.includes(docsetId));
      if (existing.length > 1 || (existing.length === 1 && !isDeepStrictEqual(existing[0], { docsets: existing[0].docsets, ...snapshot }))) {
        throw new Error(`${entry.src}: conflicting metadata snapshot for ${docsetId}`);
      }
      if (existing.length) continue;
      const overridesNode = entryNode.get('docset_overrides', true);
      const override = { docsets: [docsetId], ...snapshot };
      if (overridesNode) {
        if (!YAML.isSeq(overridesNode) || overridesNode.flow || !overridesNode.items.length) {
          throw new Error(`${entry.src}: docset_overrides must be a non-empty block sequence`);
        }
        repoEdits.push({ offset: overridesNode.range[2], text: fragment([override], 10) });
      } else {
        repoEdits.push({ offset: entryNode.range[2], text: fragment({ docset_overrides: [override] }, 8) });
      }
    }
  }
  const frozen = parse(lockSource, 'archive-lock.yaml').toJS()?.archives?.[docsetId];
  if (frozen && (docsetsEdits.length || repoEdits.length)) {
    throw new Error(`cannot modify metadata for frozen archive ${docsetId}`);
  }
  const outputs = [
    [docsetsPath, insertions(docsetsSource, docsetsEdits), docsetsSource],
    [repoDocsPath, insertions(repoDocsSource, repoEdits), repoDocsSource],
  ].filter(([, result, original]) => result !== original);
  // Complete conflict checks and parse the result before writing either input.
  for (const [path, result] of outputs) parse(result, path);
  if (write) for (const [path, result] of outputs) await writeFile(path, result);
  return { docsetId, changedPaths: outputs.map(([path]) => relative(repoRoot, path)) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    const options = {};
    let json = false;
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index];
      if (arg === '--json') json = true;
      else if (arg === '--check') options.write = false;
      else if (['--version', '--release-id', '--date'].includes(arg)) {
        const value = args[++index];
        if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value`);
        options[{ '--version': 'version', '--release-id': 'releaseId', '--date': 'date' }[arg]] = value;
      } else throw new Error(`unknown argument ${arg}`);
    }
    const result = await prepareReleaseDocsMetadata(options);
    console.log(json ? JSON.stringify(result) : `${result.docsetId}: ${result.changedPaths.join(', ') || 'metadata unchanged'}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
