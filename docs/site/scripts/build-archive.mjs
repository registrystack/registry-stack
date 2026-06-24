import { buildDocsetArchive } from './build-archives.mjs';
import { resolve } from 'node:path';
import { getDocset, loadDocsets, selectedDocsetId } from './docsets.mjs';

const dataDir = resolve(process.cwd(), 'src/data');
const docsets = await loadDocsets({ dataDir });
const docset = getDocset(docsets, selectedDocsetId(docsets));

if (docset.id === docsets.current || docset.status !== 'archived') {
  console.error('Refusing to build a non-archived docset as an archive. Set DOCS_DOCSET to an archived docset id.');
  process.exit(1);
}

await buildDocsetArchive(docset);
