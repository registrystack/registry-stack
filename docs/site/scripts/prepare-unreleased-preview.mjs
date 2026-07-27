import { lstat, readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadDocsets } from './docsets.mjs';

const previewBase = '/preview/';
const discoveryFiles = ['llms.txt', 'llms-full.txt', 'llms-small.txt', 'sitemap-index.xml'];

async function collectTextFiles(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`Main-source preview cannot contain symlinks: ${path}`);
    }
    if (info.isDirectory()) {
      files.push(...await collectTextFiles(root, path));
    } else if (
      info.isFile() &&
      (entry.name.endsWith('.html') ||
        entry.name.endsWith('.md') ||
        entry.name === 'robots.txt' ||
        /^llms(?:-(?:full|small))?\.txt$/.test(entry.name))
    ) {
      files.push(path);
    }
  }
  return files;
}

function rewriteHtml(html, archivedPaths) {
  return html.replace(
    /(\s(?:href|src)=)(["'])(\/(?!\/)[^"']*)\2/g,
    (match, attribute, quote, value) => {
      const pathname = value.split(/[?#]/, 1)[0];
      if (
        pathname === '/preview' ||
        pathname.startsWith('/preview/') ||
        pathname === '/v' ||
        pathname.startsWith('/v/') ||
        pathname === '/_archive-bundles' ||
        pathname.startsWith('/_archive-bundles/') ||
        archivedPaths.some((path) => pathname === path.slice(0, -1) || pathname.startsWith(path))
      ) {
        return match;
      }
      return `${attribute}${quote}/preview${value}${quote}`;
    },
  );
}

function rewriteDiscoveryUrls(contents) {
  let rewritten = contents;
  for (const path of discoveryFiles) {
    rewritten = rewritten.replaceAll(
      `https://docs.registrystack.org/${path}`,
      `https://docs.registrystack.org${previewBase}${path}`,
    );
  }
  return rewritten;
}

export async function prepareUnreleasedPreview({
  docsRoot = process.cwd(),
  previewRoot = resolve(docsRoot, 'dist/preview'),
} = {}) {
  const docsets = await loadDocsets({ dataDir: resolve(docsRoot, 'src/data') });
  const archivedPaths = docsets.docsets
    .filter((docset) => docset.status === 'archived')
    .map((docset) => docset.path);
  let changed = 0;
  const files = await collectTextFiles(previewRoot);
  for (const file of files) {
    const contents = await readFile(file, 'utf8');
    const withMountedLinks = file.endsWith('.html')
      ? rewriteHtml(contents, archivedPaths)
      : contents;
    const rewritten = rewriteDiscoveryUrls(withMountedLinks);
    if (rewritten !== contents) {
      await writeFile(file, rewritten, 'utf8');
      changed += 1;
    }
  }
  return { checked: files.length, changed };
}

async function main() {
  const result = await prepareUnreleasedPreview();
  console.log(
    `Prepared Main-source preview under ${previewBase}: ` +
      `${result.changed} of ${result.checked} text files rewritten.`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
