import { readFile, readdir } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const defaultSiteRoot = resolve(import.meta.dirname, '..');

// Registry Notary is retired. Current product-surface pages may still name it,
// but only to say it is gone. A block that names Notary without saying so is
// describing a product an adopter cannot start on.
const retirementFraming =
  /\bretir(?:e|ed|es|ing|ement)\b|\bno longer\b|\bremov(?:e|ed|es|al)\b|\bwas replaced\b|\bsuperseded\b/iu;

// Pages the Notary deletion cascade removes outright rather than rewrites.
// They keep describing Notary until then.
const pendingRemoval = new Set([
  'src/content/docs/explanation/evidence-issuance.mdx',
  'src/content/docs/reference/apis/registry-notary.mdx',
  'src/content/docs/spec/rs-dm-claim.mdx',
  'src/content/docs/spec/rs-pr-notary.mdx',
  'src/content/docs/tutorials/move-notary-to-production-signing.mdx',
]);

// Pages still awaiting the light-touch pass. Every entry is tracked debt: the
// list shrinks to empty, and this file is how you tell how much is left.
const pendingRewrite = new Set([
  'src/content/docs/configure/index.mdx',
  'src/content/docs/configure/oauth-client-credentials.mdx',
  'src/content/docs/explanation/data-minimization-and-purpose-limitation.mdx',
  'src/content/docs/explanation/dpi-safeguards-alignment.mdx',
  'src/content/docs/explanation/trusted-context-constraints.mdx',
  'src/content/docs/generated-artifacts/index.mdx',
  'src/content/docs/index.mdx',
  'src/content/docs/operate/advanced/compare-and-reapprove-source-change.mdx',
  'src/content/docs/operate/advanced/index.mdx',
  'src/content/docs/operate/advanced/operate-script-workers.mdx',
  'src/content/docs/operate/advanced/recover-upgrade-migrate-and-rollback.mdx',
  'src/content/docs/operate/backup-and-restore.mdx',
  'src/content/docs/operate/index.mdx',
  'src/content/docs/operate/upgrade-and-rollback.mdx',
  'src/content/docs/reference/apis/index.mdx',
  'src/content/docs/reference/apis/registry-relay.mdx',
  'src/content/docs/reference/contracts.mdx',
  'src/content/docs/reference/deprecation-policy.mdx',
  'src/content/docs/reference/diagnostics/operator.mdx',
  'src/content/docs/reference/index.mdx',
  'src/content/docs/reference/itb-semic-evidence.mdx',
  'src/content/docs/reference/project-configuration.mdx',
  'src/content/docs/reference/registryctl.mdx',
  'src/content/docs/reference/standards.mdx',
  'src/content/docs/security/index.mdx',
  'src/content/docs/security/self-assessment.mdx',
  'src/content/docs/spec/index.mdx',
  'src/content/docs/spec/rs-dm-manifest.mdx',
  'src/content/docs/spec/rs-doc.mdx',
  'src/content/docs/spec/rs-pr-evidence.mdx',
  'src/content/docs/spec/rs-pr-registryctl.mdx',
  'src/content/docs/spec/rs-pr-relay.mdx',
  'src/content/docs/start/evaluate-evidence.mdx',
  'src/content/docs/start/pre-1.0-cutover.mdx',
  'src/content/docs/start/quickstart.mdx',
  'src/content/docs/start/when-to-use.mdx',
  'src/content/docs/tutorials/author-registry-project.mdx',
  'src/content/docs/tutorials/configure-project-script-adapter.mdx',
  'src/content/docs/tutorials/deploy-standalone-with-own-data.mdx',
  'src/content/docs/tutorials/first-run-with-solmara-lab.mdx',
  'src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx',
  'src/content/docs/tutorials/use-your-spreadsheet.mdx',
  'src/content/docs/tutorials/verify-claim-registry-api.mdx',
  'src/content/docs/tutorials/verify-opencrvs-claims.mdx',
  'src/content/docs/verify/index.mdx',
]);

async function markdownFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) paths.push(...(await markdownFiles(path)));
    else if (entry.isFile() && entry.name.endsWith('.mdx')) paths.push(path);
  }
  return paths;
}

function frontmatter(source, path) {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/u);
  if (!match) throw new Error(`${path} has no frontmatter`);
  return {
    status: match[1].match(/^status:[ \t]*(\S.*)$/mu)?.[1]?.trim(),
    draft: /^draft:[ \t]*true[ \t]*$/mu.test(match[1]),
  };
}

// `status: draft` marks a page as under review; it does not hide it, so a
// reader still meets it. `status: historical` and `deprecated` are the marked
// past, and `draft: true` is unpublished.
function isProductSurface(status) {
  return status === 'current' || status === 'draft';
}

// History keeps the name: the changelog and the decision records are the record
// of what happened, not a description of what to run.
function isHistoryPage(siteRelative) {
  return (
    siteRelative.startsWith('src/content/docs/decisions/') ||
    /\/(?:changelog|release-notes)(?:\/index)?\.mdx$/u.test(siteRelative)
  );
}

// A table row or list item stands alone; ordinary prose is judged by paragraph,
// because a sentence is hard-wrapped across several lines.
function blocks(source) {
  const found = [];
  let start = 0;
  let text = '';
  const flush = () => {
    if (text.trim()) found.push({ text, start });
    text = '';
  };
  let offset = 0;
  for (const line of source.split('\n')) {
    const standalone = /^\s*(?:[|*-]|\d+\.)/u.test(line);
    if (!line.trim() || standalone) flush();
    if (line.trim()) {
      if (!text) start = offset;
      text += `${line}\n`;
      if (standalone) flush();
    }
    offset += line.length + 1;
  }
  flush();
  return found;
}

function lineNumber(source, index) {
  return source.slice(0, index).split('\n').length;
}

export async function findUnframedNotaryMentions(siteRoot = defaultSiteRoot) {
  const contentRoot = resolve(siteRoot, 'src/content/docs');
  const findings = [];
  for (const path of await markdownFiles(contentRoot)) {
    const source = await readFile(path, 'utf8');
    const metadata = frontmatter(source, path);
    const siteRelative = relative(siteRoot, path);
    if (
      !isProductSurface(metadata.status) ||
      metadata.draft ||
      siteRelative.startsWith('src/content/docs/products/') ||
      isHistoryPage(siteRelative) ||
      pendingRemoval.has(siteRelative) ||
      pendingRewrite.has(siteRelative)
    ) {
      continue;
    }
    for (const block of blocks(source)) {
      if (!/notary/iu.test(block.text)) continue;
      if (retirementFraming.test(block.text)) continue;
      findings.push({
        path: siteRelative,
        line: lineNumber(source, block.start),
        excerpt: block.text.trim().split('\n')[0].slice(0, 90),
      });
    }
  }
  return findings.sort(
    (left, right) => left.path.localeCompare(right.path) || left.line - right.line,
  );
}

export async function checkNotarySurface(siteRoot = defaultSiteRoot) {
  const findings = await findUnframedNotaryMentions(siteRoot);
  if (findings.length === 0) return;
  throw new Error(
    [
      'Current documentation describes Registry Notary as a product to use.',
      ...findings.map(({ path, line, excerpt }) => `${path}:${line}: ${excerpt}`),
      'Rewrite the page around Registry Relay, Evidence, and Registry Mint, or',
      'say in the same block that Registry Notary is retired.',
    ].join('\n'),
  );
}

export const pendingNotaryRewrites = pendingRewrite;

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  await checkNotarySurface();
  console.log(
    `Notary surface check passed: ${pendingRewrite.size} pages still awaiting the light-touch pass.`,
  );
}
