import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const siteRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const repoRoot = resolve(siteRoot, '../..');

async function page(path) {
  return readFile(resolve(siteRoot, path), 'utf8');
}

test('production Evidence tutorials keep the build, optional Mint, and Compose boundaries explicit', async () => {
  const [build, mint, compose] = await Promise.all([
    page('src/content/docs/tutorials/build-and-deploy-evidence-project.mdx'),
    page('src/content/docs/tutorials/issue-evidence-access-tokens-with-registry-mint.mdx'),
    page('src/content/docs/tutorials/integrate-evidence-candidate-with-docker-compose.mdx'),
  ]);

  assert.match(build, /evidencectl build/u);
  assert.match(build, /\.evidence\/dev/u);
  assert.match(build, /evidence --runtime "<candidate>\/runtime\.yaml" verify-audit/u);
  assert.match(build, /install -m 600 \/dev\/null "<owner-only-curl-config>"/u);
  assert.match(build, /Authorization: Bearer <access-token>/u);
  assert.match(build, /<QuickstartMeta/u);
  assert.match(mint, /Evidence Gateway does not require Mint/u);
  assert.match(mint, /--mint-config "<mint-directory>\/mint\.yaml"/u);
  assert.match(mint, /memory-only/u);
  assert.match(mint, /umask 077\nmint token/u);
  assert.match(mint, /rm -f "<owner-only-token-file>"/u);
  assert.match(mint, /<QuickstartMeta/u);
  assert.match(compose, /candidate\/bundle/u);
  assert.match(compose, /runtime\.docker\.yaml/u);
  assert.match(compose, /configurationRevision/u);
  assert.match(compose, /not output from `evidencectl build`/u);
  assert.match(compose, /user: "65532:65532"/u);
  assert.match(compose, /docker compose down/u);
  assert.match(compose, /<QuickstartMeta/u);
});

test('the maintained Compose adapter keeps Evidence independent from Mint scaffolding', async () => {
  const [readme, compose] = await Promise.all([
    readFile(resolve(repoRoot, 'docker/compose/README.md'), 'utf8'),
    readFile(resolve(repoRoot, 'docker/compose/docker-compose.yaml'), 'utf8'),
  ]);

  assert.doesNotMatch(readme, /--with-mint/u);
  assert.doesNotMatch(compose, /--with-mint/u);
  assert.doesNotMatch(compose, /MINT_(?:IMAGE|CONFIG_DIR|SECRET_ROOT)/u);
  assert.match(readme, /intentionally absent from the base adapter/u);
  for (const name of [
    'EVIDENCE_CANDIDATE_DIR',
    'EVIDENCE_RUNTIME_FILE',
    'EVIDENCE_SECRET_ROOT',
    'EVIDENCE_IMAGE',
  ]) {
    assert.match(readme, new RegExp(`export ${name}=`, 'u'));
  }
  assert.match(compose, /EVIDENCE_CANDIDATE_DIR/u);
  assert.match(compose, /EVIDENCE_SECRET_ROOT/u);
  assert.match(compose, /user: "65532:65532"/u);
});
