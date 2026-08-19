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

// These tutorials describe deployments this repository cannot replay: they need
// a real Vault or OpenBao, a deployment repository, and a target host. This file
// is therefore a drift check on the pages themselves, and it is deliberately a
// small one.
//
// One test decides whether an assertion belongs here: if a page lost this, would
// an adopter be left less safe, with nothing else noticing? A token that reaches
// a command line or stays on disk, a private key that becomes exportable, a
// service that starts holding a provider token, a retired signing version that
// can still sign, a boundary between two services that quietly disappears.
// Those stay.
//
// Command spelling, directory layouts, placeholder names, page structure, and
// component usage do not. They are what a page says rather than what the
// deployment must be, and pinning them here only makes these pages harder to
// write. If you are adding an assertion because a page happens to contain a
// string, stop.
test('production Evidence tutorials keep their secret handling, signing, and Mint boundaries explicit', async () => {
  const [build, transit, rotation, mint, compose] = await Promise.all([
    page('src/content/docs/tutorials/build-and-deploy-evidence-project.mdx'),
    page('src/content/docs/tutorials/move-evidence-to-production-signing.mdx'),
    page('src/content/docs/tutorials/rotate-evidence-signing-keys.mdx'),
    page('src/content/docs/tutorials/issue-evidence-access-tokens-with-registry-mint.mdx'),
    page('src/content/docs/tutorials/integrate-evidence-candidate-with-docker-compose.mdx'),
  ]);

  // The access token goes into an owner-only file, never onto a command line or
  // into shell history.
  assert.match(build, /install -m 600 \/dev\/null "<owner-only-curl-config>"/u);
  // The deployment procedure still verifies the audit chain it just moved.
  assert.match(build, /verify-audit/u);
  // The provider keeps the private key: it cannot be exported, and it cannot be
  // backed up in the clear.
  assert.match(transit, /exportable=false/u);
  assert.match(transit, /allow_plaintext_backup=false/u);
  // The proxy attaches the provider credential, so the service process never
  // holds one. The value carries the control: under "true" a client-supplied
  // token wins, and only "force" makes the proxy always override.
  assert.match(transit, /use_auto_auth_token\s*=\s*"force"/u);
  assert.match(transit, / receives no Vault or OpenBao token/u);
  // Rotation and revocation both depend on the floor that stops a retired
  // version from signing again.
  assert.match(rotation, /min_encryption_version/u);
  // Mint is optional, signs through Transit rather than a local private key,
  // and states the replay-protection limit an operator must not overclaim.
  assert.match(mint, /Evidence Gateway does not require Mint/u);
  assert.match(mint, /signer\.kind: transit/u);
  assert.match(mint, /memory-only/u);
  // The issued token is created owner-only and removed after use.
  assert.match(mint, /umask 077/u);
  assert.match(mint, /rm -f "<owner-only-token-file>"/u);
  // Two services, two signing paths: sharing one would let either sign as the
  // other.
  assert.match(compose, /Do not share the Evidence Gateway proxy or socket with Mint/u);
});

test('the maintained Compose adapter keeps Evidence independent from Mint scaffolding', async () => {
  const [readme, compose, runtime] = await Promise.all([
    readFile(resolve(repoRoot, 'docker/compose/README.md'), 'utf8'),
    readFile(resolve(repoRoot, 'docker/compose/docker-compose.yaml'), 'utf8'),
    readFile(resolve(repoRoot, 'docker/compose/runtime.docker.yaml'), 'utf8'),
  ]);

  assert.doesNotMatch(readme, /--with-mint/u);
  assert.doesNotMatch(compose, /--with-mint/u);
  assert.doesNotMatch(compose, /MINT_(?:IMAGE|CONFIG_DIR|SECRET_ROOT)/u);
  assert.match(readme, /intentionally absent from the base adapter/u);
  for (const name of [
    'EVIDENCE_CANDIDATE_DIR',
    'EVIDENCE_RUNTIME_FILE',
    'EVIDENCE_SECRET_ROOT',
    'EVIDENCE_TRANSIT_SOCKET_DIR',
    'EVIDENCE_IMAGE',
  ]) {
    assert.match(readme, new RegExp(`export ${name}=`, 'u'));
  }
  assert.match(compose, /EVIDENCE_CANDIDATE_DIR/u);
  assert.match(compose, /EVIDENCE_SECRET_ROOT/u);
  assert.match(compose, /EVIDENCE_TRANSIT_SOCKET_DIR/u);
  assert.match(compose, /user: "65532:65532"/u);
  assert.match(runtime, /kind: transit/u);
  assert.match(runtime, /unixSocketPath: \/run\/registry-evidence\/transit-proxy\.sock/u);
  assert.doesNotMatch(runtime, /privateKeyRef/u);
});
