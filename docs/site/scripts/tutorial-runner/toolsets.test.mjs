import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { TOOLSETS, cargoBuild, serveBinaries } from './toolsets.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');

// A toolset's commands pattern decides which pages its gate must replay, so it
// matches a command a fence runs and not a path or file that shares its name.
const CASES = {
  breg: {
    runs: ['bregctl init .', 'bregctl dev start .', 'breg --version', 'version=$(bregctl --version)', 'bregctl dev stop .; echo done'],
    names: ['cd tutorial-work/breg', 'cat .breg/dev/state.json', 'ls ./breg', 'cat breg.yaml', 'cd breg-demo', 'ls breg/'],
  },
  casework: {
    runs: ['caseworkctl dev start .', 'casework --version', 'caseworkctl check . | tail -1'],
    names: ['cd tutorial-work/casework', 'cat .casework/dev/state.json', 'cat casework.yaml', 'ls casework/'],
  },
  evidence: {
    runs: ['evidencectl init .', 'evidence --version', 'evidence-oid4vci --help', 'products/evidence/scripts/check-contracts.sh'],
    names: ['cd ~/work/evidence', 'ls .evidence/clients', 'cat evidence.yaml', 'ls evidence/', "curl --get --data-urlencode 'serviceKind=evidence' $url"],
  },
  discovery: {
    runs: ['discoveryctl check --project discovery-project --allow-loopback', 'discovery --runtime runtime.yaml', 'discoveryctl build --project . && echo ok'],
    names: ['cp -R products/discovery/tutorial/project discovery-project', 'rm -rf discovery-project', 'cat discovery.yaml', 'ls discovery/'],
  },
};

for (const [name, { runs, names }] of Object.entries(CASES)) {
  test(`the ${name} toolset matches the commands a fence runs, not paths that share their name`, () => {
    const { commands } = TOOLSETS[name];
    for (const code of runs) assert.equal(commands.test(code), true, `${name} must match: ${code}`);
    for (const code of names) assert.equal(commands.test(code), false, `${name} must not match: ${code}`);
  });
}

// A cargo that records its arguments and reports an AWS-LC FIPS build script
// whose output directory holds the crypto dylib, as a macOS build does.
async function fakeCargo({ fail = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'toolset-cargo-'));
  const artifacts = join(root, 'out', 'build', 'artifacts');
  await mkdir(artifacts, { recursive: true });
  await writeFile(join(artifacts, 'libaws_lc_fips_0_14_2_crypto.dylib'), '');
  const message = JSON.stringify({
    reason: 'build-script-executed',
    package_id: 'registry+https://github.com/rust-lang/crates.io-index#aws-lc-fips-sys@0.14.2',
    linked_libs: ['dylib=aws_lc_fips_0_14_2_crypto'],
    out_dir: join(root, 'out'),
  });
  const diagnostic = JSON.stringify({ reason: 'compiler-message', message: { rendered: 'error: it does not compile\n' } });
  const bin = join(root, 'bin');
  await mkdir(bin);
  await writeFile(
    join(bin, 'cargo'),
    `#!/bin/sh\nprintf '%s\\n' "$*" >'${join(root, 'args')}'\n` +
      (fail ? `printf '%s\\n' '${diagnostic}'\nexit 101\n` : `printf '%s\\n' '${message}'\n`),
  );
  await chmod(join(bin, 'cargo'), 0o755);
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}` };
  return { root, artifacts, env, args: () => readFileSync(join(root, 'args'), 'utf8').trim() };
}

test('a macOS build reports the directory holding the AWS-LC FIPS dylib its binaries load', async () => {
  const cargo = await fakeCargo();
  const libraryDir = cargoBuild({ repoRoot: REPO_ROOT, args: ['build', '-p', 'x'], env: cargo.env, platform: 'darwin' });
  assert.equal(libraryDir, cargo.artifacts);
  assert.equal(cargo.args(), 'build -p x --message-format=json-render-diagnostics');
});

test('a build elsewhere is a plain cargo build and reports no library directory', async () => {
  const cargo = await fakeCargo();
  const libraryDir = cargoBuild({ repoRoot: REPO_ROOT, args: ['build', '-p', 'x'], env: cargo.env, platform: 'linux' });
  assert.equal(libraryDir, undefined);
  assert.equal(cargo.args(), 'build -p x');
});

test('a failed macOS build fails the toolset and still shows the compiler diagnostics', async () => {
  const cargo = await fakeCargo({ fail: true });
  const child = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `import { cargoBuild } from ${JSON.stringify(new URL('./toolsets.mjs', import.meta.url).href)};
       try { cargoBuild({ repoRoot: ${JSON.stringify(REPO_ROOT)}, args: ['build'], platform: 'darwin' }); } catch (error) { console.log(error.message); }`,
    ],
    { env: cargo.env, encoding: 'utf8' },
  );
  assert.match(child.stdout, /cargo build failed/u, child.stderr);
  assert.match(child.stderr, /error: it does not compile/u);
});

test('a binary served with a library directory finds it even when a protected shell starts it', async () => {
  const binDir = await mkdtemp(join(tmpdir(), 'toolset-bin-'));
  await serveBinaries(binDir, [['tool', process.execPath]], '/opt/fips artifacts');
  const run = spawnSync('/bin/sh', ['-c', `tool -e 'console.log(process.env.DYLD_FALLBACK_LIBRARY_PATH)'`], {
    env: { ...process.env, PATH: `${binDir}:${process.env.PATH}` },
    encoding: 'utf8',
  });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout.trim().split(':')[0], '/opt/fips artifacts');
});

test('a binary served without a library directory is the binary itself', async () => {
  const binDir = await mkdtemp(join(tmpdir(), 'toolset-bin-'));
  await serveBinaries(binDir, [['tool', process.execPath]]);
  assert.equal(realpathSync(join(binDir, 'tool')), realpathSync(process.execPath));
});
