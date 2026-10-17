import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { TOOLSETS, cargoBuild, clientEnvironment, npmEnvironment, serveBinaries, serveNpmPackages, workspaceReleaseTag } from './toolsets.mjs';

const execFileAsync = promisify(execFile);

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
  coordinator: {
    runs: [
      'coordinatorctl run start',
      'coordinator --runtime-config runtime.yaml',
      'python3 products/coordinator/examples/reviewed-notice/session.py start',
      'reviewed-notice-input --record-id "$application"',
    ],
    names: ['cd products/coordinator', 'cat coordinator.yaml', 'ls reviewed-notice-input/'],
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

test('the release tag names the workspace version, not a member crate version', async () => {
  const root = await mkdtemp(join(tmpdir(), 'toolset-workspace-'));
  await writeFile(
    join(root, 'Cargo.toml'),
    '[workspace]\nmembers = ["a"]\n\n[workspace.dependencies]\nserde = { version = "1.0.0" }\n\n[workspace.package]\nedition = "2024"\nversion = "1.2.3"\n',
  );
  assert.equal(workspaceReleaseTag(root), 'v1.2.3');
});

test('a workspace without a package version has no release tag', async () => {
  const root = await mkdtemp(join(tmpdir(), 'toolset-workspace-'));
  await writeFile(join(root, 'Cargo.toml'), '[workspace]\nmembers = ["a"]\n');
  assert.throws(() => workspaceReleaseTag(root), /no \[workspace\.package\] version/u);
});

// The client packages a breg journey installs are assembled at the workspace
// version, so the binaries it builds must report that version too.
test('the breg toolset builds its binaries marked with the workspace release tag', () => {
  const version = /\[workspace\.package\][^[]*?\nversion = "([^"]+)"/u.exec(readFileSync(join(REPO_ROOT, 'Cargo.toml'), 'utf8'))[1];
  assert.deepEqual(TOOLSETS.breg.buildEnv(REPO_ROOT), { REGISTRY_RELEASE_TAG: `v${version}` });
});

test('the breg toolset installs the client packages only for a journey that runs their install commands', () => {
  const { clients } = TOOLSETS.breg;
  for (const code of ['python -m pip install "registry-stack-client==${version}"', 'npm install "@registrystack/client@${version}"']) {
    assert.equal(clients.test(code), true, `must match: ${code}`);
  }
  for (const code of ['bregctl dev start tutorial-work/project', 'cd registry-stack-client-demo', 'ls crates/registry-stack-client-node']) {
    assert.equal(clients.test(code), false, `must not match: ${code}`);
  }
});

// Pack a package with npm itself, as the release assembly does.
async function packPackage(dir, out, manifest) {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'package.json'), JSON.stringify(manifest));
  await writeFile(join(dir, 'index.js'), `module.exports = ${JSON.stringify(manifest.name)};\n`);
  const pack = spawnSync('npm', ['pack', '--ignore-scripts', '--pack-destination', out], { cwd: dir, encoding: 'utf8' });
  assert.equal(pack.status, 0, pack.stderr);
}

// A directory of packed packages as the release assembly leaves them: a root
// package and the one platform package this machine uses.
async function packedFixture(root) {
  const packages = join(root, 'packages');
  await mkdir(packages);
  await packPackage(join(root, 'src', 'platform'), packages, { name: '@tutorial-fake/client-here', version: '1.2.3', main: 'index.js' });
  await packPackage(join(root, 'src', 'root'), packages, {
    name: '@tutorial-fake/client',
    version: '1.2.3',
    main: 'index.js',
    // A platform package this machine does not use is not assembled, and
    // npm skips it as it skips any optional dependency it cannot fetch.
    optionalDependencies: { '@tutorial-fake/client-here': '1.2.3', '@tutorial-fake/client-elsewhere': '1.2.3' },
  });
  return packages;
}

test('a reader installs a locally assembled npm package by its published name and exact version', async () => {
  const root = await mkdtemp(join(tmpdir(), 'toolset-npm-'));
  const packages = await packedFixture(root);
  const registry = await serveNpmPackages(packages);
  try {
    const project = join(root, 'project');
    await mkdir(project);
    const env = { ...process.env, ...npmEnvironment(registry, join(root, 'npm-cache')) };
    const steps = [['init', '-y'], ['install', '@tutorial-fake/client@1.2.3']];
    // npm runs beside the registry, which answers from this process.
    for (const args of steps) await execFileAsync('npm', args, { cwd: project, env });
    assert.equal(installedVersion(project, '@tutorial-fake/client'), '1.2.3');
    assert.equal(installedVersion(project, '@tutorial-fake/client-here'), '1.2.3');
  } finally {
    await registry.close();
  }
});

function installedVersion(project, name) {
  return JSON.parse(readFileSync(join(project, 'node_modules', name, 'package.json'), 'utf8')).version;
}

test('npm reached through a served registry neither audits nor asks for funding', () => {
  const env = npmEnvironment({ url: 'http://127.0.0.1:1/', scopes: ['@registrystack'] }, '/work/npm-cache');
  assert.deepEqual(env, {
    npm_config_cache: '/work/npm-cache',
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    'npm_config_@registrystack:registry': 'http://127.0.0.1:1/',
  });
});

async function withPackagesDir(dir, body) {
  const previous = process.env.REGISTRY_CLIENT_PACKAGES_DIR;
  process.env.REGISTRY_CLIENT_PACKAGES_DIR = dir;
  try {
    return await body();
  } finally {
    if (previous === undefined) delete process.env.REGISTRY_CLIENT_PACKAGES_DIR;
    else process.env.REGISTRY_CLIENT_PACKAGES_DIR = previous;
  }
}

test('a journey that installs the client gets the packages served, and closing stops the registry', async () => {
  const root = await mkdtemp(join(tmpdir(), 'toolset-client-'));
  const packages = await packedFixture(root);
  const workRoot = join(root, 'work');
  await mkdir(workRoot);
  const steps = [{ kind: 'run', code: 'npm install "@registrystack/client@${version}"' }];
  const { env, close } = await withPackagesDir(packages, () => clientEnvironment(steps, REPO_ROOT, workRoot));
  let closed = false;
  try {
    const url = env['npm_config_@tutorial-fake:registry'];
    assert.match(url, /^http:\/\/127\.0\.0\.1:\d+\/$/u);
    assert.deepEqual(env, {
      npm_config_cache: join(workRoot, 'npm-cache'),
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      'npm_config_@tutorial-fake:registry': url,
      PIP_NO_INDEX: '1',
      PIP_FIND_LINKS: packages,
    });
    const project = join(root, 'project');
    await mkdir(project);
    const npmEnv = { ...process.env, ...env };
    for (const args of [['init', '-y'], ['install', '@tutorial-fake/client@1.2.3']]) {
      await execFileAsync('npm', args, { cwd: project, env: npmEnv });
    }
    assert.equal(installedVersion(project, '@tutorial-fake/client'), '1.2.3');
    await close();
    closed = true;
    await assert.rejects(fetch(url), (error) => error.cause?.code === 'ECONNREFUSED');
  } finally {
    if (!closed) await close();
  }
});

test('a journey that installs no client needs no packages and serves nothing', async () => {
  const steps = [{ kind: 'run', code: 'bregctl dev start tutorial-work/project' }];
  const { env, close } = await withPackagesDir('relative', () => clientEnvironment(steps, REPO_ROOT, '/work'));
  assert.deepEqual(env, {});
  await close();
});

test('a directory without an npm package is refused', async () => {
  const empty = await mkdtemp(join(tmpdir(), 'toolset-npm-'));
  await assert.rejects(serveNpmPackages(empty), /no npm package in \/\S+/u);
});
