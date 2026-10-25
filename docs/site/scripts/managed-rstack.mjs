#!/usr/bin/env node
// Prepare an isolated, integrity-recorded rstack generation around exact
// source binaries. This is a tutorial test fixture, not a release installer:
// the binaries retain their own development identity and the real rstack
// launcher still selects and validates the generation before dispatch.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants, accessSync, readFileSync } from 'node:fs';
import { chmod, lstat, mkdir, readdir, readFile, symlink, writeFile } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const quote = (value) => `'${value.replaceAll("'", `'\\''`)}'`;

function checkExecutable(label, path) {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path: ${path}`);
  try {
    accessSync(path, constants.X_OK);
  } catch {
    throw new Error(`${label} is not executable: ${path}`);
  }
}

function workspaceVersion(repoRoot) {
  const manifest = readFileSync(join(repoRoot, 'Cargo.toml'), 'utf8');
  const version = /^\[workspace\.package\]$[^[]*?^version = "([^"]+)"$/mu.exec(manifest)?.[1];
  if (version === undefined) throw new Error(`${join(repoRoot, 'Cargo.toml')} has no [workspace.package] version`);
  return version;
}

function sourceSha(repoRoot) {
  const result = spawnSync('git', ['--no-optional-locks', '-C', repoRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  const sha = result.stdout.trim();
  if (result.status !== 0 || !/^[0-9a-f]{40}$/u.test(sha)) throw new Error(`cannot identify the source checkout: ${result.stderr.trim()}`);
  return sha;
}

function platform() {
  if (process.platform === 'darwin' && process.arch === 'arm64') return 'macos-arm64';
  if (process.platform === 'linux' && process.arch === 'x64') return 'linux-amd64';
  if (process.platform === 'linux' && process.arch === 'arm64') return 'linux-arm64';
  throw new Error(`rstack has no managed tutorial platform for ${process.platform}-${process.arch}`);
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function assetName(binary, tag, target) {
  const suffix = target === 'macos-arm64' ? '.tar.gz' : '';
  return `${binary}-${tag}-${target}${suffix}`;
}

async function writeWrapper(path, executable, prefix = [], libraryDir) {
  const command = [quote(executable), ...prefix.map(quote), '"$@"'].join(' ');
  const environment =
    libraryDir === undefined || libraryDir === ''
      ? ''
      : `DYLD_FALLBACK_LIBRARY_PATH=${quote(libraryDir)}\${DYLD_FALLBACK_LIBRARY_PATH:+:\$DYLD_FALLBACK_LIBRARY_PATH}\nexport DYLD_FALLBACK_LIBRARY_PATH\n`;
  await writeFile(path, `#!/bin/sh\n${environment}exec ${command}\n`);
  await chmod(path, 0o755);
}

async function writeBinaryWrapper(path, executable, libraryDir, candidateVariables) {
  const text = ['#!/bin/sh', `unset ${candidateVariables.join(' ')}`];
  if (libraryDir !== undefined && libraryDir !== '') {
    text.push(
      `DYLD_FALLBACK_LIBRARY_PATH=${quote(libraryDir)}\${DYLD_FALLBACK_LIBRARY_PATH:+:\$DYLD_FALLBACK_LIBRARY_PATH}`,
      'export DYLD_FALLBACK_LIBRARY_PATH',
    );
  }
  text.push(`exec ${quote(executable)} "$@"`, '');
  await writeFile(path, text.join('\n'));
  await chmod(path, 0o755);
}

async function inventory(root, generation) {
  const files = {};
  const directories = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const name = relative(root, path);
      if (name === '.rstack-lease' || name === '.rstack-ownership.json') continue;
      if (entry.isSymbolicLink()) throw new Error(`managed tutorial generation entry must not be a symlink: ${name}`);
      if (entry.isDirectory()) {
        directories.push(name);
        await visit(path);
      } else if (entry.isFile()) {
        const [bytes, stat] = await Promise.all([readFile(path), lstat(path)]);
        files[name] = { size: bytes.length, sha256: digest(bytes), mode: stat.mode & 0o7777 };
      } else {
        throw new Error(`unsupported managed tutorial generation entry: ${name}`);
      }
    }
  }
  await visit(root);
  directories.sort();
  return { schema_version: 'registry-stack.generation-ownership.v1', generation, files, directories };
}

export async function prepareManagedRstack({ repoRoot, workRoot, binDir, rstackBin, components, libraryDir }) {
  checkExecutable('RSTACK_BIN', rstackBin);
  if (!isAbsolute(workRoot) || !isAbsolute(binDir)) throw new Error('managed rstack work and bin directories must be absolute');
  const names = Object.keys(components).sort();
  if (names.length === 0) throw new Error('managed rstack needs at least one component');
  for (const [component, spec] of Object.entries(components)) {
    if (!Object.hasOwn(spec.binaries, spec.entrypoint)) throw new Error(`${component} lacks its ${spec.entrypoint} entrypoint`);
    for (const [binary, path] of Object.entries(spec.binaries)) checkExecutable(`${binary.toUpperCase().replaceAll('-', '_')}_BIN`, path);
  }

  const version = workspaceVersion(repoRoot);
  const tag = `v${version}`;
  const sha = sourceSha(repoRoot);
  const target = platform();
  const installRoot = join(workRoot, 'managed-rstack');
  const generation = `source-${sha.slice(0, 12)}`;
  const generationDir = join(installRoot, 'generations', generation);
  await mkdir(join(generationDir, 'components'), { recursive: true });
  await mkdir(binDir, { recursive: true });

  await writeWrapper(join(generationDir, 'rstack'), rstackBin, ['--install-root', installRoot, '--bin-dir', binDir], libraryDir);
  const payloads = [];
  const launcherBytes = await readFile(join(generationDir, 'rstack'));
  const launcher = { name: assetName('rstack', tag, target), size: launcherBytes.length, sha256: digest(launcherBytes) };
  payloads.push({ ...launcher, kind: 'binary' });
  const componentManifest = {};
  for (const name of names) {
    const spec = components[name];
    const candidateVariables = Object.keys(spec.binaries)
      .map((binary) => `${binary.toUpperCase().replaceAll('-', '_')}_BIN`)
      .sort();
    const assets = [];
    for (const [binary, executable] of Object.entries(spec.binaries)) {
      const directory = join(generationDir, 'components', name, binary);
      await mkdir(directory, { recursive: true });
      const path = join(directory, binary);
      await writeBinaryWrapper(path, executable, libraryDir, candidateVariables);
      const bytes = await readFile(path);
      const asset = { name: assetName(binary, tag, target), size: bytes.length, sha256: digest(bytes) };
      assets.push(asset);
      payloads.push({ ...asset, kind: 'binary' });
    }
    componentManifest[name] = {
      entrypoint: spec.entrypoint,
      dependencies: [],
      platforms: { [target]: { assets, capabilities: { tooling: true, runtime: Object.hasOwn(spec.binaries, name) } } },
    };
  }
  const manifest = {
    schema_version: 'registry-stack.release-candidate.v2',
    repository: 'registrystack/registry-stack',
    release: { tag, version, source_sha: sha, release_id: `tutorial-source-${sha.slice(0, 12)}` },
    payloads,
    components: {
      schema_version: 'registry-stack.components.v1',
      release: tag,
      launcher: { [target]: launcher },
      components: componentManifest,
    },
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
  await writeFile(join(generationDir, 'manifest.json'), manifestBytes);
  await writeFile(
    join(generationDir, 'selection.json'),
    `${JSON.stringify({ schema_version: 'registry-stack.install-selection.v1', release: tag, platform: target, components: names }, null, 2)}\n`,
  );
  const checksumLines = payloads.map((asset) => `${asset.sha256}  ${asset.name}`);
  checksumLines.push(`${digest(manifestBytes)}  registry-stack-${tag}-release-manifest.json`);
  await writeFile(join(generationDir, 'SHA256SUMS'), `${checksumLines.join('\n')}\n`);
  await writeFile(join(generationDir, '.rstack-lease'), '');
  await writeFile(join(generationDir, '.rstack-ownership.json'), `${JSON.stringify(await inventory(generationDir, generation), null, 2)}\n`);
  await writeFile(join(installRoot, '.mutation.lock'), '');
  await symlink(join('generations', generation), join(installRoot, 'current'));
  await symlink(join(installRoot, 'current', 'rstack'), join(binDir, 'rstack'));
  return { installRoot, generationDir };
}

async function main(arguments_) {
  const options = { components: {} };
  let current;
  for (let i = 0; i < arguments_.length; i += 1) {
    const argument = arguments_[i];
    if (argument === '--repo-root') options.repoRoot = arguments_[++i];
    else if (argument === '--work-root') options.workRoot = arguments_[++i];
    else if (argument === '--bin-dir') options.binDir = arguments_[++i];
    else if (argument === '--rstack-bin') options.rstackBin = arguments_[++i];
    else if (argument === '--library-dir') options.libraryDir = arguments_[++i];
    else if (argument === '--component') {
      const [name, entrypoint] = arguments_[++i].split('=', 2);
      current = options.components[name] = { entrypoint, binaries: {} };
    } else if (argument === '--binary' && current) {
      const value = arguments_[++i];
      const separator = value.indexOf('=');
      current.binaries[value.slice(0, separator)] = value.slice(separator + 1);
    } else throw new Error(`unknown or misplaced managed-rstack argument: ${argument}`);
  }
  await prepareManagedRstack(options);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main(process.argv.slice(2));
  } catch (error) {
    console.error(`managed rstack: ${error.message}`);
    process.exit(1);
  }
}
