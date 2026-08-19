import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const releaseTagPattern =
  /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const productionOrigin = 'https://docs.registrystack.org';

function canonicalFromHtml(html) {
  return html.match(
    /<link\b(?=[^>]*\brel=["']canonical["'])(?=[^>]*\bhref=["']([^"']+)["'])[^>]*>/i,
  )?.[1];
}

function localPath(root, pathname) {
  const relative = pathname.replace(/^\/+/, '');
  if (pathname.endsWith('/')) return resolve(root, relative, 'index.html');
  return resolve(root, relative);
}

async function localReader(root, pathname) {
  const contents = await readFile(localPath(root, pathname));
  return {
    body: contents,
    status: 200,
    location: null,
  };
}

async function liveReader(origin, pathname) {
  const response = await fetch(new URL(pathname, origin), {
    redirect: 'manual',
    headers: { 'user-agent': 'registry-docs-deployment-smoke/1' },
  });
  return {
    body: Buffer.from(await response.arrayBuffer()),
    status: response.status,
    location: response.headers.get('location'),
  };
}

async function requireRoute(read, pathname) {
  let response;
  try {
    response = await read(pathname);
  } catch (error) {
    throw new Error(`${pathname} is missing: ${error.message}`);
  }
  if (response.status !== 200) {
    throw new Error(
      `${pathname} returned HTTP ${response.status}` +
        (response.location ? ` with Location ${response.location}` : ''),
    );
  }
  if (response.body.length === 0) throw new Error(`${pathname} returned an empty body`);
  return response.body;
}

export async function smokeDocsDeployment({
  read,
  releasedTag,
  deepRoute = '/start/when-to-use/',
} = {}) {
  if (!releaseTagPattern.test(releasedTag ?? '')) {
    throw new Error('released tag must be canonical v<major>.<minor>.<patch> text');
  }
  if (!deepRoute.startsWith('/') || !deepRoute.endsWith('/') || deepRoute === '/') {
    throw new Error('deep route must be an absolute trailing-slash route below root');
  }
  const versionPath = `/v/${releasedTag.slice(1)}/`;
  const [root, deep, dev, version] = await Promise.all([
    requireRoute(read, '/'),
    requireRoute(read, deepRoute),
    requireRoute(read, '/dev/'),
    requireRoute(read, versionPath),
  ]);
  const rootHtml = root.toString('utf8');
  const deepHtml = deep.toString('utf8');
  const devHtml = dev.toString('utf8');
  const versionHtml = version.toString('utf8');

  if (canonicalFromHtml(rootHtml) !== `${productionOrigin}/`) {
    throw new Error('/ is not root-canonical released documentation');
  }
  if (canonicalFromHtml(deepHtml) !== `${productionOrigin}${deepRoute}`) {
    throw new Error(`${deepRoute} is not canonical at the released root`);
  }
  if (canonicalFromHtml(devHtml) !== `${productionOrigin}/dev/`) {
    throw new Error('/dev/ is not canonical at the protected-main mount');
  }
  if (canonicalFromHtml(versionHtml) !== `${productionOrigin}${versionPath}`) {
    throw new Error(`${versionPath} is not canonical at the immutable version route`);
  }
  if (!rootHtml.includes(versionPath)) {
    throw new Error(`/ does not expose version navigation to ${versionPath}`);
  }
  if (!rootHtml.includes('Released docs.')) {
    throw new Error('/ does not identify the promoted bundle as released documentation');
  }
  if (/registry-docset-redirect/.test(rootHtml)) {
    throw new Error('/ still contains a version redirect document');
  }

  // Search, sitemap, and machine-readable routes on both mounts. The site
  // publishes no static asset under /generated/: the only machine-readable
  // artifact Relay V2 exposes is the OpenAPI document each deployment serves
  // from its own runtime, which no site deployment can vouch for.
  for (const route of [
    '/pagefind/pagefind.js',
    '/pagefind/pagefind-entry.json',
    '/sitemap-index.xml',
    '/llms.txt',
    '/index.md',
    '/dev/llms.txt',
    '/dev/index.md',
  ]) {
    await requireRoute(read, route);
  }
  return { deepRoute, releasedTag, versionPath };
}

export function parseSmokeArgs(args) {
  const parsed = { attempts: 1, deepRoute: '/start/when-to-use/' };
  while (args.length > 0) {
    const option = args.shift();
    if (option === '--root' && args[0]) parsed.root = resolve(args.shift());
    else if (option === '--url' && args[0]) parsed.url = args.shift();
    else if (option === '--released-tag' && args[0]) parsed.releasedTag = args.shift();
    else if (option === '--deep-route' && args[0]) parsed.deepRoute = args.shift();
    else if (option === '--attempts' && args[0]) parsed.attempts = Number(args.shift());
    else {
      throw new Error(
        'usage: smoke-docs-deployment.mjs (--root <dist>|--url <origin>) ' +
          '--released-tag <tag> [--deep-route <path>] [--attempts <count>]',
      );
    }
  }
  if ((!parsed.root && !parsed.url) || (parsed.root && parsed.url)) {
    throw new Error('exactly one of --root or --url is required');
  }
  if (!Number.isSafeInteger(parsed.attempts) || parsed.attempts < 1 || parsed.attempts > 20) {
    throw new Error('--attempts must be an integer from 1 through 20');
  }
  return parsed;
}

async function main(args) {
  const parsed = parseSmokeArgs([...args]);
  const read = parsed.root
    ? (pathname) => localReader(parsed.root, pathname)
    : (pathname) => liveReader(parsed.url, pathname);
  let failure;
  for (let attempt = 1; attempt <= parsed.attempts; attempt += 1) {
    try {
      const result = await smokeDocsDeployment({ ...parsed, read });
      console.log(
        `Docs smoke passed for /, ${result.deepRoute}, /dev/, ${result.versionPath}, ` +
          'Pagefind, sitemap, llms.txt, and machine-readable docs.',
      );
      return;
    } catch (error) {
      failure = error;
      if (attempt < parsed.attempts) {
        await new Promise((resolveWait) => setTimeout(resolveWait, 5_000));
      }
    }
  }
  throw failure;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
