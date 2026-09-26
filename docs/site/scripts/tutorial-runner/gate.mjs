// Plan a product's tutorial gate from what the pages declare.
//
// A page says how it is tested in its frontmatter:
//
//   tutorial_test:
//     toolset: breg                  the toolset its journey runs against
//     after: tutorials/first-breg    optional: the page a reader finishes first
//     skip: <reason>                 optional: why the page is not replayed
//     checkout: true                 optional: the journey starts at the root of
//                                    a copy of this checkout (checkout.mjs)
//
// A page with `after` continues where that page leaves the reader, so the
// gate replays the two as one journey, and replays the first page only as the
// start of the journeys that continue from it.
//
// Coverage is derived from the commands, not from a list: every page under
// start/ or tutorials/ whose sh fences run the toolset's commands must declare
// tutorial_test, and a page that declares the toolset must run its commands.
// A new tutorial therefore fails the gate on the commit that adds it, until it
// is replayed or says why not.

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import YAML from 'yaml';

import { readJourney } from './page.mjs';

const SECTIONS = ['start', 'tutorials'];
const KEYS = new Set(['toolset', 'after', 'skip', 'checkout']);

export function frontmatter(text) {
  const match = text.match(/^---\n([\s\S]*?)\n---\n/u);
  return match ? (YAML.parse(match[1]) ?? {}) : {};
}

async function readPages(docsRoot) {
  const pages = [];
  for (const section of SECTIONS) {
    let names;
    try {
      names = await readdir(join(docsRoot, section));
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw error;
    }
    for (const name of names.filter((candidate) => candidate.endsWith('.mdx')).sort()) {
      const text = await readFile(join(docsRoot, section, name), 'utf8');
      const slug = `${section}/${name.slice(0, -'.mdx'.length)}`;
      let declaration;
      try {
        declaration = frontmatter(text).tutorial_test;
      } catch (error) {
        pages.push({ slug, unreadable: error.message.split('\n')[0] });
        continue;
      }
      const { steps, errors } = readJourney(text);
      const commands = steps.filter((step) => step.code !== undefined).map((step) => step.code);
      pages.push({ slug, declaration, commands, annotationErrors: errors });
    }
  }
  return pages;
}

// Return { journeys, checkout, skipped, errors }: journeys are lists of page
// slugs, each replayed in order in one reader directory; checkout names the
// pages whose journey starts in a copy of the checkout; skipped pages carry
// their reason; errors are sentences naming a page, and a gate with any runs
// nothing. A page that names a toolset outside knownToolsets is an error, so a
// misspelt name cannot take a page out of every gate, and a page of this
// toolset has its annotations checked even when it is skipped.
export async function planGate(docsRoot, toolset, commandPattern, knownToolsets) {
  const errors = [];
  const skipped = [];
  const replayed = new Map();
  const skippedSlugs = new Set();
  const checkout = new Set();
  for (const { slug, unreadable, declaration, commands, annotationErrors } of await readPages(docsRoot)) {
    if (unreadable !== undefined) {
      errors.push(`${slug}.mdx: its frontmatter is not YAML: ${unreadable}`);
      continue;
    }
    const runs = commands.some((code) => commandPattern.test(code));
    if (declaration === undefined) {
      if (runs) {
        errors.push(
          `${slug}.mdx runs ${toolset} commands but declares no tutorial_test; add tutorial_test with toolset ${toolset}, and a skip reason if it cannot be replayed`,
        );
      }
      continue;
    }
    if (declaration === null || typeof declaration !== 'object' || Array.isArray(declaration)) {
      errors.push(`${slug}.mdx: tutorial_test is a mapping with toolset, after, skip, or checkout`);
      continue;
    }
    const unknown = Object.keys(declaration).filter((key) => !KEYS.has(key));
    for (const key of unknown) errors.push(`${slug}.mdx: unknown tutorial_test key ${key} (expected toolset, after, skip, or checkout)`);
    if (!declaration.toolset) {
      errors.push(`${slug}.mdx: tutorial_test needs a toolset`);
      continue;
    }
    if (!knownToolsets.includes(declaration.toolset)) {
      errors.push(`${slug}.mdx: unknown tutorial_test toolset ${declaration.toolset} (expected ${knownToolsets.join(' or ')})`);
      continue;
    }
    if (declaration.toolset !== toolset || unknown.length > 0) continue;
    for (const error of annotationErrors) errors.push(`${slug}.mdx: ${error}`);
    if (annotationErrors.length > 0) continue;
    if (!runs) {
      errors.push(`${slug}.mdx declares toolset ${toolset} but runs no ${toolset} commands; remove its tutorial_test`);
      continue;
    }
    if (declaration.checkout !== undefined && declaration.checkout !== true) {
      errors.push(`${slug}.mdx: tutorial_test.checkout is true or absent`);
      continue;
    }
    if (declaration.checkout) checkout.add(slug);
    if (declaration.skip !== undefined) {
      skipped.push({ slug, reason: String(declaration.skip) });
      skippedSlugs.add(slug);
    } else {
      replayed.set(slug, declaration.after);
    }
  }

  const chain = (slug) => {
    const pages = [slug];
    for (let after = replayed.get(slug); after !== undefined; after = replayed.get(after)) {
      if (pages.includes(after)) return undefined;
      pages.unshift(after);
    }
    return pages;
  };
  const continued = new Set();
  for (const [slug, after] of replayed) {
    if (after === undefined) continue;
    if (skippedSlugs.has(after)) errors.push(`${slug}.mdx: tutorial_test.after names ${after}, which is skipped`);
    else if (!replayed.has(after)) {
      errors.push(`${slug}.mdx: tutorial_test.after names ${after}, which no page under start/ or tutorials/ replays with ${toolset}`);
    } else if (chain(slug) === undefined) errors.push(`${slug}.mdx: tutorial_test.after leads back to itself`);
    else if (checkout.has(slug)) {
      errors.push(`${slug}.mdx: tutorial_test.checkout belongs on ${chain(slug)[0]}, where the journey starts`);
    }
    continued.add(after);
  }
  const journeys = errors.length > 0 ? [] : [...replayed.keys()].filter((slug) => !continued.has(slug)).sort().map(chain);
  return { journeys, checkout: journeys.map((journey) => journey[0]).filter((slug) => checkout.has(slug)), skipped, errors: errors.sort() };
}
