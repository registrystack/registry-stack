// Plan a product's tutorial gate from what the pages declare.
//
// A page says how it is tested in its frontmatter:
//
//   tutorial_test:
//     toolset: breg                  the toolset its journey runs against
//     after: tutorials/first-breg    optional: the page a reader finishes first
//     skip: <reason>                 optional: why the page is not replayed
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
const KEYS = new Set(['toolset', 'after', 'skip']);

function frontmatter(text) {
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
      const commands = readJourney(text)
        .steps.filter((step) => step.code !== undefined)
        .map((step) => step.code);
      pages.push({ slug: `${section}/${name.slice(0, -'.mdx'.length)}`, declaration: frontmatter(text).tutorial_test, commands });
    }
  }
  return pages;
}

// Return { journeys, skipped, errors }: journeys are lists of page slugs, each
// replayed in order in one reader directory; skipped pages carry their reason;
// errors are sentences naming a page, and a gate with any runs nothing.
export async function planGate(docsRoot, toolset, commandPattern) {
  const errors = [];
  const skipped = [];
  const replayed = new Map();
  const skippedSlugs = new Set();
  for (const { slug, declaration, commands } of await readPages(docsRoot)) {
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
      errors.push(`${slug}.mdx: tutorial_test is a mapping with toolset, after, or skip`);
      continue;
    }
    const unknown = Object.keys(declaration).filter((key) => !KEYS.has(key));
    for (const key of unknown) errors.push(`${slug}.mdx: unknown tutorial_test key ${key} (expected toolset, after, or skip)`);
    if (!declaration.toolset) {
      errors.push(`${slug}.mdx: tutorial_test needs a toolset`);
      continue;
    }
    if (declaration.toolset !== toolset || unknown.length > 0) continue;
    if (!runs) {
      errors.push(`${slug}.mdx declares toolset ${toolset} but runs no ${toolset} commands; remove its tutorial_test`);
      continue;
    }
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
    continued.add(after);
  }
  const journeys = errors.length > 0 ? [] : [...replayed.keys()].filter((slug) => !continued.has(slug)).sort().map(chain);
  return { journeys, skipped, errors: errors.sort() };
}
