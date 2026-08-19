import { readFile, stat } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';

import { parse } from 'parse5';

const distDir = resolve(process.env.DOCS_DIST_DIR || 'dist');
const interactiveRoles = new Set([
  'button', 'checkbox', 'combobox', 'link', 'listbox', 'menuitem', 'menuitemcheckbox',
  'menuitemradio', 'option', 'radio', 'searchbox', 'switch', 'tab', 'textbox', 'treeitem',
]);
const criticalPaths = [
  'index.html',
  'start/when-to-use/index.html',
  'tutorials/publish-governed-sqlite-registry/index.html',
  'verify/index.html',
  'generated-artifacts/index.html',
  'operate/index.html',
];
const optionalCriticalPaths = [];

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function attributes(node) {
  return new Map((node.attrs ?? []).map(({ name, value }) => [name.toLowerCase(), value]));
}

function hasText(node) {
  if (node.nodeName === '#text') return node.value.trim().length > 0;
  const attrs = attributes(node);
  if (attrs.get('aria-hidden') === 'true') return false;
  return (node.childNodes ?? []).some(hasText);
}

function nodes(root) {
  const found = [];
  function visit(node, parent = null) {
    if (node.tagName) found.push({ node, parent, attrs: attributes(node) });
    for (const child of node.childNodes ?? []) visit(child, node);
  }
  visit(root);
  return found;
}

function isMain({ node, attrs }) {
  return node.tagName === 'main' || attrs.get('role') === 'main';
}

function isInteractive({ node, attrs }) {
  if (attrs.has('disabled')) return false;
  if (interactiveRoles.has(attrs.get('role'))) return true;
  if (attrs.has('contenteditable')) return true;
  if (node.tagName === 'a') return attrs.has('href');
  if (node.tagName === 'button' || node.tagName === 'select' || node.tagName === 'textarea') return true;
  return node.tagName === 'input' && attrs.get('type')?.toLowerCase() !== 'hidden';
}

function isDescendant(node, ancestor) {
  for (let current = node.parentNode; current; current = current.parentNode) {
    if (current === ancestor) return true;
  }
  return false;
}

function hasAccessibleName(entry, allNodes, ids) {
  const { node, attrs } = entry;
  if (attrs.get('aria-label')?.trim()) return true;

  const labelledBy = attrs.get('aria-labelledby')?.trim();
  if (labelledBy) {
    const references = labelledBy.split(/\s+/).map((id) => ids.get(id));
    if (references.length && references.every(Boolean) && references.some(hasText)) return true;
  }

  if (attrs.get('title')?.trim()) return true;
  if (node.tagName === 'input') {
    const type = attrs.get('type')?.toLowerCase();
    if (['button', 'image', 'reset', 'submit'].includes(type) && attrs.get('value')?.trim()) return true;
  }

  if (hasText(node)) return true;

  const id = attrs.get('id');
  if (id && allNodes.some(({ node: label, attrs: labelAttrs }) =>
    label.tagName === 'label' && labelAttrs.get('for') === id && hasText(label),
  )) return true;

  return allNodes.some(({ node: label }) => label.tagName === 'label' && isDescendant(node, label) && hasText(label));
}

function checkPage(html, file) {
  const document = parse(html);
  const allNodes = nodes(document);
  const errors = [];
  if (allNodes.some(({ node, attrs }) =>
    node.tagName === 'meta' && attrs.get('http-equiv')?.toLowerCase() === 'refresh',
  )) return errors;
  const htmlElement = allNodes.find(({ node }) => node.tagName === 'html');
  if (!htmlElement?.attrs.get('lang')?.trim()) {
    errors.push(`${file} is missing a nonempty html lang attribute`);
  }

  const ids = new Map();
  for (const entry of allNodes) {
    const id = entry.attrs.get('id');
    if (id !== undefined) {
      if (ids.has(id)) errors.push(`${file} has duplicate id "${id}"`);
      else ids.set(id, entry.node);
    }
    const tabindex = entry.attrs.get('tabindex');
    if (tabindex && Number(tabindex) > 0) errors.push(`${file} has positive tabindex "${tabindex}"`);
  }

  const mains = allNodes.filter(isMain);
  if (mains.length !== 1) errors.push(`${file} must have exactly one main landmark (found ${mains.length})`);
  if (mains.length === 1) {
    const headings = allNodes.filter(({ node }) => node.tagName === 'h1' && isDescendant(node, mains[0].node));
    if (headings.length !== 1) errors.push(`${file} must have exactly one h1 in main (found ${headings.length})`);
  }

  for (const entry of allNodes) {
    if (entry.node.tagName === 'img') {
      const alt = entry.attrs.get('alt');
      const presentational = alt === '' || entry.attrs.get('role') === 'presentation' ||
        entry.attrs.get('role') === 'none' || entry.attrs.get('aria-hidden') === 'true';
      if (!presentational && !alt?.trim()) errors.push(`${file} image is missing nonempty alt text`);
    }
    if (isInteractive(entry) && !hasAccessibleName(entry, allNodes, ids)) {
      errors.push(`${file} interactive <${entry.node.tagName}> is missing an accessible name`);
    }
  }
  return errors;
}

const requiredFiles = criticalPaths.map((path) => join(distDir, path));
const optionalFiles = (await Promise.all(optionalCriticalPaths.map(async (path) => {
  const file = join(distDir, path);
  return await exists(file) ? file : null;
}))).filter(Boolean);
const errors = [];
for (const file of requiredFiles) {
  if (!await exists(file)) errors.push(`Critical-path page is missing: ${relative('.', file)}`);
}
for (const file of [...requiredFiles, ...optionalFiles]) {
  if (await exists(file)) errors.push(...checkPage(await readFile(file, 'utf8'), relative('.', file)));
}

if (errors.length) {
  console.error(`Built static accessibility gate failed:\n${errors.join('\n')}`);
  process.exit(1);
}

console.log(
  `Built static critical-path accessibility gate passed: ${requiredFiles.length + optionalFiles.length} HTML pages checked. This is not a full-site axe or human accessibility audit.`,
);
