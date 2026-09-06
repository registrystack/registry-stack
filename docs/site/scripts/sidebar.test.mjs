import assert from 'node:assert/strict';
import { test } from 'node:test';
import { flattenSidebarGroups } from '../src/lib/sidebar.mjs';
import { onRequest } from '../src/sidebar-middleware.mjs';

test('flattens generated categories without losing page order or link metadata', () => {
  const overview = { label: 'Overview', slug: 'products/example' };
  const guide = { label: 'Guide', slug: 'products/example/guide', badge: 'New' };
  const reference = { label: 'Reference', link: '/products/example/reference/', attrs: { lang: 'en' } };
  const items = [overview, {
    label: 'Guides',
    items: [guide, { label: 'Reference', items: [reference] }, { label: 'Empty', items: [] }],
  }];
  const original = structuredClone(items);

  const result = flattenSidebarGroups(items);

  assert.deepEqual(result, [overview, guide, reference]);
  assert.equal(result[1], guide);
  assert.equal(result[2], reference);
  assert.deepEqual(items, original);
  assert.deepEqual(flattenSidebarGroups([]), []);
});

test('flattens API groups after plugin middleware while retaining active links and metadata', async () => {
  const operation = {
    type: 'link', label: '/assertions', href: '/reference/apis/evidence/operations/assert/',
    isCurrent: true, badge: { text: 'POST', variant: 'success' }, attrs: { class: 'operation' },
  };
  const overview = { type: 'link', label: 'Overview', href: '/reference/apis/evidence/', isCurrent: false, attrs: {} };
  const group = (label, entries) => ({ type: 'group', label, collapsed: true, entries });
  const sidebar = [group('Evidence Gateway', [group('API operations', [
    overview, group('Operations', [group('Assertions', [operation])]),
  ])])];
  const original = structuredClone(sidebar);
  const context = { locals: { starlightRoute: { sidebar: [] } } };

  await onRequest(context, async () => {
    context.locals.starlightRoute.sidebar = sidebar;
  });

  assert.deepEqual(context.locals.starlightRoute.sidebar, [
    group('Evidence Gateway', [group('API operations', [overview, operation])]),
  ]);
  assert.equal(context.locals.starlightRoute.sidebar[0].entries[0].entries[1], operation);
  assert.deepEqual(sidebar, original);
});
