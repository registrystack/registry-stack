/**
 * @typedef {NonNullable<import('@astrojs/starlight/types').StarlightUserConfig['sidebar']>} SidebarConfig
 */

/**
 * Keep generated product pages in source order without adding category
 * disclosures inside the reference menu. Return the original leaves so their
 * destinations and any additional navigation metadata stay intact.
 *
 * @param {SidebarConfig} items
 * @returns {SidebarConfig}
 */
export function flattenSidebarGroups(items) {
  return items.flatMap((item) => typeof item === 'object' && 'items' in item
    ? flattenSidebarGroups(item.items)
    : [item]);
}

/**
 * @typedef {import('@astrojs/starlight/route-data').StarlightRouteData['sidebar']} Sidebar
 */

/** @param {Sidebar} entries @returns {Sidebar} */
function sidebarLinks(entries) {
  return entries.flatMap((entry) => entry.type === 'group' ? sidebarLinks(entry.entries) : [entry]);
}

/**
 * Retain a section and one subgroup, including for plugin-generated APIs.
 * Links keep their current-page state, badges, and attributes.
 *
 * @param {Sidebar} entries
 * @param {number} depth
 * @returns {Sidebar}
 */
export function limitSidebarDepth(entries, depth = 1) {
  return entries.map((entry) => entry.type === 'group'
    ? { ...entry, entries: depth >= 2 ? sidebarLinks(entry.entries) : limitSidebarDepth(entry.entries, depth + 1) }
    : entry);
}
