import { baseAwareHref } from './base-aware-href.mjs';

// The prerequisites a QuickstartMeta strip lists. Each is a plain label, or
// `{ label, href }` naming the page that covers it: a site path such as
// `/tutorials/first-breg/`, resolved against the site base, or an external URL.
// A missing or non-array value lists nothing; an MDX author can pass null by
// mistake, and the component's default only guards the omitted case.
export function prerequisiteItems(prerequisites, base) {
  if (!Array.isArray(prerequisites)) return [];
  return prerequisites.map((item) => {
    if (typeof item === 'string') return { label: item };
    if (!item?.label) throw new Error(`a linked prerequisite needs a label: ${JSON.stringify(item)}`);
    return { label: item.label, href: baseAwareHref(item.href, base) };
  });
}
