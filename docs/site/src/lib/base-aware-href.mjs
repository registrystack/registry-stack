export function baseAwareHref(href, baseUrl = '/') {
  if (!href.startsWith('/') || href.startsWith('//')) return href;

  const base = baseUrl === '/' ? '' : baseUrl.replace(/\/$/, '');
  return `${base}${href}`;
}
