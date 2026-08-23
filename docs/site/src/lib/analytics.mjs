export const DOCS_UMAMI_WEBSITE_ID = '0a8aa090-83c5-4207-8c90-9fcc1e50bb78';
export const DOCS_UMAMI_SCRIPT_SRC = 'https://stats.registrystack.org/script.js';
export const DOCS_UMAMI_DOMAINS = 'docs.registrystack.org';

function configuredValue(value, fallback) {
  return value?.trim() || fallback;
}

/**
 * @param {{
 *   enabled?: boolean,
 *   websiteId?: string,
 *   scriptSrc?: string,
 *   domains?: string,
 * }} [options]
 */
export function docsAnalyticsConfig({
  enabled = false,
  websiteId,
  scriptSrc,
  domains,
} = {}) {
  if (!enabled) return null;

  return {
    websiteId: configuredValue(websiteId, DOCS_UMAMI_WEBSITE_ID),
    scriptSrc: configuredValue(scriptSrc, DOCS_UMAMI_SCRIPT_SRC),
    domains: configuredValue(domains, DOCS_UMAMI_DOMAINS),
  };
}
