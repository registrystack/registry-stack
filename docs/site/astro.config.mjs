// @ts-check
import { readFileSync } from 'node:fs';
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';
import starlightOpenAPI, { createOpenAPISidebarGroup } from 'starlight-openapi';
import mermaid from 'astro-mermaid';
import remarkGfm from 'remark-gfm';
// Single source of truth for the machine-discovery pointer. Reused as the
// llms.txt `details` block so it can never drift from the header the per-page
// .md endpoint prepends (src/pages/[...slug].md.ts).
import { discoveryHeaderForBase } from './src/lib/page-markdown.ts';
import { cliReferenceSidebar } from './src/lib/cli-reference-sidebar.mjs';
import { flattenSidebarGroups } from './src/lib/sidebar.mjs';
import { buildNotaryRetirementRedirects } from './src/lib/notary-retirement-redirects.mjs';
import { buildRelayRetirementRedirects } from './src/lib/relay-retirement-redirects.mjs';
import { docsetPublishesBregOpenApi, docsetPublishesEvidenceOid4vciOpenApi } from './scripts/fetch-openapi.mjs';
import { omittedCliBinaries, productRoutes, remarkDocsetProducts } from './src/lib/docset-products.mjs';

// Marketing site that now owns the persuasion layer (the pitch). Old docs
// routes that migrated there redirect to these pages.
const marketing = 'https://registrystack.org';

// Product navigation is generated from src/data/repo-docs.yaml by
// scripts/generate-sidebar.mjs (run via `npm run generate`), so the menu is
// derived from the manifest's doc_type/nav_order and never drifts from it.
// Read it resiliently: a missing file (astro run without generating first)
// warns loudly and falls back to an empty product nav rather than failing the
// whole config; malformed JSON still throws.
function loadProductSidebar() {
  const path = new URL('./src/data/generated/sidebar.json', import.meta.url);
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      console.warn(
        '[sidebar] src/data/generated/sidebar.json missing; run `npm run generate`. Product nav will be empty.',
      );
      return [];
    }
    throw error;
  }
}

function loadDocsetsManifest() {
  const path = new URL('./src/data/generated/docsets.json', import.meta.url);
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * @param {{ current: string, released: string, docsets: Array<{ id: string, status: string, availability: string, path: string, products?: Record<string, unknown> }> }} docsets
 * @param {NodeJS.ProcessEnv} env
 */
export function resolveDocsetBuildContext(docsets, env = process.env) {
  const selectedId = env.DOCS_DOCSET || docsets.current;
  const selectedDocset = docsets.docsets.find((entry) => entry.id === selectedId);
  if (!selectedDocset) throw new Error(`selected docs docset "${selectedId}" not found`);

  const base = env.DOCS_BASE || undefined;
  const basePath = base?.replace(/\/$/, '');
  const isArchivedBuild = selectedDocset.status === 'archived';
  const isReleasedArchiveBuild =
    isArchivedBuild && env.DOCS_RELEASED_ARCHIVE === 'true';
  const isHistoricalArchiveBuild =
    isArchivedBuild && !isReleasedArchiveBuild && selectedDocset.id !== docsets.released;
  const isSearchExcludedBuild =
    isHistoricalArchiveBuild || selectedDocset.availability === 'unreleased';
  const hasCasework = Boolean(selectedDocset.products?.['registry-casework']);
  const hasScheduling = Boolean(selectedDocset.products?.['registry-scheduling']);
  const hasRender = Boolean(selectedDocset.products?.['registry-render']);
  const hasMessaging = Boolean(selectedDocset.products?.['registry-messaging']);
  const hasBregServices = Boolean(selectedDocset.products?.['registry-breg-services']);
  const hasCoordinator = Boolean(selectedDocset.products?.['registry-coordinator']);
  const currentDocset = docsets.docsets.find((entry) => entry.id === docsets.current);
  if (!currentDocset) throw new Error(`current docs docset "${docsets.current}" not found`);
  const currentHasMessaging = Boolean(currentDocset.products?.['registry-messaging']);
  const currentHasCoordinator = Boolean(currentDocset.products?.['registry-coordinator']);
  /** @param {string} path */
  const internalRedirect = (path) => basePath ? `${basePath}${path}` : path;
  /** @param {string} path */
  const currentDocsetRedirect = (path) =>
    isArchivedBuild
      ? `https://docs.registrystack.org${currentDocset.path.replace(/\/$/, '')}${path}`
      : internalRedirect(path);

  return {
    base,
    basePath,
    isArchivedBuild,
    isReleasedArchiveBuild,
    isHistoricalArchiveBuild,
    isSearchExcludedBuild,
    hasCasework,
    hasScheduling,
    hasRender,
    hasMessaging,
    hasBregServices,
    hasCoordinator,
    currentHasMessaging,
    currentHasCoordinator,
    selectedDocset,
    internalRedirect,
    currentDocsetRedirect,
  };
}

const docsetsManifest = loadDocsetsManifest();
const {
  base,
  isHistoricalArchiveBuild,
  isSearchExcludedBuild,
  hasCasework,
  hasScheduling,
  hasRender,
  hasMessaging,
  hasBregServices,
  hasCoordinator,
  currentHasMessaging,
  currentHasCoordinator,
  selectedDocset,
  internalRedirect,
  currentDocsetRedirect,
} = resolveDocsetBuildContext(docsetsManifest);
const hasBregOpenApi = docsetPublishesBregOpenApi(selectedDocset, docsetsManifest.current);
const hasEvidenceOid4vciOpenApi = docsetPublishesEvidenceOid4vciOpenApi(selectedDocset, docsetsManifest.current);
const productSidebar = loadProductSidebar();

// Lift a generated per-product group to the top level of the sidebar.
// Fails the build loudly if the generator's labels change, so the nav can
// never silently lose a product section.
/** @param {string} label */
function generatedProduct(label) {
  const group = productSidebar.find((/** @type {{ label: string }} */ entry) => entry.label === label);
  if (!group) throw new Error(`generated sidebar group "${label}" not found`);
  return group;
}

// A product absent from this docset's generated sidebar (a product newer than
// an archived docset) yields no group instead of failing the build.
/** @param {string} label */
function optionalGeneratedProduct(label) {
  return productSidebar.find((/** @type {{ label: string }} */ entry) => entry.label === label) ?? null;
}
const disabledSitemap = {
  name: '@astrojs/sitemap',
  hooks: {},
};
// Each product's operations fill their own createOpenAPISidebarGroup()
// placeholder, seated in that product's group. The plugin's shared
// openAPISidebarGroups placeholder receives every schema without a group, so
// a seat for it would show every product's operations under one product.
const evidenceOpenApiSidebarGroup = createOpenAPISidebarGroup();
const evidenceOpenApiSchema = {
  base: 'reference/apis/evidence',
  schema: './openapi/registry-evidence.render.openapi.json',
  sidebar: {
    group: evidenceOpenApiSidebarGroup,
    label: 'API operations',
    collapsed: true,
    operations: { labels: /** @type {'path'} */ ('path'), badges: true },
  },
};
// The wallet-facing OID4VCI supporting service publishes its own document.
// scripts/fetch-openapi.mjs fetches it for the current docset and release
// docsets from v0.20.0, and the same test decides whether this build renders it.
const evidenceOid4vciOpenApiSidebarGroup = createOpenAPISidebarGroup();
const evidenceOid4vciOpenApiSchema = {
  base: 'reference/apis/evidence-oid4vci',
  schema: './openapi/registry-evidence-oid4vci.render.openapi.json',
  sidebar: {
    group: evidenceOid4vciOpenApiSidebarGroup,
    label: 'API operations (wallet delivery)',
    collapsed: true,
    operations: { labels: /** @type {'path'} */ ('path'), badges: true },
  },
};
const caseworkOpenApiSidebarGroup = createOpenAPISidebarGroup();
const caseworkOpenApiSchema = {
  base: 'reference/apis/casework',
  schema: './openapi/registry-casework.render.openapi.json',
  sidebar: {
    group: caseworkOpenApiSidebarGroup,
    label: 'API operations',
    collapsed: true,
    operations: { labels: /** @type {'path'} */ ('path'), badges: true },
  },
};
const schedulingOpenApiSidebarGroup = createOpenAPISidebarGroup();
const schedulingOpenApiSchema = {
  base: 'reference/apis/scheduling',
  schema: './openapi/registry-scheduling.render.openapi.json',
  sidebar: {
    group: schedulingOpenApiSidebarGroup,
    label: 'API operations',
    collapsed: true,
    operations: { labels: /** @type {'path'} */ ('path'), badges: true },
  },
};
// The Scheduling and Render pages are gated out of the docs collection of a
// docset that does not publish the product (src/lib/docset-products.mjs), so
// their routes and Markdown twins redirect to the current docset, which
// publishes both.
const schedulingRoutes = productRoutes('registry-scheduling');
/**
 * @param {boolean} hasScheduling
 * @param {(path: string) => string} currentDocsetRedirect
 */
export function schedulingRedirects(hasScheduling, currentDocsetRedirect) {
  if (hasScheduling) return {};
  return Object.fromEntries(schedulingRoutes.flatMap((route) => [
    [route, currentDocsetRedirect(route)],
    [`${route.slice(0, -1)}.md`, currentDocsetRedirect(route)],
  ]));
}
const renderRoutes = productRoutes('registry-render');
/**
 * @param {boolean} hasRender
 * @param {(path: string) => string} currentDocsetRedirect
 */
export function renderRedirects(hasRender, currentDocsetRedirect) {
  if (hasRender) return {};
  return Object.fromEntries(renderRoutes.flatMap((route) => [
    [route, currentDocsetRedirect(route)],
    [`${route.slice(0, -1)}.md`, currentDocsetRedirect(route)],
  ]));
}
const messagingOpenApiSidebarGroup = createOpenAPISidebarGroup();
const messagingOpenApiSchema = {
  base: 'reference/apis/messaging',
  schema: './openapi/registry-messaging.render.openapi.json',
  sidebar: {
    group: messagingOpenApiSidebarGroup,
    label: 'API operations',
    collapsed: true,
    operations: { labels: /** @type {'path'} */ ('path'), badges: true },
  },
};
// The Messaging pages are gated out of the docs collection of a docset that
// does not publish Messaging (src/lib/docset-products.mjs), so their routes
// redirect instead. While the current docset does not publish Messaging
// either, there is no Messaging page to send a reader to, so every route lands
// on the current docset's home page rather than on itself.
const messagingRoutes = productRoutes('registry-messaging');
/**
 * @param {boolean} hasMessaging
 * @param {boolean} currentHasMessaging
 * @param {(path: string) => string} currentDocsetRedirect
 */
export function messagingRedirects(hasMessaging, currentHasMessaging, currentDocsetRedirect) {
  if (hasMessaging) return {};
  return Object.fromEntries(messagingRoutes.flatMap((route) => {
    const target = currentDocsetRedirect(currentHasMessaging ? route : '/');
    return [
      [route, target],
      [`${route.slice(0, -1)}.md`, target],
    ];
  }));
}
// A registry's API is compiled from its project, so the site renders the
// facility template's compiled document as an example. scripts/fetch-openapi.mjs
// fetches it for the current docset and release docsets from v0.42.0, and the
// same test decides whether this build renders it.
const bregOpenApiSidebarGroup = createOpenAPISidebarGroup();
const bregOpenApiSchema = {
  base: 'reference/apis/breg',
  schema: './openapi/registry-breg.render.openapi.json',
  sidebar: {
    group: bregOpenApiSidebarGroup,
    label: 'API operations (facility template)',
    collapsed: true,
    operations: { labels: /** @type {'path'} */ ('path'), badges: true },
  },
};
const coordinatorOpenApiSidebarGroup = createOpenAPISidebarGroup();
const coordinatorOpenApiSchema = {
  base: 'reference/apis/coordinator',
  schema: './openapi/registry-coordinator.render.openapi.json',
  sidebar: {
    group: coordinatorOpenApiSidebarGroup,
    label: 'API operations',
    collapsed: true,
    operations: { labels: /** @type {'path'} */ ('path'), badges: true },
  },
};
// The Coordinator pages follow the Messaging rule: a docset that does not
// publish the Coordinator gates its pages out and redirects their routes, to
// the same route of the current docset when that docset publishes the
// Coordinator and to its home page otherwise.
const coordinatorRoutes = productRoutes('registry-coordinator');
/**
 * @param {boolean} hasCoordinator
 * @param {boolean} currentHasCoordinator
 * @param {(path: string) => string} currentDocsetRedirect
 */
export function coordinatorRedirects(hasCoordinator, currentHasCoordinator, currentDocsetRedirect) {
  if (hasCoordinator) return {};
  return Object.fromEntries(coordinatorRoutes.flatMap((route) => {
    const target = currentDocsetRedirect(currentHasCoordinator ? route : '/');
    return [
      [route, target],
      [`${route.slice(0, -1)}.md`, target],
    ];
  }));
}
const caseworkRoutes = [
  '/start/casework/',
  '/tutorials/first-casework/',
  '/tutorials/review-breg-changes-in-casework/',
  '/explanation/how-casework-works/',
  '/configure/casework/',
  '/configure/casework-directory/',
  '/operate/casework/',
  '/operate/change-a-casework-package/',
  '/operate/casework-retention/',
  '/reference/apis/registry-casework/',
];

/**
 * @param {boolean} hasCasework
 * @param {(path: string) => string} currentDocsetRedirect
 */
export function caseworkRedirects(hasCasework, currentDocsetRedirect) {
  if (hasCasework) return {};
  return Object.fromEntries(caseworkRoutes.flatMap((route) => [
    [route, currentDocsetRedirect(route)],
    [`${route.slice(0, -1)}.md`, currentDocsetRedirect(route)],
  ]));
}

// The Base Registry Engine docs rewrite moved or folded these pages into the
// pages that now carry their content. The Actions page is named after what it
// declares, and field encryption is a thing an author does to a project, so
// both sit in the Author group.
const bregRewriteMoves = [
  ['/configure/breg-change-control/', '/configure/breg-actions/'],
  ['/explanation/breg-field-encryption/', '/configure/breg-field-encryption/'],
  ['/tutorials/review-registry-changes/', '/tutorials/change-a-registry-with-an-action/'],
  ['/tutorials/build-a-breg-production-candidate/', '/operate/breg/'],
  ['/tutorials/first-citizen-mcp/', '/configure/breg-mcp/'],
  ['/tutorials/deploy-evidence-from-breg/', '/tutorials/evidence-from-breg/'],
  ['/explanation/governed-registry-actions/', '/configure/breg-actions/'],
  ['/explanation/native-field-patterns/', '/explanation/registry-modeling-patterns/'],
  ['/explanation/breg-statistical-datasets/', '/configure/breg-statistics/'],
  ['/explanation/membership-read-boundaries/', '/configure/breg-access/'],
  ['/explanation/deriving-a-registry-from-a-model/', '/tutorials/derive-a-registry-from-publicschema/'],
  ['/explanation/openfn-adaptors/', '/start/concepts/'],
  ['/operate/breg-requirements/', '/operate/breg/'],
  ['/operate/breg-mcp/', '/configure/breg-mcp/'],
];

/**
 * @param {(path: string) => string} internalRedirect
 */
export function bregRewriteRedirects(internalRedirect) {
  return Object.fromEntries(bregRewriteMoves.flatMap(([route, target]) => [
    [route, internalRedirect(target)],
    [`${route.slice(0, -1)}.md`, internalRedirect(target)],
  ]));
}

export default defineConfig({
  site: 'https://docs.registrystack.org',
  base,
  trailingSlash: 'always',
  markdown: {
    // remarkDocsetProducts keeps or removes the <DocsetProduct> regions of
    // shared MDX pages for the products this docset publishes.
    remarkPlugins: [remarkGfm, remarkDocsetProducts(selectedDocset)],
  },
  // Redirects for content that moved in the docs/marketing split (Wave 4).
  // External redirects (to marketing) absorb the migrated persuasion pages;
  // internal redirects map the retired /projects/* and /capabilities/* routes
  // to their new homes so old links and search results keep resolving.
  redirects: {
    ...buildNotaryRetirementRedirects(currentDocsetRedirect),
    ...buildRelayRetirementRedirects(currentDocsetRedirect),
    ...caseworkRedirects(hasCasework, currentDocsetRedirect),
    ...schedulingRedirects(hasScheduling, currentDocsetRedirect),
    ...renderRedirects(hasRender, currentDocsetRedirect),
    ...messagingRedirects(hasMessaging, currentHasMessaging, currentDocsetRedirect),
    ...coordinatorRedirects(hasCoordinator, currentHasCoordinator, currentDocsetRedirect),
    '/start/': internalRedirect('/'),
    '/start/see-it-live/': internalRedirect('/'),
    '/explanation/publishing-pipeline/': internalRedirect('/products/registry-manifest/'),
    // Retired product choosers. The homepage chooses between the products, so
    // both the second chooser and the one that outlived it land there.
    '/start/quickstart/': internalRedirect('/'),
    '/start/when-to-use/': internalRedirect('/'),
    '/explanation/trust-posture-and-security-guarantees/': internalRedirect('/security/'),
    '/reference/security-self-assessment/': internalRedirect('/security/self-assessment/'),
    '/reference/openssf-evidence/': internalRedirect('/security/openssf-evidence/'),
    // Webhook binding is an operator task with its own page; history reads
    // and the event reference are sections of the API reference page.
    '/configure/breg-webhooks/': internalRedirect('/operate/breg-webhooks/'),
    '/reference/breg-history/': internalRedirect('/reference/breg-api/'),
    '/reference/breg-events/': internalRedirect('/reference/breg-api/'),
    // The operating-requirements pages moved from Start into each product's
    // Deploy group; a first visit chooses a product before it plans a deployment.
    // Evidence's requirements page was then absorbed by the one page that
    // explains how the product works, and the refusal tutorial was folded
    // into the access-control tutorial that follows it.
    '/start/evaluate-evidence/': internalRedirect('/explanation/how-evidence-works/'),
    '/operate/evidence-requirements/': internalRedirect('/explanation/how-evidence-works/'),
    '/operate/evidence-requirements.md': internalRedirect('/explanation/how-evidence-works/'),
    '/tutorials/refuse-unsafe-evidence-requests/': internalRedirect('/tutorials/control-who-can-request-evidence/'),
    '/tutorials/refuse-unsafe-evidence-requests.md': internalRedirect('/tutorials/control-who-can-request-evidence/'),
    // The deployment-configuration page and the evidencectl workflow page
    // were absorbed by the build-and-deploy tutorial and the generated CLI
    // reference: the tool introduces each noun once, where it is used.
    '/configure/evidence/': internalRedirect('/tutorials/build-and-deploy-evidence-project/'),
    '/configure/evidence.md': internalRedirect('/tutorials/build-and-deploy-evidence-project/'),
    '/reference/evidencectl/': internalRedirect('/reference/cli/evidencectl/'),
    '/reference/evidencectl.md': internalRedirect('/reference/cli/evidencectl/'),
    '/start/evaluate-breg/': internalRedirect('/operate/breg/'),
    ...bregRewriteRedirects(internalRedirect),
    // One client package documents the retained namespaces in one reference.
    '/reference/breg-client-api/': internalRedirect('/reference/client-api/'),
    // The deprecation rules are a section of the one stability promise page.
    '/reference/deprecation-policy/': internalRedirect('/reference/api-stability/'),
    '/reference/deprecation-policy.md': internalRedirect('/reference/api-stability/'),
    // Retired pages keep old links useful by sending readers to a supported
    // task or reference page.
    '/journeys/': internalRedirect('/'),
    '/journeys/spreadsheet-protected-api/': internalRedirect('/decisions/registry-relay-retirement-2026-10-03/'),
    '/journeys/instance-openapi/': internalRedirect('/reference/apis/'),
    '/journeys/bounded-http/': internalRedirect('/decisions/registry-relay-retirement-2026-10-03/'),
    '/journeys/bounded-multi-call-script/': internalRedirect('/decisions/registry-relay-retirement-2026-10-03/'),
    '/journeys/exact-snapshot/': internalRedirect('/decisions/registry-relay-retirement-2026-10-03/'),
    '/journeys/product-input-lifecycle/': internalRedirect('/decisions/registry-relay-retirement-2026-10-03/'),
    // Retired first-call and source-review routes enter the supported local path.
    '/start/your-first-call/': internalRedirect('/decisions/registry-relay-retirement-2026-10-03/'),
    '/start/test-current-source-revision/': internalRedirect('/'),
    // Retired lab tutorials land on the homepage or the Relay retirement record.
    '/tutorials/first-run-with-registry-lab/': internalRedirect('/'),
    '/tutorials/query-a-spatial-registry-from-qgis/': internalRedirect('/start/breg-quickstart/'),
    '/tutorials/review-a-dhis2-evidence-source/': internalRedirect('/tutorials/connect-an-institution-source/'),
    // The FHIR credential tutorial became the worked example of connecting an institution API.
    '/tutorials/issue-fhir-evidence-as-vcs/': internalRedirect('/tutorials/connect-an-institution-source/'),
    '/tutorials/issue-fhir-evidence-as-vcs.md': internalRedirect('/tutorials/connect-an-institution-source/'),
    // The wallet interoperability checks are one section of the wallet delivery page.
    '/tutorials/run-oid4vci-interoperability-checks/': internalRedirect('/configure/evidence-oid4vci/'),
    '/tutorials/run-oid4vci-interoperability-checks.md': internalRedirect('/configure/evidence-oid4vci/'),
    // Disclosure modes and computed answers are one section of How Evidence works.
    '/explanation/disclosure-modes-and-computed-answers/': internalRedirect('/explanation/how-evidence-works/'),
    '/explanation/disclosure-modes-and-computed-answers.md': internalRedirect('/explanation/how-evidence-works/'),
    // Retired monorepo lab tutorials and the integration-patterns page redirect to
    // the cross-product concepts page.
    '/explanation/integration-patterns/': internalRedirect('/start/concepts/'),
    '/explanation/integration-patterns.md': internalRedirect('/start/concepts/'),
    '/tutorials/configure-project-fhir-r4/': internalRedirect('/start/concepts/'),
    '/tutorials/configure-project-snapshot-materialization/': internalRedirect('/decisions/registry-relay-retirement-2026-10-03/'),
    // Problems -> marketing /why
    '/problems/': `${marketing}/why/`,
    '/problems/existing-data-not-service-ready/': `${marketing}/why/`,
    '/problems/apis-over-share-records/': `${marketing}/why/`,
    '/problems/safeguards-need-technical-enforcement/': `${marketing}/why/`,
    '/problems/one-off-integrations/': `${marketing}/why/`,
    '/problems/registry-capabilities-hard-to-discover/': `${marketing}/why/`,
    '/problems/semantics-do-not-line-up/': `${marketing}/why/`,
    '/problems/entity-identity-and-matching/': `${marketing}/why/`,
    // Use cases -> marketing /use-cases
    '/use-cases/': `${marketing}/use-cases/`,
    '/use-cases/business-registry-status/': `${marketing}/use-cases/`,
    '/use-cases/eligibility-or-entitlement-evidence/': `${marketing}/use-cases/`,
    '/use-cases/legacy-registry-api/': `${marketing}/use-cases/`,
    '/use-cases/publish-registry-metadata/': `${marketing}/use-cases/`,
    '/use-cases/inspect-before-integrating/': `${marketing}/use-cases/`,
    // Ecosystem positioning -> marketing /ecosystem
    '/ecosystem/': `${marketing}/ecosystem/`,
    // Why now -> marketing /why-now
    '/start/safer-registry-surfaces/': `${marketing}/why-now/`,
    // Capabilities taxonomy -> the Explanation pages that absorbed it (internal)
    '/capabilities/': internalRedirect('/explanation/architecture/'),
    '/capabilities/describe-registries/': internalRedirect('/explanation/architecture/'),
    '/capabilities/expose-protected-apis/': internalRedirect('/explanation/architecture/'),
    '/capabilities/certify-evidence/': internalRedirect('/explanation/architecture/'),
    '/capabilities/audit-and-operate/': internalRedirect('/explanation/architecture/'),
    '/capabilities/inspect-published-artifacts/': internalRedirect('/explanation/architecture/'),
    // Retired project routes redirect only when a current replacement exists.
    // Solmara Lab is an external adopter, not a Registry Stack product.
    '/projects/registry-lab/demo-flow/': internalRedirect('/'),
  },
  integrations: [
    // Mermaid must come BEFORE starlight: its rehype plugin rewrites
    // ```mermaid fences to <pre class="mermaid"> before Expressive Code
    // would otherwise highlight them as raw code. Diagrams render
    // client-side; autoTheme follows Starlight's data-theme (light/dark).
    mermaid({
      theme: 'default',
      autoTheme: true,
      // Quiet the per-diagram client console logging; errors still log.
      enableLog: false,
    }),
    starlight({
      title: 'Registry stack docs',
      description: 'Documentation for Registry Stack: answer bounded questions with Registry Evidence, build a writable registry with Base Registry Engine, and publish portable registry metadata.',
      // Historical archives keep their sealed search posture. A new released
      // archive is built once on the release runner and carries its exact
      // Pagefind output into production.
      pagefind: !isSearchExcludedBuild,
      plugins: [
        // Generates /llms.txt, /llms-full.txt, and /llms-small.txt for
        // machine consumption. The `details` field carries the discovery
        // pointer so LLM clients know where to find both corpus files.
        // API reference pages (reference/apis/*) are Redoc HTML embeds with
        // minimal prose; they are excluded from llms-small.txt to keep the
        // compact version useful, but remain in llms-full.txt.
        // Released archives carry their machine-readable corpus into the
        // canonical root. Historical archives retain their sealed output.
        ...(isHistoricalArchiveBuild ? [] : [starlightLlmsTxt({
          description: 'Documentation for Registry Stack tutorials, product docs, explanations, and API references.',
          details: discoveryHeaderForBase(base),
          exclude: ['reference/apis/**'],
          promote: ['index*', 'explanation/**'],
          demote: ['reference/**', 'decisions/**'],
        })]),
        // Renders the pinned OpenAPI documents as native Starlight pages, so the
        // API reference follows the light/dark theme and is indexed by Pagefind
        // search (the old Redoc HTML embeds were light-only and unsearchable).
        // Schemas are produced by scripts/fetch-openapi.mjs in `npm run generate`,
        // which runs before any build. The generated routes live alongside the
        // hand-authored narrative pages (reference/apis/registry-*), which link
        // into them; old /api/*.html links are preserved by redirects above.
        starlightOpenAPI([
          evidenceOpenApiSchema,
          ...[evidenceOid4vciOpenApiSchema].filter(() => hasEvidenceOid4vciOpenApi),
          ...[caseworkOpenApiSchema].filter(() => hasCasework),
          ...[schedulingOpenApiSchema].filter(() => hasScheduling),
          ...[messagingOpenApiSchema].filter(() => hasMessaging),
          ...[coordinatorOpenApiSchema].filter(() => hasCoordinator),
          ...[bregOpenApiSchema].filter(() => hasBregOpenApi),
        ]),
      ],
      defaultLocale: 'root',
      locales: {
        root: {
          label: 'English',
          lang: 'en',
        },
      },
      customCss: ['./src/styles/custom.css'],
      routeMiddleware: './src/sidebar-middleware.mjs',
      // Expressive Code settings live in ec.config.mjs, not here: the
      // starlight-openapi plugin replaces this key wholesale. See that file.
      components: {
        Banner: './src/components/RegistryBanner.astro',
        Head: './src/components/RegistryHead.astro',
        Header: './src/components/RegistryHeader.astro',
        PageSidebar: './src/components/RegistryPageSidebar.astro',
        PageTitle: './src/components/RegistryPageTitle.astro',
        Footer: './src/components/RegistryFooter.astro',
        MobileMenuFooter: './src/components/RegistryMobileMenuFooter.astro',
      },
      editLink: {
        baseUrl: 'https://github.com/registrystack/registry-stack/edit/main/docs/site/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/registrystack/registry-stack/tree/main/docs/site',
        },
      ],
      // Product names are the scan targets; the chooser explains their jobs.
      // Start stays open. Starlight opens the active page's ancestors even
      // when their default is collapsed, keeping other journeys out of the way.
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'How the products fit together', slug: 'start/concepts' },
          ],
        },
        {
          label: 'Registry Evidence',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/evidence-quickstart' },
            { label: 'Your first assertion', slug: 'tutorials/first-evidence-assertion' },
            { label: 'How Evidence works', slug: 'explanation/how-evidence-works' },
            // The tutorials continue on the first assertion's running project.
            {
              label: 'Tutorials',
              collapsed: true,
              items: [
                { label: 'Return a governed value', slug: 'tutorials/return-a-governed-value' },
                { label: 'Control who can request evidence', slug: 'tutorials/control-who-can-request-evidence' },
                { label: 'Assert a role-bound relationship', slug: 'tutorials/assert-a-role-bound-relationship' },
                { label: 'Request evidence as an SD-JWT VC', slug: 'tutorials/request-evidence-as-sd-jwt-vc' },
              ],
            },
            // Consumers need no deployment, but they do need the project the
            // tutorials build on, so their path follows the tutorials and stays
            // separate from wallet delivery.
            {
              label: 'Use from applications',
              collapsed: true,
              items: [
                { label: 'Request an assertion', slug: 'tutorials/request-evidence-from-an-application' },
                { label: 'Request an access token', slug: 'configure/request-an-access-token' },
                { label: 'Verify an assertion', slug: 'tutorials/verify-an-assertion-as-a-consumer' },
                { label: 'Manage verifier trust', slug: 'tutorials/manage-evidence-verifier-trust' },
              ],
            },
            {
              label: 'Connect a source',
              collapsed: true,
              items: [
                { label: 'Connect an institution API', slug: 'tutorials/connect-an-institution-source' },
                { label: 'Connect a SQLite extract', slug: 'tutorials/connect-a-sqlite-extract' },
                { label: 'Package a lookup over a registry', slug: 'tutorials/evidence-from-breg' },
              ],
            },
            {
              label: 'Prove and deploy',
              collapsed: true,
              items: [
                { label: 'Prove with fixtures', slug: 'tutorials/prove-an-evidence-project' },
                { label: 'Build and deploy', slug: 'tutorials/build-and-deploy-evidence-project' },
                { label: 'Sign with Vault Transit', slug: 'tutorials/move-evidence-to-production-signing' },
                { label: 'Run with Docker Compose', slug: 'tutorials/integrate-evidence-candidate-with-docker-compose' },
                { label: 'Rotate signing keys', slug: 'tutorials/rotate-evidence-signing-keys' },
                { label: 'Audit log', slug: 'operate/evidence-audit' },
              ],
            },
            {
              label: 'Wallet delivery',
              collapsed: true,
              items: [
                { label: 'Enable SD-JWT VC', slug: 'configure/enable-sd-jwt-vc' },
                { label: 'Deliver to a wallet', slug: 'configure/evidence-oid4vci' },
              ],
            },
            { label: 'Configuration reference', slug: 'reference/evidence-configuration' },
            { label: 'Errors and problem codes', slug: 'reference/evidence-problems' },
            { label: 'API overview', slug: 'reference/apis/registry-evidence' },
            // The API plugin supplies its own operation groups. An extra HTTP
            // API wrapper would add a disclosure without helping navigation.
            evidenceOpenApiSidebarGroup,
            ...(hasEvidenceOid4vciOpenApi ? [evidenceOid4vciOpenApiSidebarGroup] : []),
            { label: 'Security model', slug: 'security/evidence' },
          ],
        },
        {
          label: 'Base Registry Engine',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/breg-quickstart' },
            { label: 'Your first registry', slug: 'tutorials/first-breg' },
            { label: 'How a registry works', slug: 'explanation/configuration-defined-registry' },
            {
              label: 'Tutorials',
              collapsed: true,
              items: [
                { label: 'Change it with an Action', slug: 'tutorials/change-a-registry-with-an-action' },
                { label: 'Extend with a module', slug: 'tutorials/extend-a-registry-with-a-module' },
                { label: 'Derive from PublicSchema', slug: 'tutorials/derive-a-registry-from-publicschema' },
                { label: 'Query and change from Python and Node', slug: 'tutorials/query-breg-client' },
              ],
            },
            {
              label: 'Author a registry',
              collapsed: true,
              items: [
                { label: 'Author a project', slug: 'configure/breg' },
                { label: 'Modeling patterns', slug: 'explanation/registry-modeling-patterns' },
                { label: 'Control access and reads', slug: 'configure/breg-access' },
                { label: 'Actions and Proposals', slug: 'configure/breg-actions' },
                { label: 'Encrypt a field', slug: 'configure/breg-field-encryption' },
                { label: 'Publish statistics', slug: 'configure/breg-statistics' },
                { label: 'Test with journeys', slug: 'configure/breg-journeys' },
              ],
            },
            {
              label: 'Deploy and operate',
              collapsed: true,
              items: [
                { label: 'Deploy and serve', slug: 'operate/breg' },
                { label: 'Change an active registry', slug: 'operate/breg-changes' },
                { label: 'Monitor and recover', slug: 'operate/breg-monitor' },
                { label: 'Retain, erase, and audit', slug: 'operate/breg-retention' },
                { label: 'Move data in bulk', slug: 'operate/breg-data' },
                { label: 'Bind webhook receivers', slug: 'operate/breg-webhooks' },
              ],
            },
            {
              label: 'Use from applications',
              collapsed: true,
              items: [
                { label: 'Client reference', slug: 'reference/breg-client-capabilities' },
                { label: 'Client API reference', slug: 'reference/client-api' },
                { label: 'API reference', slug: 'reference/breg-api' },
                { label: 'PublicSchema wizard', slug: 'reference/bregctl-publicschema-wizard' },
                { label: 'Authenticate with eSignet', slug: 'explanation/esignet-authentication-over-breg' },
              ],
            },
            {
              label: 'Compose',
              collapsed: true,
              items: [
                { label: 'Send events to a webhook', slug: 'tutorials/send-registry-events-to-a-webhook' },
                { label: 'Serve a lookup to Evidence', slug: 'tutorials/evidence-from-breg' },
                { label: 'Review a Proposal in Casework', slug: 'tutorials/review-breg-changes-in-casework' },
              ],
            },
            // breg-mcp and breg-review are published only by docsets that carry
            // them (src/lib/docset-products.mjs).
            ...(hasBregServices ? [{
              label: 'Citizen chat assistant',
              collapsed: true,
              items: [
                { label: 'Citizen chat assistant', slug: 'configure/breg-mcp' },
              ],
            }] : []),
            { label: 'Configuration reference', slug: 'reference/breg-configuration' },
            ...(hasBregOpenApi ? [bregOpenApiSidebarGroup] : []),
          ],
        },
        ...(hasCasework ? [{
          label: 'Registry Casework',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/casework' },
            { label: 'Decide your first ReviewRequest', slug: 'tutorials/first-casework' },
            { label: 'How Casework works', slug: 'explanation/how-casework-works' },
            {
              label: 'Author a policy',
              collapsed: true,
              items: [
                { label: 'Author a policy', slug: 'configure/casework' },
                { label: 'Staff the directory', slug: 'configure/casework-directory' },
              ],
            },
            {
              label: 'Deploy and operate',
              collapsed: true,
              items: [
                { label: 'Deploy Casework', slug: 'operate/casework' },
                { label: 'Change an active package', slug: 'operate/change-a-casework-package' },
                { label: 'Retention and audit', slug: 'operate/casework-retention' },
              ],
            },
            {
              label: 'Compose',
              collapsed: true,
              items: [
                { label: 'Review a Proposal in Casework', slug: 'tutorials/review-breg-changes-in-casework' },
              ],
            },
            { label: 'API contract', slug: 'reference/apis/registry-casework' },
            caseworkOpenApiSidebarGroup,
            { label: 'Client API reference', slug: 'reference/client-api' },
          ],
        }] : []),
        ...(hasScheduling ? [{
          label: 'Registry Scheduling',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/scheduling' },
            { label: 'Prove your first booking policy', slug: 'tutorials/first-scheduling' },
            { label: 'How Scheduling works', slug: 'explanation/how-scheduling-works' },
            { label: 'Author a policy', slug: 'configure/scheduling' },
            { label: 'Deploy and operate Scheduling', slug: 'operate/scheduling' },
            { label: 'Configuration reference', slug: 'reference/scheduling-configuration' },
            { label: 'API contract', slug: 'reference/apis/registry-scheduling' },
            schedulingOpenApiSidebarGroup,
          ],
        }] : []),
        ...(hasRender ? [{
          label: 'Registry Render',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/registry-render' },
            { label: 'Render your first document', slug: 'tutorials/first-render-document' },
            { label: 'How Render works', slug: 'explanation/render-determinism' },
            { label: 'Deploy Render', slug: 'operate/registry-render' },
            { label: 'Configuration reference', slug: 'reference/render-configuration' },
          ],
        }] : []),
        ...(hasMessaging ? [{
          label: 'Registry Messaging',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/messaging' },
            { label: 'Send your first message', slug: 'tutorials/first-messaging' },
            { label: 'How Messaging works', slug: 'explanation/how-messaging-works' },
            { label: 'Author a package', slug: 'configure/messaging' },
            { label: 'Deploy Messaging', slug: 'operate/messaging' },
            { label: 'Configuration reference', slug: 'reference/messaging-configuration' },
            { label: 'API contract', slug: 'reference/apis/registry-messaging' },
            messagingOpenApiSidebarGroup,
            { label: 'Client API reference', slug: 'reference/client-api' },
          ],
        }] : []),
        ...(hasCoordinator ? [{
          label: 'Registry Coordinator',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/coordinator' },
            { label: 'Review an application and send a notice', slug: 'tutorials/review-an-application-and-send-a-notice' },
            { label: 'How Coordinator works', slug: 'explanation/how-coordinator-works' },
            { label: 'Author a flow', slug: 'configure/coordinator' },
            { label: 'Deploy Coordinator', slug: 'operate/coordinator' },
            { label: 'Configuration reference', slug: 'reference/coordinator-configuration' },
            { label: 'API contract', slug: 'reference/apis/registry-coordinator' },
            coordinatorOpenApiSidebarGroup,
          ],
        }] : []),
        {
          label: 'Registry Discovery',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/discovery' },
            { label: 'Publish and consume an index', slug: 'tutorials/publish-and-consume-discovery-index' },
            { label: 'How Discovery works', slug: 'explanation/discovery-as-an-index' },
            { label: 'Package and run an index', slug: 'configure/discovery' },
          ],
        },
        {
          label: 'Operations',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'operate/advanced' },
            { label: 'Operator handoff', slug: 'operate' },
            { label: 'Rotate credentials and trust', slug: 'operate/advanced/rotate-credentials-and-trust' },
            { label: 'Connect an OIDC issuer', slug: 'operate/advanced/connect-an-oidc-issuer' },
            { label: 'Inspect and diagnose', slug: 'operate/advanced/inspect-and-diagnose' },
            { label: 'Back up and restore', slug: 'operate/advanced/back-up-and-restore' },
            { label: 'Upgrade and retire', slug: 'operate/advanced/upgrade-and-retire' },
            { label: 'Retention and persistent state', slug: 'operate/retention-and-persistent-state' },
            { label: 'Generated files and ownership', slug: 'generated-artifacts' },
            { label: 'Production hardening', slug: 'security/hardening-checklist' },
            {
              label: 'Security',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'security' },
                { label: 'Threat model', slug: 'explanation/threat-model' },
                { label: 'Known limitations', slug: 'explanation/known-limitations' },
                { label: 'Report a vulnerability', slug: 'security/report-a-vulnerability' },
                { label: 'Support window', slug: 'security/support-window' },
                { label: 'Self-assessment', slug: 'security/self-assessment' },
                { label: 'Release trust', slug: 'security/openssf-evidence' },
              ],
            },
          ],
        },
        {
          label: 'Design',
          collapsed: true,
          items: [
            { label: 'Architecture', slug: 'explanation/architecture' },
            { label: 'Boundaries and map', slug: 'map/boundaries-and-map' },
            { label: 'Records stay home', slug: 'explanation/records-stay-home' },
            { label: 'Data minimization', slug: 'explanation/data-minimization-and-purpose-limitation' },
            { label: 'Trusted context', slug: 'explanation/trusted-context-constraints' },
            { label: 'DPI safeguards', slug: 'explanation/dpi-safeguards-alignment' },
            {
              // These records have no index; keep both destinations visible.
              label: 'Decisions',
              collapsed: true,
              items: [
                { label: 'Registry Relay retirement', slug: 'decisions/registry-relay-retirement-2026-10-03' },
                { label: 'Registry Notary retirement', slug: 'decisions/notary-retirement-2026-08-03' },
              ],
            },
          ],
        },
        {
          label: 'Reference',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'reference' },
            { label: 'Errors and status codes', slug: 'reference/errors' },
            { label: 'Environment variables', slug: 'reference/environment-variables' },
            { label: 'Configuration files', slug: 'reference/configuration-files' },
            { label: 'API overview', slug: 'reference/apis' },
            ...cliReferenceSidebar(undefined, { omit: omittedCliBinaries(selectedDocset) }),
            {
              label: 'Compatibility',
              collapsed: true,
              items: [
                { label: 'Contracts', slug: 'reference/contracts' },
                { label: 'API stability and versioning', slug: 'reference/api-stability' },
                { label: 'Standards', slug: 'reference/standards' },
                { label: 'ITB and SEMIC evidence', slug: 'reference/itb-semic-evidence' },
              ],
            },
            {
              label: 'Specifications',
              collapsed: true,
              items: [
                { label: 'Register', slug: 'spec' },
                { label: 'Documentation framework', slug: 'spec/rs-doc' },
                { label: 'Terms', slug: 'spec/rs-terms' },
                { label: 'Architecture', slug: 'spec/rs-arc-g' },
                { label: 'Registry Evidence protocol', slug: 'spec/rs-pr-evidence' },
                { label: 'Security model', slug: 'spec/rs-sec-g' },
                { label: 'Portable metadata model', slug: 'spec/rs-dm-manifest' },
              ],
            },
            // Flatten the generated Diataxis categories here: product and
            // page are enough context inside Reference.
            {
              label: 'Registry Manifest',
              collapsed: true,
              items: flattenSidebarGroups(generatedProduct('Manifest').items),
            },
            // Older docsets can predate the generated Evidence product pages.
            ...(optionalGeneratedProduct('Registry Evidence')
              ? [
                  {
                    label: 'Registry Evidence',
                    collapsed: true,
                    items: flattenSidebarGroups(generatedProduct('Registry Evidence').items),
                  },
                ]
              : []),
            { label: 'Changelog', slug: 'changelog' },
            { label: 'Privacy', slug: 'privacy' },
            { label: 'Accessibility', slug: 'accessibility' },
            // The glossary is a lookup, not a first encounter, so it ends Reference.
            { label: 'Glossary', slug: 'reference/glossary' },
          ],
        },
      ],
    }),
    ...(isSearchExcludedBuild ? [disabledSitemap] : [sitemap()]),
  ],
});
