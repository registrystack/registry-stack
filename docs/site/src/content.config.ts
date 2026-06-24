import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { z } from 'astro/zod';

const registryLegendFrontmatter = z.object({
  // These seven keys are required for every hand-authored page, but they are
  // declared optional here so that virtual pages injected by plugins (the
  // starlight-openapi reference routes) still satisfy the StarlightPage schema,
  // which they cannot carry. Required-ness for authored content under
  // src/content/docs is enforced independently by scripts/check-doc-frontmatter.mjs
  // (run as `npm run check:content`), which reads each file's raw frontmatter.
  status: z.enum(['draft', 'current', 'historical', 'deprecated']).optional(),
  owner: z.string().min(1).optional(),
  source_repos: z.array(z.string()).optional(),
  last_reviewed: z.coerce.string().optional(),
  doc_type: z
    .enum(['tutorial', 'how-to', 'explanation', 'reference', 'decision', 'specification'])
    .optional(),
  locale: z.literal('en').optional(),
  standards_referenced: z.array(z.string()).optional(),
  wide: z.boolean().optional(),
  // Formal specification layer (doc_type: specification). The three axes are
  // defined in spec/RS-DOC. They are optional here so the single shared schema
  // stays valid for every existing doc; their presence is *required* for
  // specification docs by scripts/check-doc-frontmatter.mjs (Zod `extend`
  // cannot host a conditional refinement). doc_id is the stable, citable
  // identifier; category is the document's role; evidence is how true the
  // document is against shipped code.
  doc_id: z.string().regex(/^RS-[A-Z0-9]+(-[A-Z0-9]+)*$/).optional(),
  category: z.enum(['normative', 'informative']).optional(),
  evidence: z.enum(['aspirational', 'partial', 'verified']).optional(),
  // Section 2 declaration keys (see spec/RS-DOC and spec/RS-TERMS Section 6):
  // layer is the stack layer(s) the page documents; audience is the reader
  // role(s) it serves. Both are arrays because a specification is frequently
  // cross-cutting. They are optional: most pages predate the keys, and a spec
  // that spans every layer omits `layer` rather than list all of them.
  layer: z
    .array(
      z.enum([
        'metadata',
        'consultation',
        'evaluation',
        'credential',
        'federation',
        'administration',
        'operations',
      ]),
    )
    .optional(),
  audience: z
    .array(z.enum(['integrator', 'operator', 'maintainer', 'specification editor', 'tooling']))
    .optional(),
});

export const collections = {
  docs: defineCollection({
    loader: docsLoader(),
    schema: docsSchema({ extend: registryLegendFrontmatter }),
  }),
};
