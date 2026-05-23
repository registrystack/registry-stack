import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { z } from 'astro/zod';

const registryLegendFrontmatter = z.object({
  status: z.enum(['draft', 'current', 'historical', 'deprecated']),
  owner: z.string().min(1),
  source_repos: z.array(z.string()),
  last_reviewed: z.coerce.string(),
  doc_type: z.enum(['tutorial', 'how-to', 'explanation', 'reference', 'decision']),
  locale: z.literal('en'),
  standards_referenced: z.array(z.string()),
  wide: z.boolean().optional(),
});

export const collections = {
  docs: defineCollection({
    loader: docsLoader(),
    schema: docsSchema({ extend: registryLegendFrontmatter }),
  }),
};
