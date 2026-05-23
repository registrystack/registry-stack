import type { APIRoute } from 'astro';
import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

async function docs(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const found: string[] = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...await docs(path));
    if (entry.isFile() && /\.(md|mdx)$/.test(entry.name)) found.push(path);
  }
  return found.sort();
}

export const GET: APIRoute = async () => {
  const parts = ['# Registry Legend Full Documentation\n'];
  for (const file of await docs('src/content/docs')) {
    const text = await readFile(file, 'utf8');
    parts.push(`\n\n## ${relative('src/content/docs', file)}\n\n${text}`);
  }
  return new Response(parts.join(''), {
    headers: { 'content-type': 'text/plain; charset=utf-8' },
  });
};
