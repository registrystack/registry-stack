import type { APIRoute } from 'astro';

export const GET: APIRoute = () => new Response(`# Registry stack docs

Documentation for the registry stack: six projects that publish registry metadata, serve protected registry data, and issue evidence credentials.

Core pages:
- /registry-docs/start/
- /registry-docs/map/
- /registry-docs/explanation/architecture/
- /registry-docs/reference/standards/
- /registry-docs/reference/contracts/
- /registry-docs/reference/apis/
- /registry-docs/tutorials/first-run-with-registry-lab/

Machine-readable companion:
- /registry-docs/llms-full.txt
`, {
  headers: { 'content-type': 'text/plain; charset=utf-8' },
});
