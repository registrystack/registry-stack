import type { APIRoute } from 'astro';

export const GET: APIRoute = () => new Response(`# Registry stack docs

Documentation for the registry stack: six projects that publish registry metadata, serve protected registry data, and issue evidence credentials.

Core pages:
- /registry-legend/start/
- /registry-legend/map/
- /registry-legend/explanation/architecture/
- /registry-legend/reference/standards/
- /registry-legend/reference/contracts/
- /registry-legend/reference/apis/
- /registry-legend/tutorials/first-run-with-registry-lab/

Machine-readable companion:
- /registry-legend/llms-full.txt
`, {
  headers: { 'content-type': 'text/plain; charset=utf-8' },
});
