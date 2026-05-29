import type { APIRoute } from 'astro';

export const GET: APIRoute = () => new Response(`# Registry stack docs

Documentation for the registry stack: six projects that publish registry metadata, serve protected registry data, and issue evidence credentials.

Core pages:
- /start/
- /map/
- /explanation/architecture/
- /reference/standards/
- /reference/contracts/
- /reference/apis/
- /tutorials/first-run-with-registry-lab/

Machine-readable companion:
- /llms-full.txt
`, {
  headers: { 'content-type': 'text/plain; charset=utf-8' },
});
