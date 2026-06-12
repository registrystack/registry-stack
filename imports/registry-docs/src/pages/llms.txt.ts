import type { APIRoute } from 'astro';

export const GET: APIRoute = () => new Response(`# Registry stack docs

Documentation for the registry stack: six projects that publish registry metadata, serve protected registry data, and issue evidence credentials.

Core pages:
- /start/see-it-live/
- /start/when-to-use/
- /explanation/architecture/
- /reference/apis/
- /tutorials/publish-spreadsheet-secured-registry-api/
- /tutorials/verify-claim-registry-api/

Machine-readable companion:
- /llms-full.txt
`, {
  headers: { 'content-type': 'text/plain; charset=utf-8' },
});
