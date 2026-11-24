import { fileURLToPath } from 'node:url';
import { publicDir } from 'astro:config/server';
import { buildPageMarkdown } from '../../../lib/page-markdown';
import { loadIssuedSpecimens } from '../../../lib/population-extract/verification-data.mjs';

export async function GET() {
  const issued = new URL('examples/population-extract/issued/', publicDir);
  const records = await loadIssuedSpecimens(fileURLToPath(issued));
  const links = records.map(({ reference }) =>
    `- [${reference}](./verify/?ref=${reference}) · [Receipt](./issued/${reference}/receipt.json) · [Signed PDF](./issued/${reference}/document.pdf) · [Public test certificate](./issued/${reference}/test-root.pem)`
  );
  const body = [
    'Scan the QR or enter the printed reference on the [verification page](./verify/).',
    'Select a PDF there to compare its SHA-256 on your device. To check the digital signature, use the [Render signing guide](../../operate/registry-render/#create-a-test-signed-pdf).',
    '## Published fictional extracts',
    links.join('\n'),
  ].join('\n\n');
  return new Response(buildPageMarkdown('Verify a Population register extract', undefined, body, import.meta.env.BASE_URL), {
    headers: { 'content-type': 'text/markdown; charset=utf-8' },
  });
}
