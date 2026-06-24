// QR rendering for the wallet closer: encode a short openid-credential-offer URL
// into an inline SVG path. We use qrcode-generator (the canonical Kazuhiko Arase
// implementation, MIT, dependency-free) for the encoding so the code reliably
// scans into a real wallet, and render the modules ourselves as a single SVG path
// (no innerHTML, no foreign markup, design-token colours).
//
// No raw identifiers flow through here: the caller passes a credential-offer URL.

import qrcode from 'qrcode-generator';

export type QrMatrix = { size: number; modules: boolean[][] };

// Encode UTF-8 text at ECC level Q (strong resilience for screen-scan demos),
// auto-selecting the smallest type number that fits.
export function encodeQr(text: string): QrMatrix {
  const qr = qrcode(0, 'Q');
  qr.addData(text);
  qr.make();
  const size = qr.getModuleCount();
  const modules: boolean[][] = [];
  for (let r = 0; r < size; r++) {
    const row: boolean[] = [];
    for (let c = 0; c < size; c++) row.push(qr.isDark(r, c));
    modules.push(row);
  }
  return { size, modules };
}

// Render a QR matrix to an SVG path `d` string (one 1x1 rect per dark module). A
// quiet zone of 4 modules is included via qrViewBox so the path coordinates are
// offset by 4.
export function qrToSvgPath(qr: QrMatrix): string {
  const parts: string[] = [];
  for (let r = 0; r < qr.size; r++) {
    for (let c = 0; c < qr.size; c++) {
      if (qr.modules[r][c]) parts.push(`M${c + 4} ${r + 4}h1v1h-1z`);
    }
  }
  return parts.join('');
}

// The viewBox dimension for a matrix with a 4-module quiet zone on each side.
export function qrViewBox(qr: QrMatrix): number {
  return qr.size + 8;
}
