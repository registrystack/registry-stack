// SPDX-License-Identifier: Apache-2.0
import { isIPv4 } from "node:net";

export const defaultPort = 4371;

export function isLocalIPv4(host) {
  if (!isIPv4(host)) return false;
  const [first, second] = host.split(".").map(Number);
  return first === 127 || first === 10 ||
    (first === 192 && second === 168) || (first === 172 && second >= 16 && second <= 31);
}

export function verificationOrigin(input) {
  const url = new URL(input);
  const local = isLocalIPv4(url.hostname) || url.hostname === "localhost" || url.hostname === "[::1]";
  if (url.username || url.password || url.href !== url.origin + "/" ||
      !(url.protocol === "https:" || (url.protocol === "http:" && local))) {
    throw new Error("Use an HTTPS origin or a loopback or private-network HTTP origin with no path or credentials.");
  }
  return url.origin;
}

export function verificationPage(input) {
  const url = new URL(input);
  const local = isLocalIPv4(url.hostname) || url.hostname === "localhost" || url.hostname === "[::1]";
  const verificationPath = url.pathname.endsWith("/verify") || url.pathname.endsWith("/verify/");
  if (url.username || url.password || url.href !== url.origin + url.pathname || !verificationPath ||
      !(url.protocol === "https:" || (url.protocol === "http:" && local))) {
    throw new Error("Use an HTTPS verification page or a loopback or private-network HTTP verification page ending in /verify, with no credentials, query or fragment.");
  }
  return url.href;
}

export function verificationUrl({ reference, origin, verificationPage: page }) {
  if (origin !== undefined && page !== undefined) {
    throw new Error("Supply either origin or verification page, not both.");
  }
  const url = page === undefined
    ? new URL("/verify", verificationOrigin(origin ?? `http://127.0.0.1:${defaultPort}`))
    : new URL(verificationPage(page));
  url.searchParams.set("ref", reference);
  return url.href;
}
