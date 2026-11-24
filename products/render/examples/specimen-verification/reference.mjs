// SPDX-License-Identifier: Apache-2.0
import { randomBytes } from "node:crypto";

const groupedReference = (hex) => "TEST-" + hex.match(/.{4}/g).join("-");

export function createReference() {
  return groupedReference(randomBytes(10).toString("hex").toUpperCase());
}

export function normalizeReference(input) {
  if (typeof input !== "string" || input.length > 64) return null;
  const compact = input.toUpperCase().replaceAll(/[ -]/g, "");
  if (!/^TEST[0-9A-F]{20}$/.test(compact)) return null;
  return groupedReference(compact.slice(4));
}
