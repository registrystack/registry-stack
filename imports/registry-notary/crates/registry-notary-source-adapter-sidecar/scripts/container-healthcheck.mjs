// SPDX-License-Identifier: Apache-2.0

const url =
  process.env.REGISTRY_NOTARY_SOURCE_ADAPTER_SIDECAR_HEALTHCHECK_URL ??
  process.env.REGISTRY_NOTARY_OPENFN_SIDECAR_HEALTHCHECK_URL ??
  "http://127.0.0.1:9191/healthz";
const timeoutMs = Number.parseInt(
  process.env.REGISTRY_NOTARY_SOURCE_ADAPTER_SIDECAR_HEALTHCHECK_TIMEOUT_MS ??
    process.env.REGISTRY_NOTARY_OPENFN_SIDECAR_HEALTHCHECK_TIMEOUT_MS ??
    "5000",
  10,
);

if (!Number.isFinite(timeoutMs) || timeoutMs < 1) {
  console.error("invalid source adapter sidecar healthcheck timeout");
  process.exit(1);
}

const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), timeoutMs);

try {
  const response = await fetch(url, { signal: controller.signal });
  if (!response.ok) {
    console.error(`health endpoint returned HTTP ${response.status}`);
    process.exit(1);
  }
  console.log("registry-notary-source-adapter-sidecar healthcheck ok");
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
} finally {
  clearTimeout(timeout);
}
