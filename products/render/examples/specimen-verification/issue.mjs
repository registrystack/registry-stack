// SPDX-License-Identifier: Apache-2.0
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";
import { verificationUrl } from "./origin.mjs";
import { createReference } from "./reference.mjs";

const run = promisify(execFile);
const bundleSource = fileURLToPath(new URL("./bundle/", import.meta.url));
const bundledPackages = fileURLToPath(new URL("../../bundles/certificate/packages/", import.meta.url));
const documentType = "population-register-extract";

// The issuer assigns a reference before rendering. Only a completed PDF and its receipt become visible.
export async function issueSpecimen({ registry, origin, verificationPage, render = "registry-render" }) {
  const reference = createReference();
  const url = verificationUrl({ reference, origin, verificationPage });
  const issuedAt = new Date().toISOString();
  await mkdir(registry, { recursive: true, mode: 0o700 });
  const directory = await realpath(registry);
  const scratch = await mkdtemp(join(directory, ".issuing-"));
  try {
    const bundle = join(scratch, "bundle");
    await cp(bundleSource, bundle, { recursive: true });
    await cp(bundledPackages, join(bundle, "packages"), { recursive: true });
    const example = JSON.parse(await readFile(join(bundle, "fixtures/data.json"), "utf8"));
    const data = join(scratch, "request.json");
    await writeFile(data, JSON.stringify({ ...example, reference, "verify-url": url }), { mode: 0o600 });

    const signed = join(scratch, "signed");
    const { stdout } = await run(render, ["test-seal", "--bundle", bundle, "--type", documentType,
      "--data", data, "--issued-at", issuedAt, "--output", signed, "--format", "json"]);
    const report = JSON.parse(stdout);
    const pdf = await readFile(join(signed, "document.pdf"));
    const signedFileDigest = "sha256:" + createHash("sha256").update(pdf).digest("hex");
    if (report.seal?.testOnly !== true || report.signedFileDigest !== signedFileDigest) {
      throw new Error("The Render response does not identify these exact PDF bytes as test-signed.");
    }
    const receipt = { reference, issuedAt, signedFileDigest };
    await writeFile(join(signed, "receipt.json"), JSON.stringify(receipt, null, 2) + "\n", { mode: 0o600 });
    const destination = join(directory, reference);
    await rename(signed, destination);
    return { reference, url, pdf: join(destination, "document.pdf"), root: join(destination, "test-root.pem") };
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { values } = parseArgs({ options: {
      registry: { type: "string" }, origin: { type: "string" }, "verification-page": { type: "string" },
      render: { type: "string", default: process.env.REGISTRY_RENDER_BIN ?? "registry-render" },
    } });
    if (!values.registry) throw new Error("Supply --registry with the local specimen directory.");
    console.log(JSON.stringify(await issueSpecimen({
      registry: values.registry,
      origin: values.origin,
      verificationPage: values["verification-page"],
      render: values.render,
    }), null, 2));
  } catch (error) {
    const diagnostic = error.stdout?.trim();
    console.error(diagnostic || error.message);
    process.exitCode = 1;
  }
}
