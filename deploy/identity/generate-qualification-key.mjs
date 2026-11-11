#!/usr/bin/env node
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdir, open, writeFile } from "node:fs/promises";
import path from "node:path";

const output = process.argv[2];
if (!output || !path.isAbsolute(output)) {
  throw new Error("give one absent absolute output directory");
}
await mkdir(output, { mode: 0o700 });
const guard = await open(path.join(output, ".owner"), "wx", 0o600);
await guard.close();

const { publicKey, privateKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});
const kid = `qualification-${randomUUID()}`;
const publicJwk = { ...publicKey.export({ format: "jwk" }), alg: "ES256", kid, use: "sig" };
const privateJwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid, use: "sig" };
await writeFile(
  path.join(output, "qualification-client.jwks.json"),
  `${JSON.stringify({ keys: [publicJwk] }, null, 2)}\n`,
  { mode: 0o644 },
);
await writeFile(
  path.join(output, "qualification-client.private.jwk"),
  `${JSON.stringify(privateJwk, null, 2)}\n`,
  { mode: 0o600 },
);
console.log(`Wrote a synthetic qualification key pair under ${output}.`);
