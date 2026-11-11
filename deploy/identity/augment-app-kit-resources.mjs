#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";

const [input, output] = process.argv.slice(2);
if (!input || !output) {
  throw new Error("usage: augment-app-kit-resources.mjs INPUT OUTPUT");
}

let resources = await readFile(input, "utf8");

function replaceExactly(label, needle, replacement, expected) {
  const count = resources.split(needle).length - 1;
  if (count !== expected) {
    throw new Error(`${label}: expected exactly ${expected} match(es), found ${count}`);
  }
  resources = resources.replaceAll(needle, replacement);
}

replaceExactly(
  "RegistryPerson role schema",
  "  registry_principal:\n    displayName: registry_principal\n    type: string\n",
  "  registry_principal:\n    displayName: registry_principal\n    type: string\n  registry_role:\n    displayName: registry_role\n    type: string\n  registry_scopes:\n    displayName: registry_scopes\n    type: string\n",
  1,
);
replaceExactly(
  "synthetic officer role",
  "  registry_principal: qualification-officer\n",
  "  registry_principal: qualification-officer\n  registry_role: contact-editor\n  registry_scopes: registry:directory:write\n",
  1,
);
replaceExactly(
  "App Kit access-token role",
  "          attributes:\n          - registry_principal\n",
  "          attributes:\n          - registry_principal\n          - registry_role\n          - registry_scopes\n",
  1,
);
replaceExactly(
  "App Kit ID-token role",
  "        userAttributes:\n        - registry_principal\n",
  "        userAttributes:\n        - registry_principal\n        - registry_role\n        - registry_scopes\n",
  1,
);

await writeFile(output, resources, { flag: "wx", mode: 0o600 });
