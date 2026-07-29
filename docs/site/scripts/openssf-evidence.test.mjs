import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { parse } from "yaml";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(siteRoot, "..", "..");
const evidencePath = path.join(
  siteRoot,
  "src/content/docs/security/openssf-evidence.mdx",
);
const answersPath = path.join(
  repoRoot,
  "release/openssf-best-practices-silver.yaml",
);

test("OpenSSF Silver public status matches the in-tree answer set", async () => {
  const [page, source] = await Promise.all([
    readFile(evidencePath, "utf8"),
    readFile(answersPath, "utf8"),
  ]);
  const answers = parse(source);

  assert.equal(
    answers.schema_version,
    "registry-stack.openssf-best-practices-silver.v1",
  );
  assert.equal(answers.project.badge_project_status, "silver");
  assert.equal(
    answers.project.badge_project_url,
    "https://www.bestpractices.dev/en/projects/13372/silver",
  );

  const criteria = new Map(
    answers.criteria.map((criterion) => [criterion.id, criterion]),
  );
  assert.deepEqual(
    [...criteria.keys()].sort(),
    ["build_repeatable", "signed_releases", "version_tags_signed"],
  );
  assert.equal(criteria.get("build_repeatable").status, "Met");
  assert.equal(criteria.get("signed_releases").status, "Met");
  assert.equal(criteria.get("version_tags_signed").status, "Unmet");

  for (const [id, criterion] of criteria) {
    assert.equal(criterion.level, "silver");
    assert.equal(
      criterion.authoritative_url,
      `https://www.bestpractices.dev/en/projects/13372/silver#${id}`,
    );
    assert.equal(
      criterion.definition_url,
      `https://www.bestpractices.dev/en/criteria#1.${id}`,
    );
    assert.ok(criterion.evidence_urls.length > 0);
    assert.ok(
      criterion.evidence_urls.every((url) => url.startsWith("https://")),
    );
    assert.match(
      page,
      new RegExp(`\\| \\\`${id}\\\` \\| ${criterion.status}(?: | \\|)`),
    );
  }
});

test("public evidence describes conditional repeatability and the compact release chain", async () => {
  const page = await readFile(evidencePath, "utf8");
  assert.match(
    page,
    /\| `build_repeatable` \| Met only while the latest applicable clean proof is successful and no older than 30 days \|/,
  );
  assert.match(page, /24-hour candidate manifest and bundle/i);
  assert.match(page, /one keyless Sigstore bundle authenticates `SHA256SUMS`/i);
  assert.match(
    page,
    /one compact release manifest recording candidate and promotion identity/i,
  );
});
