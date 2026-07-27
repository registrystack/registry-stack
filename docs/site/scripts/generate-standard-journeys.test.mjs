import assert from "node:assert/strict";
import { execFile as execFileCallback, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";

import YAML from "yaml";

import {
  buildStandardJourneys,
  generateStandardJourneys,
  renderStandardJourneyCommand,
  standardJourneyHeadings,
  standardJourneyIds,
  validateStandardJourneyCommand,
  validateStandardJourneyManifest,
  validateStandardJourneyPublicValue,
} from "./generate-standard-journeys.mjs";

const execFile = promisify(execFileCallback);
const repoRoot = resolve(import.meta.dirname, "../../..");
const docsRoot = resolve(repoRoot, "docs/site");
const manifestPath = resolve(
  repoRoot,
  "docs/site/src/data/standard-journeys.yaml",
);
const registryctlBinary = process.env.REGISTRYCTL_BIN;

async function readManifest() {
  return YAML.parse(await readFile(manifestPath, "utf8"));
}

async function withManifest(run) {
  const temporary = await mkdtemp(join(tmpdir(), "standard-journeys-"));
  try {
    const manifest = await readManifest();
    const candidatePath = join(temporary, "standard-journeys.yaml");
    await run({ temporary, manifest, candidatePath });
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
}

async function writeManifest(candidatePath, manifest) {
  await writeFile(candidatePath, YAML.stringify(manifest, { lineWidth: 0 }));
}

function byId(journeys) {
  return Object.fromEntries(journeys.map((journey) => [journey.id, journey]));
}

function commandSteps(journey) {
  return journey.steps.filter((step) => step.kind === "command");
}

test("builds exactly seven ordered journeys with ten stable headings", async () => {
  const journeys = await buildStandardJourneys(repoRoot);

  assert.equal(journeys.length, 7);
  assert.deepEqual(
    journeys.map((journey) => journey.id),
    standardJourneyIds,
  );
  assert.equal(standardJourneyHeadings.length, 10);
  for (const journey of journeys) {
    assert.deepEqual(journey.section_headings, standardJourneyHeadings);
    assert.deepEqual(journey.availability, {
      status: "current_unreleased",
      proof: "source_tree",
      release: null,
    });
    assert.equal(journey.source_label, "Main source (unreleased)");
  }
});

test("extracts every declared complete configuration file from its canonical source", async () => {
  const first = await buildStandardJourneys(repoRoot);
  const second = await buildStandardJourneys(repoRoot);
  assert.equal(JSON.stringify(first), JSON.stringify(second));
  const journeys = byId(first);

  assert.deepEqual(
    journeys["bounded-http"].configuration_files.map((file) => file.destination),
    [
      "registry-project/registry-stack.yaml",
      "registry-project/environments/local.yaml",
      "registry-project/integrations/person-record/integration.yaml",
    ],
  );

  const fhir = journeys["bounded-multi-call-script"];
  assert.equal(fhir.configuration_files.length, 4);
  const adapter = fhir.configuration_files.find(
    (file) => file.destination.endsWith("/adapter.rhai"),
  );
  assert.equal(adapter.language, "rhai");
  assert.equal(
    adapter.content,
    await readFile(resolve(repoRoot, adapter.source), "utf8"),
  );
  const integration = fhir.configuration_files.find(
    (file) => file.destination.endsWith("/integration.yaml"),
  );
  assert.match(integration.content, /calls: 4/u);
  assert.match(integration.content, /source_bytes: 512KiB/u);
  assert.match(integration.content, /request_bytes: 8KiB/u);
  assert.match(integration.content, /deadline: 12s/u);

  const snapshot = journeys["exact-snapshot"];
  assert.equal(snapshot.configuration_files.length, 4);
  assert.match(
    snapshot.configuration_files.find((file) =>
      file.destination.endsWith("/entities/people.yaml"),
    ).content,
    /primary_key: person_id/u,
  );

  for (const id of ["spreadsheet-protected-api", "instance-openapi"]) {
    assert.deepEqual(
      journeys[id].configuration_files.map((file) => ({
        content: file.content,
        format: file.format,
      })),
      [{ content: null, format: "scaffolded" }],
    );
  }
});

test("preserves exact scaffold ownership and emitted build paths", async () => {
  const journeys = byId(await buildStandardJourneys(repoRoot));
  const spreadsheet = journeys["spreadsheet-protected-api"];
  assert.equal(
    spreadsheet.artifacts.find(
      (artifact) => artifact.path === "my-first-api/registryctl.yaml",
    ).classification,
    "scaffolded_human_owned",
  );
  assert.equal(
    spreadsheet.artifacts.find(
      (artifact) => artifact.path === "my-first-api/relay/config.yaml",
    ).classification,
    "scaffolded_human_owned",
  );

  for (const [id, projectDirectory] of Object.entries({
    "bounded-http": "registry-project",
    "bounded-multi-call-script": "fhir-project",
    "exact-snapshot": "snapshot-project",
    "product-input-lifecycle": "registry-project",
  })) {
    const paths = new Set(journeys[id].artifacts.map((artifact) => artifact.path));
    for (const path of [
      `${projectDirectory}/.registry-stack/build/local/reviewable`,
      `${projectDirectory}/.registry-stack/build/local/private/relay`,
      `${projectDirectory}/.registry-stack/build/local/private/notary`,
    ]) {
      assert(paths.has(path), `${id} is missing exact emitted path ${path}`);
    }
    assert.equal(
      [...paths].some((path) => path.startsWith("generated/")),
      false,
      `${id} retained an invented generated path`,
    );
  }

  assert.deepEqual(
    journeys["product-input-lifecycle"].artifacts
      .filter((artifact) => artifact.classification === "generated_signed")
      .map((artifact) => artifact.path),
    [
      "journey-output/registry-relay-bundle",
      "journey-output/registry-notary-bundle",
    ],
  );
});

test("uses the current explicit registry-backed predicate and matching fixture", async () => {
  const journey = byId(await buildStandardJourneys(repoRoot))[
    "registry-backed-notary-claim"
  ];
  const project = journey.configuration_files.find((file) =>
    file.destination.endsWith("/registry-stack.yaml"),
  );

  assert.match(
    project.content,
    /cel: enrollment\.matched && enrollment\.registration_status == "active"/u,
  );
  assert.match(journey.fixture_excerpt.content, /active-registration-exists: true/u);
  assert.doesNotMatch(
    project.content + journey.fixture_excerpt.content,
    /person-registration-accepted|v0\.13\.0/u,
  );
});

test("rejects missing sections, reordered IDs, and extra journeys", async () => {
  const manifest = await readManifest();
  delete manifest.journeys[0].production_delta;
  assert.throws(
    () => validateStandardJourneyManifest(manifest),
    /missing fields: production_delta/u,
  );

  const reordered = await readManifest();
  [reordered.journeys[0], reordered.journeys[1]] = [
    reordered.journeys[1],
    reordered.journeys[0],
  ];
  assert.throws(
    () => validateStandardJourneyManifest(reordered),
    /seven standard journeys in order/u,
  );

  const extra = await readManifest();
  extra.journeys.push(structuredClone(extra.journeys[0]));
  assert.throws(
    () => validateStandardJourneyManifest(extra),
    /seven standard journeys in order/u,
  );
});

test("rejects shell control, unsupported programs, and executable placeholders", () => {
  for (const command of [
    "registryctl start; touch escaped",
    "registryctl start && registryctl smoke",
    "registryctl build $(printenv)",
    "registryctl build > report",
    "cd registry-project",
    "curl http://127.0.0.1:4242/openapi.json",
    "diff expected actual",
    "registryctl bundle verify --bundle-dir <signed-bundle>",
  ]) {
    assert.throws(
      () => validateStandardJourneyCommand(command),
      /unsafe command token|unsupported program/u,
    );
  }
  assert.doesNotThrow(() =>
    validateStandardJourneyCommand([
      "registryctl",
      "check",
      "--project-dir",
      "registry-project",
      "--environment",
      "local",
      "--explain",
    ]),
  );
});

test("keeps starter prerequisites and noninteractive commands separate from alternatives", async () => {
  const journeys = byId(await buildStandardJourneys(repoRoot));
  const starterProjects = {
    "bounded-http": "registry-project",
    "bounded-multi-call-script": "fhir-project",
    "exact-snapshot": "snapshot-project",
    "product-input-lifecycle": "registry-project",
  };
  for (const [id, projectDirectory] of Object.entries(starterProjects)) {
    const steps = journeys[id].steps;
    const required = commandSteps(journeys[id]);
    const operations = required.map((step) => step.argv.slice(1, 3).join(" "));
    assert.deepEqual(required[0].argv.slice(0, 3), [
      "registryctl",
      "init",
      "--from",
    ]);
    assert.match(operations[1], /^authoring editor/u);
    const checkIndex = required.findIndex((step) => step.argv[1] === "check");
    const compareIndex = required.findIndex((step) => step.argv[1] === "compare");
    const buildIndex = required.findIndex((step) => step.argv[1] === "build");
    assert.deepEqual(required[compareIndex].argv, [
      "registryctl",
      "compare",
      "--project-dir",
      projectDirectory,
      "--environment",
      "local",
      "--from-starter",
    ]);
    assert.equal(
      compareIndex,
      checkIndex + 1,
      `${id} must compare immediately after explained check`,
    );
    assert.equal(
      checkIndex < compareIndex && compareIndex < buildIndex,
      true,
      `${id} must compare after check and before build`,
    );
    assert.equal(
      required.findIndex((step) => step.argv[1] === "test") < checkIndex,
      true,
      `${id} must test before check`,
    );
    assert.equal(
      required.some(
        (step) =>
          step.argv[1] === "promote" ||
          step.argv.includes("--watch") ||
          renderStandardJourneyCommand(step).includes("<"),
      ),
      false,
      `${id} beginner sequence must not promote, watch, or render placeholders`,
    );
    assert.equal(
      steps.some(
        (step) =>
          step.kind === "long_running" &&
          step.argv.includes("--watch"),
      ),
      true,
      `${id} must keep watch separate`,
    );
  }
});

test("initializes every journey before its first project use", async () => {
  const journeys = await buildStandardJourneys(repoRoot);
  for (const journey of journeys) {
    const required = commandSteps(journey);
    const initIndex = required.findIndex((step) => step.argv[1] === "init");
    assert.equal(initIndex, 0, `${journey.id} must initialize first`);
    assert.equal(
      required.slice(0, initIndex).some((step) => step.argv.includes("--project-dir")),
      false,
      `${journey.id} used a project before initialization`,
    );
  }
});

test("keeps runtime and product activation claims bounded to traceable evidence", async () => {
  const journeys = byId(await buildStandardJourneys(repoRoot));
  const openapi = journeys["instance-openapi"];
  const capture = openapi.steps.find((step) => step.kind === "runtime_interface");
  assert.equal(capture.authentication, "none_disposable_local_opt_out");
  assert.equal(capture.output_path, "openapi-inspection/output/instance.openapi.json");
  assert.match(openapi.minimal_configuration.note, /product default remains true/u);
  assert.doesNotMatch(
    openapi.prerequisites.join(" "),
    /authorization material|protected instance route/u,
  );
  assert.match(
    openapi.fixture.expected_trace.join(" "),
    /explicitly sets server\.openapi_requires_auth to false/u,
  );
  assert.doesNotMatch(
    openapi.contract.proves.join(" "),
    /product default is public|runtime evidence is verified/u,
  );
  assert.equal(openapi.evidence.runtime.status, "not_claimed");

  const snapshot = journeys["exact-snapshot"];
  assert.equal(snapshot.evidence.runtime.status, "not_claimed");
  const snapshotMaterializationGate = snapshot.gates.find(
    (gate) => gate.name === "build",
  );
  assert.equal(
    snapshotMaterializationGate.proves,
    "Unsigned Relay input contains the reviewed snapshot materialization requirements.",
  );
  assert.equal(
    snapshotMaterializationGate.does_not_prove,
    "A runtime loaded a concrete snapshot generation or the upstream collection is complete.",
  );
  assert.doesNotMatch(
    [
      snapshotMaterializationGate.proves,
      JSON.stringify(snapshot.configuration_files),
      JSON.stringify(snapshot.artifacts),
    ].join(" "),
    /runtime (?:loaded|accepted) (?:a )?(?:concrete )?snapshot generation/u,
  );

  const lifecycle = journeys["product-input-lifecycle"];
  assert.equal(lifecycle.evidence.runtime.status, "not_claimed");
  assert.doesNotMatch(
    lifecycle.contract.proves.join(" "),
    /runtime accepted|reached readiness|activated the bundle/u,
  );
  assert.equal(
    lifecycle.artifacts.some((artifact) => artifact.path.startsWith("runtime/")),
    false,
  );
  assert.equal(
    lifecycle.steps.filter((step) => step.kind === "operator_interface").length >= 3,
    true,
  );
  const governedPromotion = lifecycle.steps.find(
    (step) =>
      step.kind === "operator_interface" &&
      step.procedure.includes("registryctl promote"),
  );
  const lifecycleBuildIndex = lifecycle.steps.findIndex(
    (step) => step.kind === "command" && step.argv[1] === "build",
  );
  const lifecyclePreflight = lifecycle.steps.find(
    (step) => step.id === "lifecycle-preflight",
  );
  assert.equal(lifecyclePreflight.kind, "readiness_gate");
  assert.match(
    lifecyclePreflight.note,
    /expected to exit 1 with a value-free not_ready report/u,
  );
  assert.equal(
    lifecycle.steps.indexOf(governedPromotion) > lifecycleBuildIndex,
    true,
  );
  assert.match(governedPromotion.procedure, /separate from the first-time starter comparison/u);
});

test("rejects incomplete, partial, and non-allowlisted configuration sources", async () => {
  const incomplete = await readManifest();
  incomplete.journeys[3].minimal_configuration.files.pop();
  assert.throws(
    () => validateStandardJourneyManifest(incomplete),
    /exact complete source set/u,
  );

  const ranged = await readManifest();
  ranged.journeys[3].minimal_configuration.files[0].line_start = 2;
  assert.throws(
    () => validateStandardJourneyManifest(ranged),
    /unknown fields: line_start/u,
  );

  const copied = await readManifest();
  copied.journeys[2].minimal_configuration.files[0].source =
    "docs/site/src/data/standard-journeys.yaml";
  copied.journeys[2].canonical_sources[0] =
    "docs/site/src/data/standard-journeys.yaml";
  assert.throws(
    () => validateStandardJourneyManifest(copied),
    /not an explicitly approved public configuration source/u,
  );
});

test("accepts schema-shaped secret references and rejects literal credential extraction", async () => {
  assert.doesNotThrow(() =>
    validateStandardJourneyPublicValue({
      credential: { token: { secret: "FICTIONAL_REGISTRY_TOKEN" } },
    }),
  );
  assert.throws(
    () =>
      validateStandardJourneyPublicValue({
        credential: {
          client_secret: "embedded-real-looking-token",
          token: "embedded-real-looking-token",
        },
      }),
    /structured credential reference/u,
  );
  assert.throws(
    () => validateStandardJourneyPublicValue({ Jurisdiction: "real-country" }),
    /non-public field Jurisdiction/u,
  );

  const journeys = await buildStandardJourneys(repoRoot);
  const environment = byId(journeys)["bounded-http"].configuration_files.find(
    (file) => file.destination.endsWith("/environments/local.yaml"),
  );
  assert.match(environment.content, /secret: FICTIONAL_REGISTRY_TOKEN/u);

  await withManifest(async ({ manifest, candidatePath }) => {
    const source =
      "crates/registry-relay/config/example.yaml";
    const journey = manifest.journeys[2];
    journey.canonical_sources.push(source);
    journey.minimal_configuration.files[0].source = source;
    await writeManifest(candidatePath, manifest);
    await assert.rejects(
      buildStandardJourneys(repoRoot, candidatePath),
      /not an explicitly approved public configuration source/u,
    );
  });
});

test("rejects stale canonical files, diagnostics, catalogs, and evidence links", async () => {
  await withManifest(async ({ manifest, candidatePath }) => {
    manifest.journeys[0].canonical_sources[0] =
      "crates/registryctl/src/missing.rs";
    await writeManifest(candidatePath, manifest);
    await assert.rejects(buildStandardJourneys(repoRoot, candidatePath), /ENOENT/u);
  });

  await withManifest(async ({ manifest, candidatePath }) => {
    manifest.journeys[0].troubleshooting[0] =
      "registryctl.authoring.removed";
    await writeManifest(candidatePath, manifest);
    await assert.rejects(
      buildStandardJourneys(repoRoot, candidatePath),
      /unknown diagnostic code/u,
    );
  });

  await withManifest(async ({ manifest, candidatePath }) => {
    manifest.journeys[0].catalog_references[0].id = "removed-project";
    await writeManifest(candidatePath, manifest);
    await assert.rejects(
      buildStandardJourneys(repoRoot, candidatePath),
      /catalog reference .* does not resolve/u,
    );
  });

  await withManifest(async ({ manifest, candidatePath }) => {
    manifest.journeys[0].evidence.extraction.source_path =
      "docs/site/scripts/generate-standard-journeys.mjs";
    manifest.journeys[0].evidence.extraction.test_id = "missing test id";
    await writeManifest(candidatePath, manifest);
    await assert.rejects(
      buildStandardJourneys(repoRoot, candidatePath),
      /test_id does not resolve/u,
    );
  });
});

test("rejects release-label, evidence lifecycle, and artifact ownership drift", async () => {
  const releaseMismatch = await readManifest();
  releaseMismatch.journeys[0].availability.release = "v0.13.0";
  assert.throws(
    () => validateStandardJourneyManifest(releaseMismatch),
    /must remain null/u,
  );

  const evidenceMismatch = await readManifest();
  evidenceMismatch.journeys[0].evidence.runtime.revision = "v0.13.0";
  assert.throws(
    () => validateStandardJourneyManifest(evidenceMismatch),
    /revision must be main/u,
  );

  const ownershipMismatch = await readManifest();
  ownershipMismatch.journeys[0].artifacts[0].owner = "shared";
  assert.throws(
    () => validateStandardJourneyManifest(ownershipMismatch),
    /owner has unsupported value shared/u,
  );
});

test("emits only typed safe steps and product-owned diagnostics", async () => {
  const journeys = await buildStandardJourneys(repoRoot);
  for (const journey of journeys) {
    for (const step of journey.steps) {
      if (
        ["command", "alternative", "long_running", "readiness_gate"].includes(
          step.kind,
        )
      ) {
        validateStandardJourneyCommand(step.argv);
        assert.equal(step.argv[0], "registryctl");
        assert.doesNotMatch(renderStandardJourneyCommand(step), /[<>;&|`]|\$\(/u);
      } else {
        assert.equal(Object.hasOwn(step, "argv"), false);
      }
    }
    for (const diagnostic of journey.troubleshooting) {
      assert.equal(typeof diagnostic.product, "string");
      assert.equal(typeof diagnostic.family, "string");
      assert.equal(typeof diagnostic.meaning, "string");
      assert.equal(typeof diagnostic.remediation, "string");
      assert.match(diagnostic.docs_anchor, /^\/reference\/diagnostics\//u);
      assert.equal(diagnostic.lifecycle, "unreleased");
      assert.equal(diagnostic.introduced_in, null);
    }
  }
});

test("every rendered command and combined block parses in POSIX sh, Bash, and Zsh", async () => {
  const journeys = await buildStandardJourneys(repoRoot);
  const commands = journeys.flatMap((journey) =>
    journey.steps
      .filter((step) =>
        ["command", "alternative", "long_running", "readiness_gate"].includes(
          step.kind,
        ),
      )
      .map(renderStandardJourneyCommand),
  );
  const scripts = [
    ...commands.map((command) => `set -eu\n${command}\n`),
    `set -eu\n${commands.join("\n")}\n`,
  ];
  for (const shell of ["/bin/sh", "bash", "zsh"]) {
    for (const script of scripts) {
      const result = spawnSync(shell, ["-n"], {
        encoding: "utf8",
        input: script,
      });
      assert.equal(
        result.status,
        0,
        `${shell} rejected rendered commands: ${result.stderr}`,
      );
    }
  }
});

test(
  "executes every required noninteractive sequence from a clean temporary directory",
  { skip: registryctlBinary === undefined },
  async () => {
    const version = (
      await execFile(registryctlBinary, ["--version"], { encoding: "utf8" })
    ).stdout.trim().split(/\s+/u).at(-1);
    const journeys = await buildStandardJourneys(repoRoot);

    for (const journey of journeys) {
      const temporary = await mkdtemp(join(tmpdir(), `journey-${journey.id}-`));
      try {
        const imageLock = join(temporary, "release-image-lock.json");
        await writeFile(
          imageLock,
          `${JSON.stringify(
            {
              schema_version: "registryctl.release_image_lock.v1",
              release_tag: `v${version}`,
              manifest_source_ref: "a".repeat(40),
              tag_target: "b".repeat(40),
              platform: "linux/amd64",
              images: {
                "registry-relay":
                  `ghcr.io/registrystack/registry-relay@sha256:${"a".repeat(64)}`,
                "registry-notary":
                  `ghcr.io/registrystack/registry-notary@sha256:${"b".repeat(64)}`,
              },
            },
            null,
            2,
          )}\n`,
        );
        const executableSteps = journey.steps.filter((step) =>
          ["command", "readiness_gate"].includes(step.kind),
        );
        for (const step of executableSteps) {
          const cwd = resolve(temporary, step.cwd);
          const execution = execFile(registryctlBinary, step.argv.slice(1), {
              cwd,
              env: {
                ...process.env,
                REGISTRYCTL_IMAGE_LOCK: imageLock,
                REGISTRYCTL_NO_UPDATE_CHECK: "1",
              },
              encoding: "utf8",
            });
          if (step.kind === "readiness_gate") {
            await assert.rejects(execution, (error) => {
              assert.equal(error.code, 1, `${journey.id}:${step.id} exit`);
              assert.equal(error.stderr, "", `${journey.id}:${step.id} wrote stderr`);
              const report = JSON.parse(error.stdout);
              assert.equal(report.schema_version, "registryctl.project_preflight.v1");
              assert.equal(report.status, "not_ready");
              const diagnosticCodes = new Set(
                report.diagnostics.map((diagnostic) => diagnostic.code),
              );
              assert.equal(
                diagnosticCodes.has("registryctl.preflight.secret_missing"),
                true,
              );
              assert.equal(
                diagnosticCodes.has("registryctl.preflight.runtime_file_missing"),
                true,
              );
              return true;
            });
          } else {
            const result = await execution;
            assert.equal(
              result.stderr,
              "",
              `${journey.id}:${step.id} wrote stderr`,
            );
          }
        }
      } finally {
        await rm(temporary, { force: true, recursive: true });
      }
    }
  },
);

test("renders the same ten-section component through exactly seven wrapper pages", async () => {
  const component = await readFile(
    resolve(docsRoot, "src/components/StandardJourney.astro"),
    "utf8",
  );
  for (let index = 0; index < standardJourneyHeadings.length; index += 1) {
    assert.match(
      component,
      new RegExp(`journey\\.section_headings\\[${index}\\]`, "u"),
    );
  }
  assert.match(component, /Required readiness gates/u);

  const manifest = await readManifest();
  for (const journey of manifest.journeys) {
    const page = await readFile(
      resolve(docsRoot, "src/content/docs", `${journey.slug}.mdx`),
      "utf8",
    );
    assert.match(page, /import StandardJourney/u);
    assert.match(
      page,
      new RegExp(`<StandardJourney journeyId="${journey.id}" \\/>`, "u"),
    );
    if (journey.id === "product-input-lifecycle") {
      assert.match(page, /activation handoff/u);
      assert.doesNotMatch(page, /from authoring to activation/u);
    }
  }
});

test("wires generation and exposes the seven journeys in navigation", async () => {
  const packageJson = JSON.parse(
    await readFile(resolve(docsRoot, "package.json"), "utf8"),
  );
  assert.match(
    packageJson.scripts.generate,
    /node scripts\/generate-standard-journeys\.mjs/u,
  );
  assert(
    packageJson.scripts.generate.indexOf("scripts/fetch-openapi.mjs") <
      packageJson.scripts.generate.indexOf(
        "scripts/generate-standard-journeys.mjs",
      ),
    "standard journeys must derive from the freshly fetched OpenAPI source",
  );

  const astro = await readFile(resolve(docsRoot, "astro.config.mjs"), "utf8");
  for (const id of standardJourneyIds) {
    assert.match(astro, new RegExp(`slug: 'journeys/${id}'`, "u"));
  }
});

test("generation is byte-stable and check mode fails closed on drift", async () => {
  await withManifest(async ({ temporary }) => {
    const outputs = [
      join(temporary, "internal.json"),
      join(temporary, "public.json"),
    ];
    const first = await generateStandardJourneys(repoRoot, outputs);
    const second = await generateStandardJourneys(repoRoot, outputs);
    assert.equal(first, second);
    assert.equal(
      await readFile(outputs[0], "utf8"),
      await readFile(outputs[1], "utf8"),
    );
    await generateStandardJourneys(repoRoot, outputs, { check: true });

    await writeFile(outputs[1], "{}\n");
    await assert.rejects(
      generateStandardJourneys(repoRoot, outputs, { check: true }),
      /is stale/u,
    );
  });
});

test("the exact workflow command validates both committed generated outputs", async () => {
  await execFile(
    process.execPath,
    ["scripts/generate-standard-journeys.mjs", "--check"],
    { cwd: docsRoot },
  );
  assert.equal(
    await readFile(
      resolve(docsRoot, "src/data/generated/standard-journeys.json"),
      "utf8",
    ),
    await readFile(
      resolve(docsRoot, "public/generated/standard-journeys.json"),
      "utf8",
    ),
  );
});
