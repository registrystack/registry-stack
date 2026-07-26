import { mkdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import YAML from "yaml";

import { buildProjectAuthoringJourneyMatrix } from "./generate-project-starters.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const docsRoot = resolve(scriptDirectory, "..");
const defaultRepoRoot = resolve(docsRoot, "../..");
const manifestRelative = "docs/site/src/data/standard-journeys.yaml";
const generatedRelative = "docs/site/src/data/generated/standard-journeys.json";
const publicGeneratedRelative =
  "docs/site/public/generated/standard-journeys.json";
const diagnosticCatalogs = [
  "docs/site/src/data/generated/diagnostics/authoring.json",
  "docs/site/src/data/generated/diagnostics/fixture.json",
  "docs/site/src/data/generated/diagnostics/operator.json",
];

export const standardJourneyIds = [
  "spreadsheet-protected-api",
  "instance-openapi",
  "bounded-http",
  "bounded-multi-call-script",
  "exact-snapshot",
  "registry-backed-notary-claim",
  "product-input-lifecycle",
];

export const standardJourneyHeadings = [
  "Outcome and prerequisites",
  "Smallest complete configuration",
  "Project tree and artifact ownership",
  "Synthetic fixture and expected trace",
  "Contract this journey proves",
  "Test, explain, compare, and build",
  "Review authored and generated artifacts",
  "What each gate proves",
  "Production delta",
  "Troubleshooting and next task",
];

const artifactClassifications = new Set([
  "authored",
  "environment_binding",
  "generated_unsigned",
  "generated_signed",
  "runtime_observed",
  "scaffolded_human_owned",
  "synthetic_fixture",
]);
const artifactOwners = new Set([
  "country_author",
  "registryctl",
  "registry_relay",
  "registry_notary",
  "operator",
]);
const evidenceClasses = new Set([
  "source_contract",
  "maintained_offline_fixture",
  "generated_contract",
  "source_and_generated_contract",
]);
const evidenceLifecycles = new Set(["main_unreleased"]);
const configurationFormats = new Set(["rhai", "scaffolded", "yaml"]);
const configurationBoundaries = new Set([
  "generated_template",
  "maintained_synthetic",
]);
const fixtureFormats = new Set(["generated_sample", "source_reference", "yaml"]);
const commandRecipeKinds = new Set([
  "instance_openapi",
  "matrix",
  "notary_claim",
  "product_input_lifecycle",
  "spreadsheet_runtime",
]);
const evidenceDimensions = ["extraction", "execution", "runtime"];
const evidenceStatuses = new Set(["not_claimed", "verified"]);
const catalogTypes = new Set([
  "project_authoring",
  "projects",
  "contracts",
]);
const stepKinds = new Set([
  "alternative",
  "command",
  "long_running",
  "operator_interface",
  "runtime_interface",
]);
const unsafeCommandPattern = /[\n\r;&|`<>]|\$\(/u;
const commandTokenPattern = /^[A-Za-z0-9][A-Za-z0-9._/:=-]*$/u;
const flagTokenPattern = /^--[a-z][a-z0-9-]*$/u;
const commandPrograms = new Set(["registryctl"]);
const credentialReferenceKeys = new Set([
  "api_key",
  "api_key_fingerprint",
  "api_token",
  "client_secret",
  "credential",
  "credentials",
  "private_key",
  "refresh_token",
  "secret_ref",
  "secret_refs",
  "signing_key",
  "token",
]);
const publicConfigurationSources = new Set([
  "crates/registryctl/assets/project-starters/bounded-http/environments/local.yaml",
  "crates/registryctl/assets/project-starters/bounded-http/integrations/person-record/integration.yaml",
  "crates/registryctl/assets/project-starters/bounded-http/registry-stack.yaml",
  "crates/registryctl/src/templates/notary_addon/environments/local.yaml",
  "crates/registryctl/src/templates/notary_addon/integrations/person-demographics/integration.yaml",
  "crates/registryctl/src/templates/notary_addon/registry-stack.yaml",
  "crates/registryctl/src/templates/relay_config.yaml.tmpl",
  "crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active/environments/local.yaml",
  "crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active/integrations/coverage/adapter.rhai",
  "crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active/integrations/coverage/integration.yaml",
  "crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active/registry-stack.yaml",
  "crates/registryctl/tests/fixtures/project-authoring/snapshot-exact/entities/people.yaml",
  "crates/registryctl/tests/fixtures/project-authoring/snapshot-exact/environments/local.yaml",
  "crates/registryctl/tests/fixtures/project-authoring/snapshot-exact/integrations/person-snapshot/integration.yaml",
  "crates/registryctl/tests/fixtures/project-authoring/snapshot-exact/registry-stack.yaml",
]);
const requiredConfigurationSources = new Map([
  [
    "spreadsheet-protected-api",
    ["crates/registryctl/src/templates/relay_config.yaml.tmpl"],
  ],
  [
    "instance-openapi",
    ["crates/registryctl/src/templates/relay_config.yaml.tmpl"],
  ],
  [
    "bounded-http",
    [
      "crates/registryctl/assets/project-starters/bounded-http/registry-stack.yaml",
      "crates/registryctl/assets/project-starters/bounded-http/environments/local.yaml",
      "crates/registryctl/assets/project-starters/bounded-http/integrations/person-record/integration.yaml",
    ],
  ],
  [
    "bounded-multi-call-script",
    [
      "crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active/registry-stack.yaml",
      "crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active/environments/local.yaml",
      "crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active/integrations/coverage/integration.yaml",
      "crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active/integrations/coverage/adapter.rhai",
    ],
  ],
  [
    "exact-snapshot",
    [
      "crates/registryctl/tests/fixtures/project-authoring/snapshot-exact/registry-stack.yaml",
      "crates/registryctl/tests/fixtures/project-authoring/snapshot-exact/environments/local.yaml",
      "crates/registryctl/tests/fixtures/project-authoring/snapshot-exact/entities/people.yaml",
      "crates/registryctl/tests/fixtures/project-authoring/snapshot-exact/integrations/person-snapshot/integration.yaml",
    ],
  ],
  [
    "registry-backed-notary-claim",
    [
      "crates/registryctl/src/templates/notary_addon/registry-stack.yaml",
      "crates/registryctl/src/templates/notary_addon/environments/local.yaml",
      "crates/registryctl/src/templates/notary_addon/integrations/person-demographics/integration.yaml",
    ],
  ],
  [
    "product-input-lifecycle",
    [
      "crates/registryctl/assets/project-starters/bounded-http/registry-stack.yaml",
      "crates/registryctl/assets/project-starters/bounded-http/environments/local.yaml",
      "crates/registryctl/assets/project-starters/bounded-http/integrations/person-record/integration.yaml",
    ],
  ],
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function object(value, path, allowed, required = allowed) {
  invariant(isPlainObject(value), `${path} must be an object`);
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  invariant(
    unknown.length === 0,
    `${path} contains unknown fields: ${unknown.join(", ")}`,
  );
  const missing = required.filter((key) => value[key] === undefined);
  invariant(
    missing.length === 0,
    `${path} is missing fields: ${missing.join(", ")}`,
  );
  return value;
}

function string(value, path) {
  invariant(
    typeof value === "string" && value.trim() !== "",
    `${path} must be a non-empty string`,
  );
  return value;
}

function stringArray(value, path, { minimum = 1 } = {}) {
  invariant(
    Array.isArray(value) && value.length >= minimum,
    `${path} must contain at least ${minimum} entries`,
  );
  value.forEach((entry, index) => string(entry, `${path}[${index}]`));
  invariant(
    new Set(value).size === value.length,
    `${path} must not contain duplicates`,
  );
  return value;
}

function boolean(value, path) {
  invariant(typeof value === "boolean", `${path} must be a boolean`);
  return value;
}

function enumValue(value, path, allowed) {
  string(value, path);
  invariant(allowed.has(value), `${path} has unsupported value ${value}`);
  return value;
}

function nullableString(value, path) {
  invariant(
    value === null || (typeof value === "string" && value.trim() !== ""),
    `${path} must be null or a non-empty string`,
  );
}

function validateAvailability(value, path) {
  object(value, path, ["status", "proof", "release"]);
  enumValue(value.status, `${path}.status`, new Set(["current_unreleased"]));
  enumValue(value.proof, `${path}.proof`, new Set(["source_tree"]));
  nullableString(value.release, `${path}.release`);
  invariant(
    value.release === null,
    `${path}.release must remain null for current unreleased source evidence`,
  );
}

function validateArtifact(entry, path) {
  object(entry, path, [
    "path",
    "classification",
    "owner",
    "human_edit",
    "version_control",
    "note",
  ]);
  string(entry.path, `${path}.path`);
  enumValue(
    entry.classification,
    `${path}.classification`,
    artifactClassifications,
  );
  enumValue(entry.owner, `${path}.owner`, artifactOwners);
  boolean(entry.human_edit, `${path}.human_edit`);
  boolean(entry.version_control, `${path}.version_control`);
  string(entry.note, `${path}.note`);
  const generatedOrRuntime = new Set([
    "generated_unsigned",
    "generated_signed",
    "runtime_observed",
  ]).has(entry.classification);
  invariant(
    entry.human_edit !== generatedOrRuntime,
    `${path}.human_edit conflicts with its artifact classification`,
  );
  if (
    entry.classification === "generated_signed" ||
    entry.classification === "runtime_observed"
  ) {
    invariant(
      entry.version_control === false,
      `${path}.version_control must be false for signed or runtime-observed artifacts`,
    );
  }
}

function validateGate(entry, path) {
  object(entry, path, ["name", "proves", "does_not_prove"]);
  string(entry.name, `${path}.name`);
  string(entry.proves, `${path}.proves`);
  string(entry.does_not_prove, `${path}.does_not_prove`);
}

function validateProductionDelta(value, path) {
  object(value, path, [
    "environment",
    "secrets",
    "approval",
    "signing",
    "activation",
  ]);
  for (const key of [
    "environment",
    "secrets",
    "approval",
    "signing",
    "activation",
  ]) {
    string(value[key], `${path}.${key}`);
  }
}

function validateEvidenceRecord(value, path) {
  object(value, path, [
    "status",
    "source_path",
    "test_id",
    "command",
    "workflow",
    "revision",
    "lifecycle",
  ]);
  enumValue(value.status, `${path}.status`, evidenceStatuses);
  for (const key of ["source_path", "test_id", "command", "workflow"]) {
    string(value[key], `${path}.${key}`);
  }
  invariant(
    value.workflow.includes("#"),
    `${path}.workflow must identify a workflow file and job`,
  );
  invariant(
    value.revision === "main",
    `${path}.revision must be main for unreleased source evidence`,
  );
  invariant(
    value.lifecycle === "current_unreleased",
    `${path}.lifecycle must be current_unreleased`,
  );
}

function validateJourney(journey, index) {
  const path = `journeys[${index}]`;
  object(journey, path, [
    "id",
    "slug",
    "title",
    "description",
    "outcome",
    "level",
    "prerequisites",
    "expected_time",
    "evidence_class",
    "evidence_lifecycle",
    "availability",
    "canonical_sources",
    "canonical_workspace",
    "catalog_references",
    "minimal_configuration",
    "artifacts",
    "fixture",
    "contract",
    "command_recipe",
    "review",
    "gates",
    "production_delta",
    "troubleshooting",
    "next_task",
    "evidence",
  ]);
  string(journey.id, `${path}.id`);
  string(journey.slug, `${path}.slug`);
  invariant(
    journey.slug === `journeys/${journey.id}`,
    `${path}.slug must match its id`,
  );
  for (const key of [
    "title",
    "description",
    "outcome",
    "level",
    "expected_time",
  ]) {
    string(journey[key], `${path}.${key}`);
  }
  stringArray(journey.prerequisites, `${path}.prerequisites`);
  enumValue(
    journey.evidence_class,
    `${path}.evidence_class`,
    evidenceClasses,
  );
  enumValue(
    journey.evidence_lifecycle,
    `${path}.evidence_lifecycle`,
    evidenceLifecycles,
  );
  validateAvailability(journey.availability, `${path}.availability`);
  stringArray(journey.canonical_sources, `${path}.canonical_sources`);
  object(journey.canonical_workspace, `${path}.canonical_workspace`, [
    "id",
    "path",
  ]);
  string(journey.canonical_workspace.id, `${path}.canonical_workspace.id`);
  string(journey.canonical_workspace.path, `${path}.canonical_workspace.path`);
  invariant(
    Array.isArray(journey.catalog_references) &&
      journey.catalog_references.length > 0,
    `${path}.catalog_references must contain at least one entry`,
  );
  journey.catalog_references.forEach((reference, referenceIndex) => {
    const referencePath = `${path}.catalog_references[${referenceIndex}]`;
    object(reference, referencePath, ["catalog", "id"]);
    enumValue(reference.catalog, `${referencePath}.catalog`, catalogTypes);
    string(reference.id, `${referencePath}.id`);
  });

  object(
    journey.minimal_configuration,
    `${path}.minimal_configuration`,
    ["files", "note"],
  );
  string(
    journey.minimal_configuration.note,
    `${path}.minimal_configuration.note`,
  );
  invariant(
    Array.isArray(journey.minimal_configuration.files) &&
      journey.minimal_configuration.files.length > 0,
    `${path}.minimal_configuration.files must contain a complete file set`,
  );
  for (const [fileIndex, file] of journey.minimal_configuration.files.entries()) {
    const filePath = `${path}.minimal_configuration.files[${fileIndex}]`;
    object(file, filePath, [
      "source",
      "destination",
      "format",
      "public_boundary",
    ]);
    string(file.source, `${filePath}.source`);
    string(file.destination, `${filePath}.destination`);
    enumValue(file.format, `${filePath}.format`, configurationFormats);
    enumValue(
      file.public_boundary,
      `${filePath}.public_boundary`,
      configurationBoundaries,
    );
    invariant(
      publicConfigurationSources.has(file.source),
      `${filePath}.source is not an explicitly approved public configuration source`,
    );
    invariant(
      journey.canonical_sources.includes(file.source),
      `${filePath}.source must also be a canonical source`,
    );
    invariant(
      (file.format === "scaffolded") ===
        (file.public_boundary === "generated_template"),
      `${filePath} must pair scaffolded format with generated_template boundary`,
    );
  }
  invariant(
    new Set(
      journey.minimal_configuration.files.map((file) => file.destination),
    ).size === journey.minimal_configuration.files.length,
    `${path}.minimal_configuration.files contains duplicate destinations`,
  );
  invariant(
    JSON.stringify(
      journey.minimal_configuration.files.map((file) => file.source),
    ) === JSON.stringify(requiredConfigurationSources.get(journey.id)),
    `${path}.minimal_configuration.files must contain the exact complete source set`,
  );

  invariant(
    Array.isArray(journey.artifacts) && journey.artifacts.length >= 3,
    `${path}.artifacts must contain at least three entries`,
  );
  journey.artifacts.forEach((entry, artifactIndex) =>
    validateArtifact(entry, `${path}.artifacts[${artifactIndex}]`),
  );
  invariant(
    new Set(journey.artifacts.map((entry) => entry.path)).size ===
      journey.artifacts.length,
    `${path}.artifacts contains duplicate paths`,
  );

  object(journey.fixture, `${path}.fixture`, [
    "source",
    "format",
    "expected_trace",
  ]);
  string(journey.fixture.source, `${path}.fixture.source`);
  enumValue(journey.fixture.format, `${path}.fixture.format`, fixtureFormats);
  stringArray(journey.fixture.expected_trace, `${path}.fixture.expected_trace`);

  object(journey.contract, `${path}.contract`, ["proves", "does_not_prove"]);
  stringArray(journey.contract.proves, `${path}.contract.proves`);
  stringArray(
    journey.contract.does_not_prove,
    `${path}.contract.does_not_prove`,
  );

  object(
    journey.command_recipe,
    `${path}.command_recipe`,
    ["kind", "matrix_id"],
    ["kind"],
  );
  enumValue(
    journey.command_recipe.kind,
    `${path}.command_recipe.kind`,
    commandRecipeKinds,
  );
  if (
    journey.command_recipe.kind === "matrix" ||
    journey.command_recipe.kind === "product_input_lifecycle"
  ) {
    string(
      journey.command_recipe.matrix_id,
      `${path}.command_recipe.matrix_id`,
    );
  } else {
    invariant(
      journey.command_recipe.matrix_id === undefined,
      `${path}.command_recipe.matrix_id is allowed only for matrix recipes`,
    );
  }

  stringArray(journey.review, `${path}.review`);
  invariant(
    Array.isArray(journey.gates) && journey.gates.length >= 3,
    `${path}.gates must contain at least three entries`,
  );
  journey.gates.forEach((entry, gateIndex) =>
    validateGate(entry, `${path}.gates[${gateIndex}]`),
  );
  validateProductionDelta(journey.production_delta, `${path}.production_delta`);
  stringArray(journey.troubleshooting, `${path}.troubleshooting`);

  object(journey.next_task, `${path}.next_task`, ["label", "href"]);
  string(journey.next_task.label, `${path}.next_task.label`);
  string(journey.next_task.href, `${path}.next_task.href`);
  invariant(
    journey.next_task.href.startsWith("/"),
    `${path}.next_task.href must be site-absolute`,
  );

  object(journey.evidence, `${path}.evidence`, evidenceDimensions);
  for (const dimension of evidenceDimensions) {
    validateEvidenceRecord(
      journey.evidence[dimension],
      `${path}.evidence.${dimension}`,
    );
  }
}

export function validateStandardJourneyManifest(manifest) {
  object(manifest, "manifest", ["schema_version", "journeys"]);
  invariant(
    manifest.schema_version === "registry.standard-journeys.v1",
    "manifest.schema_version must be registry.standard-journeys.v1",
  );
  invariant(
    Array.isArray(manifest.journeys),
    "manifest.journeys must be an array",
  );
  invariant(
    JSON.stringify(manifest.journeys.map((journey) => journey.id)) ===
      JSON.stringify(standardJourneyIds),
    `manifest must contain the seven standard journeys in order: ${standardJourneyIds.join(", ")}`,
  );
  manifest.journeys.forEach(validateJourney);
  return manifest;
}

async function parseYaml(path) {
  const source = await readFile(path, "utf8");
  const document = YAML.parseDocument(source, {
    strict: true,
    uniqueKeys: true,
  });
  invariant(
    document.errors.length === 0,
    `${path} is not valid YAML: ${document.errors.join("; ")}`,
  );
  return document.toJS();
}

function assertPublicSyntheticValue(value, path) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertPublicSyntheticValue(entry, `${path}[${index}]`),
    );
    return;
  }
  if (!isPlainObject(value)) return;
  if (Object.hasOwn(value, "secret")) {
    invariant(
      Object.keys(value).length === 1 &&
        typeof value.secret === "string" &&
        /^[A-Z][A-Z0-9_]*$/u.test(value.secret),
      `${path} secret reference must contain only one uppercase environment name`,
    );
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase();
    invariant(
      !["country", "jurisdiction", "password", "literal"].includes(
        normalizedKey,
      ),
      `${path} contains a non-public field ${key}`,
    );
    if (credentialReferenceKeys.has(normalizedKey)) {
      invariant(
        isPlainObject(entry),
        `${path}.${key} must use a structured credential reference`,
      );
    }
    assertPublicSyntheticValue(entry, `${path}.${key}`);
  }
}

export function validateStandardJourneyPublicValue(value) {
  assertPublicSyntheticValue(value, "public configuration");
  return value;
}

async function extractConfigurationFiles(repoRoot, journey) {
  const files = [];
  for (const file of journey.minimal_configuration.files) {
    if (file.format === "scaffolded") {
      files.push({
        ...file,
        language: null,
        content: null,
      });
      continue;
    }
    const sourcePath = resolve(repoRoot, file.source);
    if (file.format === "rhai") {
      files.push({
        ...file,
        language: "rhai",
        content: `${(await readFile(sourcePath, "utf8")).trimEnd()}\n`,
      });
      continue;
    }
    const source = await parseYaml(sourcePath);
    assertPublicSyntheticValue(source, `${journey.id}:${file.source}`);
    files.push({
      ...file,
      language: "yaml",
      content: YAML.stringify(source, {
        lineWidth: 0,
        sortMapEntries: true,
      }),
    });
  }
  return files;
}

async function extractFixture(repoRoot, fixture) {
  if (fixture.format === "generated_sample") {
    return {
      language: "text",
      content: `Generated synthetic sample: ${fixture.source}\n`,
    };
  }
  if (fixture.format === "source_reference") {
    return {
      language: "text",
      content: `Source-backed proof: ${fixture.source}\n`,
    };
  }
  const source = await parseYaml(resolve(repoRoot, fixture.source));
  assertPublicSyntheticValue(source, `${fixture.source} fixture excerpt`);
  return {
    language: "yaml",
    content: YAML.stringify(source, { lineWidth: 0, sortMapEntries: true }),
  };
}

function commandStep(id, label, command, cwd = ".") {
  return {
    id,
    kind: "command",
    label,
    cwd,
    argv: command.split(/\s+/u),
  };
}

function longRunningStep(id, label, command, cwd, note) {
  return {
    id,
    kind: "long_running",
    label,
    cwd,
    argv: command.split(/\s+/u),
    note,
  };
}

function matrixSteps(journey, matrixEntry) {
  const steps = [];
  let commandIndex = 0;
  for (const command of matrixEntry.commands) {
    const argv = command.split(/\s+/u);
    const operation =
      argv[1] === "authoring" ? `${argv[1]}-${argv[2]}` : argv[1];
    if (command.includes(" --watch")) {
      steps.push(
        longRunningStep(
          `${journey.id}-${operation}`,
          "Optional watch loop",
          command,
          ".",
          "This long-running alternative reruns the focused synthetic fixture after authored files change. It is not part of the required noninteractive sequence.",
        ),
      );
      continue;
    }
    if (operation === "compare") {
      steps.push(
        commandStep(
          `${journey.id}-semantic-comparison`,
          "Compare authored semantics with the embedded starter",
          command,
        ),
      );
      continue;
    }
    steps.push(
      commandStep(
        `${journey.id}-${operation}-${commandIndex}`,
        `Required ${operation.replaceAll("-", " ")} step`,
        command,
      ),
    );
    commandIndex += 1;
  }
  const checkIndex = steps.findIndex(
    (step) => step.kind === "command" && step.argv[1] === "check",
  );
  invariant(checkIndex >= 0, `${journey.id} matrix must contain check`);
  invariant(
    matrixEntry.starter !== undefined,
    `${journey.id} semantic comparison requires starter provenance`,
  );
  const expectedComparison = [
    "registryctl",
    "compare",
    "--project-dir",
    matrixEntry.project_dir,
    "--environment",
    "local",
    "--from-starter",
  ];
  let comparisonIndexes = steps.flatMap((step, index) =>
    step.kind === "command" && step.argv[1] === "compare" ? [index] : [],
  );
  invariant(
    comparisonIndexes.length <= 1,
    `${journey.id} matrix must contain at most one starter comparison`,
  );
  if (comparisonIndexes.length === 0) {
    steps.splice(
      checkIndex + 1,
      0,
      commandStep(
        `${journey.id}-semantic-comparison`,
        "Compare authored semantics with the embedded starter",
        expectedComparison.join(" "),
      ),
    );
    comparisonIndexes = [checkIndex + 1];
  }
  const comparison = steps[comparisonIndexes[0]];
  invariant(
    comparison.argv.length === expectedComparison.length &&
      comparison.argv.every(
        (argument, index) => argument === expectedComparison[index],
      ),
    `${journey.id} starter comparison must use the exact local embedded-starter command`,
  );
  invariant(
    comparisonIndexes[0] === checkIndex + 1,
    `${journey.id} starter comparison must immediately follow check`,
  );
  const buildIndex = steps.findIndex(
    (step) => step.kind === "command" && step.argv[1] === "build",
  );
  invariant(
    buildIndex > comparisonIndexes[0],
    `${journey.id} starter comparison must precede build`,
  );
  return steps;
}

function buildSteps(journey, matrixById) {
  const recipe = journey.command_recipe;
  if (recipe.kind === "spreadsheet_runtime") {
    return [
      commandStep(
        "spreadsheet-init",
        "Create the disposable spreadsheet scaffold",
        "registryctl init relay my-first-api --sample benefits",
      ),
      {
        id: "spreadsheet-doctor",
        kind: "alternative",
        label: "Product doctor",
        cwd: "my-first-api",
        argv: ["registryctl", "doctor", "--profile", "local"],
        note: "Run after the source-built product commands and Docker provider are available.",
      },
      longRunningStep(
        "spreadsheet-start",
        "Start the disposable local runtime",
        "registryctl start",
        "my-first-api",
        "This is a long-running runtime boundary and is exercised by the source tutorial gate, not the clean-temp authoring sequence.",
      ),
      {
        id: "spreadsheet-smoke",
        kind: "alternative",
        label: "Runtime smoke after readiness",
        cwd: "my-first-api",
        argv: ["registryctl", "smoke"],
        note: "Run only after the local runtime reports ready.",
      },
    ];
  }
  if (recipe.kind === "instance_openapi") {
    return [
      commandStep(
        "openapi-init",
        "Create the disposable local instance",
        "registryctl init relay openapi-inspection --sample benefits",
      ),
      longRunningStep(
        "openapi-start",
        "Start the disposable local instance",
        "registryctl start",
        "openapi-inspection",
        "The generated local sample explicitly opts out of OpenAPI authentication. Product defaults remain authentication-gated.",
      ),
      {
        id: "openapi-capture",
        kind: "runtime_interface",
        label: "Capture the disposable instance contract",
        method: "GET",
        url: "http://127.0.0.1:4242/openapi.json",
        authentication: "none_disposable_local_opt_out",
        output_path: "openapi-inspection/output/instance.openapi.json",
        note: "Use an HTTP client that preserves the response bytes. This interface is public only because the generated disposable local configuration sets server.openapi_requires_auth to false.",
      },
      {
        id: "openapi-consumer-review",
        kind: "operator_interface",
        label: "Consumer contract comparison",
        inputs: [
          "Captured openapi-inspection/output/instance.openapi.json",
          "Consumer-owned reviewed baseline and compatibility policy",
        ],
        outputs: ["Consumer-owned compatibility decision"],
        procedure:
          "Compare the captured bytes using the consumer's reviewed compatibility tool. Registry Stack does not turn an external baseline into an executable shell placeholder.",
      },
    ];
  }
  if (recipe.kind === "notary_claim") {
    return [
      commandStep(
        "notary-init",
        "Create the disposable Relay scaffold",
        "registryctl init relay my-first-api --sample benefits",
      ),
      commandStep(
        "notary-add",
        "Add the maintained Notary project",
        "registryctl add notary",
        "my-first-api",
      ),
      commandStep(
        "notary-test",
        "Execute every Notary project fixture offline",
        "registryctl test --project-dir my-first-api/notary/project",
      ),
      commandStep(
        "notary-check",
        "Check and explain the combined project",
        "registryctl check --project-dir my-first-api/notary/project --environment local --explain",
      ),
      commandStep(
        "notary-build",
        "Build separate unsigned product inputs",
        "registryctl build --project-dir my-first-api/notary/project --environment local",
      ),
      longRunningStep(
        "notary-start",
        "Start the combined disposable runtime",
        "registryctl start",
        "my-first-api",
        "This runtime step is exercised by the source tutorial gate and remains separate from the required clean-temp sequence.",
      ),
    ];
  }

  const matrixEntry = matrixById.get(recipe.matrix_id);
  invariant(
    matrixEntry !== undefined,
    `${journey.id} references unknown command matrix id ${recipe.matrix_id}`,
  );
  const steps = matrixSteps(journey, matrixEntry);
  if (recipe.kind !== "product_input_lifecycle") return steps;
  const comparisonIndex = steps.findIndex(
    (step) => step.kind === "command" && step.argv[1] === "compare",
  );
  invariant(
    comparisonIndex >= 0,
    `${journey.id} lifecycle must contain starter comparison`,
  );
  steps.splice(
    comparisonIndex + 1,
    0,
    {
      id: "lifecycle-preflight",
      kind: "alternative",
      label: "Inspect offline environment readiness",
      cwd: ".",
      argv: [
        "registryctl",
        "preflight",
        "--project-dir",
        matrixEntry.project_dir,
        "--environment",
        "local",
      ],
      note: "Preflight is intentionally separate because a clean synthetic workspace can report missing operator-provisioned runtime files or secret references.",
    },
    commandStep(
      "lifecycle-capabilities",
      "Inspect declared and available capabilities",
      `registryctl capabilities --project-dir ${matrixEntry.project_dir} --environment local`,
    ),
  );
  return [
    ...steps,
    {
      id: "lifecycle-governed-promotion-review",
      kind: "operator_interface",
      label: "Review against governed product baselines",
      inputs: [
        "Separately verified Relay baseline bundle and Relay trust anchor",
        "Separately verified Notary baseline bundle and Notary trust anchor",
      ],
      outputs: ["Value-safe promotion report and required-action review"],
      procedure:
        "Only after operators supply both product-owned baseline paths and trust anchors, use the registryctl promote lifecycle interface for the fixed project directory and local environment. This governed review is separate from the first-time starter comparison and does not authorize activation.",
    },
    {
      id: "lifecycle-relay-bundle",
      kind: "operator_interface",
      label: "Sign and verify the Relay product input",
      inputs: [
        "registry-project/.registry-stack/build/local/private/relay",
        "Operator-selected Relay signing key",
        "Operator-selected Relay trust anchor and anti-rollback sequence",
      ],
      outputs: ["journey-output/registry-relay-bundle"],
      procedure:
        "Use registryctl bundle sign with --out journey-output/registry-relay-bundle, then verify that directory with the product-owned Relay trust anchor. Signing material is never rendered into a shell block.",
    },
    {
      id: "lifecycle-notary-bundle",
      kind: "operator_interface",
      label: "Sign and verify the Notary product input",
      inputs: [
        "registry-project/.registry-stack/build/local/private/notary",
        "Operator-selected Notary signing key",
        "Operator-selected Notary trust anchor and anti-rollback sequence",
      ],
      outputs: ["journey-output/registry-notary-bundle"],
      procedure:
        "Use registryctl bundle sign with --out journey-output/registry-notary-bundle, then verify that directory with the product-owned Notary trust anchor. This does not claim product activation.",
    },
  ];
}

function validateCommandArgv(argv, path) {
  invariant(
    Array.isArray(argv) && argv.length > 0,
    `${path} must contain command arguments`,
  );
  argv.forEach((token, index) => string(token, `${path}[${index}]`));
  invariant(
    commandPrograms.has(argv[0]),
    `${path} invokes an unsupported program`,
  );
  invariant(
    argv.every(
      (token) =>
        commandTokenPattern.test(token) ||
        flagTokenPattern.test(token),
    ),
    `${path} contains an unsafe command token`,
  );
  invariant(
    !unsafeCommandPattern.test(argv.join(" ")),
    `${path} contains an unsafe command token`,
  );
}

function validateStep(step, path) {
  invariant(isPlainObject(step), `${path} must be an object`);
  enumValue(step.kind, `${path}.kind`, stepKinds);
  string(step.id, `${path}.id`);
  string(step.label, `${path}.label`);
  if (["command", "alternative", "long_running"].includes(step.kind)) {
    const fields =
      step.kind === "command"
        ? ["id", "kind", "label", "cwd", "argv"]
        : ["id", "kind", "label", "cwd", "argv", "note"];
    object(step, path, fields);
    safeRelativePath(step.cwd, `${path}.cwd`, { allowDot: true });
    validateCommandArgv(step.argv, `${path}.argv`);
    if (step.kind !== "command") string(step.note, `${path}.note`);
    return;
  }
  if (step.kind === "runtime_interface") {
    object(step, path, [
      "id",
      "kind",
      "label",
      "method",
      "url",
      "authentication",
      "output_path",
      "note",
    ]);
    invariant(step.method === "GET", `${path}.method must be GET`);
    invariant(
      step.authentication === "none_disposable_local_opt_out",
      `${path}.authentication must identify the disposable local public opt-out`,
    );
    string(step.url, `${path}.url`);
    safeRelativePath(step.output_path, `${path}.output_path`);
    string(step.note, `${path}.note`);
    return;
  }
  object(step, path, [
    "id",
    "kind",
    "label",
    "inputs",
    "outputs",
    "procedure",
  ]);
  stringArray(step.inputs, `${path}.inputs`);
  stringArray(step.outputs, `${path}.outputs`);
  string(step.procedure, `${path}.procedure`);
}

export function validateStandardJourneyCommand(command) {
  const rendered = Array.isArray(command) ? command.join(" ") : command;
  string(rendered, "command");
  invariant(
    !unsafeCommandPattern.test(rendered),
    "command contains an unsafe command token",
  );
  validateCommandArgv(
    Array.isArray(command) ? command : command.split(/\s+/u),
    "command",
  );
}

export function renderStandardJourneyCommand(step) {
  invariant(
    ["command", "alternative", "long_running"].includes(step.kind),
    `${step.id} is not a command-bearing step`,
  );
  validateCommandArgv(step.argv, `${step.id}.argv`);
  return step.argv.join(" ");
}

async function loadDiagnosticEntries(repoRoot) {
  const entries = [];
  for (const relativePath of diagnosticCatalogs) {
    const catalog = JSON.parse(
      await readFile(resolve(repoRoot, relativePath), "utf8"),
    );
    invariant(
      Array.isArray(catalog.entries),
      `${relativePath} does not contain entries`,
    );
    entries.push(...catalog.entries);
  }
  const byCode = new Map();
  for (const entry of entries) {
    invariant(
      !byCode.has(entry.code),
      `diagnostic code ${entry.code} is duplicated across catalogs`,
    );
    byCode.set(entry.code, entry);
  }
  return byCode;
}

function safeRelativePath(value, path, { allowDot = false } = {}) {
  string(value, path);
  const segments = value.split(/[\\/]/u);
  invariant(
    !isAbsolute(value) &&
      !value.startsWith("-") &&
      ((allowDot && value === ".") ||
        (value !== "." &&
          segments.every(
            (segment) =>
              segment !== "" && segment !== ".." && segment !== ".",
          ))),
    `${path} must be a safe repository-relative path`,
  );
}

async function canonicalRepositoryPath(repoRoot, relativePath, path, kind) {
  safeRelativePath(relativePath, path);
  const root = await realpath(repoRoot);
  const candidate = await realpath(resolve(root, relativePath));
  invariant(
    candidate === root || candidate.startsWith(`${root}${sep}`),
    `${path} resolves outside the repository`,
  );
  const metadata = await stat(candidate);
  invariant(
    (kind === "file" && metadata.isFile()) ||
      (kind === "directory" && metadata.isDirectory()),
    `${path} must resolve to a ${kind}`,
  );
  return candidate;
}

async function assertCanonicalSources(repoRoot, journey) {
  const paths = [
    ...journey.canonical_sources,
    ...journey.minimal_configuration.files.map((file) => file.source),
    journey.fixture.source,
  ];
  for (const [index, relativePath] of paths.entries()) {
    await canonicalRepositoryPath(
      repoRoot,
      relativePath,
      `${journey.id}.canonical_source[${index}]`,
      "file",
    );
  }
  await canonicalRepositoryPath(
    repoRoot,
    journey.canonical_workspace.path,
    `${journey.id}.canonical_workspace.path`,
    "directory",
  );
}

async function assertEvidenceRecords(repoRoot, journey) {
  for (const dimension of evidenceDimensions) {
    const record = journey.evidence[dimension];
    const source = await canonicalRepositoryPath(
      repoRoot,
      record.source_path,
      `${journey.id}.evidence.${dimension}.source_path`,
      "file",
    );
    const sourceContent = await readFile(source, "utf8");
    invariant(
      sourceContent.includes(record.test_id),
      `${journey.id}.evidence.${dimension}.test_id does not resolve in ${record.source_path}`,
    );
    const [workflowPath, workflowJob] = record.workflow.split("#");
    invariant(
      workflowJob !== undefined && workflowJob !== "",
      `${journey.id}.evidence.${dimension}.workflow must name a job`,
    );
    const workflow = await canonicalRepositoryPath(
      repoRoot,
      workflowPath,
      `${journey.id}.evidence.${dimension}.workflow`,
      "file",
    );
    const workflowContent = await readFile(workflow, "utf8");
    invariant(
      workflowContent.includes(`\n  ${workflowJob}:`),
      `${journey.id}.evidence.${dimension}.workflow job ${workflowJob} does not resolve`,
    );
  }
}

async function loadCatalogIds(repoRoot, matrix) {
  const projects = JSON.parse(
    await readFile(
      resolve(repoRoot, "docs/site/src/data/generated/projects.json"),
      "utf8",
    ),
  );
  const contracts = JSON.parse(
    await readFile(
      resolve(repoRoot, "docs/site/src/data/generated/contracts.json"),
      "utf8",
    ),
  );
  return {
    project_authoring: new Set(matrix.map((entry) => entry.id)),
    projects: new Set(projects.map((entry) => entry.id)),
    contracts: new Set(contracts.map((entry) => entry.id)),
  };
}

function assertCatalogReferences(journey, catalogIds) {
  invariant(
    Object.values(catalogIds).some((ids) =>
      ids.has(journey.canonical_workspace.id),
    ),
    `${journey.id}.canonical_workspace.id does not resolve current catalogs`,
  );
  for (const reference of journey.catalog_references) {
    invariant(
      catalogIds[reference.catalog].has(reference.id),
      `${journey.id} catalog reference ${reference.catalog}:${reference.id} does not resolve`,
    );
  }
}

export async function buildStandardJourneys(
  repoRoot = defaultRepoRoot,
  manifestPath = manifestRelative,
) {
  const manifest = validateStandardJourneyManifest(
    await parseYaml(resolve(repoRoot, manifestPath)),
  );
  const matrix = await buildProjectAuthoringJourneyMatrix(repoRoot);
  const matrixById = new Map(matrix.map((entry) => [entry.id, entry]));
  const catalogIds = await loadCatalogIds(repoRoot, matrix);
  const diagnosticsByCode = await loadDiagnosticEntries(repoRoot);
  const output = [];

  for (const journey of manifest.journeys) {
    await assertCanonicalSources(repoRoot, journey);
    await assertEvidenceRecords(repoRoot, journey);
    assertCatalogReferences(journey, catalogIds);
    const troubleshooting = journey.troubleshooting.map((code) => {
      const entry = diagnosticsByCode.get(code);
      invariant(
        entry !== undefined,
        `${journey.id} references unknown diagnostic code ${code}`,
      );
      return {
        code,
        family: entry.family,
        product: entry.product,
        meaning: entry.safe_meaning,
        remediation: entry.safe_remediation,
        docs_anchor: entry.docs_anchor,
        lifecycle: entry.lifecycle,
        introduced_in: entry.introduced_in,
        evidence_limitation: entry.evidence_limitation,
      };
    });
    const steps = buildSteps(journey, matrixById);
    steps.forEach((step, index) =>
      validateStep(step, `${journey.id}.steps[${index}]`),
    );
    invariant(
      new Set(steps.map((step) => step.id)).size === steps.length,
      `${journey.id}.steps contains duplicate ids`,
    );
    output.push({
      ...journey,
      source_label: "Main source (unreleased)",
      section_headings: standardJourneyHeadings,
      configuration_files: await extractConfigurationFiles(repoRoot, journey),
      fixture_excerpt: await extractFixture(repoRoot, journey.fixture),
      steps,
      troubleshooting,
    });
  }
  return output;
}

export async function generateStandardJourneys(
  repoRoot = defaultRepoRoot,
  outputPaths = [generatedRelative, publicGeneratedRelative],
  { check = false } = {},
) {
  const journeys = await buildStandardJourneys(repoRoot);
  const content = `${JSON.stringify(journeys, null, 2)}\n`;
  const destinations = (Array.isArray(outputPaths) ? outputPaths : [outputPaths]).map(
    (outputPath) =>
      isAbsolute(outputPath) ? outputPath : resolve(repoRoot, outputPath),
  );
  for (const destination of destinations) {
    if (check) {
      let committed;
      try {
        committed = await readFile(destination, "utf8");
      } catch (error) {
        if (error?.code === "ENOENT") {
          throw new Error(
            `${relative(repoRoot, destination)} is missing; run generate-standard-journeys.mjs`,
          );
        }
        throw error;
      }
      invariant(
        committed === content,
        `${relative(repoRoot, destination)} is stale; run generate-standard-journeys.mjs`,
      );
    } else {
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, content);
    }
  }
  if (!check) {
    console.log(`Generated ${journeys.length} normalized standard journeys.`);
  }
  return content;
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const args = process.argv.slice(2);
  invariant(
    args.every((argument) => argument === "--check") &&
      args.filter((argument) => argument === "--check").length <= 1,
    "usage: node scripts/generate-standard-journeys.mjs [--check]",
  );
  await generateStandardJourneys(defaultRepoRoot, undefined, {
    check: args.includes("--check"),
  });
}
