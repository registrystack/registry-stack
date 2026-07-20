import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

import YAML from 'yaml';

const workflowPath = resolve(import.meta.dirname, '../../../.github/workflows/docs-pages.yml');

async function loadWorkflow() {
  return YAML.parse(await readFile(workflowPath, 'utf8'));
}

test('docs deployment always builds current HEAD before assembling archives', async () => {
  const workflow = await loadWorkflow();
  const steps = workflow.jobs.build.steps;
  const currentIndex = steps.findIndex((step) => step.name === 'Build latest docs');
  const archiveIndex = steps.findIndex((step) => step.name === 'Build archived docs');

  assert.notEqual(currentIndex, -1);
  assert.notEqual(archiveIndex, -1);
  assert.ok(currentIndex < archiveIndex);
  assert.equal(steps[currentIndex].run, 'npm run build');
  assert.match(steps[archiveIndex].run, /build:archives:/);
});

test('push, schedule, and manual docs runs select the required archive modes', async () => {
  const workflow = await loadWorkflow();
  const archiveMode = workflow.on.workflow_dispatch.inputs.archive_mode;
  const modeStep = workflow.jobs.build.steps.find(
    (step) => step.name === 'Select archive build mode',
  );
  const keyStep = workflow.jobs.build.steps.find(
    (step) => step.name === 'Compute archive cache key',
  );
  const cacheStep = workflow.jobs.build.steps.find(
    (step) => step.name === 'Restore archived documentation cache',
  );

  assert.deepEqual(workflow.on.schedule, [{ cron: '0 3 * * 1' }]);
  assert.equal(archiveMode.default, 'full');
  assert.deepEqual(archiveMode.options, ['full', 'incremental']);
  assert.equal(modeStep.env.EVENT_NAME, '${{ github.event_name }}');
  assert.match(modeStep.run, /push\)\s+mode="incremental"/);
  assert.match(modeStep.run, /schedule\)\s+mode="full"/);
  assert.match(modeStep.run, /workflow_dispatch\)\s+mode="\$\{REQUESTED_MODE:-full\}"/);
  assert.deepEqual(Object.keys(keyStep.env).sort(), [
    'PUBLIC_UMAMI_DOMAINS',
    'PUBLIC_UMAMI_SCRIPT_SRC',
    'PUBLIC_UMAMI_WEBSITE_ID',
  ]);
  assert.equal(cacheStep.if, "steps.archives.outputs.mode == 'incremental'");
});
