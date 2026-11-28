import assert from 'node:assert/strict'
import test from 'node:test'

import * as tasks from '../tasks/index.ts'

test('the task index exports the helpers the per-service file attaches', () => {
  assert.equal(typeof tasks.proposalCommands, 'function')
  assert.equal(typeof tasks.documentCommands, 'function')
  assert.equal(typeof tasks.proposalStatus, 'function')
  assert.equal(typeof tasks.proposalFromServed, 'function')
  assert.equal(typeof tasks.saveBlob, 'function')
  assert.equal(typeof tasks.availabilityMessages, 'object')
})
