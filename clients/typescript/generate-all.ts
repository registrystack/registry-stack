import { fileURLToPath } from 'node:url'
import { generateFile } from './generate.ts'

const inputs = {
  casework: 'casework/generated/registry-casework.openapi.json',
  coordinator: 'coordinator/generated/openapi/coordinator.openapi.json',
  documents: 'documents/generated/registry-documents.openapi.json',
  evidence: 'evidence/generated/registry-evidence.openapi.json',
  messaging: 'messaging/generated/registry-messaging.openapi.json',
  scheduling: 'scheduling/generated/registry-scheduling.openapi.json',
  'breg-minimal': 'breg/generated/minimal/generated/openapi.json',
  'breg-facility': 'breg/generated/facility/generated/openapi.json',
}

// Test documents for shapes no product document carries yet. Their clients sit beside them.
const fixtures = {
  'breg-list': 'tests/fixtures/breg-list.openapi.json',
}

const sources = [
  ...Object.entries(inputs).map(([name, path]) =>
    [name, '../../products/' + path, './generated/' + name + '.ts'] as const),
  ...Object.entries(fixtures).map(([name, path]) =>
    [name, './' + path, './tests/fixtures/' + name + '.ts'] as const),
]

for (const [name, source, output] of sources) {
  try {
    generateFile(
      fileURLToPath(new URL(source, import.meta.url)),
      fileURLToPath(new URL(output, import.meta.url)),
      process.argv.includes('--check'), name.startsWith('breg-'),
    )
  } catch (error) {
    console.error(name + ': ' + (error instanceof Error ? error.message : String(error)))
    process.exitCode = 1
  }
}
