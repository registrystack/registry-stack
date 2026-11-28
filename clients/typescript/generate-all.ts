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

for (const [name, path] of Object.entries(inputs)) {
  try {
    generateFile(
      fileURLToPath(new URL('../../products/' + path, import.meta.url)),
      fileURLToPath(new URL('./generated/' + name + '.ts', import.meta.url)),
      process.argv.includes('--check'), name.startsWith('breg-'),
    )
  } catch (error) {
    console.error(name + ': ' + (error instanceof Error ? error.message : String(error)))
    process.exitCode = 1
  }
}
