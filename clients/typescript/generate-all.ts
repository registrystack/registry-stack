import { fileURLToPath } from 'node:url'
import { generateFile } from './generate.ts'
import { generateServiceFile, type ServiceDescription } from './generate-service.ts'

const inputs = {
  casework: 'casework/generated/registry-casework.openapi.json',
  coordinator: 'coordinator/generated/openapi/coordinator.openapi.json',
  documents: 'documents/generated/registry-documents.openapi.json',
  evidence: 'evidence/generated/registry-evidence.openapi.json',
  'evidence-oid4vci': 'evidence/generated/registry-evidence-oid4vci.openapi.json',
  messaging: 'messaging/generated/registry-messaging.openapi.json',
  scheduling: 'scheduling/generated/registry-scheduling.openapi.json',
  'breg-minimal': 'breg/generated/minimal/generated/openapi.json',
  'breg-facility': 'breg/generated/facility/generated/openapi.json',
}

// Test documents for shapes no product document carries yet. Their clients sit beside them.
const fixtures = {
  'breg-list': 'tests/fixtures/breg-list.openapi.json',
}

// One generated example per service shape: a register and the products installed beside it.
const services: Record<string, ServiceDescription> = {
  'breg-facility-documents-casework-evidence': {
    register: 'breg-facility', products: ['documents', 'casework', 'evidence'],
    authorProfile: 'facility-correction-author',
  },
  'breg-minimal-casework': {
    register: 'breg-minimal', products: ['casework'],
    authorProfile: 'directory-editor',
  },
  'breg-facility-all-products': {
    register: 'breg-facility',
    authorProfile: 'facility-correction-author',
    products: ['casework', 'coordinator', 'documents', 'evidence', 'evidence-oid4vci', 'messaging', 'scheduling'],
  },
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

for (const [name, description] of Object.entries(services)) {
  try {
    generateServiceFile(description, fileURLToPath(new URL('./generated/services/' + name + '.ts', import.meta.url)),
      process.argv.includes('--check'))
  } catch (error) {
    console.error(name + ': ' + (error instanceof Error ? error.message : String(error)))
    process.exitCode = 1
  }
}
