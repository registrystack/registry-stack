import test from 'node:test'
import assert from 'node:assert/strict'
import { Client as MinimalClient, createRegistryClient as createMinimalClient } from '../generated/breg-minimal.ts'
import { Client as FacilityClient, createRegistryClient as createFacilityClient } from '../generated/breg-facility.ts'

const options = { baseUrl: 'http://localhost', token: () => 'fixture' }

test('each registry module builds its own client under the one factory name', () => {
  assert.ok(createMinimalClient(options) instanceof MinimalClient)
  assert.ok(createFacilityClient(options) instanceof FacilityClient)
  assert.ok(!(createFacilityClient(options) instanceof MinimalClient))
})

// Type-checked by `npm run check:types`, never called: each factory is typed to its own
// registry's operations.
export function typedToItsOwnContract(): void {
  const minimal: MinimalClient = createMinimalClient(options)
  const facility: FacilityClient = createFacilityClient(options)
  void minimal.records_contact_listPage()
  // @ts-expect-error the facility registry has no contact records
  void facility.records_contact_listPage()
  // @ts-expect-error the minimal registry has no register-facility action
  void minimal.call('actions.register-facility.invoke', { body: { input: {} } })
}
