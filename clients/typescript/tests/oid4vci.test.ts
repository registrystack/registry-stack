import assert from 'node:assert/strict'
import test from 'node:test'
import { Client } from '../generated/evidence-oid4vci.ts'
import { createRegistryServerClient } from '../generated/services/breg-facility-all-products.ts'

test('createCredentialOffer sends a typed back-office request and decodes the offer', async () => {
  const body = { credentialConfigurationId: 'licence', subjects: [{ role: 'holder' }] }
  const offer = {
    credentialOffer: {
      credential_configuration_ids: ['licence'],
      credential_issuer: 'https://issuer.example.org',
      grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'fixture-code' } },
    },
    credentialOfferUri: 'openid-credential-offer://fixture',
    expiresIn: 60,
  }
  let dispatches = 0
  const registry = createRegistryServerClient({
    baseUrl: 'https://registry.example.org', token: () => 'fixture',
    fetch: async (url, init) => {
      dispatches++
      assert.equal(String(url), 'https://registry.example.org/offers')
      assert.equal(init?.method, 'POST')
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer fixture')
      assert.deepEqual(JSON.parse(String(init?.body)), body)
      return Response.json(offer, { status: 201 })
    },
  })
  const answer = await registry.oid4vci.call('createCredentialOffer', { body })
  assert.equal(answer.status, 201)
  assert.deepEqual(answer.data, offer)
  assert.equal(dispatches, 1)
})

function typeChecks(client: Client) {
  // @ts-expect-error the offer requires subjects
  void client.call('createCredentialOffer', { body: { credentialConfigurationId: 'licence' } })
  // @ts-expect-error health and readiness are ambiguous on the service base the modules share
  void client.call('health')
  // @ts-expect-error health and readiness are ambiguous on the service base the modules share
  void client.call('readiness')
  // @ts-expect-error wallet token exchange is outside the back-office client
  void client.call('redeemPreAuthorizedCode', { body: '' })
}
void typeChecks
