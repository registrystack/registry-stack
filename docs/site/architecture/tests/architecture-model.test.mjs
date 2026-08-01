import assert from 'node:assert/strict'
import { access, readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { LikeC4 } from 'likec4'

const testsDirectory = path.dirname(fileURLToPath(import.meta.url))
const architectureDirectory = path.resolve(testsDirectory, '..')
const repositoryDirectory = path.resolve(architectureDirectory, '..', '..', '..')
const likec4 = await LikeC4.fromWorkspace(architectureDirectory, {
  logger: false,
  throwIfInvalid: true,
})
const model = likec4.computedModel()
const relationships = [...model.relationships()]

after(async () => {
  await likec4.dispose()
})

function relationsFrom(elementId, kind) {
  return relationships.filter(
    relation => relation.source.id === elementId && (!kind || relation.kind === kind),
  )
}

function relationsTo(elementId, kind) {
  return relationships.filter(
    relation => relation.target.id === elementId && (!kind || relation.kind === kind),
  )
}

async function c4Files(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = await Promise.all(entries.map(async entry => {
    const entryPath = path.join(directory, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'tests') {
        return []
      }
      return c4Files(entryPath)
    }
    return entry.name.endsWith('.c4') ? [entryPath] : []
  }))
  return files.flat()
}

async function filesWithExtension(directory, extension) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = await Promise.all(entries.map(async entry => {
    const entryPath = path.join(directory, entry.name)
    if (entry.isDirectory()) {
      return filesWithExtension(entryPath, extension)
    }
    return entry.name.endsWith(extension) ? [entryPath] : []
  }))
  return files.flat()
}

function relationBetween(sourceId, targetId, kind) {
  return relationships.find(
    relation =>
      relation.source.id === sourceId
      && relation.target.id === targetId
      && (!kind || relation.kind === kind),
  )
}

test('the model contains the C4 hierarchy and supporting views', () => {
  const expectedViews = new Map([
    ['delegatedEvaluation', ['dynamic', 'softwareSystemDynamicView']],
    ['index', ['element', 'portfolioView']],
    ['notaryComponents', ['element', 'componentView']],
    ['notaryContainers', ['element', 'containerView']],
    ['notaryContext', ['element', 'systemContextView']],
    ['notaryIssuanceCode', ['element', 'codeView']],
    ['protectedRegistryApi', ['dynamic', 'softwareSystemDynamicView']],
    ['registryBackedIssuance', ['dynamic', 'softwareSystemDynamicView']],
    ['relayComponents', ['element', 'componentView']],
    ['relayContainers', ['element', 'containerView']],
    ['relayContext', ['element', 'systemContextView']],
    ['relayProtectedReadCode', ['element', 'codeView']],
    ['singleNodeDeployment', ['deployment', 'deploymentView']],
  ])

  assert.deepEqual([...model.views()].map(view => view.id).sort(), [...expectedViews.keys()].sort())

  for (const [viewId, [viewType, tag]] of expectedViews) {
    const view = model.view(viewId)
    assert.equal(view._type, viewType)
    assert.equal(view.tags.includes(tag), true, `${viewId} must carry #${tag}`)
  }
})

test('C4 views form two explicit system-to-code zoom paths', () => {
  const scopedViews = new Map([
    ['relayContext', 'registryStack.relay'],
    ['relayContainers', 'registryStack.relay'],
    ['relayComponents', 'registryStack.relay.server'],
    ['relayProtectedReadCode', 'registryStack.relay.server.protectedRead'],
    ['notaryContext', 'registryStack.notary'],
    ['notaryContainers', 'registryStack.notary'],
    ['notaryComponents', 'registryStack.notary.server'],
    ['notaryIssuanceCode', 'registryStack.notary.server.issuance'],
  ])

  for (const [viewId, scopeId] of scopedViews) {
    assert.equal(model.view(viewId).viewOf?.id, scopeId, `${viewId} must scope ${scopeId}`)
  }

  const levelKinds = new Map([
    [
      'systemContextView',
      new Set(['actor', 'externalSystem', 'offlineApplication', 'softwareSystem']),
    ],
    ['containerView', new Set(['container', 'dataStore', 'softwareSystem', 'externalSystem'])],
    [
      'componentView',
      new Set(['component', 'container', 'dataStore', 'softwareSystem', 'externalSystem']),
    ],
    ['codeView', new Set(['component', 'codeElement'])],
  ])

  for (const view of model.views()) {
    const levelTag = [...levelKinds.keys()].find(tag => view.tags.includes(tag))
    if (!levelTag) {
      continue
    }

    for (const node of view.nodes()) {
      if (!node.hasElement()) {
        continue
      }
      assert.equal(
        levelKinds.get(levelTag).has(node.element.kind),
        true,
        `${view.id} must not mix ${node.element.kind} into #${levelTag}`,
      )
    }
  }
})

test('C4 views contain no unexplained unconnected elements', () => {
  const c4ViewTags = new Set([
    'systemContextView',
    'containerView',
    'componentView',
    'codeView',
  ])

  for (const view of model.views()) {
    if (!view.tags.some(tag => c4ViewTags.has(tag))) {
      continue
    }

    const connectedIds = new Set(
      [...view.edges()].flatMap(edge => [edge.source.id, edge.target.id]),
    )
    const viewElements = [...view.nodes()]
      .filter(node => node.hasElement())
      .map(node => node.element)
    for (const node of view.nodes()) {
      if (!node.hasElement() || node.element.id === view.viewOf?.id) {
        continue
      }
      const containsVisibleDescendant = viewElements.some(element => {
        let parent = element.parent
        while (parent) {
          if (parent.id === node.element.id) {
            return true
          }
          parent = parent.parent
        }
        return false
      })
      if (containsVisibleDescendant) {
        continue
      }
      assert.equal(
        connectedIds.has(node.id),
        true,
        `${view.id} contains unconnected element ${node.element.id}`,
      )
    }
  }
})

test('containers, components, and selected code elements declare technology and evidence', async () => {
  const c4Elements = [...model.elements()].filter(element =>
    ['container', 'dataStore', 'component', 'codeElement'].includes(element.kind),
  )

  for (const element of c4Elements) {
    assert.ok(element.technology, `${element.id} must declare its technology`)
    assert.ok(element.getMetadata('evidence'), `${element.id} must declare evidence`)
  }

  for (const codeElement of c4Elements.filter(element => element.kind === 'codeElement')) {
    const evidence = codeElement.getMetadata('evidence')
    const symbol = codeElement.getMetadata('symbol')

    assert.ok(symbol, `${codeElement.id} must name its source symbol`)
    const source = await readFile(path.join(repositoryDirectory, evidence), 'utf8')
    assert.equal(
      source.includes(symbol),
      true,
      `${codeElement.id} symbol ${symbol} must exist in ${evidence}`,
    )
  }
})

test('the portfolio view excludes deployment-only infrastructure', () => {
  const portfolioElements = [...model.view('index').nodes()]
    .filter(node => node.hasElement())
    .map(node => node.element.id)
    .sort()

  assert.deepEqual(portfolioElements, [
    'decisionOwner',
    'evidenceConsumer',
    'registryStack',
    'registryStack.manifest',
    'registryStack.notary',
    'registryStack.platform',
    'registryStack.relay',
    'registryctl',
    'solmaraLab',
  ])
})

test('formal products carry explicit C4 roles, ownership, and evidence metadata', () => {
  const formalProducts = [...model.elements()].filter(element => element.isTagged('formalProduct'))

  assert.deepEqual(
    Object.fromEntries(formalProducts.map(element => [element.id, element.kind])),
    {
      'registryStack.platform': 'supportingLibrary',
      'registryStack.manifest': 'offlineApplication',
      'registryStack.relay': 'softwareSystem',
      'registryStack.notary': 'softwareSystem',
    },
  )

  for (const product of formalProducts) {
    assert.ok(product.getMetadata('sourceRepo'), `${product.id} must name its source repository`)
    assert.ok(product.getMetadata('evidence'), `${product.id} must name architecture evidence`)
  }
})

test('logical elements and relationships carry resolvable evidence', async () => {
  const specDirectory = path.join(repositoryDirectory, 'docs/site/src/content/docs/spec')
  const specificationSources = await Promise.all(
    (await filesWithExtension(specDirectory, '.mdx')).map(filename => readFile(filename, 'utf8')),
  )

  const evidenceOwners = [
    ...[...model.elements()].map(element => [element.id, element.getMetadata('evidence')]),
    ...relationships.map(relation => [
      `${relation.source.id} -> ${relation.target.id}`,
      relation.getMetadata('evidence'),
    ]),
    ...[...model.deployment.relationships()].map(relation => [
      `${relation.source.id} -> ${relation.target.id}`,
      relation.getMetadata('evidence'),
    ]),
  ]

  for (const [owner, evidence] of evidenceOwners) {
    assert.ok(evidence, `${owner} must name evidence`)

    for (const reference of evidence.split(',').map(value => value.trim())) {
      if (reference.startsWith('REQ-')) {
        assert.equal(
          specificationSources.some(source => source.includes(`${reference}:`)),
          true,
          `${owner} cites missing requirement ${reference}`,
        )
        continue
      }

      assert.equal(path.isAbsolute(reference), false, `${owner} evidence must be repository-relative`)
      assert.equal(reference.split('/').includes('..'), false, `${owner} evidence must not escape`)
      await access(path.join(repositoryDirectory, reference))
    }
  }
})

test('Registry Manifest stays offline and never reaches a registry source', () => {
  const manifest = model.element('registryStack.manifest')

  assert.equal(manifest.getMetadata('runtime'), 'false')
  assert.equal(manifest.getMetadata('productionDataAccess'), 'forbidden')
  assert.equal(relationsFrom(manifest.id).some(relation => relation.target.id === 'registrySource'), false)
  assert.equal(relationsTo(manifest.id).some(relation => relation.source.id === 'registrySource'), false)
  assert.deepEqual(
    relationsFrom(manifest.id).map(relation => relation.kind),
    ['describes'],
  )
})

test('Registry Relay exclusively owns registry source access', () => {
  const sourceRelations = relationships.filter(
    relation => relation.source.id === 'registrySource' || relation.target.id === 'registrySource',
  )

  assert.deepEqual(
    sourceRelations.map(relation => relation.source.id).sort(),
    [
      'registryStack.relay',
      'registryStack.relay.server',
      'registryStack.relay.server.sourceExecution',
    ],
  )
  for (const relation of sourceRelations) {
    assert.equal(relation.target.id, 'registrySource')
    assert.equal(relation.kind, 'reads')
    assert.equal(relation.getMetadata('owner'), 'registry-relay')
  }
})

test('Registry Platform supplies both runtime systems and does not run as a service', () => {
  const platform = model.element('registryStack.platform')
  const consumers = relationsFrom(platform.id, 'provides').map(relation => relation.target.id).sort()

  assert.equal(platform.kind, 'supportingLibrary')
  assert.equal(platform.getMetadata('runtime'), 'false')
  assert.deepEqual(consumers, ['registryStack.notary', 'registryStack.relay'])
})

test('Registry Notary consults Relay and never reads a registry source directly', () => {
  const notary = model.element('registryStack.notary')
  const consultations = relationships.filter(
    relation =>
      relation.kind === 'consults'
      && relation.source.id.startsWith('registryStack.notary')
      && relation.target.id.startsWith('registryStack.relay'),
  )

  assert.equal(
    relationships.some(
      relation =>
        relation.source.id.startsWith(notary.id) && relation.target.id === 'registrySource',
    ),
    false,
  )
  assert.deepEqual(
    consultations.map(relation => [relation.source.id, relation.target.id]).sort(),
    [
      ['registryStack.notary', 'registryStack.relay'],
      ['registryStack.notary', 'registryStack.relay.server'],
      ['registryStack.notary', 'registryStack.relay.server.consultation'],
      ['registryStack.notary.server', 'registryStack.relay'],
      ['registryStack.notary.server', 'registryStack.relay.server'],
      ['registryStack.notary.server.relayClient', 'registryStack.relay.server'],
    ],
  )
  for (const relation of consultations) {
    assert.equal(relation.getMetadata('executionProvenance'), 'exact')
    assert.equal(relation.getMetadata('registrySourceCredential'), 'forbidden')
  }
  assert.ok(relationBetween('registryStack.relay', 'registryStack.notary', 'returns'))
})

test('credential issuance requires exact Relay-backed provenance', () => {
  const issuance = relationships.filter(
    relation =>
      relation.kind === 'issues'
      && relation.source.id.startsWith('registryStack.notary')
      && relation.target.id === 'evidenceConsumer',
  )

  assert.deepEqual(
    issuance.map(relation => relation.source.id).sort(),
    ['registryStack.notary', 'registryStack.notary.server'],
  )
  for (const relation of issuance) {
    assert.equal(relation.getMetadata('provenance'), 'exact-relay-backed')
    assert.equal(relation.getMetadata('delegatedEvaluation'), 'forbidden')
    assert.equal(relation.getMetadata('sourceFreeEvaluation'), 'forbidden')
  }
})

test('peer federation models only the shipped inbound, source-free capability', () => {
  const inboundDelegations = relationsFrom('peerNotary', 'delegates')
  const response = relationBetween('registryStack.notary', 'peerNotary', 'returns')

  assert.deepEqual(
    inboundDelegations.map(relation => relation.target.id).sort(),
    [
      'registryStack.notary',
      'registryStack.notary.server',
      'registryStack.notary.server.federation',
    ],
  )
  assert.equal(relationsFrom('registryStack.notary', 'delegates').length, 0)
  for (const inboundDelegation of inboundDelegations) {
    assert.equal(inboundDelegation.getMetadata('trustDiscovery'), 'static-config')
    assert.equal(inboundDelegation.getMetadata('credentialIssuance'), 'forbidden')
    assert.equal(inboundDelegation.getMetadata('registryBackedClaims'), 'forbidden')
    assert.equal(inboundDelegation.getMetadata('replayScope'), 'peer-scoped')
    assert.equal(inboundDelegation.getMetadata('runtimeIsolationGate'), 'absent')
  }
  assert.equal(response.getMetadata('credentialIssuance'), 'forbidden')
})

test('selected code views pin the protected-read and issuance gates', () => {
  const relayCode = 'registryStack.relay.server.protectedRead'
  assert.ok(relationBetween(`${relayCode}.entityRoute`, `${relayCode}.governedAccess`, 'invokes'))
  assert.ok(relationBetween(`${relayCode}.entityRoute`, `${relayCode}.principalBinding`, 'invokes'))
  assert.ok(relationBetween(`${relayCode}.entityRoute`, `${relayCode}.queryEngine`, 'invokes'))
  assert.ok(
    relationBetween(`${relayCode}.principalBinding`, `${relayCode}.requiredFilterGate`, 'authorizes'),
  )
  assert.ok(
    relationBetween(`${relayCode}.queryEngine`, `${relayCode}.requiredFilterGate`, 'authorizes'),
  )

  const issuanceCode = 'registryStack.notary.server.issuance'
  const provenanceGate = relationBetween(
    `${issuanceCode}.issueCredential`,
    `${issuanceCode}.provenanceGate`,
    'authorizes',
  )
  const issuerCall = relationBetween(
    `${issuanceCode}.issueCredential`,
    `${issuanceCode}.sdJwtIssue`,
    'invokes',
  )

  assert.ok(provenanceGate)
  assert.ok(issuerCall)
  assert.equal(issuerCall.title.includes('after provenance'), true)
})

test('Relay and Notary do not cross the accountable decision boundary', () => {
  const decisionRelations = relationsTo('decisionOwner')

  assert.equal(decisionRelations.length, 1)
  assert.equal(decisionRelations[0].source.id, 'evidenceConsumer')
  assert.equal(decisionRelations[0].kind, 'informs')
  assert.equal(model.element('registryStack.relay').getMetadata('decisionOwner'), 'false')
  assert.equal(model.element('registryStack.notary').getMetadata('decisionOwner'), 'false')
})

test('runtime systems retain audit, signing, and optional OIDC boundaries', () => {
  for (const runtimeId of ['registryStack.relay', 'registryStack.notary']) {
    const audit = relationBetween(runtimeId, 'auditDestination', 'audits')
    const identity = relationBetween(runtimeId, 'identityProvider', 'verifiesWith')

    assert.ok(audit, `${runtimeId} must retain its audit relationship`)
    assert.ok(identity, `${runtimeId} must retain its optional OIDC relationship`)
    assert.equal(identity.getMetadata('optional'), 'true')
  }

  assert.ok(relationBetween('registryStack.notary', 'keyProvider', 'uses'))

  for (const forbiddenKind of ['delegates', 'evaluates', 'issues', 'informs']) {
    assert.equal(relationsFrom('registryStack.relay', forbiddenKind).length, 0)
  }
})

test('every dynamic step traces to a logical model relationship', () => {
  for (const view of model.views()) {
    if (view._type !== 'dynamic') {
      continue
    }

    for (const edge of view.edges()) {
      assert.ok(
        [...edge.relationships()].length > 0,
        `${view.id}: ${edge.source.id} -> ${edge.target.id} must trace to the logical model`,
      )
    }
  }
})

test('the production target deploys containers with separate PostgreSQL state', () => {
  const relay = model.deployment.instance(
    'singleNode.institution.applicationHost.runtime.relay',
  )
  const notary = model.deployment.instance(
    'singleNode.institution.applicationHost.runtime.notary',
  )
  const relayState = model.deployment.instance(
    'singleNode.institution.applicationHost.data.relayState',
  )
  const notaryState = model.deployment.instance(
    'singleNode.institution.applicationHost.data.notaryState',
  )
  const deploymentIds = [...model.deployment.elements()].map(element => element.id)

  assert.equal(relay.element.kind, 'container')
  assert.equal(notary.element.kind, 'container')
  assert.equal(relayState.element.kind, 'dataStore')
  assert.equal(notaryState.element.kind, 'dataStore')
  assert.equal(relayState.technology, 'PostgreSQL')
  assert.equal(notaryState.technology, 'PostgreSQL')
  assert.equal(deploymentIds.some(id => id.includes('management')), false)
  assert.equal([...model.deployment.instancesOf('registryctl')].length, 0)

  const notaryStateRelation = [...model.deployment.relationships()].find(
    relation => relation.target.id === notaryState.id,
  )
  assert.ok(notaryStateRelation)
  assert.equal(notaryStateRelation.title.includes('audit'), false)
})

test('Solmara Lab remains outside the formal product boundary', () => {
  const lab = model.element('solmaraLab')

  assert.equal(lab.kind, 'adopterProject')
  assert.equal(lab.isTagged('external'), true)
  assert.equal(lab.isTagged('adopter'), true)
  assert.equal(lab.getMetadata('formalProduct'), 'false')
  assert.equal(lab.parent, null)
})

test('LikeC4 sources pass repository source-hygiene checks', async () => {
  for (const filename of await c4Files(architectureDirectory)) {
    const source = await readFile(filename, 'utf8')
    const relativeName = path.relative(architectureDirectory, filename)

    assert.equal(source.endsWith('\n'), true, `${relativeName} must end with a newline`)
    assert.equal(source.includes('\r'), false, `${relativeName} must use LF line endings`)
    assert.equal(source.includes('\t'), false, `${relativeName} must not contain tabs`)
    assert.equal(/[ \t]+$/mu.test(source), false, `${relativeName} has trailing whitespace`)
    assert.equal(
      /[\u00a0\u2013\u2014\u2018\u2019\u201c\u201d]/u.test(source),
      false,
      `${relativeName} must not contain typographic punctuation`,
    )
  }
})
