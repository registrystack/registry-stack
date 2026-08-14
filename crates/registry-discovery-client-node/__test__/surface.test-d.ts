import { DiscoveryClient, selectExact, type ServiceSelection } from '../client';

async function useDiscoveryClient(): Promise<void> {
  const client = new DiscoveryClient('https://discovery.example.invalid/');
  const response = await client.searchServices({ serviceKind: ['evidence'] });
  const selection: ServiceSelection = selectExact(response, {
    recordId: response.items[0].recordId,
    matchedCapability: { kind: 'evidence-type', id: 'urn:example:type' },
  });
  selection.originContentDigest;
}

void useDiscoveryClient;
