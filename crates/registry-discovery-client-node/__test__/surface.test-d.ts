import {
  AcceptedServiceSelection,
  DiscoveryClient,
  acceptSelection,
  renewUnchangedSelection,
  selectEvidenceAlternative,
  selectEvidenceService,
  selectRelayService,
  validateSelection,
  validateSelectionStructure,
  type EvidenceServiceSelection,
  type RelayServiceSelection,
  type ServiceRecord,
} from '../client';

declare function expectType<T>(value: T): void;
declare function adopterChooseRecord(items: ServiceRecord[]): ServiceRecord;

async function useDiscoveryClient(): Promise<void> {
  const client = new DiscoveryClient('https://discovery.example.invalid/');
  const resolved = await client.resolveEvidenceTypes({ requirementId: 'urn:example:requirement' });
  const context = selectEvidenceAlternative(resolved);
  const response = await client.searchEvidenceServices({
    evidenceTypeId: context.evidenceTypeIds[0],
  });
  const selection: EvidenceServiceSelection = selectEvidenceService(response, {
    recordId: adopterChooseRecord(response.items).recordId,
    evidenceTypeId: context.evidenceTypeIds[0],
    resolution: context,
  });
  expectType<string>(selection.originContentDigest);
  expectType<EvidenceServiceSelection>(validateSelectionStructure(selection));
  expectType<EvidenceServiceSelection>(validateSelection(selection));
  const accepted = acceptSelection(selection, (candidate) => candidate.serviceKind === 'evidence');
  expectType<AcceptedServiceSelection<EvidenceServiceSelection>>(accepted);
  expectType<string>(accepted.endpointUrl);
  expectType<EvidenceServiceSelection>(accepted.selection);
  expectType<EvidenceServiceSelection>(renewUnchangedSelection(selection, selection));

  // @ts-expect-error Only acceptSelection can construct the accepted handoff.
  const forged: AcceptedServiceSelection<EvidenceServiceSelection> = {
    endpointUrl: selection.endpointUrl,
    selection,
  };
  void forged;

  const relayResponse = await client.searchRelayServices({
    semanticClassId: 'urn:example:business',
    operationFamilyId: 'urn:example:list',
  });
  const relay: RelayServiceSelection = selectRelayService(relayResponse, {
    recordId: adopterChooseRecord(relayResponse.items).recordId,
    capabilityMatch: {
      semanticClassId: 'urn:example:business',
      operationFamilyId: 'urn:example:list',
    },
  });
  expectType<string | undefined>(relay.relayCapabilityMatch.semanticClassId);

  // @ts-expect-error Relay intent must name at least one public capability.
  await client.searchRelayServices({});
  // @ts-expect-error Relay selection must retain at least one matched capability.
  selectRelayService(relayResponse, { recordId: relay.recordId, capabilityMatch: {} });
}

void useDiscoveryClient;
