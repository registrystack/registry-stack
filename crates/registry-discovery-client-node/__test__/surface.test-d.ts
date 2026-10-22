import {
  AcceptedServiceSelection,
  DiscoveryClient,
  acceptSelection,
  renewUnchangedSelection,
  selectEvidenceAlternative,
  selectEvidenceService,
  validateSelectionStructure,
  type EvidenceServiceSelection,
  type ServiceRecord,
} from '../client';

import * as discovery from '../client';
import * as native from '../index';

// @ts-expect-error Structural validation exports only its explicit canonical name.
void discovery.validateSelection;
// @ts-expect-error The native binding also removes the ambiguous alias.
void native.validateSelection;

declare function expectType<T>(value: T): void;
declare function adopterChooseRecord(items: ServiceRecord[]): ServiceRecord;

async function useDiscoveryClient(): Promise<void> {
  const client = new DiscoveryClient({
    baseUrl: 'https://discovery.example.invalid/',
    attemptTimeoutMilliseconds: 1500,
    maximumResponseBytes: 1500,
    trustedRootCertificates: '-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----',
  });
  // @ts-expect-error trust roots are PEM text, not binary data
  new DiscoveryClient({ baseUrl: 'https://discovery.example.invalid/', trustedRootCertificates: Buffer.from('certificate') });
  // @ts-expect-error null is not an omission in JavaScript configuration
  new DiscoveryClient({ baseUrl: 'https://discovery.example.invalid/', attemptTimeoutMilliseconds: null });
  // @ts-expect-error the per-exchange timeout is named for one attempt
  new DiscoveryClient({ baseUrl: 'https://discovery.example.invalid/', requestTimeoutMilliseconds: 1500 });
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
}

void useDiscoveryClient;
