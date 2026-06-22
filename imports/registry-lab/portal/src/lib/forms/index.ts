// Public API for the forms + flows layer (the integration surface the routes use).

export {
  FORMS,
  getForm,
  CATALOG,
  autoFetchFields,
  manualField,
  delegatedFields
} from './descriptors';
export type { CatalogEntry } from './descriptors';

export { clientFeed } from './clientFeed.svelte';
export { ui } from './ui.svelte';
export { evaluateField } from './evaluate';
export type { EvaluateArgs } from './evaluate';
export { buildIdentityTrace } from './identity';

export { encodeQr, qrToSvgPath, qrViewBox } from './qr';
export type { QrMatrix } from './qr';
export { buildCredentialOffer, buildCredentialOfferUrl } from './walletOffer';
export type { CredentialOfferInput } from './walletOffer';
