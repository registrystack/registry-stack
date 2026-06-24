// Build the OID4VCI credential-offer URL the wallet closer QR encodes.
//
// Phase 0 mock: a real, well-formed openid-credential-offer:// URL with an inline
// credential_offer (a pre-authorized-code grant) for a single SD-JWT VC. A real
// wallet that supports OID4VCI parses this and would attempt the issuance flow
// against the (mock) issuer. The shape is the load-bearing part for the demo: the
// audience sees a genuine credential offer, not a placeholder.
//
// No raw citizen identifier appears in the offer: it references a credential
// configuration id and an opaque pre-authorized code, never a national id.

export type CredentialOfferInput = {
  // the issuer base URL (the portal origin in Phase 0)
  issuer: string;
  // which credential configuration is being offered, e.g. a birth-certificate VC
  configurationId: string;
  // an opaque, non-identifying pre-authorized code (server-minted in Phase 1)
  preAuthorizedCode: string;
};

// The credential_offer object, per OID4VCI (draft). Kept minimal but structurally
// valid so a conformant wallet can parse it.
export function buildCredentialOffer(input: CredentialOfferInput): Record<string, unknown> {
  return {
    credential_issuer: input.issuer,
    credential_configuration_ids: [input.configurationId],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': input.preAuthorizedCode,
        tx_code: { input_mode: 'numeric', length: 6, description: 'Enter the code shown in the portal' }
      }
    }
  };
}

// The scannable URL: openid-credential-offer://?credential_offer=<url-encoded JSON>.
export function buildCredentialOfferUrl(input: CredentialOfferInput): string {
  const offer = buildCredentialOffer(input);
  const param = encodeURIComponent(JSON.stringify(offer));
  return `openid-credential-offer://?credential_offer=${param}`;
}
