// Reason codes stay consistent: the same mono code always maps to the same human
// sentence. The human sentence carries the meaning; the code is gov-system
// realism shown in small mono alongside it.
export const REASON_CODES: Record<string, string> = {
  'VR-RED-02': 'Voucher already redeemed this cycle.',
  'VR-RED-04': 'Not on the registered-farmer roll for this district.',
  'VR-AMB-01': 'More than one matching record was found.',
  'VR-ERR-01': 'The authority could not be reached.'
};

// Returns the human sentence for a code, or undefined when the caller already
// carries its own display sentence (we never invent meaning for an unknown code).
export function reasonSentence(code: string | undefined): string | undefined {
  if (code === undefined) return undefined;
  return REASON_CODES[code];
}
