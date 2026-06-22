// Public API for the EvidenceField renderer. Everything in the portal renders
// through <EvidenceField>; the forms agent integrates against the props
// documented on the component.
export { default as EvidenceField } from './EvidenceField.svelte';
export { default as StatusIcon } from './StatusIcon.svelte';

// Presentation helpers (pure, testable): how a FieldState maps to a channel,
// icon, ARIA role, and whether it plays the stamp animation.
export { presentationFor, stampsOnEntry } from './states';
export type { Channel, StatusIcon as StatusIconName, StatePresentation } from './states';

// Authority and reason-code lookups, the single source of truth for how a
// NotaryId reads to a citizen and how a reason code maps to a human sentence.
export { authorityName, AUTHORITY_NAMES } from './authorities';
export { reasonSentence, REASON_CODES } from './reasonCodes';
