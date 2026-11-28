// Task helpers over the generated clients: Proposals as plain data with commands, and
// files in the Document Store. The generated service file attaches them as
// `registry.proposals` and `registry.documents`.

export {
  availabilityMessages,
  proposalCommands,
  proposalFromServed,
  proposalStatus,
} from './proposals.ts'
export type {
  AttachmentView,
  Availability,
  CommandName,
  JsonChanges,
  JsonObject,
  ProgressCallback,
  Proposal,
  ProposalClient,
  ProposalCommands,
  ProposalListFilter,
  ProposalState,
  ProposalStatus,
  ServedApplication,
  ServedApplicationStatus,
  ServedLink,
  ServedProposal,
  ServedSlot,
  Turn,
} from './proposals.ts'

export { documentCommands, saveBlob } from './files.ts'
export type {
  DocumentClient,
  DocumentCommands,
  DocumentGrantView,
  DocumentStatus,
  DocumentView,
} from './files.ts'
