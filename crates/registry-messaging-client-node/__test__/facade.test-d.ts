import {
  MessagingClient,
  MessagingClientError,
  type MessageReceipt,
  type MessageView,
  type MessagingOutcome,
  type MessagingProblemCode,
  type MessagingProtocolFailure,
  type SubmitMessageRequest,
} from '../client'

const client = new MessagingClient({ baseUrl: 'https://messaging.example.test/' })
const token: string = 'header.payload.signature'
const messageId = '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d'
const templated: SubmitMessageRequest = {
  senderProfile: 'reminders-sms',
  to: { phone: '+15550100' },
  template: { id: 'appointment-reminder', version: '1' },
  locale: 'en',
  data: { time: '10:00' },
  correlationId: 'case-42',
}
const direct: SubmitMessageRequest = {
  senderProfile: 'notices-email',
  to: { email: 'person@example.test' },
  content: { subject: 'Notice', text: 'Your appointment is confirmed.' },
  notBefore: '2026-09-25T10:00:00Z',
  expiresAt: '2026-09-26T10:00:00Z',
}

const health: Promise<MessagingOutcome<null>> = client.health()
const ready: Promise<MessagingOutcome<null>> = client.ready()
const receipt: Promise<MessagingOutcome<MessageReceipt>> = client.submit(token, 'reminder-1', templated)
void client.submit(token, 'notice-1', direct)
const view: Promise<MessagingOutcome<MessageView>> = client.message(token, messageId)
void health
void ready
void receipt
void view

async function statusOf(): Promise<string> {
  const outcome = await client.message(token, messageId)
  const traceId: string = outcome.traceId
  void traceId
  const attempts: ReadonlyArray<{ readonly outcome: string }> = outcome.value.attempts
  void attempts
  return outcome.value.status
}
void statusOf

function recover(error: unknown): MessagingProblemCode | MessagingProtocolFailure | undefined {
  if (!(error instanceof MessagingClientError)) return undefined
  if (error.kind === 'problem') return error.code
  return error.protocolFailure
}
void recover

const known: MessagingProblemCode = 'idempotency.key-reused'
void known

// @ts-expect-error the recipient is one email address or one phone number
const neither: SubmitMessageRequest = { senderProfile: 'reminders-sms', to: {}, content: { text: 'x' } }
void neither
// @ts-expect-error the idempotency key is required
void client.submit(token, templated)
