import type { ReviewClockOccurrence, ReviewPolicyClosure, ReviewStageAsksPolicy, ReviewTaskMarker } from '../client'

const marker: ReviewTaskMarker = 'expired'
const state: ReviewClockOccurrence['state'] = 'paused'
const asks: ReviewStageAsksPolicy = { answerWithin: { hours: 48 }, onDue: 'return-to-reviewer', pauseClocks: true }
const resubmission: ReviewPolicyClosure['resubmission'] = 'resume-at-returning-stage'
void marker; void state; void asks; void resubmission

// @ts-expect-error expiry does not authorise an automatic decision
const unsupported: ReviewStageAsksPolicy = { onDue: 'approve' }
void unsupported
