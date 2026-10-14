import { ProjectClient, type RegisterFacilityInput, type CorrectAddressInput, type CorrectAddressRefusal } from '../../../../generated/facility/generated/sdk/project';

/** The host supplies authenticated native clients, one per explicitly selected profile. */
export async function facilityConsole(reader: ProjectClient, registrar: ProjectClient, author: ProjectClient, facilityId: string, input: RegisterFacilityInput, correction: CorrectAddressInput) {
  const facility = await reader.read('facility', facilityId);
  const assignments = await reader.related('facility', facilityId, 'assignments');
  const firstAssignment = assignments.items[0];
  const operator = firstAssignment
    ? await reader.related('facility-assignment', firstAssignment.id, 'operator') : null;
  const nextAssignments = assignments.next ? await assignments.next() : undefined;
  const registered = await registrar.invoke('register-facility', input, 'console-register-1');
  const draft = await author.invoke('correct-address', correction, 'console-correction-1');
  const submit = author.prepare(draft, 'submit', {}, 'console-submit-1');
  const submitted = await author.execute<CorrectAddressInput, CorrectAddressRefusal>(submit);
  const open = await author.listProposals('correct-address');
  const current = open.items[0] ? await author.resumeProposal(open.items[0]) : submitted;
  const availability = current.document.links.apply?.availability;
  return { title: facility.title, operatorTitle: operator?.title, assignments: assignments.items,
    nextAssignments, registered, current, unavailableReason: availability?.available === false ? availability.reason : undefined };
}

// These fail if generated Action input/refusal contracts lose their precision.
// @ts-expect-error A required input is missing.
const incomplete: RegisterFacilityInput = { name: 'Example' };
// @ts-expect-error Package refusal codes are a closed generated extension.
const unknownRefusal: CorrectAddressRefusal = 'unrecognized-refusal';
void incomplete; void unknownRefusal;
