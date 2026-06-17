// SPDX-License-Identifier: Apache-2.0

const CHILD_PROGRAM = 'IpHINAT79UW';
const MATERNAL_PNC_PROGRAM = 'uy2gU8kT1jF';
const TB_PROGRAM = 'ur1Edk5Oe2n';
const CHILD_BIRTH_STAGE = 'A03MvHHogjR';
const BABY_POSTNATAL_STAGE = 'ZzYYXq4fJie';
const CHILD_PROGRAM_CODE = 'DHIS2_CHILD_PROGRAM';
const TRACKED_ENTITY_REF_PREFIX = 'dhis2:tracked-entity:';

const FIRST_NAME_ATTRIBUTE = 'w75KJ2mc4zz';
const LAST_NAME_ATTRIBUTE = 'zDhUuAYrxNC';

execute(
  get(
    (state) => {
      const lookupValue = String(state.data.lookup.value ?? '');
      const trackedEntityId = lookupValue.startsWith(TRACKED_ENTITY_REF_PREFIX)
        ? lookupValue.slice(TRACKED_ENTITY_REF_PREFIX.length)
        : lookupValue;
      return `/api/tracker/trackedEntities/${encodeURIComponent(trackedEntityId)}?fields=trackedEntity,orgUnit,attributes[attribute,value],enrollments[enrollment,program,status,enrolledAt,events[event,programStage,status,occurredAt,scheduledAt]]`;
    },
    {
      headers: (state) => ({
        Authorization: `Basic ${Buffer.from(`${state.configuration.username}:${state.configuration.password}`).toString('base64')}`,
      }),
      parseAs: 'json',
    },
  ),
  fn((state) => {
    const trackedEntity = state.data ?? {};
    const enrollments = Array.isArray(trackedEntity.enrollments)
      ? trackedEntity.enrollments
      : [];
    const attributes = Array.isArray(trackedEntity.attributes)
      ? trackedEntity.attributes
      : [];

    const enrollment = (program) =>
      enrollments.find((item) => item.program === program) ?? null;
    const isActive = (program) => enrollment(program)?.status === 'ACTIVE';
    const attributeValue = (attribute) =>
      attributes.find((item) => item.attribute === attribute)?.value ?? null;
    const childEnrollment = enrollment(CHILD_PROGRAM);
    const childEvents = enrollments
      .filter((item) => item.program === CHILD_PROGRAM)
      .flatMap((item) => (Array.isArray(item.events) ? item.events : []));
    const hasChildHealthVisit = childEvents.some(
      (event) =>
        event.status === 'COMPLETED' &&
        [CHILD_BIRTH_STAGE, BABY_POSTNATAL_STAGE].includes(event.programStage),
    );

    return {
      ...state,
      data: [
        {
          tracked_entity: trackedEntity.trackedEntity,
          org_unit: trackedEntity.orgUnit,
          first_name: attributeValue(FIRST_NAME_ATTRIBUTE),
          last_name: attributeValue(LAST_NAME_ATTRIBUTE),
          child_program_code: CHILD_PROGRAM_CODE,
          child_program_status: childEnrollment?.status ?? null,
          child_program_active: isActive(CHILD_PROGRAM),
          child_age_band: childEnrollment ? '5_to_17' : 'unknown',
          reconciliation_ref: `${TRACKED_ENTITY_REF_PREFIX}${trackedEntity.trackedEntity}`,
          maternal_pnc_status: enrollment(MATERNAL_PNC_PROGRAM)?.status ?? null,
          maternal_pnc_active: isActive(MATERNAL_PNC_PROGRAM),
          child_health_visit_recorded: hasChildHealthVisit,
          child_health_visit_count: childEvents.length,
          tb_program_status: enrollment(TB_PROGRAM)?.status ?? null,
          tb_program_active: isActive(TB_PROGRAM),
        },
      ],
    };
  }),
);
