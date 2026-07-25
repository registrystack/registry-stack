// Demo UIDs keep project-owned DHIS2 semantics visible and replaceable.
fn attribute_value(attributes, uid) {
    for attribute in attributes {
        if attribute.attribute == uid {
            return attribute.value;
        }
    }
    ()
}

fn enrollment_for(enrollments, programme_uid) {
    for enrollment in enrollments {
        if enrollment.program == programme_uid {
            return enrollment;
        }
    }
    ()
}

fn enrollment_active(enrollment) {
    if enrollment == () {
        return ();
    }
    enrollment.status == "ACTIVE"
}

fn completed_stage_evidence(enrollment, stage_uid) {
    if enrollment == () {
        return ();
    }
    let stage_exists = false;
    for event in enrollment.events {
        if event.programStage == stage_uid {
            if event.status == "COMPLETED" {
                return true;
            }
            stage_exists = true;
        }
    }
    if stage_exists { false } else { () }
}

fn consult(ctx) {
    let child_program_uid = "DEMO_CHILD_PROGRAM_UID";
    let maternal_program_uid = "DEMO_MATERNAL_PROGRAM_UID";
    let tb_program_uid = "DEMO_TB_PROGRAM_UID";
    let child_visit_stage_uid = "DEMO_CHILD_VISIT_STAGE_UID";
    let bcg_birth_stage_uid = "DEMO_BCG_BIRTH_STAGE_UID";
    let opv_birth_stage_uid = "DEMO_OPV_BIRTH_STAGE_UID";
    let measles_stage_uid = "DEMO_MEASLES_STAGE_UID";
    let first_name_uid = "DEMO_FIRST_NAME_ATTRIBUTE_UID";
    let last_name_uid = "DEMO_LAST_NAME_ATTRIBUTE_UID";
    let birth_date_uid = "DEMO_BIRTH_DATE_ATTRIBUTE_UID";
    let reconciliation_uid = "DEMO_RECONCILIATION_ATTRIBUTE_UID";

    let target = source.path(
        "/api/tracker/trackedEntities/{tracked_entity}",
        #{ tracked_entity: ctx.input.tracked_entity }
    );
    let response = source.get(target, #{
        query: #{
            fields: "trackedEntity,attributes[attribute,value],enrollments[program,status,events[programStage,status]]",
            includeDeleted: ctx.input.include_inactive
        }
    });
    if response.status == 404 {
        return result.no_match();
    }
    if response.status != 200 {
        return result.fail(failure.source_rejected);
    }

    let entity = response.body;
    if entity.trackedEntity != ctx.input.tracked_entity {
        return result.fail(failure.subject_mismatch);
    }

    let child = enrollment_for(entity.enrollments, child_program_uid);
    let maternal = enrollment_for(entity.enrollments, maternal_program_uid);
    let tb = enrollment_for(entity.enrollments, tb_program_uid);
    result.match(#{
        first_name: attribute_value(entity.attributes, first_name_uid),
        last_name: attribute_value(entity.attributes, last_name_uid),
        date_of_birth: attribute_value(entity.attributes, birth_date_uid),
        child_program_active: enrollment_active(child),
        programme_code: if child == () { () } else { "DEMO_CHILD_PROGRAM" },
        reconciliation_reference: attribute_value(entity.attributes, reconciliation_uid),
        maternal_postnatal_active: enrollment_active(maternal),
        child_health_visit_recorded: completed_stage_evidence(child, child_visit_stage_uid),
        tb_program_active: enrollment_active(tb),
        bcg_birth_dose_recorded: completed_stage_evidence(child, bcg_birth_stage_uid),
        opv_birth_dose_recorded: completed_stage_evidence(child, opv_birth_stage_uid),
        measles_dose_recorded: completed_stage_evidence(child, measles_stage_uid)
    })
}
