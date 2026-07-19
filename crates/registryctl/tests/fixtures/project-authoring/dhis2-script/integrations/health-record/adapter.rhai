// Demo UIDs keep project-owned DHIS2 semantics visible and replaceable.
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
    let bcg_birth_stage_uid = "DEMO_BCG_BIRTH_STAGE_UID";
    let opv_birth_stage_uid = "DEMO_OPV_BIRTH_STAGE_UID";
    let measles_stage_uid = "DEMO_MEASLES_STAGE_UID";

    let target = source.path(
        "/api/tracker/trackedEntities/{tracked_entity}",
        #{ tracked_entity: ctx.input.tracked_entity }
    );
    let response = source.get(target, #{
        query: #{
            fields: "trackedEntity,enrollments[program,status,events[programStage,status]]",
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
    result.match(#{
        programme_enrollment_active: enrollment_active(child),
        bcg_birth_dose_recorded: completed_stage_evidence(child, bcg_birth_stage_uid),
        opv_birth_dose_recorded: completed_stage_evidence(child, opv_birth_stage_uid),
        measles_dose_recorded: completed_stage_evidence(child, measles_stage_uid)
    })
}
