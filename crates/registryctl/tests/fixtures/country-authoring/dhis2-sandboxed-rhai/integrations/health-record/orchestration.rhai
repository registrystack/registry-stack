fn consult(input, prior) {
    if !prior.contains("identity") {
        return #{ operations: ["identity"], facts: #{} };
    }
    if !prior.identity.presence {
        return #{ operations: [], facts: #{
            exists: #{ type: "presence", value: false },
            first_name: #{ type: "string", value: () },
            last_name: #{ type: "string", value: () },
            date_of_birth: #{ type: "date", value: () },
            child_program_active: #{ type: "boolean", value: () },
            programme_code: #{ type: "string", value: () },
            reconciliation_reference: #{ type: "string", value: () },
            maternal_postnatal_active: #{ type: "boolean", value: () },
            child_health_visit_recorded: #{ type: "boolean", value: () },
            tb_program_active: #{ type: "boolean", value: () }
        }};
    }
    if !prior.contains("child_program") || !prior.contains("care") || !prior.contains("tb_program") {
        return #{
            operations: ["child_program", "care", "tb_program"],
            facts: #{}
        };
    }
    return #{ operations: [], facts: #{
        exists: #{ type: "presence", value: true },
        first_name: #{ type: "string", value: prior.identity.first_name },
        last_name: #{ type: "string", value: prior.identity.last_name },
        date_of_birth: #{ type: "date", value: prior.identity.date_of_birth },
        child_program_active: #{ type: "boolean", value: prior.child_program.active },
        programme_code: #{ type: "string", value: prior.child_program.programme_code },
        reconciliation_reference: #{ type: "string", value: prior.child_program.reconciliation_reference },
        maternal_postnatal_active: #{ type: "boolean", value: prior.care.maternal_postnatal_active },
        child_health_visit_recorded: #{ type: "boolean", value: prior.care.child_health_visit_recorded },
        tb_program_active: #{ type: "boolean", value: prior.tb_program.active }
    }};
}
