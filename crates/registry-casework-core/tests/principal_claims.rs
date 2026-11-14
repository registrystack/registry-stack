//! One principal claim per human identity: the Casework project refuses access
//! profiles that name different claims for people, because one person would
//! then appear as two principals.
use registry_casework_core::*;
use serde_json::{json, Value};

const CODE: &str = "casework.access-profile.mixed-principal-claims";

/// A project with every profile kind the code distinguishes: three reviewer
/// roles, an initiator profile, a plain requester profile and a producer
/// profile, all naming `principal`.
fn project_value() -> Value {
    json!({
        "apiVersion":CASEWORK_API_VERSION,"kind":CASEWORK_KIND,
        "project":{"id":"review-project","version":"1"},
        "accessProfiles":{
            "reviewer":{"actsAs":"staff","principalClaim":"principal","requiredScopes":["casework:review"]},
            "supervisor":{"actsAs":"supervisor","principalClaim":"principal","requiredScopes":["casework:supervise"]},
            "administrator":{"actsAs":"administrator","principalClaim":"principal","requiredScopes":["casework:admin"]},
            "initiator":{"actsAs":"requester","principalClaim":"principal","requiredScopes":["casework:initiate"]},
            "requester":{"actsAs":"requester","principalClaim":"principal","requiredScopes":["casework:request-own"]},
            "producer":{"actsAs":"requester","principalClaim":"principal","requiredScopes":["casework:request"]}
        },
        "queues":{"reviews":{"label":"Reviews"}},
        "teams":{"review-team":{"label":"Review team","serves":["reviews"],"memberProfiles":["reviewer"],"supervisorProfiles":["supervisor"]}},
        "clocks":{"decision-due":{"type":"subject","anchor":{"type":"request-accepted"},"after":{"hours":48}}},
        "reviewPolicies":{"notice-review":{
            "version":"1","purpose":"approval","context":{"mode":"submitted"},
            "stages":[{"id":"review","queue":"reviews","decidingProfiles":["reviewer"],"requiredApprovals":2,"excludeInitiator":true}],
            "clocks":["decision-due"],"retention":{"terminalRetentionDays":30,"accountabilityRetentionDays":90},
            "outcomes":{"approved":{"label":"Approve","settlement":"approved","reasonRequired":false,"publicReason":"optional"},"rejected":{"label":"Reject","settlement":"rejected","reasonRequired":true,"publicReason":"required"}},
            "displaySchema":{"type":"object","additionalProperties":false,"required":["title"],"properties":{"title":{"type":"string","maxLength":160}}}
        }},
        "trustedProducers":{"notice-service":{"profile":"producer","issuer":"https://issuer.example","subject":"notice-service","trustedInitiatorIssuer":"https://people.example","initiatorProfile":"initiator","sourceNamespaces":["notice-source"],"reviewPolicies":["notice-review"],"retention":{"receiptRetentionDays":7}}}
    })
}

/// The codes and messages the load refuses the project with; empty when it loads.
fn refusals(value: &Value) -> Vec<(String, String)> {
    match CaseworkProject::from_slice(&serde_json::to_vec(value).unwrap()) {
        Ok(_) => Vec::new(),
        Err(ConfigLoadError::Refused(report)) => report
            .into_diagnostics()
            .into_iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.message))
            .collect(),
        Err(other) => panic!("unexpected load failure: {other}"),
    }
}

#[test]
fn the_baseline_project_loads() {
    assert_eq!(refusals(&project_value()), Vec::new());
}

#[test]
fn every_human_profile_kind_must_share_the_claim_of_the_others() {
    // Reviewer roles are staff, supervisor and administrator; the other two
    // human kinds are requester profiles an initiator or a requester uses.
    for odd in [
        "reviewer",
        "supervisor",
        "administrator",
        "initiator",
        "requester",
    ] {
        let mut value = project_value();
        value["accessProfiles"][odd]["principalClaim"] = json!("sub");
        let refused = refusals(&value);
        assert_eq!(refused.len(), 1, "{odd}: {refused:?}");
        let (code, message) = &refused[0];
        assert_eq!(code, CODE, "{odd}");
        assert!(message.contains("\"sub\""), "{odd}: {message}");
        assert!(message.contains("\"principal\""), "{odd}: {message}");
        assert!(message.contains(&format!("'{odd}'")), "{odd}: {message}");
        assert!(message.contains("one claim"), "{odd}: {message}");
    }
}

#[test]
fn one_claim_everywhere_loads() {
    for claim in ["principal", "sub"] {
        let mut value = project_value();
        for profile in value["accessProfiles"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            profile["principalClaim"] = json!(claim);
        }
        assert_eq!(refusals(&value), Vec::new(), "{claim}");
    }
}

#[test]
fn a_producer_may_use_a_claim_the_people_do_not() {
    let mut value = project_value();
    value["accessProfiles"]["producer"]["principalClaim"] = json!("client_id");
    assert_eq!(refusals(&value), Vec::new());
}

#[test]
fn producers_must_share_a_claim_among_themselves() {
    let mut value = project_value();
    value["accessProfiles"]["producer-b"] = json!({"actsAs":"requester","principalClaim":"client_id","requiredScopes":["casework:request-b"]});
    let mut second = value["trustedProducers"]["notice-service"].clone();
    second["profile"] = json!("producer-b");
    second["subject"] = json!("other-service");
    second.as_object_mut().unwrap().remove("initiatorProfile");
    value["trustedProducers"]["other-service"] = second;
    let refused = refusals(&value);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].0, CODE);
    assert!(refused[0].1.contains("producers"));
}

#[test]
fn the_finding_points_at_the_profile_outside_the_majority_claim() {
    // `administrator` sorts first by id, so it is the first profile read,
    // yet it is the only one on `registry_principal`; the other four people
    // profiles share `sub`.
    let mut value = project_value();
    for profile in value["accessProfiles"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        profile["principalClaim"] = json!("sub");
    }
    value["accessProfiles"]["administrator"]["principalClaim"] = json!("registry_principal");
    let Err(ConfigLoadError::Refused(report)) =
        CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap())
    else {
        panic!("the mixed project must be refused");
    };
    let findings: Vec<_> = report
        .into_diagnostics()
        .into_iter()
        .filter(|diagnostic| diagnostic.code == CODE)
        .collect();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(
        findings[0].path,
        "/accessProfiles/administrator/principalClaim"
    );
    let message = &findings[0].message;
    assert!(message.contains("'administrator'"), "{message}");
    assert!(message.contains("\"registry_principal\""), "{message}");
    assert!(message.contains("\"sub\""), "{message}");
}

#[test]
fn a_tie_takes_the_claim_of_the_first_profile_by_id_as_the_reference() {
    // Six people profiles: three on `principal`, three on `sub`. Profiles are
    // read sorted by id, whatever order the file writes them in; the first by
    // id is `administrator`, so `principal` is the reference.
    let mut value = project_value();
    value["accessProfiles"]["auditor"] =
        json!({"actsAs":"staff","principalClaim":"sub","requiredScopes":["casework:audit"]});
    for odd in ["supervisor", "requester"] {
        value["accessProfiles"][odd]["principalClaim"] = json!("sub");
    }
    let Err(ConfigLoadError::Refused(report)) =
        CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap())
    else {
        panic!("the mixed project must be refused");
    };
    let paths: Vec<_> = report
        .into_diagnostics()
        .into_iter()
        .filter(|diagnostic| diagnostic.code == CODE)
        .map(|diagnostic| diagnostic.path)
        .collect();
    assert_eq!(
        paths,
        [
            "/accessProfiles/auditor/principalClaim",
            "/accessProfiles/requester/principalClaim",
            "/accessProfiles/supervisor/principalClaim"
        ]
    );
}
