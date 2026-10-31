// SPDX-License-Identifier: Apache-2.0

//! One-off probe: run the authoring checks over the adapter.job bad corpus
//! members, converted to JSON beside this run, and print the codes each
//! refusal carries. The scratch Python converter fills the directory.

use registry_adapter_core::{
    check_job, check_job_boundaries, check_pack, check_routes, AdapterJob, AdapterPack,
    AdapterProject,
};

#[test]
fn probe_prints_job_member_codes() {
    let root = std::path::Path::new("/tmp/adapter-job-corpus-json");
    let mut members: Vec<PathBuf> = std::fs::read_dir(root)
        .expect("converted corpus; run the scratch converter first")
        .flatten()
        .map(|entry| entry.path())
        .collect();
    members.sort();
    for member in members {
        let name = member.file_name().unwrap().to_str().unwrap().to_string();
        let pack: AdapterPack = serde_json::from_str(
            &std::fs::read_to_string(member.join("pack.json")).expect("pack"),
        )
        .expect("pack decodes");
        let project: AdapterProject = serde_json::from_str(
            &std::fs::read_to_string(member.join("project.json")).expect("project"),
        )
        .expect("project decodes");
        let mut codes: Vec<String> = check_pack(&pack)
            .into_iter()
            .chain(check_routes(&pack, &project))
            .chain(check_job_boundaries(&pack, &project))
            .map(|finding| finding.code)
            .collect();
        codes.sort();
        codes.dedup();
        println!("MEMBER {name}: {codes:?}");
        if member.join("job.json").exists() {
            let job: AdapterJob =
                serde_json::from_str(&std::fs::read_to_string(member.join("job.json")).expect("job"))
                    .expect("job decodes");
            let mut job_codes: Vec<String> = check_job(&job, &pack)
                .into_iter()
                .map(|finding| finding.code)
                .collect();
            job_codes.sort();
            job_codes.dedup();
            println!("MEMBER {name} JOB: {job_codes:?}");
        }
    }
}

use std::path::PathBuf;
