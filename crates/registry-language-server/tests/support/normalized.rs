#![allow(dead_code)]
use registry_language_server::ProjectIndex;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tower_lsp_server::ls_types::Position;
pub const PROJECT: &str = "evidence.yaml";
pub const DERIVE: &str = "functions/derive.rhai";
pub const SOURCE: &str = r#"apiVersion: id.registrystack.org/formats/evidence/project/v1alpha1
kind: EvidenceProject
id: synthetic
selectorProfiles:
  person-by-id: {maximumAggregateBytes: 64, fields: {person-id: {type: string, minimumBytes: 1, maximumBytes: 64}}}
functions:
  - {id: derive-status, interface: assertion-derive/v1, source: functions/derive.rhai}
sources:
  person:
    pack: {id: population, version: '1'}
    route: person-lookup
    connection: population
    inputs:
      personId: {selector: {role: person, profile: person-by-id, field: person-id}}
    acquisitionPosture: record-transformed
assertionDefinitions:
  active-status:
    question: Is the person active?
    semantics: {requirement: 'urn:example:requirement:active', kind: criterion, evidenceType: 'urn:example:evidence:active', referenceFrameworks: ['urn:example:framework:status']}
    purpose: status-verification
    grantCeiling: {authorities: [organizational], actorKinds: [service], valueOrigins: [request], audiences: ['urn:example:audience:consumer']}
    subjects: [{role: person, selectors: [person-by-id]}]
    acquisition: {source: person}
    derive: {function: derive-status}
    outputs:
      active: {concept: 'urn:example:concept:active', type: boolean}
    validitySeconds: 300
    subjectBinding: audience-scoped
    representations: [signed-jws]
"#;
pub const AUTHORITY: &str = r#"apiVersion: id.registrystack.org/formats/evidence/target-authority/v1alpha1
kind: EvidenceTargetAuthority
target: local
project: synthetic
accessProfiles:
  consumer:
    authority: organizational
    actorKind: service
    requesterTags: [consumer]
    grants:
      - definition: active-status
        purpose: status-verification
        audienceFrom: authenticated-requester
        representations: [signed-jws]
        subjectBinding: audience-scoped
        subjects: [{role: person, selectorProfile: person-by-id, valueOrigin: request}]
"#;
pub struct Project {
    _temp: tempfile::TempDir,
    pub root: PathBuf,
}
impl Project {
    pub fn new(source: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let this = Self { _temp: temp, root };
        this.write(PROJECT, source);
        this.write(DERIVE,"fn derive(facts, selectors, context) { [#{output: \"active\", value: facts.active}] }\n");
        this
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    pub fn write(&self, name: &str, source: &str) {
        let path = self.path(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, source).unwrap();
    }
    pub fn read(&self, name: &str) -> String {
        fs::read_to_string(self.path(name)).unwrap()
    }
    pub fn index(&self) -> ProjectIndex {
        ProjectIndex::load_evidence(&self.root).unwrap()
    }
    pub fn at(&self, name: &str, needle: &str) -> Position {
        at(&self.read(name), needle)
    }
}
pub fn at(source: &str, needle: &str) -> Position {
    let offset = source
        .find(needle)
        .unwrap_or_else(|| panic!("missing {needle:?}"));
    let prefix = &source[..offset];
    Position::new(
        prefix.bytes().filter(|&x| x == b'\n').count() as u32,
        prefix.rsplit('\n').next().unwrap().encode_utf16().count() as u32,
    )
}
pub fn after(source: &str, prefix: &str) -> Position {
    let offset = source.find(prefix).unwrap() + prefix.len();
    let text = &source[..offset];
    Position::new(
        text.bytes().filter(|&x| x == b'\n').count() as u32,
        text.rsplit('\n').next().unwrap().encode_utf16().count() as u32,
    )
}
pub fn labels(index: &ProjectIndex, path: &Path, at: Position) -> Vec<String> {
    index
        .completions_at(path, at)
        .iter()
        .map(|x| x.filter_text.clone())
        .collect()
}
