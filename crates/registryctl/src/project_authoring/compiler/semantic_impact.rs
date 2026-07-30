// SPDX-License-Identifier: Apache-2.0

/// Produces the conservative semantic-impact view that is justified by the
/// signed approval state.
///
/// Approval state v1 binds whole-dimension digests. It does not bind an
/// addressable field diff, so this producer deliberately reports dimension
/// precision and does not attempt to recover fields, values, or change
/// direction from the current authored documents.
fn project_semantic_impact_report(
    loaded: &LoadedRegistryProject,
    baseline: Option<&Value>,
    disclosure_digest: &str,
) -> ProjectSemanticImpactReportV1 {
    let report_baseline = if baseline.is_some() {
        ProjectBaseline::VerifiedSignedBundle
    } else {
        ProjectBaseline::InitialWithoutBaseline
    };
    let direction = if baseline.is_some() {
        SemanticDirection::Changed
    } else {
        SemanticDirection::Unbaselined
    };
    let changes = changed_semantic_dimensions(loaded, baseline, disclosure_digest)
        .into_iter()
        .filter(|dimension| {
            affected_products(loaded, baseline, *dimension).any()
                && (baseline.is_some() || semantic_dimension_has_current_subjects(loaded, *dimension))
        })
        .map(|dimension| semantic_impact_for_dimension(loaded, baseline, dimension, direction))
        .collect();

    ProjectSemanticImpactReportV1 {
        schema_version: ProjectSemanticImpactSchemaVersion::V1,
        baseline: report_baseline,
        changes,
    }
}

fn semantic_dimension_has_current_subjects(
    loaded: &LoadedRegistryProject,
    dimension: SemanticDimension,
) -> bool {
    match dimension {
        SemanticDimension::Claim | SemanticDimension::Disclosure => loaded
            .project
            .services
            .values()
            .any(|service| !service.claims.is_empty()),
        SemanticDimension::Integration => {
            !loaded.project.integrations.is_empty()
                || !loaded.project.entities.is_empty()
                || loaded
                    .project
                    .services
                    .values()
                    .any(|service| !service.consultations.is_empty())
        }
        SemanticDimension::ServicePolicy => !loaded.project.services.is_empty(),
        SemanticDimension::OperatorSecurity | SemanticDimension::Compiler => true,
    }
}

fn changed_semantic_dimensions(
    loaded: &LoadedRegistryProject,
    baseline: Option<&Value>,
    disclosure_digest: &str,
) -> Vec<SemanticDimension> {
    let previous_digests = baseline.and_then(|state| state.get("semantic_digests"));
    let mut changes = [
        (
            SemanticDimension::Claim,
            loaded.semantic_digests.claim.as_str(),
            previous_digests
                .and_then(|digests| digests.get("claim"))
                .and_then(Value::as_str),
        ),
        (
            SemanticDimension::Integration,
            loaded.semantic_digests.integration.as_str(),
            previous_digests
                .and_then(|digests| digests.get("integration"))
                .and_then(Value::as_str),
        ),
        (
            SemanticDimension::ServicePolicy,
            loaded.semantic_digests.service_policy.as_str(),
            previous_digests
                .and_then(|digests| digests.get("service_policy"))
                .and_then(Value::as_str),
        ),
        (
            SemanticDimension::OperatorSecurity,
            loaded.semantic_digests.operator_security.as_str(),
            previous_digests
                .and_then(|digests| digests.get("operator_security"))
                .and_then(Value::as_str),
        ),
        (
            SemanticDimension::Disclosure,
            disclosure_digest,
            baseline
                .and_then(|state| state.get("disclosure_digest"))
                .and_then(Value::as_str),
        ),
    ]
    .into_iter()
    .filter(|(_, current, previous)| *previous != Some(*current))
    .map(|(dimension, _, _)| dimension)
    .collect::<Vec<_>>();

    // Compiler changes remain independent of authored semantic dimensions.
    // An initial report has no prior compiler to compare, matching the legacy
    // semantic_changes projection.
    if baseline
        .and_then(|state| state.get("compiler_version"))
        .and_then(Value::as_str)
        .is_some_and(|version| version != env!("CARGO_PKG_VERSION"))
    {
        changes.push(SemanticDimension::Compiler);
    }
    changes.sort_unstable();
    changes.dedup();
    changes
}

fn semantic_impact_for_dimension(
    loaded: &LoadedRegistryProject,
    baseline: Option<&Value>,
    dimension: SemanticDimension,
    direction: SemanticDirection,
) -> ProjectSemanticImpact {
    let affected_products = affected_products(loaded, baseline, dimension);
    ProjectSemanticImpact {
        location: SemanticImpactLocation::Dimension,
        dimension,
        direction,
        affected_subjects: affected_subjects(
            loaded,
            affected_products,
            has_consultation_signing_input(loaded, baseline),
        ),
        consumers: consumers(affected_products),
        review_classes: review_classes(dimension, affected_products),
        product_impacts: product_impacts(dimension, affected_products),
        requirements: requirements(affected_products),
    }
}

#[derive(Clone, Copy)]
struct AffectedProducts {
    relay_public: bool,
    relay_consultation: bool,
    notary: bool,
}

impl AffectedProducts {
    const fn none() -> Self {
        Self {
            relay_public: false,
            relay_consultation: false,
            notary: false,
        }
    }

    const fn both() -> Self {
        Self {
            relay_public: true,
            relay_consultation: true,
            notary: true,
        }
    }

    const fn any(self) -> bool {
        self.relay_public || self.relay_consultation || self.notary
    }

    const fn any_relay(self) -> bool {
        self.relay_public || self.relay_consultation
    }

    const fn union(self, other: Self) -> Self {
        Self {
            relay_public: self.relay_public || other.relay_public,
            relay_consultation: self.relay_consultation || other.relay_consultation,
            notary: self.notary || other.notary,
        }
    }

    const fn intersect(self, other: Self) -> Self {
        Self {
            relay_public: self.relay_public && other.relay_public,
            relay_consultation: self.relay_consultation && other.relay_consultation,
            notary: self.notary && other.notary,
        }
    }
}

fn affected_products(
    loaded: &LoadedRegistryProject,
    baseline: Option<&Value>,
    dimension: SemanticDimension,
) -> AffectedProducts {
    let (requires_relay, requires_notary) = project_product_topology(&loaded.project);
    let current_products = AffectedProducts {
        relay_public: requires_relay,
        relay_consultation: requires_relay
            && loaded
                .project
                .services
                .values()
                .any(|service| !service.consultations.is_empty()),
        notary: requires_notary,
    };
    let product_topology = current_products.union(baseline_product_topology(baseline));
    let dimension_products = match dimension {
        SemanticDimension::Claim | SemanticDimension::Disclosure => AffectedProducts {
            relay_public: false,
            relay_consultation: false,
            notary: true,
        },
        SemanticDimension::Integration => AffectedProducts {
            relay_public: !product_topology.relay_consultation,
            relay_consultation: product_topology.relay_consultation,
            notary: true,
        },
        SemanticDimension::ServicePolicy
        | SemanticDimension::OperatorSecurity
        | SemanticDimension::Compiler => AffectedProducts {
            relay_public: true,
            relay_consultation: true,
            notary: true,
        },
    };
    dimension_products.intersect(product_topology)
}

fn baseline_product_topology(baseline: Option<&Value>) -> AffectedProducts {
    let Some(baseline) = baseline else {
        return AffectedProducts::none();
    };
    if let Some(products) = baseline
        .pointer("/promotion_projection/products")
        .and_then(Value::as_array)
    {
        let mut topology = AffectedProducts::none();
        for product in products {
            match product.as_str() {
                Some("relay") => topology.relay_public = true,
                Some("notary") => topology.notary = true,
                _ => return AffectedProducts::both(),
            }
        }
        topology.relay_consultation = baseline
            .pointer("/generated_closure_digests/relay_consultation")
            .is_some_and(Value::is_string);
        return topology;
    }

    if let Some(digests) = baseline
        .get("generated_closure_digests")
        .and_then(Value::as_object)
    {
        let topology = AffectedProducts {
            relay_public: digests.get("relay").is_some_and(Value::is_string),
            relay_consultation: digests
                .get("relay_consultation")
                .is_some_and(Value::is_string),
            notary: digests.get("notary").is_some_and(Value::is_string),
        };
        if topology.any() {
            return topology;
        }
    }

    // Older or malformed signed baselines do not provide enough product
    // inventory to prove that a removed product has no retirement obligation.
    AffectedProducts::both()
}

fn affected_subjects(
    loaded: &LoadedRegistryProject,
    products: AffectedProducts,
    has_consultation_signing_input: bool,
) -> Vec<AffectedSubject> {
    let mut subjects = BTreeMap::<(u8, String), AffectedSubjectKind>::new();
    let mut add = |kind: AffectedSubjectKind, id: String| {
        subjects
            .entry((subject_kind_rank(kind), id))
            .or_insert(kind);
    };

    // A dimension digest cannot identify the changed member. Include the full
    // authored identity closure that can feed compilation, fixture validation,
    // policy review, or disclosure review. Only stable authored identifiers and
    // aliases are retained, never authored values or filesystem locations.
    for (integration_alias, integration) in &loaded.integrations {
        add(AffectedSubjectKind::Integration, integration_alias.clone());
        for (_, fixture) in &integration.fixtures {
            add(
                AffectedSubjectKind::Fixture,
                format!("{integration_alias}.{}", fixture.name),
            );
        }
    }
    for (service_id, service) in &loaded.project.services {
        add(AffectedSubjectKind::ServicePolicy, service_id.clone());
        for consultation_id in service.consultations.keys() {
            add(
                AffectedSubjectKind::Consultation,
                format!("{service_id}.{consultation_id}"),
            );
        }
        for claim_id in service.claims.keys() {
            let id = format!("{service_id}.{claim_id}");
            add(AffectedSubjectKind::Claim, id.clone());
            add(AffectedSubjectKind::Disclosure, id);
        }
    }

    if products.relay_public {
        add(
            AffectedSubjectKind::ProductInput,
            "registry-relay.config".to_string(),
        );
    }
    if products.relay_consultation && has_consultation_signing_input {
        add(
            AffectedSubjectKind::ProductInput,
            "registry-relay.consultation.config".to_string(),
        );
    }
    if products.any_relay() {
        for artifact in [
            "registry-relay.consultation-contracts",
            "registry-relay.integration-packs",
            "registry-relay.private-bindings",
            "registry-relay.runtime-config",
        ] {
            add(AffectedSubjectKind::GeneratedArtifact, artifact.to_string());
        }
    }
    if products.notary {
        add(
            AffectedSubjectKind::ProductInput,
            "registry-notary.config".to_string(),
        );
        for artifact in [
            "registry-notary.claim-configuration",
            "registry-notary.disclosure-policy",
            "registry-notary.runtime-config",
        ] {
            add(AffectedSubjectKind::GeneratedArtifact, artifact.to_string());
        }
    }

    subjects
        .into_iter()
        .map(|((_, id), kind)| AffectedSubject { kind, id })
        .collect()
}

fn has_consultation_signing_input(
    loaded: &LoadedRegistryProject,
    baseline: Option<&Value>,
) -> bool {
    loaded
        .project
        .services
        .values()
        .any(|service| !service.consultations.is_empty())
        || baseline
            .and_then(|state| {
                state.pointer("/generated_closure_digests/relay_consultation")
            })
            .is_some_and(Value::is_string)
}

const fn subject_kind_rank(kind: AffectedSubjectKind) -> u8 {
    match kind {
        AffectedSubjectKind::Integration => 0,
        AffectedSubjectKind::Fixture => 1,
        AffectedSubjectKind::ServicePolicy => 2,
        AffectedSubjectKind::Consultation => 3,
        AffectedSubjectKind::Claim => 4,
        AffectedSubjectKind::Disclosure => 5,
        AffectedSubjectKind::ProductInput => 6,
        AffectedSubjectKind::GeneratedArtifact => 7,
    }
}

fn consumers(products: AffectedProducts) -> Vec<ImpactConsumer> {
    let mut consumers = vec![ImpactConsumer::RegistryctlAuthoring];
    if products.any_relay() {
        consumers.push(ImpactConsumer::RegistryRelay);
    }
    if products.notary {
        consumers.push(ImpactConsumer::RegistryNotary);
    }
    consumers.push(ImpactConsumer::EditorTooling);
    consumers.push(ImpactConsumer::DocsGenerator);
    consumers.push(ImpactConsumer::BundleSigner);
    consumers.push(ImpactConsumer::DeploymentTooling);
    consumers.push(ImpactConsumer::Operator);
    consumers
}

fn review_classes(
    dimension: SemanticDimension,
    products: AffectedProducts,
) -> Vec<ImpactReviewClass> {
    let mut classes = match dimension {
        SemanticDimension::OperatorSecurity => vec![
            ImpactReviewClass::Contract,
            ImpactReviewClass::Authoring,
            ImpactReviewClass::Interoperability,
            ImpactReviewClass::Privacy,
            ImpactReviewClass::Security,
            ImpactReviewClass::Relay,
            ImpactReviewClass::Notary,
            ImpactReviewClass::Compatibility,
            ImpactReviewClass::Testing,
            ImpactReviewClass::Operations,
            ImpactReviewClass::Release,
        ],
        SemanticDimension::Claim | SemanticDimension::Disclosure => vec![
            ImpactReviewClass::Contract,
            ImpactReviewClass::Authoring,
            ImpactReviewClass::Semantics,
            ImpactReviewClass::Interoperability,
            ImpactReviewClass::Privacy,
            ImpactReviewClass::Security,
            ImpactReviewClass::Notary,
            ImpactReviewClass::Compatibility,
            ImpactReviewClass::Documentation,
            ImpactReviewClass::Testing,
            ImpactReviewClass::Operations,
            ImpactReviewClass::Release,
        ],
        SemanticDimension::Integration
        | SemanticDimension::ServicePolicy
        | SemanticDimension::Compiler => vec![
            ImpactReviewClass::Contract,
            ImpactReviewClass::Authoring,
            ImpactReviewClass::Semantics,
            ImpactReviewClass::Interoperability,
            ImpactReviewClass::Privacy,
            ImpactReviewClass::Security,
            ImpactReviewClass::Relay,
            ImpactReviewClass::Notary,
            ImpactReviewClass::Compatibility,
            ImpactReviewClass::Documentation,
            ImpactReviewClass::Testing,
            ImpactReviewClass::Operations,
            ImpactReviewClass::Release,
        ],
    };
    if !products.any_relay() {
        classes.retain(|class| *class != ImpactReviewClass::Relay);
    }
    if !products.notary {
        classes.retain(|class| *class != ImpactReviewClass::Notary);
    }
    classes
}

fn product_impacts(
    dimension: SemanticDimension,
    products: AffectedProducts,
) -> Vec<ProductImpact> {
    let runtime_impact = if dimension == SemanticDimension::OperatorSecurity {
        ProductImpactClass::Reconfigure
    } else {
        ProductImpactClass::Regenerate
    };
    let mut impacts = vec![ProductImpact {
        product: ProjectProduct::Registryctl,
        impact: ProductImpactClass::Revalidate,
    }];
    if products.any_relay() {
        impacts.push(ProductImpact {
            product: ProjectProduct::Relay,
            impact: runtime_impact,
        });
    }
    if products.notary {
        impacts.push(ProductImpact {
            product: ProjectProduct::Notary,
            impact: runtime_impact,
        });
    }
    impacts.push(ProductImpact {
        product: ProjectProduct::Docs,
        impact: ProductImpactClass::Republish,
    });
    impacts
}

fn requirements(products: AffectedProducts) -> ImpactRequirements {
    let actions = [
        (
            products.relay_public,
            RequiredProductAction::RelayPublic,
        ),
        (
            products.relay_consultation,
            RequiredProductAction::RelayConsultation,
        ),
        (products.notary, RequiredProductAction::Notary),
    ]
    .into_iter()
    .filter_map(|(required, action)| required.then_some(action))
    .collect::<Vec<_>>();
    ImpactRequirements {
        signing: actions.clone(),
        activation: actions.clone(),
        restart: actions,
    }
}

#[cfg(test)]
mod semantic_impact_tests {
    use super::*;

    fn loaded_project() -> LoadedRegistryProject {
        load_registry_project(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/project-authoring/dhis2-tracker"),
            Some("local"),
        )
        .expect("semantic-impact fixture loads")
    }

    fn loaded_relay_only_project() -> LoadedRegistryProject {
        load_registry_project(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/project-authoring/relay-only-materialization"),
            Some("local"),
        )
        .expect("Relay-only semantic-impact fixture loads")
    }

    fn disclosure_digest() -> String {
        format!("sha256:{}", "d".repeat(64))
    }

    fn matching_baseline(loaded: &LoadedRegistryProject, disclosure_digest: &str) -> Value {
        json!({
            "compiler_version": env!("CARGO_PKG_VERSION"),
            "semantic_digests": {
                "claim": loaded.semantic_digests.claim,
                "integration": loaded.semantic_digests.integration,
                "service_policy": loaded.semantic_digests.service_policy,
                "operator_security": loaded.semantic_digests.operator_security,
            },
            "disclosure_digest": disclosure_digest,
        })
    }

    fn dimensions(report: &ProjectSemanticImpactReportV1) -> Vec<SemanticDimension> {
        report
            .changes
            .iter()
            .map(|change| change.dimension)
            .collect()
    }

    fn actions(actions: &[RequiredProductAction]) -> Vec<RequiredProductAction> {
        actions.to_vec()
    }

    fn consumer_rank(consumer: ImpactConsumer) -> u8 {
        match consumer {
            ImpactConsumer::RegistryctlAuthoring => 0,
            ImpactConsumer::RegistryRelay => 1,
            ImpactConsumer::RegistryNotary => 2,
            ImpactConsumer::EditorTooling => 3,
            ImpactConsumer::DocsGenerator => 4,
            ImpactConsumer::BundleSigner => 5,
            ImpactConsumer::DeploymentTooling => 6,
            ImpactConsumer::Operator => 7,
        }
    }

    fn review_class_rank(class: ImpactReviewClass) -> u8 {
        match class {
            ImpactReviewClass::Contract => 0,
            ImpactReviewClass::Authoring => 1,
            ImpactReviewClass::Semantics => 2,
            ImpactReviewClass::Interoperability => 3,
            ImpactReviewClass::Privacy => 4,
            ImpactReviewClass::Security => 5,
            ImpactReviewClass::Relay => 6,
            ImpactReviewClass::Notary => 7,
            ImpactReviewClass::Compatibility => 8,
            ImpactReviewClass::Documentation => 9,
            ImpactReviewClass::Testing => 10,
            ImpactReviewClass::Operations => 11,
            ImpactReviewClass::Release => 12,
        }
    }

    fn product_rank(product: ProjectProduct) -> u8 {
        match product {
            ProjectProduct::Registryctl => 0,
            ProjectProduct::Relay => 1,
            ProjectProduct::Notary => 2,
            ProjectProduct::Editor => 3,
            ProjectProduct::Docs => 4,
        }
    }

    #[test]
    fn initial_report_is_dimension_precise_and_preserves_legacy_projection() {
        let loaded = loaded_project();
        let disclosure_digest = disclosure_digest();
        let report = project_semantic_impact_report(&loaded, None, &disclosure_digest);

        assert_eq!(report.baseline, ProjectBaseline::InitialWithoutBaseline);
        assert_eq!(
            dimensions(&report),
            vec![
                SemanticDimension::Claim,
                SemanticDimension::Integration,
                SemanticDimension::ServicePolicy,
                SemanticDimension::OperatorSecurity,
                SemanticDimension::Disclosure,
            ]
        );
        assert!(report.changes.iter().all(|change| {
            change.location == SemanticImpactLocation::Dimension
                && change.direction == SemanticDirection::Unbaselined
        }));

        let legacy = semantic_change_records(&loaded, None, &disclosure_digest);
        assert_eq!(
            serde_json::to_value(report.dimension_only_changes()).expect("projection serializes"),
            serde_json::to_value(legacy).expect("legacy changes serialize"),
        );
    }

    #[test]
    fn verified_baseline_reports_each_changed_dimension_conservatively() {
        let loaded = loaded_project();
        let disclosure_digest = disclosure_digest();
        let dimension_cases = [
            (SemanticDimension::Claim, "claim"),
            (SemanticDimension::Integration, "integration"),
            (SemanticDimension::ServicePolicy, "service_policy"),
            (SemanticDimension::OperatorSecurity, "operator_security"),
            (SemanticDimension::Disclosure, "disclosure_digest"),
            (SemanticDimension::Compiler, "compiler_version"),
        ];

        for (expected, key) in dimension_cases {
            let mut baseline = matching_baseline(&loaded, &disclosure_digest);
            match key {
                "disclosure_digest" | "compiler_version" => {
                    baseline[key] = Value::String("previous".to_string());
                }
                semantic_digest => {
                    baseline["semantic_digests"][semantic_digest] =
                        Value::String(format!("sha256:{}", "0".repeat(64)));
                }
            }
            let report =
                project_semantic_impact_report(&loaded, Some(&baseline), &disclosure_digest);
            assert_eq!(report.baseline, ProjectBaseline::VerifiedSignedBundle);
            assert_eq!(
                dimensions(&report),
                vec![expected],
                "unexpected change set for {key}"
            );
            let change = &report.changes[0];
            assert_eq!(change.location, SemanticImpactLocation::Dimension);
            assert_eq!(change.direction, SemanticDirection::Changed);
        }
    }

    #[test]
    fn matching_verified_baseline_has_no_changes() {
        let loaded = loaded_project();
        let disclosure_digest = disclosure_digest();
        let baseline = matching_baseline(&loaded, &disclosure_digest);
        let report = project_semantic_impact_report(&loaded, Some(&baseline), &disclosure_digest);

        assert_eq!(report.baseline, ProjectBaseline::VerifiedSignedBundle);
        assert!(report.changes.is_empty());
        assert!(report.dimension_only_changes().is_empty());
    }

    #[test]
    fn relay_only_impact_never_requires_notary_review_signing_or_activation() {
        let loaded = loaded_relay_only_project();
        let report = project_semantic_impact_report(&loaded, None, &disclosure_digest());

        assert_eq!(
            dimensions(&report),
            vec![
                SemanticDimension::Integration,
                SemanticDimension::OperatorSecurity,
            ]
        );
        for change in report.changes {
            assert!(change.consumers.contains(&ImpactConsumer::RegistryRelay));
            assert!(!change.consumers.contains(&ImpactConsumer::RegistryNotary));
            assert!(change.review_classes.contains(&ImpactReviewClass::Relay));
            assert!(!change.review_classes.contains(&ImpactReviewClass::Notary));
            assert!(change
                .product_impacts
                .iter()
                .any(|impact| impact.product == ProjectProduct::Relay));
            assert!(!change
                .product_impacts
                .iter()
                .any(|impact| impact.product == ProjectProduct::Notary));
            let expected = actions(&[RequiredProductAction::RelayPublic]);
            assert_eq!(change.requirements.signing, expected);
            assert_eq!(change.requirements.activation, expected);
            assert_eq!(change.requirements.restart, expected);
            assert!(!change.affected_subjects.iter().any(|subject| {
                subject.id.starts_with("registry-notary.")
                    || subject.id == "registry-relay.consultation.config"
                    || matches!(
                        subject.kind,
                        AffectedSubjectKind::Claim | AffectedSubjectKind::Disclosure
                    )
            }));
        }
    }

    #[test]
    fn relay_impact_names_the_separate_consultation_signing_input() {
        let loaded = loaded_project();
        let impact = semantic_impact_for_dimension(
            &loaded,
            None,
            SemanticDimension::Integration,
            SemanticDirection::Changed,
        );
        let product_inputs = impact
            .affected_subjects
            .iter()
            .filter(|subject| subject.kind == AffectedSubjectKind::ProductInput)
            .map(|subject| subject.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            product_inputs,
            vec![
                "registry-notary.config",
                "registry-relay.consultation.config",
            ]
        );
    }

    #[test]
    fn verified_baseline_product_removal_keeps_removed_product_obligations() {
        let current = loaded_relay_only_project();
        let previous = loaded_project();
        let mut baseline = matching_baseline(
            &previous,
            &format!("sha256:{}", "b".repeat(64)),
        );
        for digest in [
            "claim",
            "integration",
            "service_policy",
            "operator_security",
        ] {
            baseline["semantic_digests"][digest] =
                Value::String(format!("sha256:{}", "0".repeat(64)));
        }
        baseline["promotion_projection"] = json!({
            "products": ["relay", "notary"],
        });
        baseline["generated_closure_digests"] = json!({
            "relay_consultation": format!("sha256:{}", "c".repeat(64)),
        });
        let report =
            project_semantic_impact_report(&current, Some(&baseline), &disclosure_digest());

        for dimension in [SemanticDimension::Claim, SemanticDimension::Disclosure] {
            let change = report
                .changes
                .iter()
                .find(|change| change.dimension == dimension)
                .unwrap_or_else(|| panic!("{dimension:?} product-removal impact is retained"));
            assert!(change.consumers.contains(&ImpactConsumer::RegistryNotary));
            assert!(!change.consumers.contains(&ImpactConsumer::RegistryRelay));
            let expected = actions(&[RequiredProductAction::Notary]);
            assert_eq!(change.requirements.signing, expected);
            assert_eq!(change.requirements.activation, expected);
            assert_eq!(change.requirements.restart, expected);
        }
        for dimension in [
            SemanticDimension::Integration,
            SemanticDimension::ServicePolicy,
            SemanticDimension::OperatorSecurity,
        ] {
            let change = report
                .changes
                .iter()
                .find(|change| change.dimension == dimension)
                .unwrap_or_else(|| panic!("{dimension:?} product-removal impact is retained"));
            let expected = if dimension == SemanticDimension::Integration {
                actions(&[
                    RequiredProductAction::RelayConsultation,
                    RequiredProductAction::Notary,
                ])
            } else {
                actions(&[
                    RequiredProductAction::RelayPublic,
                    RequiredProductAction::RelayConsultation,
                    RequiredProductAction::Notary,
                ])
            };
            assert_eq!(change.requirements.signing, expected);
            assert_eq!(change.requirements.activation, expected);
            assert_eq!(change.requirements.restart, expected);
        }
    }

    #[test]
    fn legacy_baseline_without_product_inventory_stays_conservative() {
        let current = loaded_relay_only_project();
        let previous = loaded_project();
        let mut baseline =
            matching_baseline(&previous, &format!("sha256:{}", "b".repeat(64)));
        baseline["semantic_digests"]["integration"] =
            Value::String(format!("sha256:{}", "0".repeat(64)));
        let report =
            project_semantic_impact_report(&current, Some(&baseline), &disclosure_digest());
        let integration = report
            .changes
            .iter()
            .find(|change| change.dimension == SemanticDimension::Integration)
            .expect("legacy baseline conservatively retains integration impact");

        let expected = actions(&[
            RequiredProductAction::RelayConsultation,
            RequiredProductAction::Notary,
        ]);
        assert_eq!(integration.requirements.signing, expected);
        assert_eq!(integration.requirements.activation, expected);
        assert_eq!(integration.requirements.restart, expected);
    }

    #[test]
    fn each_dimension_has_conservative_signing_activation_and_restart() {
        let loaded = loaded_project();
        let expected = [
            (
                SemanticDimension::Claim,
                actions(&[RequiredProductAction::Notary]),
            ),
            (
                SemanticDimension::Integration,
                actions(&[
                    RequiredProductAction::RelayConsultation,
                    RequiredProductAction::Notary,
                ]),
            ),
            (
                SemanticDimension::ServicePolicy,
                actions(&[
                    RequiredProductAction::RelayPublic,
                    RequiredProductAction::RelayConsultation,
                    RequiredProductAction::Notary,
                ]),
            ),
            (
                SemanticDimension::OperatorSecurity,
                actions(&[
                    RequiredProductAction::RelayPublic,
                    RequiredProductAction::RelayConsultation,
                    RequiredProductAction::Notary,
                ]),
            ),
            (
                SemanticDimension::Disclosure,
                actions(&[RequiredProductAction::Notary]),
            ),
            (
                SemanticDimension::Compiler,
                actions(&[
                    RequiredProductAction::RelayPublic,
                    RequiredProductAction::RelayConsultation,
                    RequiredProductAction::Notary,
                ]),
            ),
        ];

        for (dimension, expected) in expected {
            let impact = semantic_impact_for_dimension(
                &loaded,
                None,
                dimension,
                SemanticDirection::Changed,
            );
            assert_eq!(impact.requirements.signing, expected);
            assert_eq!(impact.requirements.activation, expected);
            assert_eq!(impact.requirements.restart, expected);
            assert!(impact.consumers.contains(&ImpactConsumer::BundleSigner));
            assert!(impact
                .consumers
                .contains(&ImpactConsumer::DeploymentTooling));
            assert!(impact.consumers.contains(&ImpactConsumer::Operator));
            assert!(impact
                .review_classes
                .contains(&ImpactReviewClass::Operations));
            assert!(impact.review_classes.contains(&ImpactReviewClass::Release));
        }
    }

    #[test]
    fn each_dimension_names_the_full_safe_authored_identity_closure() {
        let loaded = loaded_project();
        for dimension in [
            SemanticDimension::Claim,
            SemanticDimension::Integration,
            SemanticDimension::ServicePolicy,
            SemanticDimension::OperatorSecurity,
            SemanticDimension::Disclosure,
            SemanticDimension::Compiler,
        ] {
            let impact = semantic_impact_for_dimension(
                &loaded,
                None,
                dimension,
                SemanticDirection::Changed,
            );
            let subjects = impact
                .affected_subjects
                .iter()
                .map(|subject| (subject_kind_rank(subject.kind), subject.id.as_str()))
                .collect::<Vec<_>>();
            let unique = subjects.iter().copied().collect::<BTreeSet<_>>();
            assert_eq!(subjects.len(), unique.len());
            assert!(subjects.windows(2).all(|pair| pair[0] < pair[1]));
            let consumer_ranks = impact
                .consumers
                .iter()
                .copied()
                .map(consumer_rank)
                .collect::<Vec<_>>();
            assert!(consumer_ranks.windows(2).all(|pair| pair[0] < pair[1]));
            let review_ranks = impact
                .review_classes
                .iter()
                .copied()
                .map(review_class_rank)
                .collect::<Vec<_>>();
            assert!(review_ranks.windows(2).all(|pair| pair[0] < pair[1]));
            let product_ranks = impact
                .product_impacts
                .iter()
                .map(|product| product_rank(product.product))
                .collect::<Vec<_>>();
            assert!(product_ranks.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(impact.affected_subjects.iter().any(|subject| {
                subject.kind == AffectedSubjectKind::Integration && subject.id == "health-record"
            }));
            assert!(impact.affected_subjects.iter().any(|subject| {
                subject.kind == AffectedSubjectKind::Fixture
                    && subject.id == "health-record.complete-child-health-evidence"
            }));
            assert!(impact.affected_subjects.iter().any(|subject| {
                subject.kind == AffectedSubjectKind::ServicePolicy
                    && subject.id == "health-verification"
            }));
            assert!(impact.affected_subjects.iter().any(|subject| {
                subject.kind == AffectedSubjectKind::Consultation
                    && subject.id == "health-verification.health"
            }));
            assert!(impact.affected_subjects.iter().any(|subject| {
                subject.kind == AffectedSubjectKind::Claim
                    && subject.id == "health-verification.child-program-active"
            }));
            assert!(impact.affected_subjects.iter().any(|subject| {
                subject.kind == AffectedSubjectKind::Disclosure
                    && subject.id == "health-verification.child-program-active"
            }));
            assert!(impact
                .affected_subjects
                .iter()
                .any(|subject| { subject.kind == AffectedSubjectKind::ProductInput }));
            assert!(impact
                .affected_subjects
                .iter()
                .any(|subject| { subject.kind == AffectedSubjectKind::GeneratedArtifact }));
        }
    }

    #[test]
    fn report_never_exposes_runtime_or_fixture_values() {
        let loaded = loaded_project();
        let report = ProjectSemanticImpactReportV1 {
            schema_version: ProjectSemanticImpactSchemaVersion::V1,
            baseline: ProjectBaseline::VerifiedSignedBundle,
            changes: [
                SemanticDimension::Claim,
                SemanticDimension::Integration,
                SemanticDimension::ServicePolicy,
                SemanticDimension::OperatorSecurity,
                SemanticDimension::Disclosure,
                SemanticDimension::Compiler,
            ]
            .into_iter()
            .map(|dimension| {
                semantic_impact_for_dimension(
                    &loaded,
                    None,
                    dimension,
                    SemanticDirection::Changed,
                )
            })
            .collect(),
        };
        let rendered = serde_json::to_string(&report).expect("semantic impact serializes");

        for forbidden in [
            "https://health-registry.invalid",
            "127.0.0.1",
            "/run/secrets/relay-workload-token",
            "HEALTH_REGISTRY_USERNAME",
            "REGISTRY_NOTARY_ISSUER_JWK",
            "health-relay-client",
            "A0000000001",
            "Nia",
            "REF-0001",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "semantic impact exposed unsafe value {forbidden}"
            );
        }
    }

    #[test]
    fn verified_projection_matches_legacy_changes_including_compiler() {
        let loaded = loaded_project();
        let disclosure_digest = disclosure_digest();
        let mut baseline = matching_baseline(&loaded, &disclosure_digest);
        baseline["semantic_digests"]["claim"] = Value::String(format!("sha256:{}", "0".repeat(64)));
        baseline["compiler_version"] = Value::String("previous".to_string());

        let report = project_semantic_impact_report(&loaded, Some(&baseline), &disclosure_digest);
        let legacy = semantic_change_records(&loaded, Some(&baseline), &disclosure_digest);
        assert_eq!(
            serde_json::to_value(report.dimension_only_changes()).expect("projection serializes"),
            serde_json::to_value(legacy).expect("legacy changes serialize"),
        );
    }
}
