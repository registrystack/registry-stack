// SPDX-License-Identifier: Apache-2.0

//! The registry's time zone: required wherever BReg resolves "today".

use std::collections::BTreeMap;

use crate::contract::FieldTypeSource;
use crate::diagnostics::Diagnostic;
use crate::model::{
    CompiledActionInventory, CompiledEntity, CompiledQueryKind, CompiledRouteInventory,
    CompiledStatisticalDataset,
};

const PATH: &str = "project.timezone";
const EXAMPLE: &str = "for example `timezone: Asia/Colombo`, or `timezone: UTC` to keep UTC dates";

/// Refuse an unknown zone, and refuse a project that answers "today"
/// without one. Each refusal names the site that needs the zone and the
/// line to add.
pub(crate) fn validate(
    timezone: Option<&str>,
    entities: &BTreeMap<String, CompiledEntity>,
    routes: &CompiledRouteInventory,
    actions: &CompiledActionInventory,
    statistical_datasets: &BTreeMap<String, CompiledStatisticalDataset>,
) -> Vec<Diagnostic> {
    if let Some(timezone) = timezone {
        return if registry_platform_calendar::local_date(chrono::DateTime::UNIX_EPOCH, timezone)
            .is_ok()
        {
            Vec::new()
        } else {
            vec![Diagnostic::error(
                "breg.timezone.unknown",
                PATH,
                concat!(
                    "`project.timezone` is not an IANA time zone name; ",
                    "write a name such as `Asia/Colombo`, `Europe/Paris` or `UTC`"
                ),
            )]
        };
    }
    today_sites(entities, routes, actions, statistical_datasets)
        .into_iter()
        .map(|site| {
            Diagnostic::error(
                "breg.timezone.required",
                PATH,
                &format!(
                    "{site} uses today's date, so the registry must declare its time zone; add a `timezone:` line under `project:`, {EXAMPLE}"
                ),
            )
        })
        .collect()
}

fn today_sites(
    entities: &BTreeMap<String, CompiledEntity>,
    routes: &CompiledRouteInventory,
    actions: &CompiledActionInventory,
    statistical_datasets: &BTreeMap<String, CompiledStatisticalDataset>,
) -> Vec<String> {
    let mut sites = Vec::new();
    for route in &routes.routes {
        if route.query_kind == Some(CompiledQueryKind::Current)
            && entities
                .get(&route.entity_id)
                .is_some_and(has_date_interval)
        {
            sites.push(format!("the route `{}` (`{}`)", route.id, route.path));
        }
    }
    for action in &actions.actions {
        for requirement in action
            .requires
            .iter()
            .filter(|requirement| requirement.current_date.is_some())
        {
            sites.push(format!(
                "the Action `{}` requirement on `{}` field `{}` (`currentDate`)",
                action.id, requirement.entity_id, requirement.field
            ));
        }
    }
    for entity in entities.values() {
        for relation in entity
            .derived_relations
            .values()
            .filter(|relation| relation.uses_evaluation_date)
        {
            let fields = entity
                .derived_fields
                .values()
                .filter(|field| field.derivation_id == relation.id)
                .map(|field| format!("`{}`", field.logical.id))
                .collect::<Vec<_>>()
                .join(", ");
            sites.push(format!(
                "the record type `{}` derived field {fields} (`registry_context.evaluation_date()`)",
                entity.id
            ));
        }
    }
    for dataset in statistical_datasets.keys() {
        sites.push(format!(
            "the statistics dataset `{dataset}` (its current period)"
        ));
    }
    sites
}

fn has_date_interval(entity: &CompiledEntity) -> bool {
    entity.temporal.as_ref().is_some_and(|temporal| {
        entity
            .fields
            .get(&temporal.start_field)
            .is_some_and(|field| field.field_type == FieldTypeSource::Date)
    })
}
