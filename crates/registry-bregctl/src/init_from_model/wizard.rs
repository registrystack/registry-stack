// SPDX-License-Identifier: Apache-2.0
//! The questions a model-driven `init` asks when it is given neither a
//! selection file nor a starter.
//!
//! Every prompt the command can raise lives in this module, so the rest of
//! the derivation stays promptless: the answers become the same selection
//! document a starter ships or `--selection` reads, and the pipeline behind
//! it cannot tell the three apart. A prompt is only ever raised when both
//! standard streams are terminals, which the caller checks before it comes
//! here.
//!
//! The questions offer only what the resolver can carry, and validate
//! identifiers with the resolver's own grammar, so an answer accepted here is
//! never refused afterwards. A prompt cannot be driven from a test, so every
//! decision is a pure function beneath a thin prompt layer, and the prompt
//! layer only turns those functions' output into questions.

use std::collections::BTreeSet;

use inquire::error::InquireError;
use inquire::validator::{MinLengthValidator, Validation};
use inquire::{Confirm, CustomUserError, MultiSelect, Select, Text};

use registry_breg::Diagnostic;
use registry_linkml::publicschema::{self, Sensitivity};
use registry_linkml::{ClassDef, Model, Range, SlotDef};

use super::resolve::{self, INLINE_VOCABULARY_THRESHOLD};
use super::selection::{
    EntitySelection, ModelName, PropertySelection, RegistrySelection, Selection, VocabularyMode,
    VocabularySelection, API_VERSION, KIND,
};
use crate::diagnostic;

/// The longest description shown beside an option. A model definition can
/// describe itself in paragraphs; the list stays readable instead.
const DESCRIPTION_BUDGET: usize = 60;

/// The share of the systems behind the model that must already record a
/// property for it to be offered ticked.
const TICKED_CONVERGENCE_SHARE: f64 = 0.6;

/// One concept, as the concept question offers it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ConceptOption {
    concept: String,
    label: String,
}

/// One property, as the property question offers it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PropertyOption {
    name: String,
    label: String,
    /// True when the property is offered already ticked.
    ticked: bool,
}

/// A property the resolver cannot carry, with the resolver's own sentence
/// saying why and what to do instead.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WithheldProperty {
    name: String,
    reason: String,
}

/// What the property question offers for one concept, and what it leaves out.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PropertyOffer {
    offered: Vec<PropertyOption>,
    withheld: Vec<WithheldProperty>,
}

/// One concept the adopter chose, with every answer gathered about it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ChosenEntity {
    concept: String,
    properties: Vec<ChosenProperty>,
    naming: Naming,
}

/// One property the adopter chose.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ChosenProperty {
    name: String,
    /// The concept a reference points at, when more than one chosen concept
    /// fits its range. The entity identifier is only settled by the naming
    /// question, which comes later, so the answer is carried as a concept
    /// until the selection is assembled.
    target: Option<String>,
}

/// The identifiers of one entity, each set only where the adopter changed the
/// default the resolver would derive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Naming {
    id: Option<String>,
    route: Option<String>,
    identifier_field: Option<String>,
}

/// The identifiers already spoken for while the naming questions are asked.
/// The resolver refuses a selection that names one entity twice or routes two
/// entities the same way, so the prompt refuses it first, while the adopter is
/// still there to answer again.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Taken {
    ids: Vec<String>,
    routes: Vec<String>,
}

/// A reference the adopter has to settle: more than one chosen concept fits
/// the property's range.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceQuestion {
    /// Where the property sits in the answers so far.
    entity: usize,
    property: usize,
    /// The concepts that fit, in the order they were chosen.
    choices: Vec<String>,
}

/// One enumeration a chosen property draws on, as the code-list question
/// offers it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct VocabularyOption {
    r#enum: String,
    label: String,
    /// True when the project lists the enumeration in full unless the adopter
    /// says otherwise, which is the size rule the resolver applies to a
    /// selection that stays silent.
    listed: bool,
}

/// Asks for a selection and returns the document the answers describe.
pub(super) fn gather(model_name: ModelName, model: &Model) -> Result<Selection, Diagnostic> {
    let version = resolve::model_facts(model)?.version;
    let registry = ask_registry()?;
    let concepts = ask_concepts(model)?;

    let mut entities = Vec::new();
    for concept in &concepts {
        let offer = property_offer(model, concept, &concepts)?;
        let title = title(&model.classes[concept]);
        if let Some(line) = withheld_line(&title, &offer.withheld) {
            eprintln!("{line}");
        }
        entities.push(ChosenEntity {
            concept: concept.clone(),
            properties: ask_properties(&title, &offer)?,
            naming: Naming::default(),
        });
    }

    // The references come after every concept is chosen, because a property
    // may point at a concept chosen after the one that carries it.
    for question in reference_questions(model, &entities)? {
        let carrier = &entities[question.entity];
        let concept = carrier.concept.clone();
        let property = carrier.properties[question.property].name.clone();
        let target = ask_target(&concept, &property, &question.choices)?;
        entities[question.entity].properties[question.property].target = Some(target);
    }

    ask_naming(&mut entities)?;

    let options = vocabulary_options(model, &entities)?;
    let vocabularies = if options.is_empty() {
        Vec::new()
    } else {
        vocabulary_overrides(&options, &ask_vocabularies(&options)?)
    };

    let selection = assemble(model_name, &version, registry, &entities, vocabularies);
    if confirm_selection(&selection)? {
        Ok(selection)
    } else {
        Err(cancelled())
    }
}

/// Asks what the registry is called.
fn ask_registry() -> Result<RegistrySelection, Diagnostic> {
    let id = Text::new("Registry identifier")
        .with_help_message(
            "lowercase letters, digits, and hyphens; it names the registry in its IRIs, scopes, and the catalogue",
        )
        .with_validator(identifier_validator("the registry identifier", Vec::new()))
        .prompt()
        .map_err(prompt_error)?;
    let default = default_title(&id);
    let title = Text::new("Registry title")
        .with_help_message("the name a reader sees; enter to keep the default")
        .with_default(&default)
        .with_validator(|input: &str| -> Result<Validation, CustomUserError> {
            Ok(if input.trim().is_empty() {
                Validation::Invalid("the registry title must not be empty".into())
            } else {
                Validation::Valid
            })
        })
        .prompt()
        .map_err(prompt_error)?;
    Ok(RegistrySelection { id, title })
}

/// Asks which concepts become entities.
fn ask_concepts(model: &Model) -> Result<Vec<String>, Diagnostic> {
    let options = concept_options(model)?;
    let labels: Vec<&str> = options.iter().map(|option| option.label.as_str()).collect();
    let chosen = MultiSelect::new("Which concepts become entities?", labels)
        .with_validator(MinLengthValidator::new(1))
        .with_help_message("space to toggle, type to filter, enter to confirm")
        .raw_prompt()
        .map_err(prompt_error)?;
    Ok(chosen
        .into_iter()
        .map(|option| options[option.index].concept.clone())
        .collect())
}

/// Asks which properties of one concept become fields.
fn ask_properties(title: &str, offer: &PropertyOffer) -> Result<Vec<ChosenProperty>, Diagnostic> {
    let labels: Vec<&str> = offer
        .offered
        .iter()
        .map(|option| option.label.as_str())
        .collect();
    let ticked: Vec<usize> = offer
        .offered
        .iter()
        .enumerate()
        .filter(|(_, option)| option.ticked)
        .map(|(index, _)| index)
        .collect();
    let message = format!("Which properties of {title} become fields?");
    let chosen = MultiSelect::new(&message, labels)
        .with_default(&ticked)
        .with_validator(MinLengthValidator::new(1))
        .with_help_message("space to toggle, type to filter, enter to confirm")
        .raw_prompt()
        .map_err(prompt_error)?;
    Ok(chosen
        .into_iter()
        .map(|option| ChosenProperty {
            name: offer.offered[option.index].name.clone(),
            target: None,
        })
        .collect())
}

/// Asks which chosen entity a reference points at. The answer is the concept
/// behind the identifier shown, because the naming question may still rename
/// the entity that carries it.
fn ask_target(concept: &str, property: &str, choices: &[String]) -> Result<String, Diagnostic> {
    let ids: Vec<String> = choices
        .iter()
        .map(|name| resolve::kebab_case(name))
        .collect();
    let message = format!("Which entity does {concept}.{property} point at?");
    let chosen = Select::new(&message, ids)
        .with_help_message("type to filter, arrows to move, enter to select")
        .raw_prompt()
        .map_err(prompt_error)?;
    Ok(choices[chosen.index].clone())
}

/// Shows the identifiers the entities would carry and asks whether to keep
/// them.
fn ask_naming(entities: &mut [ChosenEntity]) -> Result<(), Diagnostic> {
    for entity in entities.iter() {
        let id = resolve::kebab_case(&entity.concept);
        eprintln!(
            "{id}: route {}, identifier field {id}-code",
            resolve::pluralize(&id)
        );
    }
    let keep = Confirm::new("Keep the default identifiers and routes?")
        .with_default(true)
        .with_help_message(
            "they name the collection routes, the record identifiers, and the fields a client reads",
        )
        .prompt()
        .map_err(prompt_error)?;
    if keep {
        return Ok(());
    }
    let mut taken = Taken::default();
    for entity in entities {
        entity.naming = ask_entity_naming(&entity.concept, &mut taken)?;
    }
    Ok(())
}

/// Asks for the three identifiers of one entity. Each default is what the
/// resolver derives from the answer before it, so an answer left at its
/// default is left out of the selection entirely.
fn ask_entity_naming(concept: &str, taken: &mut Taken) -> Result<Naming, Diagnostic> {
    let default_id = resolve::kebab_case(concept);
    let id = ask_identifier(
        &format!("Entity identifier for {concept}"),
        &default_id,
        "an entity identifier",
        &taken.ids,
    )?;
    let default_route = resolve::pluralize(&id);
    let route = ask_identifier(
        &format!("Collection route for {concept}"),
        &default_route,
        "a route",
        &taken.routes,
    )?;
    let default_field = format!("{id}-code");
    let identifier_field = ask_identifier(
        &format!("Identifier field for {concept}"),
        &default_field,
        "a field identifier",
        &[],
    )?;
    taken.ids.push(id.clone());
    taken.routes.push(route.clone());
    Ok(Naming {
        id: (id != default_id).then_some(id),
        route: (route != default_route).then_some(route),
        identifier_field: (identifier_field != default_field).then_some(identifier_field),
    })
}

fn ask_identifier(
    message: &str,
    default: &str,
    what: &'static str,
    taken: &[String],
) -> Result<String, Diagnostic> {
    Text::new(message)
        .with_default(default)
        .with_help_message("enter to keep the default")
        .with_validator(identifier_validator(what, taken.to_vec()))
        .prompt()
        .map_err(prompt_error)
}

/// Asks which code lists the project writes out in full.
fn ask_vocabularies(options: &[VocabularyOption]) -> Result<Vec<usize>, Diagnostic> {
    let labels: Vec<&str> = options.iter().map(|option| option.label.as_str()).collect();
    let listed: Vec<usize> = options
        .iter()
        .enumerate()
        .filter(|(_, option)| option.listed)
        .map(|(index, _)| index)
        .collect();
    let chosen = MultiSelect::new("Which code lists should the project list in full?", labels)
        .with_default(&listed)
        .with_help_message(
            "space to toggle, enter to confirm; an unticked list is carried as a bounded code instead",
        )
        .raw_prompt()
        .map_err(prompt_error)?;
    Ok(chosen.into_iter().map(|option| option.index).collect())
}

/// Shows the selection the answers describe and asks whether to derive from
/// it.
fn confirm_selection(selection: &Selection) -> Result<bool, Diagnostic> {
    eprintln!("{}", selection.to_yaml());
    Confirm::new("Derive the project from this selection?")
        .with_default(true)
        .with_help_message("the document above is written into the project beside what it derives")
        .prompt()
        .map_err(prompt_error)
}

/// Refuses an answer the resolver would refuse, inline at the prompt and in
/// the resolver's own words: one it reads as no identifier at all, and one
/// another entity of this run already carries.
fn identifier_validator(
    what: &'static str,
    taken: Vec<String>,
) -> impl Fn(&str) -> Result<Validation, CustomUserError> + Clone {
    move |input: &str| {
        if let Some(refusal) = resolve::identifier_refusal(input, what) {
            return Ok(Validation::Invalid(refusal.into()));
        }
        Ok(if taken.iter().any(|value| value == input) {
            Validation::Invalid(format!("`{input}` is already taken by another entity").into())
        } else {
            Validation::Valid
        })
    }
}

/// The registry title offered by default: the identifier read back in words.
fn default_title(id: &str) -> String {
    id.split('-')
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut characters = word.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(characters).collect()
            })
        })
        .collect::<Vec<String>>()
        .join(" ")
}

/// The concepts a project can be derived from, by schema file then name.
///
/// An abstract concept is left out: it exists to be specialised, and the
/// resolver refuses it by name. So is a concept with no property the resolver
/// can carry, because the property question would have nothing to ask about
/// it.
fn concept_options(model: &Model) -> Result<Vec<ConceptOption>, Diagnostic> {
    let mut classes: Vec<&ClassDef> = model
        .classes
        .values()
        .filter(|class| !class.is_abstract)
        .collect();
    classes.sort_by(|left, right| (&left.schema, &left.name).cmp(&(&right.schema, &right.name)));
    let mut options = Vec::new();
    for class in classes {
        let alone = [class.name.clone()];
        if property_offer(model, &class.name, &alone)?
            .offered
            .is_empty()
        {
            continue;
        }
        let mut label = format!("{} ({})", title(class), class.schema);
        let summary = summary(class.description.as_deref().unwrap_or_default());
        if !summary.is_empty() {
            label.push_str(": ");
            label.push_str(&summary);
        }
        options.push(ConceptOption {
            concept: class.name.clone(),
            label,
        });
    }
    Ok(options)
}

/// What the property question offers for `concept` beside `concepts`, and
/// what it leaves out because the resolver cannot carry it.
fn property_offer(
    model: &Model,
    concept: &str,
    concepts: &[String],
) -> Result<PropertyOffer, Diagnostic> {
    let slots = model
        .induced_slots(concept)
        .map_err(|error| resolve::model_error("model", &error))?;
    let mut offered = Vec::new();
    let mut withheld = Vec::new();
    for slot in slots {
        match resolve::property_support(model, slot, concepts) {
            Ok(()) => offered.push(PropertyOption {
                name: slot.name.clone(),
                label: property_label(model, slot, concepts)?,
                ticked: ticked(slot)?,
            }),
            Err(reason) => withheld.push(WithheldProperty {
                name: slot.name.clone(),
                reason,
            }),
        }
    }
    Ok(PropertyOffer { offered, withheld })
}

/// The one line a property is offered by: its name in the model, the shape
/// the field takes, how the model rates it, and how many of the systems
/// behind the model record it.
fn property_label(
    model: &Model,
    slot: &SlotDef,
    concepts: &[String],
) -> Result<String, Diagnostic> {
    let mut label = format!("{}: {}", slot.name, shape(model, slot, concepts));
    match publicschema::sensitivity(slot)
        .map_err(|error| resolve::convention_error("model", &error))?
    {
        Some(Sensitivity::Sensitive) => label.push_str(", sensitive"),
        Some(Sensitivity::Restricted) => label.push_str(", restricted"),
        None => {}
    }
    if let Some(convergence) = convergence(slot)? {
        label.push_str(&format!(
            " ({} of {} systems)",
            convergence.system_count, convergence.total_systems
        ));
    }
    Ok(label)
}

/// A short phrase for the field a property becomes. Whether a property can
/// become a field at all is the resolver's rule; this only names the shape
/// the answer takes, so a reader recognises it in the derived project.
fn shape(model: &Model, slot: &SlotDef, concepts: &[String]) -> String {
    match &slot.range {
        Range::Type(name) => {
            if publicschema::bespoke_type(slot).is_some() {
                "structured value".to_owned()
            } else if slot.multivalued {
                format!("list of {}", scalar_shape(name))
            } else {
                scalar_shape(name).to_owned()
            }
        }
        Range::Enum(_) => {
            if slot.multivalued {
                "list of codes from a code list".to_owned()
            } else {
                "code from a code list".to_owned()
            }
        }
        Range::Class(name) => {
            if concepts
                .iter()
                .any(|concept| resolve::fits_range(model, concept, name))
            {
                "reference".to_owned()
            } else {
                "structured value carried inline".to_owned()
            }
        }
    }
}

fn scalar_shape(name: &str) -> &str {
    match name {
        "string" | "ncname" => "text",
        "uri" | "uriorcurie" | "curie" => "URI",
        "integer" => "whole number",
        "float" | "double" | "decimal" => "decimal number",
        "date" => "date",
        "datetime" | "date_or_datetime" => "date and time",
        "boolean" => "yes or no",
        other => other,
    }
}

/// True for a property offered already ticked: one the model requires, or one
/// that most of the systems behind the model already record.
fn ticked(slot: &SlotDef) -> Result<bool, Diagnostic> {
    if slot.required {
        return Ok(true);
    }
    Ok(convergence(slot)?
        .is_some_and(|convergence| convergence.share() >= TICKED_CONVERGENCE_SHARE))
}

fn convergence(slot: &SlotDef) -> Result<Option<publicschema::Convergence>, Diagnostic> {
    publicschema::convergence(slot).map_err(|error| resolve::convention_error("model", &error))
}

/// The one line printed before the property question when the concept
/// carries properties the project cannot.
fn withheld_line(title: &str, withheld: &[WithheldProperty]) -> Option<String> {
    if withheld.is_empty() {
        return None;
    }
    let entries: Vec<String> = withheld
        .iter()
        .map(|property| format!("{} ({})", property.name, property.reason))
        .collect();
    Some(format!("Not offered for {title}: {}", entries.join("; ")))
}

/// The references the adopter has to settle, in the order they are asked.
fn reference_questions(
    model: &Model,
    entities: &[ChosenEntity],
) -> Result<Vec<ReferenceQuestion>, Diagnostic> {
    let concepts: Vec<&str> = entities
        .iter()
        .map(|entity| entity.concept.as_str())
        .collect();
    let mut questions = Vec::new();
    for (position, entity) in entities.iter().enumerate() {
        for (index, property) in entity.properties.iter().enumerate() {
            let slot = induced_slot(model, &entity.concept, &property.name)?;
            let Range::Class(range) = &slot.range else {
                continue;
            };
            if slot.multivalued {
                continue;
            }
            let choices: Vec<String> = concepts
                .iter()
                .filter(|concept| resolve::fits_range(model, concept, range))
                .map(|concept| (*concept).to_owned())
                .collect();
            if choices.len() > 1 {
                questions.push(ReferenceQuestion {
                    entity: position,
                    property: index,
                    choices,
                });
            }
        }
    }
    Ok(questions)
}

/// The enumerations the chosen properties draw on, in model-name order.
fn vocabulary_options(
    model: &Model,
    entities: &[ChosenEntity],
) -> Result<Vec<VocabularyOption>, Diagnostic> {
    let mut drawn = BTreeSet::new();
    for entity in entities {
        for property in &entity.properties {
            let slot = induced_slot(model, &entity.concept, &property.name)?;
            if let Range::Enum(name) = &slot.range {
                drawn.insert(name.clone());
            }
        }
    }
    Ok(drawn
        .into_iter()
        .map(|name| {
            let definition = &model.enums[&name];
            VocabularyOption {
                label: format!("{} ({} values)", title(definition), definition.values.len()),
                listed: definition.values.len() <= INLINE_VOCABULARY_THRESHOLD,
                r#enum: name,
            }
        })
        .collect())
}

/// The code-list answers worth writing down: the ones that differ from the
/// size rule the resolver applies on its own, so the echoed selection stays
/// as short as the project it describes.
fn vocabulary_overrides(
    options: &[VocabularyOption],
    listed: &[usize],
) -> Vec<VocabularySelection> {
    options
        .iter()
        .enumerate()
        .filter_map(|(index, option)| {
            let inline = listed.contains(&index);
            (inline != option.listed).then(|| VocabularySelection {
                r#enum: option.r#enum.clone(),
                mode: if inline {
                    VocabularyMode::Inline
                } else {
                    VocabularyMode::Code
                },
            })
        })
        .collect()
}

/// The selection the answers describe.
fn assemble(
    model_name: ModelName,
    model_version: &str,
    registry: RegistrySelection,
    entities: &[ChosenEntity],
    vocabularies: Vec<VocabularySelection>,
) -> Selection {
    Selection {
        api_version: API_VERSION.to_owned(),
        kind: KIND.to_owned(),
        model: model_name,
        model_version: Some(model_version.to_owned()),
        registry,
        entities: entities
            .iter()
            .map(|entity| EntitySelection {
                concept: entity.concept.clone(),
                id: entity.naming.id.clone(),
                route: entity.naming.route.clone(),
                identifier_field: entity.naming.identifier_field.clone(),
                // Every entity keeps the classification the resolver assigns;
                // the README written beside the selection says how to raise
                // one where the records deserve it.
                classification: None,
                properties: entity
                    .properties
                    .iter()
                    .map(|property| PropertySelection {
                        name: property.name.clone(),
                        target: property
                            .target
                            .as_ref()
                            .map(|concept| entity_id(entities, concept)),
                    })
                    .collect(),
            })
            .collect(),
        vocabularies,
    }
}

/// The identifier the entity of `concept` carries: the answer to the naming
/// question when there was one, and the identifier the resolver derives
/// otherwise.
fn entity_id(entities: &[ChosenEntity], concept: &str) -> String {
    entities
        .iter()
        .find(|entity| entity.concept == concept)
        .and_then(|entity| entity.naming.id.clone())
        .unwrap_or_else(|| resolve::kebab_case(concept))
}

/// The slot a concept carries under `property`.
fn induced_slot<'a>(
    model: &'a Model,
    concept: &str,
    property: &str,
) -> Result<&'a SlotDef, Diagnostic> {
    model
        .induced_slots(concept)
        .map_err(|error| resolve::model_error("model", &error))?
        .into_iter()
        .find(|slot| slot.name == property)
        .ok_or_else(|| {
            diagnostic(
                "init.model.invalid",
                "model",
                &format!("`{concept}` carries no property named `{property}`"),
            )
        })
}

/// A definition's own label, or its name when the model gives it none.
fn title(item: &impl publicschema::Labeled) -> String {
    publicschema::label(item, "en").map_or_else(|| item.name().to_owned(), str::to_owned)
}

/// The first sentence of a description, on one line and cut to the
/// description budget. A definition can describe itself in paragraphs; the
/// list stays readable instead.
fn summary(description: &str) -> String {
    let line = description.split_whitespace().collect::<Vec<_>>().join(" ");
    let sentence = match line.find(". ") {
        Some(stop) => &line[..=stop],
        None => line.as_str(),
    };
    if sentence.chars().count() <= DESCRIPTION_BUDGET {
        return sentence.to_owned();
    }
    let kept: String = sentence.chars().take(DESCRIPTION_BUDGET).collect();
    format!("{kept}\u{2026}")
}

/// Turns an inquire failure into a diagnostic. Cancelling a prompt is an
/// ordinary outcome of an interactive session, not a defect, so it reports
/// what did not happen rather than a library error.
fn prompt_error(error: InquireError) -> Diagnostic {
    match error {
        InquireError::OperationCanceled | InquireError::OperationInterrupted => cancelled(),
        other => diagnostic(
            "init.selection.prompt",
            "arguments",
            &format!("a question could not be asked: {other}"),
        ),
    }
}

/// The refusal a cancelled session reports. Nothing is written until the last
/// question is answered, so there is nothing to undo.
fn cancelled() -> Diagnostic {
    diagnostic(
        "init.selection.cancelled",
        "arguments",
        "cancelled at a prompt; nothing was written",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;

    fn model() -> &'static Model {
        static MODEL: OnceLock<Model> = OnceLock::new();
        MODEL.get_or_init(|| publicschema::model().expect("the snapshot reads"))
    }

    fn offer(concept: &str, concepts: &[&str]) -> PropertyOffer {
        let concepts: Vec<String> = concepts.iter().map(|name| (*name).to_owned()).collect();
        property_offer(model(), concept, &concepts).expect("the concept offers its properties")
    }

    fn offered<'a>(offer: &'a PropertyOffer, name: &str) -> &'a PropertyOption {
        offer
            .offered
            .iter()
            .find(|option| option.name == name)
            .unwrap_or_else(|| panic!("{name} is offered"))
    }

    fn chosen(concept: &str, properties: &[&str]) -> ChosenEntity {
        ChosenEntity {
            concept: concept.to_owned(),
            properties: properties
                .iter()
                .map(|name| ChosenProperty {
                    name: (*name).to_owned(),
                    target: None,
                })
                .collect(),
            naming: Naming::default(),
        }
    }

    fn registry() -> RegistrySelection {
        RegistrySelection {
            id: "example".to_owned(),
            title: "Example".to_owned(),
        }
    }

    #[test]
    fn a_registry_title_reads_the_identifier_back_in_words() {
        assert_eq!(default_title("household-registry"), "Household Registry");
        assert_eq!(default_title("places"), "Places");
        assert_eq!(default_title("admin-2-units"), "Admin 2 Units");
    }

    #[test]
    fn an_identifier_answer_is_refused_at_the_prompt_the_way_the_resolver_would() {
        let validate = identifier_validator("an entity identifier", vec!["home".to_owned()]);
        assert_eq!(validate("place").expect("validated"), Validation::Valid);
        assert_eq!(
            validate("Place").expect("validated"),
            Validation::Invalid(
                resolve::identifier_refusal("Place", "an entity identifier")
                    .expect("refused")
                    .into()
            )
        );
        assert_eq!(
            validate("home").expect("validated"),
            Validation::Invalid("`home` is already taken by another entity".into())
        );
    }

    #[test]
    fn concepts_are_offered_by_schema_then_name_without_the_abstract_ones() {
        let options = concept_options(model()).expect("the model lists its concepts");
        let keys: Vec<(&str, &str)> = options
            .iter()
            .map(|option| {
                let class = &model().classes[&option.concept];
                (class.schema.as_str(), class.name.as_str())
            })
            .collect();
        let mut ordered = keys.clone();
        ordered.sort_unstable();
        assert_eq!(keys, ordered);
        assert!(options.iter().any(|option| option.concept == "Person"));
        assert!(
            !options.iter().any(|option| option.concept == "Party"),
            "an abstract concept is not offered"
        );
        let person = options
            .iter()
            .find(|option| option.concept == "Person")
            .expect("Person is offered");
        assert!(
            person.label.starts_with("Person (publicschema-identity): "),
            "{}",
            person.label
        );
        assert!(
            person.label.ends_with('…'),
            "a long description is cut: {}",
            person.label
        );
        let service_point = options
            .iter()
            .find(|option| option.concept == "ServicePoint")
            .expect("ServicePoint is offered");
        assert!(
            service_point.label.starts_with("Service Point ("),
            "a concept is named by its label: {}",
            service_point.label
        );
    }

    #[test]
    fn a_property_holding_many_concepts_is_withheld_with_the_resolver_sentence() {
        let offer = offer("Location", &["Location"]);
        assert!(offer.offered.iter().all(|option| option.name != "geocodes"));
        let withheld = offer
            .withheld
            .iter()
            .find(|property| property.name == "geocodes")
            .expect("a multivalued reference is withheld");
        assert!(
            withheld.reason.contains("holds many"),
            "{}",
            withheld.reason
        );
        let line = withheld_line("Location", &offer.withheld).expect("a line is printed");
        assert!(line.starts_with("Not offered for Location: "), "{line}");
        assert!(line.contains("geocodes ("), "{line}");
        assert_eq!(withheld_line("Location", &[]), None);
    }

    #[test]
    fn a_property_is_labelled_by_shape_sensitivity_and_convergence() {
        let places = offer("Location", &["Location"]);
        let offer = offer("Person", &["Person"]);
        assert_eq!(
            offered(&offer, "marital_status").label,
            "marital_status: code from a code list, sensitive (3 of 5 systems)"
        );
        assert_eq!(
            offered(&offer, "religion").label,
            "religion: text, restricted"
        );
        assert_eq!(
            offered(&offer, "date_of_birth").label,
            "date_of_birth: date (6 of 6 systems)"
        );
        assert_eq!(
            offered(&offer, "domicile").label,
            "domicile: structured value carried inline"
        );
        assert_eq!(
            offered(&places, "administrative_level").label,
            "administrative_level: whole number (3 of 6 systems)"
        );
    }

    #[test]
    fn properties_are_ticked_when_the_evidence_says_most_systems_record_them() {
        let offer = offer("Person", &["Person"]);
        assert!(offered(&offer, "date_of_birth").ticked, "6 of 6 systems");
        assert!(offered(&offer, "marital_status").ticked, "3 of 5 systems");
        assert!(!offered(&offer, "occupation").ticked, "2 of 6 systems");
        assert!(!offered(&offer, "religion").ticked, "no evidence recorded");
    }

    #[test]
    fn a_property_pointing_at_a_chosen_concept_is_offered_as_a_reference() {
        let alone = offer("Household", &["Household"]);
        assert_eq!(
            offered(&alone, "location").label,
            "location: structured value carried inline (2 of 4 systems)"
        );
        let beside = offer("Household", &["Household", "Location"]);
        assert_eq!(
            offered(&beside, "location").label,
            "location: reference (2 of 4 systems)"
        );
    }

    #[test]
    fn a_reference_that_fits_two_chosen_concepts_becomes_a_question() {
        let entities = [
            chosen("GroupMembership", &["group", "role"]),
            chosen("Household", &["name"]),
            chosen("Family", &["name"]),
        ];
        let questions = reference_questions(model(), &entities).expect("the model resolves ranges");
        assert_eq!(
            questions,
            [ReferenceQuestion {
                entity: 0,
                property: 0,
                choices: vec!["Household".to_owned(), "Family".to_owned()],
            }]
        );
        let single = [
            chosen("GroupMembership", &["group"]),
            chosen("Household", &["name"]),
        ];
        assert!(reference_questions(model(), &single)
            .expect("the model resolves ranges")
            .is_empty());
    }

    #[test]
    fn code_lists_are_listed_in_full_by_size_and_only_differences_are_written() {
        let entities = [chosen(
            "Person",
            &["sex", "preferred_language", "given_name"],
        )];
        let options = vocabulary_options(model(), &entities).expect("the model lists its enums");
        let names: Vec<&str> = options
            .iter()
            .map(|option| option.r#enum.as_str())
            .collect();
        assert_eq!(names, ["Language", "Sex"]);
        let sex = &options[1];
        assert!(sex.listed, "a short code list is listed in full");
        assert!(sex.label.starts_with("Sex ("), "{}", sex.label);
        assert!(sex.label.ends_with(" values)"), "{}", sex.label);
        assert!(!options[0].listed, "a long code list is carried as a code");

        assert!(vocabulary_overrides(&options, &[1]).is_empty());
        assert_eq!(
            vocabulary_overrides(&options, &[0, 1]),
            [VocabularySelection {
                r#enum: "Language".to_owned(),
                mode: VocabularyMode::Inline,
            }]
        );
        assert_eq!(
            vocabulary_overrides(&options, &[]),
            [VocabularySelection {
                r#enum: "Sex".to_owned(),
                mode: VocabularyMode::Code,
            }]
        );
    }

    #[test]
    fn a_scripted_run_assembles_a_selection_that_round_trips_and_resolves() {
        let entities = [
            ChosenEntity {
                naming: Naming {
                    id: Some("member".to_owned()),
                    route: Some("members".to_owned()),
                    identifier_field: None,
                },
                ..chosen("Person", &["given_name", "sex"])
            },
            ChosenEntity {
                properties: vec![
                    ChosenProperty {
                        name: "group".to_owned(),
                        target: Some("Household".to_owned()),
                    },
                    ChosenProperty {
                        name: "person".to_owned(),
                        target: None,
                    },
                ],
                ..chosen("GroupMembership", &[])
            },
            chosen("Household", &["name"]),
            chosen("Family", &["name"]),
        ];
        let selection = assemble(
            ModelName::Publicschema,
            "0.3.0",
            registry(),
            &entities,
            vocabulary_overrides(
                &vocabulary_options(model(), &entities).expect("the model lists its enums"),
                &[],
            ),
        );
        assert_eq!(selection.api_version, API_VERSION);
        assert_eq!(selection.kind, KIND);
        assert_eq!(selection.model_version.as_deref(), Some("0.3.0"));
        assert_eq!(selection.entities[0].id.as_deref(), Some("member"));
        assert_eq!(selection.entities[0].route.as_deref(), Some("members"));
        assert_eq!(selection.entities[0].identifier_field, None);
        assert_eq!(selection.entities[0].classification, None);
        assert_eq!(
            selection.entities[1].properties[0].target.as_deref(),
            Some("household"),
            "a target names the entity, not the concept"
        );
        assert_eq!(selection.entities[1].properties[1].target, None);
        assert_eq!(
            selection.vocabularies,
            [VocabularySelection {
                r#enum: "Sex".to_owned(),
                mode: VocabularyMode::Code,
            }]
        );

        let echoed = Selection::parse("echo", selection.to_yaml().as_bytes()).expect("parses");
        assert_eq!(echoed, selection);
        let plan = resolve::resolve(&selection, model()).expect("the selection resolves");
        assert_eq!(plan.entities[0].id, "member");
    }

    #[test]
    fn a_target_answered_before_a_rename_still_names_the_renamed_entity() {
        let entities = [
            ChosenEntity {
                properties: vec![ChosenProperty {
                    name: "group".to_owned(),
                    target: Some("Household".to_owned()),
                }],
                ..chosen("GroupMembership", &[])
            },
            ChosenEntity {
                naming: Naming {
                    id: Some("home".to_owned()),
                    ..Naming::default()
                },
                ..chosen("Household", &["name"])
            },
            chosen("Family", &["name"]),
        ];
        let selection = assemble(
            ModelName::Publicschema,
            "0.3.0",
            registry(),
            &entities,
            Vec::new(),
        );
        assert_eq!(
            selection.entities[0].properties[0].target.as_deref(),
            Some("home")
        );
        resolve::resolve(&selection, model()).expect("the selection resolves");
    }

    #[test]
    fn every_concept_resolves_from_the_answers_the_wizard_can_produce() {
        let options = concept_options(model()).expect("the model lists its concepts");
        for class in model().classes.values().filter(|class| !class.is_abstract) {
            let concepts = [class.name.clone()];
            let offer = property_offer(model(), &class.name, &concepts)
                .expect("the concept offers its properties");
            let offered_here = options.iter().any(|listed| listed.concept == class.name);
            if offer.offered.is_empty() {
                assert!(
                    !offered_here,
                    "{} carries no property and is not offered",
                    class.name
                );
                continue;
            }
            assert!(offered_here, "{} is offered", class.name);
            for properties in [
                offer
                    .offered
                    .iter()
                    .filter(|property| property.ticked)
                    .collect::<Vec<_>>(),
                offer.offered.iter().collect::<Vec<_>>(),
            ] {
                let entity = ChosenEntity {
                    concept: class.name.clone(),
                    properties: properties
                        .iter()
                        .map(|property| ChosenProperty {
                            name: property.name.clone(),
                            target: None,
                        })
                        .collect(),
                    naming: Naming::default(),
                };
                let entities = [entity];
                assert!(
                    reference_questions(model(), &entities)
                        .expect("the model resolves ranges")
                        .is_empty(),
                    "{} alone leaves a reference unanswered",
                    class.name
                );
                let selection = assemble(
                    ModelName::Publicschema,
                    &resolve::model_facts(model())
                        .expect("the model is pinned")
                        .version,
                    registry(),
                    &entities,
                    vocabulary_overrides(
                        &vocabulary_options(model(), &entities).expect("the model lists its enums"),
                        &[],
                    ),
                );
                resolve::resolve(&selection, model()).unwrap_or_else(|refusal| {
                    panic!("{}: {}", class.name, refusal.message);
                });
            }
        }
    }

    #[test]
    fn a_cancelled_prompt_reports_that_nothing_was_written() {
        let cancelled = prompt_error(InquireError::OperationCanceled);
        assert_eq!(cancelled.code, "init.selection.cancelled");
        assert_eq!(cancelled.path, "arguments");
        assert_eq!(
            cancelled.message,
            "cancelled at a prompt; nothing was written"
        );
        assert_eq!(
            prompt_error(InquireError::OperationInterrupted).code,
            "init.selection.cancelled"
        );
        assert_eq!(
            prompt_error(InquireError::NotTTY).code,
            "init.selection.prompt"
        );
    }
}
